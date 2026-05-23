#include "ProxyInboundClientConnection.h"
#include "ProxyRunner.hpp"
#include "auto/tl/cocoon_api.h"
#include "checksum.h"
#include "cocoon-tl-utils/cocoon-tl-utils.hpp"
#include "td/actor/PromiseFuture.h"
#include "td/actor/actor.h"
#include "td/utils/buffer.h"
#include "tl/TlObject.h"

namespace cocoon {

void ProxyInboundClientConnection::receive_handshake_query(td::BufferSlice message,
                                                           td::Promise<td::BufferSlice> promise) {
  auto P = td::PromiseCreator::lambda([promise = std::move(promise), connection_id = connection_id(),
                                       self_id = actor_id(runner())](td::Result<td::BufferSlice> R) mutable {
    if (R.is_error()) {
      td::actor::send_closure(self_id, &ProxyRunner::close_connection, connection_id);
    }
    promise.set_result(std::move(R));
  });
  switch (state_) {
    case State::None:
      return receive_connect_to_proxy_query(std::move(message), std::move(P));
    case State::Auth:
      return receive_auth_query(std::move(message), std::move(P));
    case State::Ok:
      return P.set_error(td::Status::Error("already authorized"));
    case State::Failed:
      return P.set_error(td::Status::Error("connection is closing"));
  }
}

void ProxyInboundClientConnection::receive_connect_to_proxy_query(td::BufferSlice message,
                                                                  td::Promise<td::BufferSlice> promise) {
  TRY_RESULT_PROMISE(promise, obj, cocoon::fetch_tl_object<cocoon_api::client_connectToProxy>(message, true));
  if (!(obj->params_->flags_ & 1)) {
    return promise.set_error(td::Status::Error(ton::ErrorCode::error, "too old client"));
  }
  if (obj->params_->is_test_ != runner()->is_test()) {
    return promise.set_error(td::Status::Error(ton::ErrorCode::error, "test mode mismatch"));
  }
  TRY_RESULT_PROMISE(promise, client_owner_address, block::StdAddress::parse(obj->params_->client_owner_address_));
  if (!client_owner_address.is_valid()) {
    return promise.set_error(td::Status::Error(ton::ErrorCode::error, "cannot parse client owner address"));
  }
  if ((td::uint32)obj->min_config_version_ > runner()->active_config_version()) {
    return promise.set_error(td::Status::Error(ton::ErrorCode::error, "active config version is too low"));
  }
  auto remote_min_proto_version = (obj->params_->flags_ & 2) ? obj->params_->min_proto_version_ : 0;
  auto remote_max_proto_version = (obj->params_->flags_ & 2) ? obj->params_->max_proto_version_ : 0;

  if (remote_max_proto_version < runner()->min_proto_version() ||
      runner()->max_proto_version() < remote_min_proto_version) {
    return promise.set_error(
        td::Status::Error(ton::ErrorCode::protoviolation, "cannot choose common protocol version"));
  }
  proto_version_ = std::min(remote_max_proto_version, runner()->max_proto_version());

  client_owner_address.bounceable = false;
  client_owner_address.testnet = runner()->is_testnet();
  client_owner_address_str_ = client_owner_address.rserialize(true);
  client_info_ = runner()->get_client(client_owner_address_str_);

  if (client_info_ && (client_info_->is_closing() || client_info_->is_closed())) {
    return promise.set_error(td::Status::Error(ton::ErrorCode::error, "client is closing"));
  }

  if (runner()->ton_disabled()) {
    if (!client_info_) {
      TRY_RESULT_PROMISE_ASSIGN(promise, client_info_, runner()->register_client(client_owner_address));
      client_info_->pseudo_initialize();
    }
    send_connected(ton::create_tl_object<cocoon_api::client_proxyConnectionAuthShort>(client_info_->secret_hash(), 0),
                   std::move(promise));
    return;
  }

  TRY_RESULT_PROMISE_ASSIGN(promise, connecting_client_info_,
                            runner()->register_connecting_client(client_owner_address, connection_id()));

  CHECK(connecting_client_info_);
  if (client_info_) {
    send_connected(ton::create_tl_object<cocoon_api::client_proxyConnectionAuthShort>(client_info_->secret_hash(),
                                                                                      connecting_client_info_->nonce),
                   std::move(promise));
  } else {
    send_connected(ton::create_tl_object<cocoon_api::client_proxyConnectionAuthLong>(connecting_client_info_->nonce),
                   std::move(promise));
  }
}

void ProxyInboundClientConnection::send_connected(ton::tl_object_ptr<cocoon_api::client_ProxyConnectionAuth> auth,
                                                  td::Promise<td::BufferSlice> promise) {
  state_ = State::Auth;
  auto params = ton::create_tl_object<cocoon_api::proxy_params>(
      1 | (proto_version_ > 0 ? 2 : 0), runner()->public_key(), runner()->owner_address().rserialize(true),
      runner()->cur_sc_address().rserialize(true), runner()->is_test(), proto_version_);
  promise.set_value(cocoon::create_serialize_tl_object<cocoon_api::client_connectedToProxy>(
      std::move(params), client_sc_address().rserialize(true), std::move(auth),
      client_info_ ? client_info_->signed_payment() : ton::create_tl_object<cocoon_api::proxy_signedPaymentEmpty>()));
}

block::StdAddress ProxyInboundClientConnection::client_sc_address() const {
  if (client_info_) {
    return client_info_->client_sc_address();
  } else {
    CHECK(connecting_client_info_);
    return connecting_client_info_->smartcontract;
  }
}

void ProxyInboundClientConnection::receive_auth_query(td::BufferSlice message, td::Promise<td::BufferSlice> promise) {
  if (client_info_ && (client_info_->is_closing() || client_info_->is_closed())) {
    return promise.set_error(td::Status::Error(ton::ErrorCode::error, "client is closing"));
  }
  auto R1 = fetch_tl_object<cocoon_api::client_authorizeWithProxyLong>(message, true);
  if (R1.is_ok()) {
    return receive_auth_query(*R1.move_as_ok(), std::move(promise));
  }
  auto R2 = fetch_tl_object<cocoon_api::client_authorizeWithProxyShort>(message, true);
  if (R2.is_ok()) {
    return receive_auth_query(*R2.move_as_ok(), std::move(promise));
  }
  return promise.set_error(td::Status::Error("expected auth message"));
}

void ProxyInboundClientConnection::receive_auth_query(cocoon_api::client_authorizeWithProxyLong &auth,
                                                      td::Promise<td::BufferSlice> promise) {
  if (runner()->ton_disabled()) {
    send_auth_success(std::move(promise));
    return;
  }
  if (connecting_client_info_->received) {
    connecting_client_info_ = nullptr;
    send_auth_success(std::move(promise));
    return;
  }

  if (connecting_client_info_->promise) {
    return promise.set_error(td::Status::Error("duplicate auth message"));
  }

  connecting_client_info_->promise = std::move(promise);
}

void ProxyInboundClientConnection::receive_auth_query(cocoon_api::client_authorizeWithProxyShort &auth,
                                                      td::Promise<td::BufferSlice> promise) {
  if (client_info_ && td::sha256_bits256(auth.data_.as_slice()) == client_info_->secret_hash()) {
    send_auth_success(std::move(promise));
    return;
  }

  return promise.set_error(td::Status::Error("sha256 mismatch"));
}

void ProxyInboundClientConnection::send_auth_success(td::Promise<td::BufferSlice> promise) {
  state_ = State::Ok;
  handshake_completed();
  runner()->sign_client_payment(*client_info_);
  promise.set_value(cocoon::create_serialize_tl_object<cocoon_api::client_authorizationWithProxySuccess>(
      client_info_->signed_payment(), client_info_->tokens_committed_to_db(), client_info_->tokens_max()));
  remove_connecting_info();
}

void ProxyInboundClientConnection::send_auth_fail(td::Status error, td::Promise<td::BufferSlice> promise) {
  promise.set_value(cocoon::create_serialize_tl_object<cocoon_api::client_authorizationWithProxyFailed>(
      error.code(), error.message().str()));
  state_ = State::Failed;
  remove_connecting_info();
  fail_connection(std::move(error));
}

void ProxyInboundClientConnection::received_register_message(std::shared_ptr<ProxyClientInfo> client_info) {
  if (state_ != State::Auth) {
    return;
  }
  client_info_ = std::move(client_info);
  if (!connecting_client_info_->promise) {
    connecting_client_info_->received = true;
    return;
  }

  send_auth_success(std::move(connecting_client_info_->promise));
}

void ProxyInboundClientConnection::pre_close() {
  remove_connecting_info();
  state_ = State::Failed;
}

void ProxyInboundClientConnection::remove_connecting_info() {
  if (connecting_client_info_) {
    runner()->unregister_connecting_client(connecting_client_info_->nonce);
    connecting_client_info_ = nullptr;
  }
}

}  // namespace cocoon
