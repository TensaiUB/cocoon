#include "ClientProxyConnection.h"
#include "ClientRunner.hpp"

#include "auto/tl/cocoon_api.h"
#include "auto/tl/cocoon_api.hpp"
#include "cocoon-tl-utils/cocoon-tl-utils.hpp"
#include "errorcode.h"
#include "td/actor/actor.h"
#include "td/utils/int_types.h"
#include "td/utils/overloaded.h"
#include "tl/TlObject.h"
#include <memory>

namespace cocoon {

ClientRunner *ClientProxyConnection::runner() {
  return static_cast<ClientRunner *>(ProxyOutboundConnection::runner());
}

void ClientProxyConnection::send_handshake() {
  LOG(INFO) << "created connection " << connection_id() << ", sending handshake";
  if (runner()->check_image_hashes()) {
    if (!runner()->runner_config()->root_contract_config->has_proxy_hash(remote_app_hash())) {
      LOG(WARNING) << "proxy hash not in root contract registry (hash=" << remote_app_hash().to_hex() << "), but allowing anyway";
    }
  }
  {
    auto S = runner()->check_verification_key(remote_app_type(), verified_by());
    if (S.is_error()) {
      return fail_connection(std::move(S));
    }
  }
  auto params = ton::create_tl_object<cocoon_api::client_params>(3, runner()->cocoon_wallet_address().rserialize(true),
                                                                 runner()->is_test(), runner()->min_proto_version(),
                                                                 runner()->max_proto_version());
  auto req = cocoon::create_serialize_tl_object<cocoon_api::client_connectToProxy>(
      std::move(params), runner()->runner_config()->root_contract_config->version());
  runner()->send_handshake_query_to_connection(
      connection_id(), "connect", std::move(req), td::Timestamp::in(30.0),
      [runner_actor_id = actor_id(runner()), runner = runner(),
       connection_id = connection_id()](td::Result<td::BufferSlice> R) {
        td::actor::send_lambda(runner_actor_id, [runner, connection_id, R = std::move(R)]() mutable {
          auto self = (ClientProxyConnection *)runner->get_connection(connection_id);
          if (!self) {
            return;
          }
          if (R.is_ok()) {
            self->received_handshake_answer(R.move_as_ok());
          } else {
            self->fail_connection(R.move_as_error());
          }
        });
      });
}

void ClientProxyConnection::received_handshake_answer(td::BufferSlice answer) {
  std::shared_ptr<ClientProxyInfo> proxy;
  ton::tl_object_ptr<cocoon_api::client_ProxyConnectionAuth> auth;
  auto S = [&]() -> td::Status {
    TRY_RESULT(obj, fetch_tl_object<cocoon_api::client_connectedToProxy>(answer, true));
    if (!(obj->params_->flags_ & 3)) {
      return td::Status::Error(ton::ErrorCode::error, "too old proxy");
    }
    TRY_RESULT(proxy_owner_address, block::StdAddress::parse(obj->params_->proxy_owner_address_));
    TRY_RESULT(proxy_sc_address, block::StdAddress::parse(obj->params_->proxy_sc_address_));
    TRY_RESULT(client_sc_address, block::StdAddress::parse(obj->client_sc_address_));
    if (obj->params_->is_test_ != runner()->is_test()) {
      return td::Status::Error(ton::ErrorCode::protoviolation, "test mode mismatch");
    }
    proto_version_ = obj->params_->proto_version_;
    TRY_RESULT(proxy, runner()->register_proxy(connection_id(), obj->params_->proxy_public_key_, proxy_owner_address,
                                               proxy_sc_address, client_sc_address, std::move(obj->signed_payment_)));
    proxy_ = proxy;
    auth = std::move(obj->auth_);
    return td::Status::OK();
  }();
  if (S.is_error()) {
    return fail_connection(S.move_as_error_prefix("failed to parse connection handshake answer: "));
  }
  LOG(DEBUG) << "connection " << connection_id() << ": processed handshake answer, running auth";

  // now try to run auth
  run_authorization(proxy_, std::move(auth));
}

void ClientProxyConnection::run_authorization(std::shared_ptr<ClientProxyInfo> proxy,
                                              ton::tl_object_ptr<cocoon_api::client_ProxyConnectionAuth> auth) {
  cocoon_api::downcast_call(
      *auth, td::overloaded([&](cocoon_api::client_proxyConnectionAuthLong &obj) { authorize_long(proxy, obj.nonce_); },
                            [&](cocoon_api::client_proxyConnectionAuthShort &obj) {
                              if (runner()->secret_hash() == obj.secret_hash_) {
                                authorize_short(proxy);
                              } else {
                                authorize_long(proxy, obj.nonce_);
                              }
                            }));
}

void ClientProxyConnection::authorize_long(std::shared_ptr<ClientProxyInfo> proxy, td::uint64 nonce) {
  LOG(DEBUG) << "connection " << connection_id() << ": running long auth";
  auto msg = proxy->sc()->create_proxy_register_message(nonce);
  runner()->cocoon_wallet()->send_transaction(proxy->sc()->address(), to_nano(1.0), {}, std::move(msg), {});
  runner()->send_handshake_query_to_connection(
      connection_id(), "auth", cocoon::create_serialize_tl_object<cocoon_api::client_authorizeWithProxyLong>(),
      td::Timestamp::in(300),
      [self_id = actor_id(runner()), connection_id = connection_id()](td::Result<td::BufferSlice> R) {
        td::actor::send_lambda(self_id, [connection_id, self_id, R = std::move(R)]() mutable {
          auto conn = static_cast<ClientProxyConnection *>(self_id.get_actor_unsafe().get_connection(connection_id));
          if (conn) {
            conn->process_auth_answer(std::move(R));
          }
        });
      });
}

void ClientProxyConnection::authorize_short(std::shared_ptr<ClientProxyInfo> proxy) {
  LOG(DEBUG) << "connection " << connection_id() << ": running short auth";
  runner()->send_handshake_query_to_connection(
      connection_id(), "auth",
      cocoon::create_serialize_tl_object<cocoon_api::client_authorizeWithProxyShort>(
          td::BufferSlice(runner()->secret_string())),
      td::Timestamp::in(300),
      [self_id = actor_id(runner()), connection_id = connection_id()](td::Result<td::BufferSlice> R) {
        td::actor::send_lambda(self_id, [connection_id, self_id, R = std::move(R)]() mutable {
          auto conn = static_cast<ClientProxyConnection *>(self_id.get_actor_unsafe().get_connection(connection_id));
          if (conn) {
            conn->process_auth_answer(std::move(R));
          }
        });
      });
}

void ClientProxyConnection::process_auth_answer(td::Result<td::BufferSlice> R) {
  if (R.is_error()) {
    fail_connection(R.move_as_error_prefix("auth unsuccessful: "));
    return;
  }

  auto R2 = fetch_tl_object<cocoon_api::client_AuthorizationWithProxy>(R.move_as_ok(), true);
  if (R2.is_error()) {
    fail_connection(R2.move_as_error_prefix("received incorrect auth answer from proxy: "));
    return;
  }

  auto obj = R2.move_as_ok();

  cocoon_api::downcast_call(
      *obj,
      td::overloaded(
          [&](cocoon_api::client_authorizationWithProxySuccess &r) {
            proxy_->process_signed_payment_data(*r.signed_payment_);
            proxy_->update_tokens_committed_to_db(r.tokens_committed_to_db_);
            proxy_->update_tokens_used(r.max_tokens_);
            handshake_completed();
            LOG(DEBUG) << "connection " << connection_id() << ": handshake completed successfully";
          },
          [&](cocoon_api::client_authorizationWithProxyFailed &r) {
            fail_connection(td::Status::Error(PSTRING() << "auth unsuccessfull: " << r.error_code_ << " " << r.error_));
          }));
}

}  // namespace cocoon
