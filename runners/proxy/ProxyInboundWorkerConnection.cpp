#include "ProxyInboundWorkerConnection.h"
#include "cocoon-tl-utils/cocoon-tl-utils.hpp"
#include "ProxyRunner.hpp"

namespace cocoon {

void ProxyInboundWorkerConnection::receive_handshake_query(td::BufferSlice message,
                                                           td::Promise<td::BufferSlice> promise) {
  auto P = td::PromiseCreator::lambda([promise = std::move(promise), connection_id = connection_id(),
                                       self_id = actor_id(runner())](td::Result<td::BufferSlice> R) mutable {
    if (R.is_error()) {
      td::actor::send_closure(self_id, &ProxyRunner::fail_connection, connection_id, R.error().clone());
    }
    promise.set_result(std::move(R));
  });
  switch (state_) {
    case State::None:
      return receive_connect_to_proxy_query(std::move(message), std::move(P));
    case State::Ok:
      return P.set_error(td::Status::Error("connection is already ready"));
    case State::Compare:
      return receive_compare_payment_query(std::move(message), std::move(P));
    case State::CompareExt:
      return receive_compare_payment_ext_query(std::move(message), std::move(P));
    case State::FinishingHandshake:
      return receive_handshake_finish_query(std::move(message), std::move(P));
    case State::Failed:
    default:
      return P.set_error(td::Status::Error("connection is already closing"));
  }
}

void ProxyInboundWorkerConnection::receive_connect_to_proxy_query(td::BufferSlice query,
                                                                  td::Promise<td::BufferSlice> promise) {
  if (runner()->check_image_hashes()) {
    if (!runner()->sc()->runner_config()->root_contract_config->has_worker_hash(remote_app_hash())) {
      return promise.set_error(td::Status::Error(
          ton::ErrorCode::protoviolation, PSTRING() << "invalid worker image hash " << remote_app_hash().to_hex()));
    }
  }
  {
    auto S = runner()->check_verification_key(remote_app_type(), verified_by());
    if (S.is_error()) {
      return fail_connection(std::move(S));
    }
  }
  TRY_RESULT_PROMISE(promise, obj, fetch_tl_object<cocoon_api::worker_connectToProxy>(std::move(query), true));
  if (!(obj->params_->flags_ & 1)) {
    return promise.set_error(td::Status::Error(ton::ErrorCode::error, "too old worker"));
  }
  if (obj->params_->is_test_ != runner()->is_test()) {
    return promise.set_error(td::Status::Error(ton::ErrorCode::error, "test mode mismatch"));
  }
  if (obj->params_->model_ == "") {
    return promise.set_error(td::Status::Error(ton::ErrorCode::protoviolation, "invalid worker hash or worker type"));
  }
  if (obj->params_->coefficient_ < 0 || obj->params_->coefficient_ >= 1000000000) {
    return promise.set_error(td::Status::Error(ton::ErrorCode::protoviolation, "invalid coefficient value"));
  }
  if (obj->params_->max_active_requests_ < 1) {
    return promise.set_error(td::Status::Error(ton::ErrorCode::protoviolation, "invalid max_active_requests value"));
  }
  if (obj->params_->proxy_cnt_ < 1) {
    return promise.set_error(td::Status::Error(ton::ErrorCode::protoviolation, "invalid proxy_cnt value"));
  }
  if (runner()->check_image_hashes()) {
    if (!runner()->sc()->runner_config()->root_contract_config->has_model_hash(
            td::sha256_bits256(obj->params_->model_))) {
      return promise.set_error(td::Status::Error(ton::ErrorCode::protoviolation,
                                                 PSTRING() << "invalid worker model '" << obj->params_->model_ << "'"));
    }
  }
  auto remote_min_proto_version = (obj->params_->flags_ & 2) ? obj->params_->min_proto_version_ : 0;
  auto remote_max_proto_version = (obj->params_->flags_ & 2) ? obj->params_->max_proto_version_ : 0;

  if (remote_max_proto_version < runner()->min_proto_version() ||
      runner()->max_proto_version() < remote_min_proto_version) {
    return promise.set_error(
        td::Status::Error(ton::ErrorCode::protoviolation, "cannot choose common protocol version"));
  }
  proto_version_ = std::min(remote_max_proto_version, runner()->max_proto_version());

  TRY_RESULT_PROMISE(promise, worker_owner_address, block::StdAddress::parse(obj->params_->worker_owner_address_));
  worker_owner_address.bounceable = false;
  worker_owner_address.testnet = runner()->is_testnet();
  worker_owner_address_str_ = worker_owner_address.rserialize(true);

  TRY_RESULT_PROMISE_ASSIGN(promise, worker_info_, runner()->register_worker(worker_owner_address));
  TRY_RESULT_PROMISE_ASSIGN(
      promise, worker_connection_info_,
      runner()->register_worker_connection(
          worker_info_, connection_id(), remote_app_hash(), obj->params_->model_, obj->params_->coefficient_,
          (obj->params_->max_active_requests_ + obj->params_->proxy_cnt_ - 1) / obj->params_->proxy_cnt_,
          obj->params_->machine_description_json_));

  state_ = State::Compare;
  auto params = ton::create_tl_object<cocoon_api::proxy_params>(
      1 | (proto_version_ > 0 ? 2 : 0), runner()->public_key(), runner()->owner_address().rserialize(true),
      runner()->cur_sc_address().rserialize(true), runner()->is_test(), proto_version_);
  promise.set_value(cocoon::create_serialize_tl_object<cocoon_api::worker_connectedToProxy>(
      std::move(params), worker_info_->worker_sc_address().rserialize(true)));
}

void ProxyInboundWorkerConnection::receive_compare_payment_query(td::BufferSlice query,
                                                                 td::Promise<td::BufferSlice> promise) {
  TRY_RESULT_PROMISE(promise, obj, fetch_tl_object<cocoon_api::worker_compareBalanceWithProxy>(std::move(query), true));

  LOG_CHECK(obj->tokens_committed_to_blockchain_ <= worker_info_->tokens_committed_to_blockchain())
      << obj->tokens_committed_to_blockchain_ << " " << worker_info_->tokens_committed_to_blockchain();
  CHECK(obj->tokens_committed_to_db_ <= worker_info_->tokens_committed_to_db());

  runner()->sign_worker_payment(*worker_info_);
  if (obj->max_tokens_ <= worker_info_->tokens_max()) {
    state_ = State::FinishingHandshake;
    promise.set_value(cocoon::create_serialize_tl_object<cocoon_api::worker_compareBalanceWithProxyResult>(
        worker_info_->signed_payment(), worker_info_->tokens_committed_to_db(), worker_info_->tokens_max(), 0));
  } else {
    state_ = State::CompareExt;
    promise.set_value(cocoon::create_serialize_tl_object<cocoon_api::worker_compareBalanceWithProxyResult>(
        worker_info_->signed_payment(), worker_info_->tokens_committed_to_db(), worker_info_->tokens_max(), 1));
  }
}

void ProxyInboundWorkerConnection::receive_compare_payment_ext_query(td::BufferSlice query,
                                                                     td::Promise<td::BufferSlice> promise) {
  TRY_RESULT_PROMISE(promise, obj,
                     fetch_tl_object<cocoon_api::worker_extendedCompareBalanceWithProxy>(std::move(query), true));

  LOG(WARNING) << "skipping extended tokens compare: not implemented yet";
  promise.set_value(cocoon::create_serialize_tl_object<cocoon_api::worker_extendedCompareBalanceWithProxyResult>(0));
}

void ProxyInboundWorkerConnection::receive_handshake_finish_query(td::BufferSlice query,
                                                                  td::Promise<td::BufferSlice> promise) {
  TRY_RESULT_PROMISE(promise, obj, fetch_tl_object<cocoon_api::worker_proxyHandshakeComplete>(std::move(query), true));

  worker_connection_info_->is_disabled = obj->is_disabled_;
  state_ = State::Ok;

  promise.set_value(cocoon::create_serialize_tl_object<cocoon_api::worker_proxyHandshakeCompleted>());
  handshake_completed();
}

void ProxyInboundWorkerConnection::pre_close() {
  if (worker_connection_info_) {
    runner()->unregister_worker_connection(worker_connection_info_);
    worker_connection_info_ = nullptr;
  }
  state_ = State::Failed;
}

}  // namespace cocoon
