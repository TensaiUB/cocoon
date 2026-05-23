#pragma once

#include "auto/tl/cocoon_api.h"
#include "auto/tl/cocoon_api.hpp"
#include "common/bitstring.h"
#include "errorcode.h"
#include "runners/BaseRunner.hpp"
#include "td/actor/ActorId.h"
#include "ProxyStats.h"
#include "td/actor/common.h"
#include "td/utils/buffer.h"
#include "tl/TlObject.h"
#include <memory>
#include "ProxyClientInfo.h"
#include "ProxyWorkerConnectionInfo.h"
#include "runners/helpers/CountTokens.hpp"

namespace cocoon {

class ProxyRunner;

struct ProxyRunningRequest : public td::actor::Actor {
  ProxyRunningRequest(td::Bits256 id, td::Bits256 client_request_id, TcpClient::ConnectionId client_connection_id,
                      td::int32 client_proto_version, std::shared_ptr<ProxyClientInfo> client,
                      td::int32 worker_proto_version, std::shared_ptr<ProxyWorkerConnectionInfo> worker,
                      td::BufferSlice data, td::Bits256 encrypted_with, double timeout, bool enable_debug,
                      td::int64 reserved_tokens, td::actor::ActorId<ProxyRunner> runner,
                      std::shared_ptr<ProxyStats> stats)
      : id_(id)
      , client_request_id_(client_request_id)
      , client_connection_id_(client_connection_id)
      , client_proto_version_(client_proto_version)
      , client_(std::move(client))
      , worker_proto_version_(worker_proto_version)
      , worker_(std::move(worker))
      , data_(std::move(data))
      , encrypted_with_(encrypted_with)
      , timeout_(timeout)
      , enable_debug_(enable_debug)
      , reserved_tokens_(reserved_tokens)
      , runner_(runner)
      , stats_(std::move(stats)) {
    coefficient_ = worker_->coefficient;
  }

  void start_up() override;

  void alarm() override {
    fail(td::Status::Error(ton::ErrorCode::timeout, "timeout in proxy"));
  }

  void receive_answer_ex_impl(cocoon_api::proxy_queryAnswerEx &ans);
  void receive_answer_ex_impl(cocoon_api::proxy_queryAnswerErrorEx &ans);
  void receive_answer_ex_impl(cocoon_api::proxy_queryAnswerPartEx &ans);
  void receive_answer_ex(ton::tl_object_ptr<cocoon_api::proxy_QueryAnswerEx> ans) {
    cocoon_api::downcast_call(*ans, [&](auto &ans) { receive_answer_ex_impl(ans); });
  }

  void receive_answer(ton::tl_object_ptr<cocoon_api::proxy_queryAnswer> ans);
  void receive_answer_error(ton::tl_object_ptr<cocoon_api::proxy_queryAnswerError> ans);
  void receive_answer_part(ton::tl_object_ptr<cocoon_api::proxy_queryAnswerPart> ans);
  void receive_answer_part_error(ton::tl_object_ptr<cocoon_api::proxy_queryAnswerPartError> ans);
  void fail(td::Status error);
  void finish(bool is_success);

  auto stats() const {
    return stats_.get();
  }

  ton::tl_object_ptr<cocoon_api::tokensUsed> tokens_used() const {
    return ton::create_tl_object<cocoon_api::tokensUsed>(
        tokens_used_->prompt_tokens_used_, tokens_used_->cached_tokens_used_, tokens_used_->completion_tokens_used_,
        tokens_used_->reasoning_tokens_used_, tokens_used_->total_tokens_used_);
  }

  std::string generate_proxy_debug() {
    if (enable_debug_) {
      return generate_proxy_debug_inner();
    } else {
      return "{}";
    }
  }

  ton::tl_object_ptr<cocoon_api::client_queryFinalInfo> create_final_info(cocoon_api::proxy_queryFinalInfo *info);
  ton::tl_object_ptr<cocoon_api::proxy_queryFinalInfo> create_final_info_from_old(
      ton::tl_object_ptr<cocoon_api::tokensUsed> info);

 private:
  std::string generate_proxy_debug_inner();
  td::Bits256 id_;
  td::Bits256 client_request_id_;
  TcpClient::ConnectionId client_connection_id_;
  td::int32 client_proto_version_;
  std::shared_ptr<ProxyClientInfo> client_;
  td::int32 worker_proto_version_;
  std::shared_ptr<ProxyWorkerConnectionInfo> worker_;
  td::BufferSlice data_;
  td::Bits256 encrypted_with_;
  double timeout_;
  bool enable_debug_;
  td::int64 reserved_tokens_;

  td::actor::ActorId<ProxyRunner> runner_;
  std::shared_ptr<ProxyStats> stats_;

  bool sent_answer_{false};

  auto run_time() const {
    return td::Clocks::monotonic() - start_time_monotonic_;
  }

  double start_time_monotonic_ = td::Clocks::monotonic();
  double start_time_unix_ = td::Clocks::system();
  double received_answer_time_unix_ = td::Clocks::system();
  td::int64 payload_parts_{0};
  td::int64 payload_bytes_{0};

  ton::tl_object_ptr<cocoon_api::tokensUsed> tokens_used_ =
      ton::create_tl_object<cocoon_api::tokensUsed>(0, 0, 0, 0, 0);

  td::int64 coefficient_;
  double worker_run_time_{0};
};

}  // namespace cocoon
