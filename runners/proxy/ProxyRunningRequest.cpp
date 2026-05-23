#include "ProxyRunningRequest.hpp"
#include "ProxyRunner.hpp"
#include "auto/tl/cocoon_api.h"
#include "auto/tl/ton_api.h"
#include "errorcode.h"
#include "keys/encryptor.h"

#include "cocoon-tl-utils/cocoon-tl-utils.hpp"
#include "td/actor/actor.h"
#include "td/utils/buffer.h"
#include "td/utils/port/Clocks.h"
#include "tl/TlObject.h"

#include <nlohmann/json.hpp>

namespace cocoon {

void ProxyRunningRequest::start_up() {
  LOG(INFO) << "starting proxy request " << id_.to_hex() << ", worker connection id " << worker_->connection_id
            << " client_request_id=" << client_request_id_.to_hex();

  alarm_timestamp() = td::Timestamp::in(timeout_);

  stats()->requests_received++;

  auto R = cocoon::fetch_tl_object<cocoon_api::http_request>(data_.as_slice(), true);
  if (R.is_error()) {
    fail(R.move_as_error_prefix("proxy: received incorrect request: "));
    return;
  }
  auto req = R.move_as_ok();
  stats()->request_bytes_received += (double)req->payload_.size();

  td::BufferSlice fwd_query;
  if (worker_proto_version_ > 0) {
    fwd_query = cocoon::create_serialize_tl_object<cocoon_api::proxy_runQueryEx>(
        std::move(data_), worker_->info->signed_payment(), coefficient_, timeout_ * 0.95, id_,
        1 | (worker_proto_version_ >= 3 ? 2 : 0), enable_debug_, encrypted_with_);
  } else {
    fwd_query = cocoon::create_serialize_tl_object<cocoon_api::proxy_runQuery>(
        std::move(data_), worker_->info->signed_payment(), coefficient_, timeout_ * 0.95, id_);
  }

  td::actor::send_closure(runner_, &ProxyRunner::send_message_to_connection, worker_->connection_id,
                          std::move(fwd_query));
}

void ProxyRunningRequest::receive_answer_ex_impl(cocoon_api::proxy_queryAnswerEx &ans) {
  if (sent_answer_) {
    fail(td::Status::Error(ton::ErrorCode::protoviolation, "out of order answer parts"));
    return;
  }

  LOG(DEBUG) << "proxy request " << id_.to_hex() << ": received answer";

  received_answer_time_unix_ = td::Clocks::system();

  auto R = cocoon::fetch_tl_object<cocoon_api::http_response>(ans.answer_.as_slice(), true);
  if (R.is_error()) {
    fail(td::Status::Error(ton::ErrorCode::protoviolation,
                           PSTRING() << "received malformed answer from worker: " << R.move_as_error()));
    return;
  }
  auto http_ans = R.move_as_ok();
  if (http_ans->payload_.size() > 0) {
    stats()->answer_bytes_sent += (double)http_ans->payload_.size();
    payload_parts_++;
    payload_bytes_ += http_ans->payload_.size();
  }

  bool is_completed = ans.flags_ & 1;
  if (is_completed) {
    CHECK(ans.final_info_);
    tokens_used_ = std::move(ans.final_info_->tokens_used_);
    worker_run_time_ = ans.final_info_->worker_end_time_ - ans.final_info_->worker_start_time_;
  }

  // Add proxy timing headers to the existing HTTP response using Unix timestamps
  http_ans->headers_.push_back(cocoon::cocoon_api::make_object<cocoon_api::http_header>(
      "X-Cocoon-Proxy-Start", PSTRING() << td::StringBuilder::FixedDouble(start_time_unix_, 6)));
  http_ans->headers_.push_back(cocoon::cocoon_api::make_object<cocoon_api::http_header>(
      "X-Cocoon-Proxy-End", PSTRING() << td::StringBuilder::FixedDouble(td::Clocks::system(), 6)));

  // Re-serialize the modified HTTP response
  auto modified_answer = cocoon::serialize_tl_object(http_ans, true);

  td::BufferSlice res;
  if (client_proto_version_ == 0) {
    res = cocoon::create_serialize_tl_object<cocoon_api::client_queryAnswer>(std::move(modified_answer), is_completed,
                                                                             client_request_id_, tokens_used());
  } else {
    ton::tl_object_ptr<cocoon_api::client_queryFinalInfo> final_info;
    if (is_completed) {
      final_info = create_final_info(ans.final_info_.get());
    }
    res = cocoon::create_serialize_tl_object<cocoon_api::client_queryAnswerEx>(
        client_request_id_, std::move(modified_answer), (is_completed ? 1 : 0), std::move(final_info));
  }

  td::actor::send_closure(runner_, &ProxyRunner::send_message_to_connection, client_connection_id_, std::move(res));

  sent_answer_ = true;

  if (is_completed) {
    finish(true);
  } else {
    if (tokens_used_ && tokens_used_->total_tokens_used_ > reserved_tokens_) {
      return fail(td::Status::Error(ton::ErrorCode::error,
                                    PSTRING() << "reserved_tokens depleted: reserved_tokens=" << reserved_tokens_
                                              << " used=" << tokens_used_->prompt_tokens_used_ << "+"
                                              << tokens_used_->completion_tokens_used_));
    }
  }
}

void ProxyRunningRequest::receive_answer(ton::tl_object_ptr<cocoon_api::proxy_queryAnswer> ans) {
  ton::tl_object_ptr<cocoon_api::proxy_queryFinalInfo> final_info;
  if (ans->is_completed_) {
    final_info = create_final_info_from_old(std::move(ans->tokens_used_));
  }
  bool has_final_info = final_info != nullptr;
  receive_answer_ex_impl(*ton::create_tl_object<cocoon_api::proxy_queryAnswerEx>(
      ans->request_id_, std::move(ans->answer_), has_final_info ? 1 : 0, std::move(final_info)));
}

void ProxyRunningRequest::receive_answer_ex_impl(cocoon_api::proxy_queryAnswerErrorEx &ans) {
  LOG(DEBUG) << "proxy request " << id_.to_hex() << ": received error";

  worker_run_time_ = ans.final_info_->worker_end_time_ - ans.final_info_->worker_start_time_;

  td::BufferSlice res;
  if (client_proto_version_ > 0) {
    auto final_info = create_final_info(ans.final_info_.get());
    res = cocoon::create_serialize_tl_object<cocoon_api::client_queryAnswerErrorEx>(
        client_request_id_, ans.error_code_, ans.error_, 1, std::move(final_info));
  } else {
    if (!sent_answer_) {
      res = cocoon::create_serialize_tl_object<cocoon_api::client_queryAnswerError>(ans.error_code_, ans.error_,
                                                                                    client_request_id_, tokens_used());
    } else {
      res = cocoon::create_serialize_tl_object<cocoon_api::client_queryAnswerPartError>(
          ans.error_code_, ans.error_, client_request_id_, tokens_used());
    }
  }
  td::actor::send_closure(runner_, &ProxyRunner::send_message_to_connection, client_connection_id_, std::move(res));
  finish(false);
}

void ProxyRunningRequest::receive_answer_error(ton::tl_object_ptr<cocoon_api::proxy_queryAnswerError> ans) {
  auto final_info = create_final_info_from_old(std::move(ans->tokens_used_));
  receive_answer_ex_impl(*ton::create_tl_object<cocoon_api::proxy_queryAnswerErrorEx>(
      ans->request_id_, ans->error_code_, ans->error_, 1, std::move(final_info)));
}

void ProxyRunningRequest::receive_answer_ex_impl(cocoon_api::proxy_queryAnswerPartEx &ans) {
  if (!sent_answer_) {
    fail(td::Status::Error(ton::ErrorCode::protoviolation, "out of order answer parts"));
    return;
  }

  LOG(DEBUG) << "proxy request " << id_.to_hex() << ": received payload part";

  stats()->answer_bytes_sent += (double)ans.answer_.size();
  payload_parts_++;
  payload_bytes_ += ans.answer_.size();

  bool is_completed = ans.flags_ & 1;
  if (is_completed) {
    CHECK(ans.final_info_);
    tokens_used_ = std::move(ans.final_info_->tokens_used_);
    worker_run_time_ = ans.final_info_->worker_end_time_ - ans.final_info_->worker_start_time_;
  }

  td::BufferSlice res;
  if (client_proto_version_ == 0) {
    res = cocoon::create_serialize_tl_object<cocoon_api::client_queryAnswerPart>(std::move(ans.answer_), is_completed,
                                                                                 client_request_id_, tokens_used());
  } else {
    ton::tl_object_ptr<cocoon_api::client_queryFinalInfo> final_info;
    if (is_completed) {
      final_info = create_final_info(ans.final_info_.get());
    }
    res = cocoon::create_serialize_tl_object<cocoon_api::client_queryAnswerPartEx>(
        client_request_id_, std::move(ans.answer_), (is_completed ? 1 : 0), std::move(final_info));
  }
  td::actor::send_closure(runner_, &ProxyRunner::send_message_to_connection, client_connection_id_, std::move(res));
  if (is_completed) {
    finish(true);
  } else {
    if (tokens_used_ && tokens_used_->total_tokens_used_ > reserved_tokens_) {
      return fail(td::Status::Error(ton::ErrorCode::error,
                                    PSTRING() << "reserved_tokens depleted: reserved_tokens=" << reserved_tokens_
                                              << " used=" << tokens_used_->prompt_tokens_used_ << "+"
                                              << tokens_used_->completion_tokens_used_));
    }
  }
}

void ProxyRunningRequest::receive_answer_part(ton::tl_object_ptr<cocoon_api::proxy_queryAnswerPart> ans) {
  ton::tl_object_ptr<cocoon_api::proxy_queryFinalInfo> final_info;
  if (ans->is_completed_) {
    final_info = create_final_info_from_old(std::move(ans->tokens_used_));
  }
  bool has_final_info = final_info != nullptr;
  receive_answer_ex_impl(*ton::create_tl_object<cocoon_api::proxy_queryAnswerPartEx>(
      ans->request_id_, std::move(ans->answer_), has_final_info ? 1 : 0, std::move(final_info)));
}

void ProxyRunningRequest::receive_answer_part_error(ton::tl_object_ptr<cocoon_api::proxy_queryAnswerPartError> ans) {
  auto final_info = create_final_info_from_old(std::move(ans->tokens_used_));
  receive_answer_ex_impl(*ton::create_tl_object<cocoon_api::proxy_queryAnswerErrorEx>(
      ans->request_id_, ans->error_code_, ans->error_, 1, std::move(final_info)));
}

void ProxyRunningRequest::fail(td::Status error) {
  LOG(WARNING) << "proxy request " << id_.to_hex() << " is failed: " << error;
  td::BufferSlice res;
  if (client_proto_version_ > 0) {
    auto final_info = create_final_info(nullptr);
    res = cocoon::create_serialize_tl_object<cocoon_api::client_queryAnswerErrorEx>(
        client_request_id_, error.code(), error.message().str(), 1, std::move(final_info));
  } else if (!sent_answer_) {
    res = cocoon::create_serialize_tl_object<cocoon_api::client_queryAnswerError>(error.code(), error.message().str(),
                                                                                  client_request_id_, tokens_used());
  } else {
    res = cocoon::create_serialize_tl_object<cocoon_api::client_queryAnswerPartError>(
        error.code(), error.message().str(), client_request_id_, tokens_used());
  }
  td::actor::send_closure(runner_, &ProxyRunner::send_message_to_connection, client_connection_id_, std::move(res));
  finish(false);
}

void ProxyRunningRequest::finish(bool is_success) {
  CHECK(tokens_used_);
  LOG(INFO) << "proxy request " << id_.to_hex() << ": completed: success=" << (is_success ? "YES" : "NO")
            << " time=" << run_time() << " payload_parts=" << payload_parts_ << " payload_bytes=" << payload_bytes_
            << " tokens_used=" << tokens_used_->prompt_tokens_used_ << "+" << tokens_used_->cached_tokens_used_ << "+"
            << tokens_used_->completion_tokens_used_ << "+" << tokens_used_->reasoning_tokens_used_ << "="
            << tokens_used_->total_tokens_used_;
  if (is_success) {
    stats()->requests_success++;
  } else {
    stats()->requests_failed++;
  }

  auto work_time = run_time();
  stats_->total_requests_time += work_time;
  stats_->total_worker_requests_time += worker_run_time_;

  td::actor::send_closure(runner_, &ProxyRunner::finish_request, id_, client_request_id_, client_,
                          client_connection_id_, worker_->info, worker_, std::move(tokens_used_), reserved_tokens_,
                          is_success, work_time, worker_run_time_);
  stop();
}

std::string ProxyRunningRequest::generate_proxy_debug_inner() {
  nlohmann::json v;
  v["type"] = "proxy_stats";
  v["start_time"] = start_time_unix_;
  v["answer_receive_start_at"] = received_answer_time_unix_;
  v["answer_receive_end_at"] = td::Clocks::system();
  return v.dump();
}

ton::tl_object_ptr<cocoon_api::client_queryFinalInfo> ProxyRunningRequest::create_final_info(
    cocoon_api::proxy_queryFinalInfo *info) {
  return ton::create_tl_object<cocoon_api::client_queryFinalInfo>(
      (enable_debug_ ? 1 : 0) | (client_proto_version_ >= 2 ? 2 : 0), tokens_used(), info ? info->worker_debug_ : "",
      generate_proxy_debug(), start_time_unix_, td::Clocks::system(), info ? info->worker_start_time_ : 0,
      info ? info->worker_end_time_ : 0);
}

ton::tl_object_ptr<cocoon_api::proxy_queryFinalInfo> ProxyRunningRequest::create_final_info_from_old(
    ton::tl_object_ptr<cocoon_api::tokensUsed> tokens_used) {
  return ton::create_tl_object<cocoon_api::proxy_queryFinalInfo>(0, std::move(tokens_used), "", 0, 0);
}

}  // namespace cocoon
