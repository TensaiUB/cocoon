#include "WorkerContract.hpp"
#include "runners/BaseRunner.hpp"
#include "Ed25519.h"
#include "auto/tl/tonlib_api.h"
#include "Opcodes.hpp"
#include "block.h"
#include "cocoon-tl-utils/parsers.hpp"
#include "common/bitstring.h"
#include "td/utils/Random.h"
#include "td/utils/SharedSlice.h"
#include "vm/boc.h"
#include "vm/cells/CellBuilder.h"
#include "vm/cells/CellSlice.h"
#include <memory>

namespace cocoon {

WorkerContract::WorkerContract(const block::StdAddress &owner_address, const block::StdAddress &proxy_sc_address,
                               const td::Bits256 &proxy_public_key, std::unique_ptr<WorkerContract::Callback> callback,
                               BaseRunner *runner, std::shared_ptr<RunnerConfig> runner_config)
    : TonScWrapper({}, {}, runner, std::move(runner_config))
    , owner_address_(owner_address)
    , proxy_sc_address_(proxy_sc_address)
    , proxy_public_key_(proxy_public_key) {
  set_code(this->runner_config()->root_contract_config->worker_sc_code());
  sc_update_address();
}

void WorkerContract::on_state_update(ton::tl_object_ptr<ton::tonlib_api::raw_fullAccountState> raw_state) {
  if (raw_state->data_.size() == 0) {
    state_ = 0;
    tokens_processed_ = 0;
    return;
  }
  auto R = vm::std_boc_deserialize(raw_state->data_);
  if (R.is_error()) {
    LOG(FATAL) << "failed to deserialize contract state: " << R.move_as_error();
    return;
  }

  vm::CellSlice cs{vm::NoVm{}, R.move_as_ok()};
  block::StdAddress tmp;

  unsigned long long state = 0;
  unsigned long long tokens_processed = 0;
  if (!fetch_address(cs, tmp, runner_config()->is_testnet, false) ||
      !fetch_address(cs, tmp, runner_config()->is_testnet, false) || !cs.skip_first(256) ||
      !cs.fetch_ulong_bool(2, state) || !cs.fetch_ulong_bool(64, tokens_processed)) {
    LOG(FATAL) << "failed to parse contract state: not enough data";
    return;
  }
  state_ = (unsigned int)state;
  tokens_processed_ = tokens_processed;
}

void WorkerContract::on_transaction(ton::tl_object_ptr<ton::tonlib_api::raw_transaction> trans) {
  auto &in_msg = trans->in_msg_;
  CHECK(in_msg);

  if (in_msg->msg_data_->get_id() != ton::tonlib_api::msg_dataRaw::ID) {
    LOG(FATAL) << "msg data is not in a raw format";
    return;
  }

  auto data = static_cast<ton::tonlib_api::msg_dataRaw *>(in_msg->msg_data_.get())->body_;

  auto R = vm::std_boc_deserialize(data);
  if (R.is_error()) {
    LOG(ERROR) << "failed to deserialize inbound message: " << R.move_as_error();
    return;
  }

  block::StdAddress source;
  if (!rdeserialize(source, trans->in_msg_->source_->account_address_, runner_config()->is_testnet)) {
    LOG(ERROR) << "failed to deserialize inbound message source: " << trans->in_msg_->source_->account_address_;
    return;
  }

  vm::CellSlice cs{vm::NoVm{}, R.move_as_ok()};

  unsigned long long op = 0;
  unsigned long long qid = 0;

  if (!cs.fetch_ulong_bool(32, op) || !cs.fetch_ulong_bool(64, qid)) {
    return;
  }

  if (callback_) {
    callback_->on_transaction(source, (td::uint32)op, qid);
  }
}

td::Ref<vm::Cell> WorkerContract::init_data_cell() {
  const auto &root_contract_config = runner_config()->root_contract_config;
  vm::CellBuilder cb;
  store_address(cb, owner_address_);
  store_address(cb, proxy_sc_address_);
  cb.store_bytes(proxy_public_key_.as_slice());
  cb.store_long(0, 2);  // state
  cb.store_long(0, 64);
  cb.store_ref(root_contract_config->serialize_worker_params_cell());
  return cb.finalize();
}

td::Ref<vm::Cell> WorkerContract::create_pay_message(td::int64 tokens_processed) {
  vm::CellBuilder cb;
  CHECK(cb.store_long_bool(opcodes::ext_worker_payout_request_signed, 32));
  CHECK(cb.store_long_bool(td::Random::fast_uint64(), 64));
  CHECK(cb.store_long_bool(tokens_processed, 64));
  store_address(cb, address());
  return cb.finalize();
}

td::Ref<vm::Cell> WorkerContract::create_last_pay_message(td::int64 tokens_processed) {
  vm::CellBuilder cb;
  CHECK(cb.store_long_bool(opcodes::ext_worker_last_payout_request_signed, 32));
  CHECK(cb.store_long_bool(td::Random::fast_uint64(), 64));
  CHECK(cb.store_long_bool(tokens_processed, 64));
  store_address(cb, address());
  return cb.finalize();
}

td::Result<td::int64> WorkerContract::check_signed_pay_message(vm::CellSlice &cs) {
  unsigned long long op, op_copy, qid, qid_copy, tokens_processed;
  block::StdAddress addr;
  td::uint8 signature[64];
  if (!cs.fetch_ulong_bool(32, op) || op != opcodes::ext_worker_payout_request_signed ||
      !cs.fetch_ulong_bool(64, qid) || !fetch_address(cs, addr, runner_config()->is_testnet, false) ||
      !cs.fetch_bytes(signature, 64) || cs.size() != 0) {
    return td::Status::Error("failed to parse");
  }

  if (cs.size_refs() != 1) {
    return td::Status::Error("failed to parse");
  }

  auto payload = cs.fetch_ref();

  auto hash = payload->get_hash();

  vm::CellSlice pcs(vm::NoVm{}, payload);

  if (!pcs.fetch_ulong_bool(32, op_copy) || op_copy != op || !pcs.fetch_ulong_bool(64, qid_copy) || qid_copy != qid ||
      !pcs.fetch_ulong_bool(64, tokens_processed) || !fetch_address(pcs, addr, runner_config()->is_testnet, false) ||
      pcs.size() != 0) {
    return td::Status::Error("failed to parse");
  }

  if (addr.addr != address().addr || addr.workchain != address().workchain) {
    return td::Status::Error("bad owner");
  }

  td::Ed25519::PublicKey pubk(td::SecureString(proxy_public_key_.as_slice()));
  TRY_STATUS(pubk.verify_signature(hash.as_slice(), td::Slice((char *)signature, 64)));

  return (td::int64)tokens_processed;
}

td::Result<td::int64> WorkerContract::check_signed_pay_message(td::Slice data) {
  auto R = vm::std_boc_deserialize(data);
  if (R.is_error()) {
    return R.move_as_error();
  }
  vm::CellSlice cs(vm::NoVm{}, R.move_as_ok());
  return check_signed_pay_message(cs);
}

td::Ref<vm::Cell> WorkerContract::repack_signed_pay_message(td::Slice data, const block::StdAddress &send_excesses_to,
                                                            td::uint64 *qid_ptr) {
  auto R = vm::std_boc_deserialize(data).move_as_ok();
  vm::CellSlice cs(vm::NoVm{}, std::move(R));

  unsigned long long op, qid;
  block::StdAddress addr;
  td::uint8 signature[64];
  CHECK(cs.fetch_ulong_bool(32, op) && op == opcodes::ext_worker_payout_request_signed &&
        cs.fetch_ulong_bool(64, qid) && fetch_address(cs, addr, runner_config()->is_testnet, false) &&
        cs.fetch_bytes(signature, 64) && cs.size() == 0);

  vm::CellBuilder cb;
  cb.store_long(op, 32).store_long(qid, 64);
  store_address(cb, send_excesses_to);
  cb.store_bytes(signature, 64);
  cb.store_ref(cs.fetch_ref());

  if (qid_ptr) {
    *qid_ptr = qid;
  }

  return cb.finalize();
}

}  // namespace cocoon
