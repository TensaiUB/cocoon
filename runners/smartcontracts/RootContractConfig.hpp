#pragma once

#include "block.h"
#include "common/refcnt.hpp"
#include "td/utils/Random.h"
#include "td/utils/UInt.h"
#include "td/utils/port/IPAddress.h"
#include "crypto/common/bitstring.h"
#include "crypto/vm/cells/CellSlice.h"
#include "vm/cells/Cell.h"
#include "auto/tl/cocoon_api.h"
#include <algorithm>
#include <set>
#include <vector>

namespace cocoon {

class BaseRunner;
struct SimpleJsonSerializer;

struct RootContractPublicKeyInfo {
  td::uint8 key_type;
  td::uint32 expire_at;
};

class RootContractConfig {
 public:
  RootContractConfig() = default;

  struct ProxyInfo {
    td::IPAddress address_for_workers;
    td::IPAddress address_for_clients;
    td::uint32 seqno;
  };
  struct WorkerTypeInfo {
    td::Bits256 worker_type;
    std::vector<td::Bits256> hashes;

    bool operator<(const WorkerTypeInfo &other) const {
      return worker_type < other.worker_type;
    }
  };

  static td::Result<std::unique_ptr<RootContractConfig>> load_from_state(vm::CellSlice &cell_slice, bool is_testnet);
  static td::Result<std::unique_ptr<RootContractConfig>> load_from_json(td::CSlice file_name, bool is_testnet);
  static td::Result<std::unique_ptr<RootContractConfig>> load_from_tl(const cocoon_api::rootConfig_Config &config,
                                                                      bool is_testnet);
  static td::Result<std::unique_ptr<RootContractConfig>> load_from_tl(const cocoon_api::rootConfig_pseudo &config,
                                                                      bool is_testnet);
  static td::Result<std::unique_ptr<RootContractConfig>> load_from_tl(const cocoon_api::rootConfig_configV7 &config,
                                                                      bool is_testnet);

  ton::tl_object_ptr<cocoon_api::rootConfig_Config> serialize() const;

  ProxyInfo *get_random_proxy() {
    if (proxies_.size() == 0) {
      return nullptr;
    }
    auto x = td::Random::fast(0, (int)proxies_.size() - 1);
    return &proxies_[x];
  }

  auto version() const {
    return version_;
  }
  auto params_version() const {
    return params_version_;
  }

  auto proxy_sc_code() const {
    return proxy_sc_code_;
  }
  auto worker_sc_code() const {
    return worker_sc_code_;
  }
  auto client_sc_code() const {
    return client_sc_code_;
  }

  auto price_per_token() const {
    return price_per_token_;
  }
  auto worker_fee_per_token() const {
    return worker_fee_per_token_;
  }
  auto proxy_delay_before_close() const {
    return proxy_delay_before_close_;
  }
  auto client_delay_before_close() const {
    return client_delay_before_close_;
  }
  auto min_proxy_stake() const {
    return min_proxy_stake_;
  }
  auto min_client_stake() const {
    return min_client_stake_;
  }

  bool has_worker_hash(const td::Bits256 &hash) const {
    return std::binary_search(workers_.begin(), workers_.end(), hash);
  }
  bool has_model_hash(const td::Bits256 &hash) const {
    return std::binary_search(models_.begin(), models_.end(), hash);
  }
  bool has_proxy_hash(const td::Bits256 &hash) const {
    return std::binary_search(accepted_proxy_hashes_.begin(), accepted_proxy_hashes_.end(), hash);
  }

  td::Ref<vm::Cell> serialize_params_cell(td::int32 value);
  td::Ref<vm::Cell> serialize_root_params_cell() {
    return serialize_params_cell(7);
  }
  td::Ref<vm::Cell> serialize_proxy_params_cell() {
    return serialize_params_cell(6);
  }
  td::Ref<vm::Cell> serialize_worker_params_cell() {
    return serialize_params_cell(0);
  }
  td::Ref<vm::Cell> serialize_client_params_cell() {
    return serialize_params_cell(0);
  }

  const auto &owner_address() const {
    return owner_;
  }

  auto proxies_types_cnt() const {
    return accepted_proxy_hashes_.size();
  }

  auto worker_types_cnt() const {
    return workers_.size();
  }
  auto model_types_cnt() const {
    return models_.size();
  }

  auto registered_proxies_cnt() const {
    return proxies_.size();
  }
  const auto &registered_proxies() const {
    return proxies_;
  }

  auto last_proxy_seqno() const {
    return last_proxy_seqno_;
  }

  auto unique_id() const {
    return unique_id_;
  }

  bool is_test() const {
    return is_test_;
  }

  auto prompt_tokens_price_multiplier() const {
    return prompt_tokens_price_multiplier_;
  }
  auto cached_tokens_price_multiplier() const {
    return cached_tokens_price_multiplier_;
  }
  auto completion_tokens_price_multiplier() const {
    return completion_tokens_price_multiplier_;
  }
  auto reasoning_tokens_price_multiplier() const {
    return reasoning_tokens_price_multiplier_;
  }

  void store_stat(BaseRunner *runner, td::StringBuilder &sb);
  void store_stat(BaseRunner *runner, SimpleJsonSerializer &sb);

  const auto &key_manager_address() const {
    return key_manager_addr_;
  }

  const auto &key_manager_image_hash() const {
    return key_manager_image_hash_;
  }

  bool has_proxy_verified_key(const td::Bits256 &key) const {
    return std::binary_search(verified_proxy_keys_.begin(), verified_proxy_keys_.end(), key);
  }
  bool has_worker_verified_key(const td::Bits256 &key) const {
    return std::binary_search(verified_worker_keys_.begin(), verified_worker_keys_.end(), key);
  }
  bool has_key_manager_verified_key(const td::Bits256 &key) const {
    return std::binary_search(verified_key_manager_keys_.begin(), verified_key_manager_keys_.end(), key);
  }

 private:
  block::StdAddress owner_;

  std::vector<ProxyInfo> proxies_;
  std::vector<td::Bits256> accepted_proxy_hashes_;
  td::uint32 last_proxy_seqno_;
  std::vector<td::Bits256> workers_;
  std::vector<td::Bits256> models_;
  td::uint32 version_;

  td::uint8 struct_version_;
  td::uint32 params_version_;
  td::uint32 unique_id_;
  bool is_test_;
  td::uint64 price_per_token_;
  td::uint64 worker_fee_per_token_;
  td::uint32 prompt_tokens_price_multiplier_{10000};
  td::uint32 cached_tokens_price_multiplier_{10000};
  td::uint32 completion_tokens_price_multiplier_{10000};
  td::uint32 reasoning_tokens_price_multiplier_{10000};
  td::uint32 proxy_delay_before_close_;
  td::uint32 client_delay_before_close_;
  td::uint64 min_proxy_stake_;
  td::uint64 min_client_stake_;

  std::map<td::Bits256, RootContractPublicKeyInfo> public_keys_;
  td::Bits256 key_manager_public_key_ = td::Bits256::zero();
  td::Bits256 key_manager_image_hash_ = td::Bits256::zero();
  td::IPAddress key_manager_addr_;

  std::vector<td::Bits256> verified_proxy_keys_;
  std::vector<td::Bits256> verified_worker_keys_;
  std::vector<td::Bits256> verified_key_manager_keys_;

  td::Ref<vm::Cell> proxy_sc_code_;
  td::Ref<vm::Cell> worker_sc_code_;
  td::Ref<vm::Cell> client_sc_code_;
};

}  // namespace cocoon
