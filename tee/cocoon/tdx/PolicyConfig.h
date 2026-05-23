#pragma once

#include "td/utils/JsonBuilder.h"
#include "td/utils/Status.h"
#include "td/utils/StringBuilder.h"
#include "td/utils/UInt.h"

namespace tdx {

/**
 * @brief Policy configuration for attestation validation
 */
struct PolicyConfig {
  // TDX measurement validation
  std::vector<td::UInt384> allowed_mrtd;                 ///< Allowed MRTD values (empty = any)
  std::vector<std::array<td::UInt384, 4>> allowed_rtmr;  ///< Allowed RTMR sets (empty = any)

  // Image hash verification
  std::vector<td::UInt256> allowed_image_hashes;  ///< Expected image hashes (empty = no verification)

  // Collateral root hash verification (Intel DCAP root key IDs)
  std::vector<td::UInt384> allowed_collateral_root_hashes;  ///< Allowed Intel root key IDs (empty = any)
};

td::Result<PolicyConfig> parse_policy_config(td::JsonObject &obj);
td::StringBuilder &operator<<(td::StringBuilder &sb, const PolicyConfig &config);

}  // namespace tdx
