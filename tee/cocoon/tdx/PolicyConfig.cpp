#include "tee/cocoon/tdx/PolicyConfig.h"

#include "td/utils/format.h"

#include "tee/cocoon/utils.h"

namespace tdx {

// Helper function to parse TDX policy configuration
td::Result<PolicyConfig> parse_policy_config(td::JsonObject &obj) {
  PolicyConfig tdx_config;

  // Parse allowed_mrtd array
  auto r_mrtd_array = obj.extract_optional_field("allowed_mrtd", td::JsonValue::Type::Array);
  if (r_mrtd_array.is_ok() && r_mrtd_array.ok().type() == td::JsonValue::Type::Array) {
    for (const auto &item : r_mrtd_array.ok().get_array()) {
      if (item.type() == td::JsonValue::Type::String) {
        TRY_RESULT(mrtd, cocoon::parse_hex_uint<td::UInt384>(item.get_string()));
        tdx_config.allowed_mrtd.push_back(mrtd);
      }
    }
  }

  // Parse allowed_rtmr array (array of 4-element arrays)
  auto r_rtmr_array = obj.extract_optional_field("allowed_rtmr", td::JsonValue::Type::Array);
  if (r_rtmr_array.is_ok() && r_rtmr_array.ok().type() == td::JsonValue::Type::Array) {
    for (const auto &rtmr_set : r_rtmr_array.ok().get_array()) {
      if (rtmr_set.type() == td::JsonValue::Type::Array) {
        const auto &rtmr_array = rtmr_set.get_array();
        if (rtmr_array.size() == 4) {
          std::array<td::UInt384, 4> rtmr_set_values;
          for (size_t i = 0; i < 4; i++) {
            if (rtmr_array[i].type() == td::JsonValue::Type::String) {
              TRY_RESULT(rtmr_val, cocoon::parse_hex_uint<td::UInt384>(rtmr_array[i].get_string()));
              rtmr_set_values[i] = rtmr_val;
            }
          }
          tdx_config.allowed_rtmr.push_back(rtmr_set_values);
        }
      }
    }
  }

  // Parse allowed_image_hashes (can be string or array of strings)
  auto r_image_hash_field = obj.extract_optional_field("allowed_image_hashes", td::JsonValue::Type::Null);
  if (r_image_hash_field.is_ok()) {
    auto &hash_value = r_image_hash_field.ok();
    if (hash_value.type() == td::JsonValue::Type::String) {
      // Single hash as string
      TRY_RESULT(hash, cocoon::parse_hex_uint<td::UInt256>(hash_value.get_string()));
      tdx_config.allowed_image_hashes.push_back(hash);
    } else if (hash_value.type() == td::JsonValue::Type::Array) {
      // Multiple hashes as array
      for (const auto &item : hash_value.get_array()) {
        if (item.type() == td::JsonValue::Type::String) {
          TRY_RESULT(hash, cocoon::parse_hex_uint<td::UInt256>(item.get_string()));
          tdx_config.allowed_image_hashes.push_back(hash);
        }
      }
    }
  }

  // Also support legacy "allowed_image_hash" (singular) for backward compatibility
  auto r_image_hash = obj.get_optional_string_field("allowed_image_hash");
  if (r_image_hash.is_ok() && !r_image_hash.ok().empty()) {
    TRY_RESULT(hash, cocoon::parse_hex_uint<td::UInt256>(r_image_hash.ok()));
    tdx_config.allowed_image_hashes.push_back(hash);
  }

  // Parse allowed_collateral_root_hashes (can be string or array of strings)
  auto r_collateral_field = obj.extract_optional_field("allowed_collateral_root_hashes", td::JsonValue::Type::Null);
  if (r_collateral_field.is_ok()) {
    auto &collateral_value = r_collateral_field.ok();
    if (collateral_value.type() == td::JsonValue::Type::String) {
      // Single hash as string
      TRY_RESULT(hash, cocoon::parse_hex_uint<td::UInt384>(collateral_value.get_string()));
      tdx_config.allowed_collateral_root_hashes.push_back(hash);
    } else if (collateral_value.type() == td::JsonValue::Type::Array) {
      // Multiple hashes as array
      for (const auto &item : collateral_value.get_array()) {
        if (item.type() == td::JsonValue::Type::String) {
          TRY_RESULT(hash, cocoon::parse_hex_uint<td::UInt384>(item.get_string()));
          tdx_config.allowed_collateral_root_hashes.push_back(hash);
        }
      }
    }
  }

  return tdx_config;
}

td::StringBuilder &operator<<(td::StringBuilder &sb, const PolicyConfig &config) {
  sb << "{\n";

  if (!config.allowed_mrtd.empty()) {
    sb << "  allowed_mrtd: " << config.allowed_mrtd << "\n";
  }

  if (!config.allowed_rtmr.empty()) {
    sb << "  allowed_rtmr: " << config.allowed_rtmr << "\n";
  }

  if (!config.allowed_image_hashes.empty()) {
    sb << "  allowed_image_hashes: " << config.allowed_image_hashes << "\n";
  }

  if (!config.allowed_collateral_root_hashes.empty()) {
    sb << "  allowed_collateral_root_hashes: " << config.allowed_collateral_root_hashes << "\n";
  }

  if (config.allowed_mrtd.empty() && config.allowed_rtmr.empty() && config.allowed_image_hashes.empty() &&
      config.allowed_collateral_root_hashes.empty()) {
    sb << "  (default - no restrictions)\n";
  }

  sb << "}";
  return sb;
}

}  // namespace tdx
