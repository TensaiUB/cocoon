#include "tee/cocoon/sev/PolicyConfig.h"

#include "td/utils/format.h"

#include "tee/cocoon/utils.h"

namespace sev {

td::Result<PolicyConfig> parse_policy_config(td::JsonObject &obj) {
  PolicyConfig config;

  // Parse allowed_measurement array
  auto r_measurement_array = obj.extract_optional_field("allowed_measurement", td::JsonValue::Type::Array);
  if (r_measurement_array.is_ok() && r_measurement_array.ok().type() == td::JsonValue::Type::Array) {
    for (const auto &item : r_measurement_array.ok().get_array()) {
      if (item.type() == td::JsonValue::Type::String) {
        TRY_RESULT(measurement, cocoon::parse_hex_uint<td::UInt384>(item.get_string()));
        config.allowed_measurement.push_back(measurement);
      }
    }
  }

  // Parse allowed_image_id array
  auto r_image_id_array = obj.extract_optional_field("allowed_image_id", td::JsonValue::Type::Array);
  if (r_image_id_array.is_ok() && r_image_id_array.ok().type() == td::JsonValue::Type::Array) {
    for (const auto &item : r_image_id_array.ok().get_array()) {
      if (item.type() == td::JsonValue::Type::String) {
        TRY_RESULT(image_hash, cocoon::parse_hex_uint<td::UInt256>(item.get_string()));
        config.allowed_image_hashes.push_back(image_hash);
      }
    }
  }

  return config;
}

td::StringBuilder &operator<<(td::StringBuilder &sb, const PolicyConfig &config) {
  sb << "{\n";

  if (!config.allowed_measurement.empty()) {
    sb << "  allowed_measurement: " << config.allowed_measurement << "\n";
  }

  if (!config.allowed_image_hashes.empty()) {
    sb << "  allowed_image_hashes: " << config.allowed_image_hashes << "\n";
  }

  if (config.allowed_measurement.empty() && config.allowed_image_hashes.empty()) {
    sb << "  (default - no restrictions)\n";
  }

  sb << "}";

  return sb;
}

}  // namespace sev
