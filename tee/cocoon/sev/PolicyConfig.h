#pragma once

#include <vector>

#include "td/utils/JsonBuilder.h"
#include "td/utils/Status.h"
#include "td/utils/StringBuilder.h"
#include "td/utils/UInt.h"

namespace sev {

struct PolicyConfig {
  std::vector<td::UInt384> allowed_measurement;
  std::vector<td::UInt256> allowed_image_hashes;
};

td::Result<PolicyConfig> parse_policy_config(td::JsonObject &obj);
td::StringBuilder &operator<<(td::StringBuilder &sb, const PolicyConfig &config);

}  // namespace sev
