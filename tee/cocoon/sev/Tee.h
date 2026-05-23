#pragma once

#include <optional>
#include <string>

#include "tee/cocoon/Tee.h"

#include "td/utils/Status.h"

namespace sev {

struct TeeConfig {
  std::string PKI_ROOT_DIR{"/etc/tee/sev/"};
};

td::Result<cocoon::TeeInterfaceRef> make_tee(bool fake, const TeeConfig &config);

}  // namespace sev
