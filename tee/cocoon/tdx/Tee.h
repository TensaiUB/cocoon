#pragma once

#include "tee/cocoon/Tee.h"

namespace tdx {

struct TeeConfig {};

td::Result<cocoon::TeeInterfaceRef> make_tee(bool fake, const TeeConfig& config);

}  // namespace tdx
