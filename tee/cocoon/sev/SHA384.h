#pragma once

#include "td/utils/Slice-decl.h"
#include "td/utils/UInt.h"

#include <openssl/sha.h>

namespace sev {

static inline td::UInt384 SHA384(td::Slice m) {
  td::UInt384 md;

  ::SHA384(m.ubegin(), m.size(), md.raw);

  return md;
}

}  // namespace sev
