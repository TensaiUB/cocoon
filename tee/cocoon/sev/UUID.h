#pragma once

#include <string>

#include "td/utils/Slice-decl.h"
#include "td/utils/Status.h"
#include "td/utils/UInt.h"

namespace sev {

td::Result<td::UInt128> uuid_to_bytes(td::CSlice uuid);
std::string uuid_to_string(td::UInt128 uuid);
void uuid_bswap(td::UInt128& uuid);
td::UInt128 uuid_bswap(const td::UInt128& uuid);


}  // namespace sev
