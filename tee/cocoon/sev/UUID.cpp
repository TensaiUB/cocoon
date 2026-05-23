#include "tee/cocoon/sev/UUID.h"

#include <byteswap.h>

#include "td/utils/Slice-decl.h"

namespace sev {

namespace {

constexpr td::CSlice UUID_FMT =
    "%02hhx%02hhx%02hhx%02hhx-"
    "%02hhx%02hhx-%02hhx%02hhx-"
    "%02hhx%02hhx-"
    "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx";


}  // namespace

td::Result<td::UInt128> uuid_to_bytes(td::CSlice uuid) {
  td::UInt128 b;

  if (uuid.size() != 36) {
    return td::Status::Error("Cannot parse UUID");
  }

  if (sscanf(uuid.c_str(), UUID_FMT.c_str(), &b.raw[0], &b.raw[1], &b.raw[2], &b.raw[3], &b.raw[4], &b.raw[5],
             &b.raw[6], &b.raw[7], &b.raw[8], &b.raw[9], &b.raw[10], &b.raw[11], &b.raw[12], &b.raw[13], &b.raw[14],
             &b.raw[15]) != 16) {
    return td::Status::Error("Cannot parse UUID");
  }

  return b;
}

std::string uuid_to_string(td::UInt128 uuid) {
  std::string str(36, '\0');
  CHECK(sprintf(str.data(), UUID_FMT.c_str(), uuid.raw[0], uuid.raw[1], uuid.raw[2], uuid.raw[3], uuid.raw[4],
                uuid.raw[5], uuid.raw[6], uuid.raw[7], uuid.raw[8], uuid.raw[9], uuid.raw[10], uuid.raw[11],
                uuid.raw[12], uuid.raw[13], uuid.raw[14], uuid.raw[15]) == 36);

  return str;
}

void uuid_bswap(td::UInt128& uuid) {
  *reinterpret_cast<uint32_t*>(&uuid.raw[0]) = bswap_32(*reinterpret_cast<uint32_t*>(&uuid.raw[0]));
  *reinterpret_cast<uint16_t*>(&uuid.raw[4]) = bswap_16(*reinterpret_cast<uint16_t*>(&uuid.raw[4]));
  *reinterpret_cast<uint16_t*>(&uuid.raw[6]) = bswap_16(*reinterpret_cast<uint16_t*>(&uuid.raw[6]));
}

td::UInt128 uuid_bswap(const td::UInt128& uuid) {
  auto swapped = uuid;
  uuid_bswap(swapped);

  return swapped;
}

}  // namespace sev
