#include "tee/cocoon/sev/SEVHashes.h"

#include <stdio.h>

#include <cstddef>
#include <type_traits>

#include "td/utils/crypto.h"
#include "td/utils/filesystem.h"
#include "td/utils/port/FileFd.h"
#include "td/utils/port/MemoryMapping.h"

#include "tee/cocoon/sev/UUID.h"

namespace sev {

namespace {

template <class T, class U>
struct not_a_pointer {
  typedef U type;
};

template <class T, class U>
struct not_a_pointer<T*, U> {};

template <class T>
constexpr inline typename not_a_pointer<T, T>::type align_up_pow2(T value, size_t alignment) noexcept {
  return T((value + (T(alignment) - 1)) & ~T(alignment - 1));
}

}  // namespace

td::Result<SEVHashes> SEVHashes::open(td::Slice kernel_path, td::Slice initrd_path, td::Slice cmdline_path) {
  TRY_RESULT(kernel_fd, td::FileFd::open(kernel_path.str(), td::FileFd::Read));
  TRY_RESULT(kernel_mapping, td::MemoryMapping::create_from_file(kernel_fd));
  auto kernel_hash = td::sha256(kernel_mapping.as_slice());

  // qemu/target/i386/sev.c
  auto initrd_hash = td::sha256("");
  if (!initrd_path.empty()) {
    TRY_RESULT(initrd_fd, td::FileFd::open(initrd_path.str(), td::FileFd::Read));
    TRY_RESULT(initrd_mapping, td::MemoryMapping::create_from_file(initrd_fd));
    initrd_hash = td::sha256(initrd_mapping.as_slice());
  }

  std::string cmdline_hash = td::sha256("\0");
  if (!cmdline_path.empty()) {
    TRY_RESULT(cmdline, td::read_file_str(cmdline_path.str()));
    cmdline.push_back('\0');
    cmdline_hash = td::sha256(cmdline);
  }

  return SEVHashes(std::move(kernel_hash), std::move(initrd_hash), std::move(cmdline_hash));
}

SEVHashes::SEVHashes(std::string kernel_hash, std::string initrd_hash, std::string cmdline_hash)
    : kernel_hash_(std::move(kernel_hash))
    , initrd_hash_(std::move(initrd_hash))
    , cmdline_hash_(std::move(cmdline_hash)) {
}

td::Status SEVHashes::build_table(Table* t) {
  TRY_RESULT_ASSIGN(t->guid, uuid_to_bytes("9438d606-4f22-4cc9-b479-a793d411fd21"));
  TRY_RESULT_ASSIGN(t->cmdline.guid, uuid_to_bytes("97d02dd8-bd20-4c94-aa78-e7714d36ab2a"));
  TRY_RESULT_ASSIGN(t->initrd.guid, uuid_to_bytes("44baf731-3a2f-4bd7-9af1-41e29169781d"));
  TRY_RESULT_ASSIGN(t->kernel.guid, uuid_to_bytes("4de79437-abd2-427f-b835-d5b172d2045b"));
  uuid_bswap(t->guid);
  uuid_bswap(t->cmdline.guid);
  uuid_bswap(t->initrd.guid);
  uuid_bswap(t->kernel.guid);
  t->initrd.hash.as_mutable_slice().copy_from(initrd_hash_);
  t->cmdline.hash.as_mutable_slice().copy_from(cmdline_hash_);
  t->kernel.hash.as_mutable_slice().copy_from(kernel_hash_);

  CHECK(t->length == sizeof(*t));
  CHECK(t->cmdline.length == 50);
  CHECK(t->initrd.length == 50);
  CHECK(t->kernel.length == 50);

  return td::Status::OK();
}

td::Result<td::Slice> SEVHashes::build_page(td::uint64 offset) {
  offset &= kPageMask;
  const auto size = align_up_pow2(sizeof(Table), 16);
  if (kPageSize < offset || kPageSize < offset + size) {
    return td::Status::Error(PSTRING() << "SEVHashes: bad page offset");
  }

  page_.fill(0);
  auto t = new (page_.data() + offset) Table;
  TRY_STATUS(build_table(t));

  return td::Slice(page_.data(), page_.size());
}

td::StringBuilder& operator<<(td::StringBuilder& sb, const SEVHashes::Table& t) {
#if 0
  return sb << "SEVHashesTable: guid:" << uuid_to_string(uuid_bswap(t.guid))
            << " cmdline: guid:" << uuid_to_string(uuid_bswap(t.cmdline.guid)) << ", length:" << t.cmdline.length
            << ", hash:" << td::format::as_hex_dump<0>(t.cmdline.hash.as_slice())
            << " initrd: guid:" << uuid_to_string(uuid_bswap(t.initrd.guid)) << ", length:" << t.initrd.length
            << ", hash:" << td::format::as_hex_dump<0>(t.initrd.hash.as_slice())
            << " kernel: guid:" << uuid_to_string(uuid_bswap(t.kernel.guid)) << ", length:" << t.kernel.length
            << ", hash:" << td::format::as_hex_dump<0>(t.kernel.hash.as_slice());
#endif

  return sb << td::format::as_hex_dump<0>(td::Slice(reinterpret_cast<const char*>(&t.cmdline), sizeof(t.cmdline)));
}

}  // namespace sev
