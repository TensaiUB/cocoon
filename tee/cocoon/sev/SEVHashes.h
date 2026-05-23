#pragma once

#include <string>
#include <array>

#include "td/utils/Slice-decl.h"
#include "td/utils/Status.h"
#include "td/utils/StringBuilder.h"
#include "td/utils/UInt.h"
#include "td/utils/int_types.h"

namespace sev {

class SEVHashes {
 public:
  static constexpr size_t kPageSize{4096};
  static constexpr size_t kPageMask{kPageSize - 1};

 public:
  struct Entry {
    td::UInt128 guid;
    td::uint16 length{50};
    td::UInt256 hash;
  } __attribute__((packed));
  static_assert(sizeof(Entry) == 50);

  struct Table {
    td::UInt128 guid;
    td::uint16 length{168};
    Entry cmdline;
    Entry initrd;
    Entry kernel;
  } __attribute__((packed));
  static_assert(sizeof(Table) == 168);

 public:
  // This reconstruct SEV hashes the way QEMU does to compute digest
  static td::Result<SEVHashes> open(td::Slice kernel_path, td::Slice initrd_path, td::Slice cmdline_path);

 public:
  SEVHashes(std::string kernel_hash, std::string initrd_hash, std::string cmdline_hash);

 public:
  td::Status build_table(Table *t);
  td::Result<td::Slice> build_page(td::uint64 offset);

 private:
  std::string kernel_hash_;
  std::string initrd_hash_;
  std::string cmdline_hash_;
  std::array<td::uint8, kPageSize> page_{};
};
td::StringBuilder &operator<<(td::StringBuilder &sb, const SEVHashes::Table &t);


}  // namespace sev
