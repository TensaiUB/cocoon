#pragma once

#include <vector>

#include "td/utils/port/MemoryMapping.h"
#include "td/utils/int_types.h"
#include "td/utils/optional.h"
#include "td/utils/Slice-decl.h"
#include "td/utils/Status.h"

namespace sev {

class OVMF {
  struct footer_table {
    struct SEV_hashes {
      td::uint32 base;
      td::uint32 size;
    };
    struct SEV_secret_block {
      td::uint32 base;
      td::uint32 size;
    };

    td::optional<SEV_hashes> sev_hashes;
    td::optional<SEV_secret_block> sev_secret_block;
    td::optional<td::uint32> sev_ap_reset_rip;
    td::optional<td::uint32> sev_metadata_base;
  };

 public:
  enum class SectionKind : td::uint32 {
    SnpSecMem = 1,
    SnpSecrets = 2,
    CpuId = 3,
    SnpSvsmCaa = 4,
    KernelHashes = 16,
  };

  struct Section {
    td::uint32 address;
    td::uint32 length;
    SectionKind kind;
  };

 public:
  static td::Result<OVMF> open(td::CSlice path);

 public:
  OVMF(td::FileFd fd, td::MemoryMapping mapping, footer_table ft, std::vector<Section> sections)
      : fd_(std::move(fd)), mapping_(std::move(mapping)), ft_(ft), sections_(std::move(sections)) {
  }

 public:
  td::uint64 gpa() const {
    return (4ULL << 30) - mapping_.as_slice().size();
  }

  td::Slice image() const {
    return mapping_.as_slice();
  }

  template <typename F>
  void for_each_section(F f) const {
    for (auto &s : sections_) {
      f(s);
    }
  }

 private:
  td::FileFd fd_;
  td::MemoryMapping mapping_;
  footer_table ft_;
  std::vector<Section> sections_;
};

}  // namespace sev
