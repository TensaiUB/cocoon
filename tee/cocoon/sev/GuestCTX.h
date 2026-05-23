#pragma once

#include "td/utils/Status.h"
#include "td/utils/UInt.h"
#include "td/utils/int_types.h"

namespace sev {

class GuestCTX {
 public:
  static constexpr size_t kPageSize{4096};
  enum class PageType : td::uint8 {
    Normal = 1,
    VMSA = 2,
    Zero = 3,
    Unmeasured = 4,
    Secrets = 5,
    CpuId = 6,
  };

  struct PageInfo {
    td::UInt384 digest_cur;
    td::UInt384 contents;
    td::uint16 length{112};
    td::uint8 page_type;
    td::uint8 reserved : 7 {0};
    td::uint8 imi_page : 1;
    td::uint8 vmpl3_perms;
    td::uint8 vmpl2_perms;
    td::uint8 vmpl1_perms;
    td::uint8 reserved2{0};
    td::uint64 gpa;
  };
  static_assert(sizeof(PageInfo) == 112);

 public:
  const auto &digest() const {
    return digest_;
  }

 public:
  td::Status update_normal_pages(td::uint64 gpa, td::Slice pages);
  td::Status update_vmsa_page(td::Slice page);
  td::Status update_zero_pages(td::uint64 gpa, td::uint64 size);

 private:
  // 8.17 SNP_LAUNCH_UPDATE
  void update(PageType page_type, td::uint64 gpa, const td::UInt384 &contents);

 private:
  td::UInt384 digest_{td::UInt384::zero()};
};

}  // namespace sev
