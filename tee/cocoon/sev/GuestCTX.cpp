#include "tee/cocoon/sev/GuestCTX.h"

#include "tee/cocoon/sev/SHA384.h"

namespace sev {

namespace {

template <typename T>
constexpr typename std::enable_if<std::is_integral<T>::value, bool>::type is_pow2_aligned(T value,
                                                                                          size_t alignment) noexcept {
  return !(value & (static_cast<T>(alignment - 1)));
}

}  // namespace

td::Status GuestCTX::update_normal_pages(td::uint64 gpa, td::Slice pages) {
  if (!is_pow2_aligned(pages.size(), kPageSize)) {
    return td::Status::Error(PSTRING() << "GuestCTX: zero pages are not aligned to page size: " << pages.size());
  }

  td::uint64 offset = 0;
  while (offset != pages.size()) {
    const auto page = pages.substr(offset, kPageSize);
    update(PageType::Normal, offset, SHA384(page));

    offset += kPageSize;
  }

  return td::Status::OK();
}

td::Status GuestCTX::update_vmsa_page(td::Slice page) {
  if (page.size() != kPageSize) {
    return td::Status::Error(PSTRING() << "GuestXTX: unexpected VMSA page size: " << page.size());
  }

  update(PageType::VMSA, 0xfffffffff000ULL, SHA384(page));

  return td::Status::OK();
}

td::Status GuestCTX::update_zero_pages(td::uint64 gpa, td::uint64 size) {
  if (!is_pow2_aligned(size, kPageSize)) {
    return td::Status::Error(PSTRING() << "GuestCTX: zero pages are not aligned to page size: " << size);
  }

  td::uint64 offset = 0;
  const auto zero = td::UInt384::zero();
  while (offset < size) {
    update(PageType::Zero, gpa + offset, zero);
    offset += kPageSize;
  }

  return td::Status::OK();
}

void GuestCTX::update(PageType page_type, td::uint64 gpa, const td::UInt384& contents) {
  PageInfo page_info;

  page_info.digest_cur = digest_;
  page_info.contents = contents;
  page_info.page_type = static_cast<std::underlying_type_t<PageType>>(page_type);
  page_info.imi_page = 0;
  page_info.vmpl3_perms = 0;
  page_info.vmpl2_perms = 0;
  page_info.vmpl1_perms = 0;
  page_info.gpa = gpa;

  CHECK(page_info.length == sizeof(page_info));
  CHECK(!page_info.reserved);
  CHECK(!page_info.reserved2);

  digest_ = SHA384(td::Slice(reinterpret_cast<const char*>(&page_info), sizeof(page_info)));
}

}  // namespace sev
