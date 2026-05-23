#include "tee/cocoon/sev/OVMF.h"

#include "tee/cocoon/sev/UUID.h"

namespace sev {

td::Result<OVMF> OVMF::open(td::CSlice path) {
  TRY_RESULT(fd, td::FileFd::open(path.str(), td::FileFd::Read));
  TRY_RESULT(mapping, td::MemoryMapping::create_from_file(fd));

  auto parse_footer_table = [](td::Slice image) -> td::Result<footer_table> {
    constexpr size_t kTailSize = 32;
    constexpr size_t kEntrySize = 18;

    if (image.size() < kTailSize + kEntrySize) {
      return td::Status::Error("Too small image size");
    }
    auto last_entry = image.substr(image.size() - kTailSize - kEntrySize, kEntrySize);

    TRY_RESULT(guid, uuid_to_bytes("96b582de-1fb2-45f7-baea-a366c55a082d"));
    uuid_bswap(guid);
    if (last_entry.substr(sizeof(td::uint16), sizeof(guid)) != guid.as_slice()) {
      return td::Status::Error("Cannot find OVMF table footer GUID");
    }

    td::uint16 l = *reinterpret_cast<const td::uint16*>(last_entry.data());
    if (image.size() < (l + kTailSize)) {
      return td::Status::Error("Too small image size");
    }

    auto match_uuid = [](td::CSlice uuid, td::Slice binary) {
      auto guid = uuid_to_bytes(uuid).move_as_ok();
      uuid_bswap(guid);

      return guid.as_slice() == binary;
    };

    auto fetch_end = [](auto& v, td::Slice& bytes) -> td::Status {
      if (bytes.size() < sizeof(v)) {
        return td::Status::Error("Not enough data");
      }

      v = *reinterpret_cast<std::add_pointer_t<std::add_const_t<std::remove_reference_t<decltype(v)>>>>(
          bytes.data() + bytes.size() - sizeof(v));
      bytes.remove_suffix(sizeof(v));

      return td::Status::OK();
    };

    auto bytes = image.substr(image.size() - kTailSize - l, l - kEntrySize);
    footer_table ft;

    while (!bytes.empty()) {
      if (bytes.size() < kEntrySize) {
        return td::Status::Error("Not enough data in footer table");
      }
      auto uuid = bytes.substr(bytes.size() - sizeof(guid), sizeof(guid));
      bytes.remove_suffix(sizeof(guid));
      td::uint16 entry_l;
      TRY_STATUS(fetch_end(entry_l, bytes));

      if (entry_l < kEntrySize) {
        return td::Status::Error("Not enough data in footer table");
      }

      if (match_uuid("7255371f-3a3b-4b04-927b-1da6efa8d454", uuid)) {
        CHECK(entry_l == 0x1a);

        td::uint32 size, base;
        TRY_STATUS(fetch_end(size, bytes));
        TRY_STATUS(fetch_end(base, bytes));
        ft.sev_hashes = footer_table::SEV_hashes{size, base};

        continue;
      }

      if (match_uuid("4c2eb361-7d9b-4cc3-8081-127c90d3d294", uuid)) {
        CHECK(entry_l == 0x1a);

        td::uint32 size, base;
        TRY_STATUS(fetch_end(size, bytes));
        TRY_STATUS(fetch_end(base, bytes));
        ft.sev_secret_block = footer_table::SEV_secret_block{size, base};

        continue;
      }

      if (match_uuid("00f771de-1a7e-4fcb-890e-68c77e2fb44e", uuid)) {
        CHECK(entry_l == 0x16);

        td::uint32 sev_ap_reset_rip;
        TRY_STATUS(fetch_end(sev_ap_reset_rip, bytes));
        ft.sev_ap_reset_rip = sev_ap_reset_rip;

        continue;
      }

      if (match_uuid("dc886566-984a-4798-A75e-5585a7bf67cc", uuid)) {
        CHECK(entry_l == 0x16);

        td::uint32 sev_metadata_base;
        TRY_STATUS(fetch_end(sev_metadata_base, bytes));
        ft.sev_metadata_base = sev_metadata_base;

        continue;
      }

      LOG(INFO) << "Found unknown guid: " << td::format::as_hex_dump<0>(uuid);
      bytes.remove_suffix(entry_l - kEntrySize);
    }

    return ft;
  };

  auto parse_sev_metadata = [](td::Slice image, td::uint32 SEV_MetaData_base) -> td::Result<std::vector<Section>> {
    // The details are in OvmfSevMetadata.asm

    struct SEV_MetaData {
      td::uint32 signature;
      td::uint32 length;
      td::uint32 version;
      td::uint32 num_sections;
    };
    static_assert(sizeof(SEV_MetaData) == 16);

    if (image.size() < SEV_MetaData_base || image.size() < (SEV_MetaData_base + sizeof(SEV_MetaData))) {
      return td::Status::Error(PSTRING() << "Bad SEV_MetaData_base: " << SEV_MetaData_base);
    }

    auto sev_metadata = reinterpret_cast<const SEV_MetaData*>(image.data() + image.size() - SEV_MetaData_base);
    if (sev_metadata->signature != 0x56455341) {
      return td::Status::Error(PSTRING() << "SEV MetaData has bad signature: "
                                         << td::format::as_hex(sev_metadata->signature));
    }
    if (sev_metadata->version != 1) {
      return td::Status::Error("SEV MetaData has bad version");
    }
    if (sev_metadata->length < 16 || (sev_metadata->length - 16) != sev_metadata->num_sections * 12) {
      return td::Status::Error("SEV MetaData has length and num sections mismatch");
    }

    auto fetch = []<typename T>(T& v, td::Slice& bytes) -> td::Status {
      if (bytes.size() < sizeof(T)) {
        return td::Status::Error("SEV MetaData not enough bytes in section");
      }

      v = *reinterpret_cast<const T*>(bytes.data());
      bytes.remove_prefix(sizeof(T));

      return td::Status::OK();
    };

    auto bytes = image.substr(image.size() - SEV_MetaData_base + sizeof(SEV_MetaData), sev_metadata->length - 16);
    std::vector<Section> sections;
    sections.reserve(sev_metadata->num_sections);

    while (!bytes.empty()) {
      auto from_raw_kind = [](td::uint32 kind) -> td::Result<SectionKind> {
        switch (kind) {
          case static_cast<std::underlying_type_t<SectionKind>>(SectionKind::SnpSecMem):
            return SectionKind::SnpSecMem;
          case static_cast<std::underlying_type_t<SectionKind>>(SectionKind::SnpSecrets):
            return SectionKind::SnpSecrets;
          case static_cast<std::underlying_type_t<SectionKind>>(SectionKind::CpuId):
            return SectionKind::CpuId;
          case static_cast<std::underlying_type_t<SectionKind>>(SectionKind::SnpSvsmCaa):
            return SectionKind::SnpSvsmCaa;
          case static_cast<std::underlying_type_t<SectionKind>>(SectionKind::KernelHashes):
            return SectionKind::KernelHashes;
        }

        return td::Status::Error(PSTRING() << "SEV MetaData unexpected section kind: " << kind);
      };

      Section s;
      td::uint32 raw_kind;
      TRY_STATUS(fetch(s.address, bytes));
      TRY_STATUS(fetch(s.length, bytes));
      TRY_STATUS(fetch(raw_kind, bytes));
      TRY_RESULT_ASSIGN(s.kind, from_raw_kind(raw_kind));

      sections.push_back(s);
    }

    return sections;
  };

  TRY_RESULT(footer_table, parse_footer_table(mapping.as_slice()));
  if (!footer_table.sev_metadata_base) {
    return td::Status::Error("No SevMetaData found in OVMF");
  }

  TRY_RESULT(sections, parse_sev_metadata(mapping.as_slice(), footer_table.sev_metadata_base.value()));

  return OVMF(std::move(fd), std::move(mapping), std::move(footer_table), std::move(sections));
}

}  // namespace sev
