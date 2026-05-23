#pragma once

#include <string>
#include <vector>

#include "td/utils/MovableValue.h"
#include "td/utils/Status.h"
#include "td/utils/UInt.h"
#include "td/utils/int_types.h"

#include "tee/cocoon/sev/ABI.h"

namespace sev {

class GuestDevice {
  using Fd = td::MovableValue<int, -1>;

  struct MsgReportRsp {
    td::uint32 status;
    td::uint32 report_size;
    td::uint8 reserved[24];
    AttestationReport report;
  };
  static_assert(sizeof(MsgReportRsp) == sizeof(AttestationReport) + 32);

 public:
  struct CertTableEntry {
    td::UInt128 guid;
    std::string cert;
  };

 public:
  static td::Result<GuestDevice> open();

 public:
  GuestDevice() = default;
  explicit GuestDevice(Fd fd) : fd_(std::move(fd)) {
  }

 public:
  GuestDevice(GuestDevice &&) = default;
  GuestDevice(const GuestDevice &) = delete;

 public:
  ~GuestDevice();

 public:
  GuestDevice &operator=(GuestDevice &&) = default;
  GuestDevice &operator=(const GuestDevice &) = delete;

 public:
  td::Result<AttestationReport> get_report(const td::UInt512 &user_claims_hash) const;
  td::Result<std::pair<AttestationReport, std::vector<CertTableEntry>>> get_extended_report(
      const td::UInt512 &user_claims_hash) const;
  td::Result<td::UInt256> get_derived_key(td::Slice name) const;

 private:
  Fd fd_;
};

}  // namespace sev
