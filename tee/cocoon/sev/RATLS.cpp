#include "tee/cocoon/sev/RATLS.h"

#include <cstring>

#include "td/utils/misc.h"
#include "td/utils/tl_helpers.h"

#include "tee/cocoon/sev/ABI.h"
#include "tee/cocoon/sev/PKI.h"

namespace sev {

td::UInt256 image_hash(const RATLSAttestationReport &report) {
  auto copy = report;
  copy.reportdata = td::UInt512{};
  auto serialized = td::serialize(copy);

  td::UInt256 hash;
  td::sha256(serialized, hash.as_mutable_slice());

  return hash;
}

td::StringBuilder &operator<<(td::StringBuilder &sb, const RATLSAttestationReport &report) {
  auto p = [&](td::Slice name, auto value) {
    sb << name << ": " << td::Slice(td::hex_encode(value.as_slice())) << "\n";
  };

  sb << "AMD SEV AttestationReport\n";
  p("MEASUREMENT", report.measurement);
  p("REPORTDATA", report.reportdata);

  return sb;
}

td::Result<RATLSVerifier> RATLSVerifier::make(td::actor::Scheduler *scheduler, const Config &config) {
  TRY_RESULT(trust_chain_manager, TrustChainManager::make(scheduler, config.PKI_ROOT_DIR));

  return RATLSVerifier(std::move(trust_chain_manager));
}

td::Result<RATLSAttestationReport> RATLSVerifier::verify(const td::UInt512 &user_claims,
                                                         const RATLSExtensions &extensions) const {
  if (!extensions.report_data.has_value()) {
    return td::Status::Error("No SEV_REPORT_DATA extension found");
  }
  const auto &report_data = extensions.report_data.value();
  if (report_data.size() != sizeof(user_claims.raw)) {
    return td::Status::Error("Unexpected SEV_REPORT_DATA size");
  }
  if (memcmp(&user_claims.raw[0], report_data.data(), sizeof(user_claims.raw))) {
    return td::Status::Error("SEV_REPORT_DATA mismatch with user_claims");
  }

  if (!extensions.attestation_report.has_value()) {
    return td::Status::Error("No SEV_ATTESTATION_REPORT extension found");
  }
  const AttestationReport *attestation_report;
  if (extensions.attestation_report.value().size() != sizeof(*attestation_report)) {
    return td::Status::Error("Unexpected SEV_ATTESTATION_REPORT size");
  }
  attestation_report = reinterpret_cast<const AttestationReport *>(extensions.attestation_report.value().data());
  if (attestation_report->report_data != user_claims) {
    return td::Status::Error("AttestationReport has wrong report_data");
  }

  if (!extensions.vcek.has_value()) {
    return td::Status::Error("No SEV_VCEK extension found");
  }
  TRY_RESULT(vcek, VCEKCertificate::create(extensions.vcek.value()));
  TRY_RESULT(product_name_string, vcek.productName());
  TRY_RESULT(product_name, product_name_from_name(product_name_string));
  TRY_STATUS(trust_chain_manager_.verify_cert(product_name, vcek.native_handle()));

  TRY_RESULT(hw_id, vcek.hwID());
  if (hw_id != attestation_report->chip_id.as_slice().substr(0, hw_id.size())) {
    return td::Status::Error("VCEK certificate hw_id mismatches chip_id from attestation report");
  }

  TRY_STATUS(vcek.verify_report(*attestation_report, user_claims));

  return RATLSAttestationReport{.measurement = attestation_report->measurement,
                                .reportdata = attestation_report->report_data};
}

}  // namespace sev
