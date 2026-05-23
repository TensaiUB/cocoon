#include "tee/cocoon/tdx/RATLS.h"

#include "td/utils/crypto.h"
#include "td/utils/misc.h"

#include "tee/cocoon/tdx/tdx.h"

namespace tdx {

td::StringBuilder &operator<<(td::StringBuilder &sb, const RATLSAttestationReport &report) {
  sb << "Intel TDX AttestationReport\n";
  auto p = [&](td::Slice name, auto value) {
    sb << name << ": " << td::Slice(td::hex_encode(value.as_slice())) << "\n";
  };
  p("MRTD", report.mr_td);
  p("MRCONFIGID", report.mr_config_id);
  p("MROWNER", report.mr_owner);
  p("MROWNERCONFIG", report.mr_owner_config);
  for (int i = 0; i < 4; i++) {
    p(PSLICE() << "RTMR" << i, report.rtmr[i]);
  }
  p("REPORTDATA", report.reportdata);
  return sb;
}

RATLSAttestationReport make_report(const TdxAttestationData &attestation, const td::UInt384 &root_key_id) {
  RATLSAttestationReport report;
  report.mr_td = attestation.mr_td;
  report.mr_config_id = attestation.mr_config_id;
  report.mr_owner = attestation.mr_owner;
  report.mr_owner_config = attestation.mr_owner_config;
  report.rtmr = attestation.rtmr;
  report.reportdata = attestation.reportdata;
  report.collateral_root_hash = root_key_id;

  return report;
}

td::UInt256 image_hash(const RATLSAttestationReport &report) {
  TdxAttestationData attestation_data;

  attestation_data.mr_td = report.mr_td;
  attestation_data.mr_config_id = report.mr_config_id;
  attestation_data.mr_owner = report.mr_owner;
  attestation_data.mr_owner_config = report.mr_owner_config;
  attestation_data.rtmr = report.rtmr;
  attestation_data.reportdata = td::UInt512{};

  auto serialized = td::serialize(attestation_data);

  td::UInt256 hash;
  td::sha256(serialized, hash.as_mutable_slice());

  return hash;
}

td::Result<RATLSVerifier> RATLSVerifier::make(const Config &config) {
  return RATLSVerifier();
}

td::Result<RATLSAttestationReport> RATLSVerifier::verify(const td::UInt512 &user_claims,
                                                         const RATLSExtensions &extensions) const {
#if TD_TDX_ATTESTATION
  if (!extensions.quote.has_value()) {
    return td::Status::Error("No TDX_QUOTE extension found");
  }

  if (!extensions.user_claims.has_value()) {
    return td::Status::Error("No TDX_USER_CLAIMS extension found");
  }

  Quote quote{extensions.quote.value()};
  TRY_RESULT(R, tdx_validate_quote(quote));
  const auto &[attestation, root_key_id] = R;

  return make_report(attestation, root_key_id);
#endif

  return td::Status::Error("TDX is not supported on this platform");
}

}  // namespace tdx
