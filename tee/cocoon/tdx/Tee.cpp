#include "tee/cocoon/tdx/Tee.h"

#if TD_TDX_ATTESTATION
#include "tdx_attest.h"
#endif

#include "td/utils/as.h"

#include "tee/cocoon/tdx/RATLS.h"
#include "tee/cocoon/tdx/tdx.h"

namespace tdx {

namespace {

// XXX:
// TODO
// It seems that quote isn't needed here

class FakeTdxTee : public cocoon::TeeInterface {
 public:
  td::Status prepare_cert_config(cocoon::TeeCertConfig& config,
                                 const tde2e_core::PublicKey& public_key) const override {
    UserClaims user_claims{public_key};
    RATLSAttestationReport report{};
    report.reportdata = user_claims.to_hash();
    config.extra_extensions.emplace_back(OID::TDX_QUOTE.c_str(), td::serialize(report));
    config.extra_extensions.emplace_back(OID::TDX_USER_CLAIMS.c_str(), user_claims.serialize());

    return td::Status::OK();
  }

  td::Result<cocoon::RATLSAttestationReport> make_report(const td::UInt512& user_claims) const override {
    RATLSAttestationReport report;

    report.reportdata = user_claims;

    return report;
  }
};

class TdxTee : public cocoon::TeeInterface {
 public:
  td::Status prepare_cert_config(cocoon::TeeCertConfig& config,
                                 const tde2e_core::PublicKey& public_key) const override {
    UserClaims user_claims{public_key};
    TRY_RESULT(quote, make_quote(user_claims.to_hash()));
    config.extra_extensions.emplace_back(OID::TDX_QUOTE.c_str(), quote.raw_quote);
    config.extra_extensions.emplace_back(OID::TDX_USER_CLAIMS.c_str(), user_claims.serialize());

    return td::Status::OK();
  }

  td::Result<cocoon::RATLSAttestationReport> make_report(const td::UInt512& user_claims) const override {
    TRY_RESULT(tdx_raw_report, tdx_make_report(user_claims));
    TRY_RESULT(attestation, tdx_parse_report(tdx_raw_report));

    return tdx::make_report(attestation, td::UInt384::zero());
  }

 private:
  td::Result<Quote> make_quote(const td::UInt512& user_claims) const {
#if TD_TDX_ATTESTATION
    // Prepare report data structure
    tdx_report_data_t report_data;
    static_assert(TDX_REPORT_DATA_SIZE == 64, "TDX report data must be 64 bytes");
    static_assert(sizeof(report_data.d) == TDX_REPORT_DATA_SIZE, "Report data structure size mismatch");

    // Copy user claims hash into report data
    td::as<td::UInt512>(report_data.d) = user_claims;

    // Prepare quote generation parameters
    tdx_uuid_t selected_attestation_key_id{};
    uint8_t* quote_buffer = nullptr;
    uint32_t quote_size = 0;

    // Generate TDX quote
    auto status =
        tdx_att_get_quote(&report_data, nullptr, 0, &selected_attestation_key_id, &quote_buffer, &quote_size, 0);

    if (status != TDX_ATTEST_SUCCESS) {
      return td::Status::Error(PSLICE() << "Failed to generate TDX quote: " << to_str(status) << " (0x"
                                        << td::format::as_hex(status) << ")");
    }

    if (!quote_buffer || quote_size == 0) {
      return td::Status::Error("TDX quote generation returned null buffer or zero size");
    }

    // Copy quote data and free the allocated buffer
    Quote result{td::Slice(quote_buffer, quote_size).str()};
    tdx_att_free_quote(quote_buffer);

    return result;
#else
    return td::Status::Error("TDX is not supported on this platform");
#endif
  }
};

}  // namespace

td::Result<cocoon::TeeInterfaceRef> make_tee(bool fake, const TeeConfig& config) {
  if (fake) {
    return std::make_shared<FakeTdxTee>();
  }

  return std::make_shared<TdxTee>();
}

}  // namespace tdx
