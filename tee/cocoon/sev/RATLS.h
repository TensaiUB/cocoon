#pragma once

#include <optional>
#include <string>

#include "td/actor/common.h"
#include "td/net/utils.h"
#include "td/utils/StringBuilder.h"
#include "td/utils/UInt.h"
#include "td/utils/tl_helpers.h"

#include "tee/cocoon/sev/PKI.h"

namespace sev {

/**
 * @brief Custom OID constants for TEE extensions
 *
 * Using private enterprise OID space: 1.3.6.1.4.1
 * We use 1.3.6.1.4.1.12345.x for our custom extensions
 */
namespace OID {

constexpr td::CSlice SEV_REPORT_DATA = "1.3.6.1.4.1.12345.100";
constexpr td::CSlice SEV_ATTESTATION_REPORT = "1.3.6.1.4.1.12345.101";
constexpr td::CSlice SEV_VCEK = "1.3.6.1.4.1.12345.102";

}  // namespace OID

struct RATLSAttestationReport {
  td::UInt384 measurement;
  td::UInt512 reportdata;           ///< User-defined report data
				    ///
  template <class StorerT>
  void store(StorerT &storer) const {
    using td::store;
    store(measurement, storer);
    store(reportdata, storer);
  }

  template <class ParserT>
  void parse(ParserT &parser) {
    using td::parse;
    parse(measurement, parser);
    parse(reportdata, parser);
  }
};
td::StringBuilder &operator<<(td::StringBuilder &sb, const RATLSAttestationReport& report);

td::UInt256 image_hash(const RATLSAttestationReport &report);

struct RATLSExtensions {
  std::optional<std::string> report_data;
  std::optional<std::string> attestation_report;
  std::optional<std::string> vcek;
};

class RATLSVerifier {
 public:
  struct Config {
    std::string PKI_ROOT_DIR{"/etc/tee/sev/"};
  };

 public:
  static td::Result<RATLSVerifier> make(td::actor::Scheduler *scheduler, const Config &config);

 public:
  explicit RATLSVerifier(TrustChainManager trust_chain_manager) : trust_chain_manager_(std::move(trust_chain_manager)) {
  }

 public:
  td::Result<RATLSAttestationReport> verify(const td::UInt512 &user_claims, const RATLSExtensions &extensions) const;

 private:
  TrustChainManager trust_chain_manager_;
};

}  // namespace sev
