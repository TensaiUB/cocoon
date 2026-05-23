#pragma once

#include <optional>
#include <string>

#include "td/net/utils.h"
#include "td/utils/Status.h"
#include "td/utils/UInt.h"
#include "td/utils/tl_helpers.h"

namespace tdx {

struct TdxAttestationData;

/**
 * @brief Custom OID constants for TDX extensions
 *
 * Using private enterprise OID space: 1.3.6.1.4.1
 * We use 1.3.6.1.4.1.12345.x for our custom extensions
 */
namespace OID {

constexpr td::CSlice TDX_QUOTE = "1.3.6.1.4.1.12345.1";
constexpr td::CSlice TDX_USER_CLAIMS = "1.3.6.1.4.1.12345.2";

}  // namespace OID

struct RATLSAttestationReport {
  td::UInt384 mr_td;                ///< Measurement of initial TD contents
  td::UInt384 mr_config_id;         ///< Software-defined config ID
  td::UInt384 mr_owner;             ///< TD owner identifier
  td::UInt384 mr_owner_config;      ///< Owner-defined config
  std::array<td::UInt384, 4> rtmr;  ///< Runtime measurement registers [0..3]
  td::UInt512 reportdata;           ///< User-defined report data
  td::UInt384 collateral_root_hash;

  template <class StorerT>
  void store(StorerT &storer) const {
    using td::store;
    store(mr_td, storer);
    store(mr_config_id, storer);
    store(mr_owner, storer);
    store(mr_owner_config, storer);
    for (size_t i = 0; i < 4; i++) {
      store(rtmr[i], storer);
    }
    store(reportdata, storer);
    store(collateral_root_hash, storer);
  }

  template <class ParserT>
  void parse(ParserT &parser) {
    using td::parse;
    parse(mr_td, parser);
    parse(mr_config_id, parser);
    parse(mr_owner, parser);
    parse(mr_owner_config, parser);
    for (size_t i = 0; i < 4; i++) {
      parse(rtmr[i], parser);
    }
    parse(reportdata, parser);
    parse(collateral_root_hash, parser);
  }
};

td::StringBuilder &operator<<(td::StringBuilder &sb, const RATLSAttestationReport &report);

RATLSAttestationReport make_report(const TdxAttestationData &attestation, const td::UInt384 &root_key_id);
td::UInt256 image_hash(const RATLSAttestationReport &report);

struct RATLSExtensions {
  std::optional<std::string> quote;
  std::optional<std::string> user_claims;
};

class RATLSVerifier {
 public:
  struct Config {};

 public:
  static td::Result<RATLSVerifier> make(const Config &config);

 public:
  td::Result<RATLSAttestationReport> verify(const td::UInt512 &user_claims, const RATLSExtensions &extensions) const;
};

}  // namespace tdx
