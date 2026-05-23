#pragma once

#include <map>
#include <optional>
#include <string>

#include <openssl/x509.h>

#include "td/actor/actor.h"
#include "td/actor/common.h"
#include "td/actor/coro_task.h"
#include "td/e2e/Keys.h"
#include "td/utils/JsonBuilder.h"
#include "td/utils/UInt.h"
#include "td/utils/Variant.h"
#include "td/utils/Variant.h"
#include "td/utils/port/IPAddress.h"

#include "tee/cocoon/sev/PolicyConfig.h"
#include "tee/cocoon/sev/RATLS.h"
#include "tee/cocoon/tdx/PolicyConfig.h"
#include "tee/cocoon/tdx/RATLS.h"
#include "tee/cocoon/tdx/tdx.h"

namespace cocoon {

enum class TeeType { Tdx, Sev };

class AttestationCache;

struct RATLSPolicyConfig {
  tdx::PolicyConfig tdx_config;
  sev::PolicyConfig sev_config;

  std::map<std::string, std::string> parameters;
};

td::Result<RATLSPolicyConfig> parse_ratls_policy_from_json(td::JsonObject& obj);
td::StringBuilder& operator<<(td::StringBuilder& sb, const RATLSPolicyConfig& config);

class RATLSAttestationReport {
 public:
  RATLSAttestationReport() = default;
  explicit RATLSAttestationReport(const tdx::RATLSAttestationReport& report);
  explicit RATLSAttestationReport(const sev::RATLSAttestationReport& report);

 public:
  TeeType type() const {
    CHECK(!report_.empty());

    return report_.get_offset() == 0 ? TeeType::Tdx : TeeType::Sev;
  }

  tdx::RATLSAttestationReport as_tdx() const {
    CHECK(type() == TeeType::Tdx);

    return report_.get<tdx::RATLSAttestationReport>();
  }

  sev::RATLSAttestationReport as_sev() const {
    CHECK(type() == TeeType::Sev);

    return report_.get<sev::RATLSAttestationReport>();
  }

  td::CSlice short_description() const;
  td::UInt256 image_hash() const;
  td::Slice as_slice() const;

 public:
  template <class StorerT>
  void store(StorerT& storer) const {
    CHECK(!report_.empty());
    // This is hack to keep ABI for AttestedPeerInfo
    using td::store;
    td::store(2, storer);
    store(report_, storer);
  }

  template <class ParserT>
  void parse(ParserT& parser) {
    using td::parse;

    int kludge;
    parse(kludge, parser);
    if (kludge < 2) {
      bool has_value = static_cast<bool>(kludge);
      if (!has_value) {
        LOG(FATAL) << "No AttestedPeerInfo in old ABI version";
      }

      tdx::TdxAttestationData attestation_data;
      attestation_data.parse(parser);
      td::UInt384 collateral_root_hash;
      parse(collateral_root_hash, parser);

      tdx::RATLSAttestationReport report;
      report.mr_td = attestation_data.mr_td;
      report.mr_config_id = attestation_data.mr_config_id;
      report.mr_owner = attestation_data.mr_owner;
      report.mr_owner_config = attestation_data.mr_owner_config;
      report.rtmr = attestation_data.rtmr;
      report.reportdata = attestation_data.reportdata;
      report.collateral_root_hash = collateral_root_hash;

      report_ = std::move(report);
    } else if (kludge == 2) {
      parse(report_, parser);
      CHECK(!report_.empty());
    } else {
      LOG(FATAL) << "Unexpected kludge version: " << kludge;
    }
  }

 private:
  td::Variant<tdx::RATLSAttestationReport, sev::RATLSAttestationReport> report_;
};
td::StringBuilder& operator<<(td::StringBuilder& sb, const RATLSAttestationReport& report);

// NB! Changes break ABI
struct RATLSPeerInfo {
  std::string source_ip;
  int source_port;
  std::string destination_ip;
  int destination_port;

  template <class StorerT>
  void store(StorerT& storer) const {
    using td::store;
    store(source_ip, storer);
    store(source_port, storer);
    store(destination_ip, storer);
    store(destination_port, storer);
  }

  template <class ParserT>
  void parse(ParserT& parser) {
    using td::parse;
    parse(source_ip, parser);
    parse(source_port, parser);
    parse(destination_ip, parser);
    parse(destination_port, parser);
  }
};

// NB! Changes break ABI
class RATLSAttestedPeerInfo {
 public:
  RATLSAttestedPeerInfo() = default;
  RATLSAttestedPeerInfo(RATLSAttestationReport report, const tde2e_core::PublicKey& public_key, RATLSPeerInfo peer_info)
      : report_(std::move(report)), public_key_(public_key), peer_info_(std::move(peer_info)) {
  }

 public:
  const auto& report() const {
    return report_;
  }

  const auto& public_key() const {
    return public_key_;
  }

  const auto& peer_info() const {
    return peer_info_;
  }

 public:
  template <class StorerT>
  void store(StorerT& storer) const {
    using td::store;
    store(report_, storer);
    store(public_key_.to_secure_string(), storer);
    store(peer_info_, storer);
  }

  template <class ParserT>
  void parse(ParserT& parser) {
    using td::parse;
    parse(report_, parser);

    std::string public_key_string;
    parse(public_key_string, parser);
    auto r_key = tde2e_core::PublicKey::from_slice(td::Slice(public_key_string));
    if (r_key.is_error()) {
      parser.set_error(PSTRING() << "Failed to parse PublicKey: " << r_key.error());
      return;
    }
    public_key_ = r_key.move_as_ok();
    parse(peer_info_, parser);
  }

 private:
  RATLSAttestationReport report_;
  tde2e_core::PublicKey public_key_;
  RATLSPeerInfo peer_info_;
};

class RATLSInterface;
using RATLSInterfaceRef = std::shared_ptr<const RATLSInterface>;

class RATLSInterface {
 public:
  struct Config {
    tdx::RATLSVerifier::Config tdx_config;
    sev::RATLSVerifier::Config sev_config;
  };

 public:
  static td::Result<RATLSInterfaceRef> make(td::actor::Scheduler* scheduler = nullptr, bool fake = false,
                                            const Config& config = {});
  static td::Result<RATLSInterfaceRef> add_cache(RATLSInterfaceRef ratls,
                                                 std::shared_ptr<cocoon::AttestationCache> cache);

 public:
  virtual ~RATLSInterface() = default;

 public:
  virtual td::Result<sev::RATLSAttestationReport> attest(const td::UInt512& user_claims,
                                                         const sev::RATLSExtensions& extensions) const = 0;

  virtual td::Result<tdx::RATLSAttestationReport> attest(const td::UInt512& user_claims,
                                                         const tdx::RATLSExtensions& extensions) const = 0;
};

class RATLSPolicy;
using RATLSPolicyRef = std::shared_ptr<const RATLSPolicy>;

class RATLSPolicy {
 public:
  static RATLSPolicyRef make(RATLSInterfaceRef ratls);
  static RATLSPolicyRef make(RATLSInterfaceRef ratls, RATLSPolicyConfig config);

 public:
  virtual ~RATLSPolicy() = default;

  virtual td::Result<RATLSAttestationReport> validate(const tde2e_core::PublicKey& public_key) const;
  virtual td::Result<RATLSAttestationReport> validate(const tde2e_core::PublicKey& public_key,
                                                      const tdx::RATLSExtensions& extensions) const = 0;
  virtual td::Result<RATLSAttestationReport> validate(const tde2e_core::PublicKey& public_key,
                                                      const sev::RATLSExtensions& extensions) const = 0;
};

td::UInt512 hash_public_key(const tde2e_core::PublicKey& public_key);

class RATLSPolicyHelper : public RATLSPolicy {
 public:
  RATLSPolicyHelper(RATLSPolicyRef policy, td::actor::StartedTask<RATLSAttestedPeerInfo>::ExternalPromise promise,
                    const td::IPAddress& src, const td::IPAddress& dst)
      : policy_(std::move(policy)), promise_(std::move(promise)), src_(src), dst_(dst) {
  }

  td::Result<RATLSAttestationReport> validate(const tde2e_core::PublicKey& public_key) const override;
  td::Result<RATLSAttestationReport> validate(const tde2e_core::PublicKey& public_key,
                                              const tdx::RATLSExtensions& extensions) const override;
  td::Result<RATLSAttestationReport> validate(const tde2e_core::PublicKey& public_key,
                                              const sev::RATLSExtensions& extensions) const override;

 private:
  RATLSAttestedPeerInfo make_peer_info(const tde2e_core::PublicKey& public_key,
                                       const RATLSAttestationReport& report) const;

 private:
  RATLSPolicyRef policy_;
  mutable td::actor::StartedTask<RATLSAttestedPeerInfo>::ExternalPromise promise_;
  td::IPAddress src_;
  td::IPAddress dst_;
};

struct RATLSVerifyCallbackBuilder {
  static std::function<int(int, void*)> from_policy(RATLSPolicyRef policy);
};

struct RATLSContext {
  RATLSContext() = default;
  RATLSContext(const RATLSContext&) = delete;
  RATLSContext& operator=(const RATLSContext&) = delete;
  RATLSContext(RATLSContext&&) = delete;
  RATLSContext& operator=(RATLSContext&&) = delete;
  std::function<int(int, void*)> custom_verify_callback{};
};

RATLSContext* RATLS_extract_context(SSL_CTX* ssl_ctx, bool create_if_empty);
int RATLS_verify_callback(int preverify_ok, X509_STORE_CTX* ctx);

}  // namespace cocoon
