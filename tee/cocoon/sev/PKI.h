#pragma once

#include <time.h>

#include <string>
#include <unordered_map>

#include "openssl/ec.h"
#include "openssl/objects.h"
#include "openssl/x509.h"
#include <openssl/bn.h>
#include <openssl/ecdsa.h>

#include "td/actor/actor.h"
#include "td/actor/common.h"
#include "td/utils/SharedValue.h"
#include "td/utils/Slice-decl.h"
#include "td/utils/Status.h"
#include "td/utils/StringBuilder.h"
#include "td/utils/UInt.h"

#include "tee/cocoon/openssl_utils.h"
#include "tee/cocoon/sev/ABI.h"

namespace sev {

td::Result<std::string> make_product_cert_chain_prefix(td::Slice SEV_PKI_ROOT_DIR, ProductName product);
td::Result<std::string> make_product_cert_chain_path(td::Slice SEV_PKI_ROOT_DIR, ProductName product);
td::Result<std::string> make_product_cert_chain_crl_path(td::Slice SEV_PKI_ROOT_DIR, ProductName product);
td::Result<std::string> make_vcek_path(td::Slice SEV_PKI_ROOT_DIR);

std::string make_kds_url_cert_chain(ProductName product_name);
std::string make_kds_url_cert_chain_crl(ProductName product_name);
std::string make_kds_url_vcek(ProductName product_name, td::Slice hwID, TCBVersionV0 tcb);
std::string make_kds_url_vcek(ProductName product_name, td::Slice hwID, TCBVersionV1 tcb);

class ECDSASignature {
 public:
  static td::Result<ECDSASignature> create(const ECDSAP384withSHA384Signature &signature) {
    OPENSSL_MAKE_PTR(sig, ECDSA_SIG_new(), ECDSA_SIG_free, "Cannot create ECDSA_SIG");

    const auto &R = signature.R.raw;
    const auto &S = signature.S.raw;
    OPENSSL_MAKE_PTR(R_bn, BN_lebin2bn(R, sizeof(R), nullptr), BN_free, "Cannot create BIGNUM from R");
    OPENSSL_MAKE_PTR(S_bn, BN_lebin2bn(S, sizeof(S), nullptr), BN_free, "Cannot create BIGNUM from S");

    if (!ECDSA_SIG_set0(sig.get(), R_bn.get(), S_bn.get())) {
      return td::create_openssl_error(-1, "Cannot set Signature R and S");
    }
    R_bn.release();
    S_bn.release();

    return sig;
  }

 public:
  explicit ECDSASignature(openssl_ptr<ECDSA_SIG, ECDSA_SIG_free> sig) : sig_(std::move(sig)) {
  }

 public:
  const ECDSA_SIG *native_handle() const {
    return sig_.get();
  }

 private:
  openssl_ptr<ECDSA_SIG, ECDSA_SIG_free> sig_;
};

class Certificate {
 public:
  Certificate() = default;
  Certificate(const Certificate &) = delete;
  Certificate(Certificate &&) = default;
  explicit Certificate(X509 *x509) : x509_(x509) {
  }

 public:
  Certificate &operator=(const Certificate &) = delete;
  Certificate &operator=(Certificate &&) = default;

 protected:
  td::Result<X509_EXTENSION *> get_extension(td::CSlice oid, td::CSlice sn) const;

 protected:
  openssl_ptr<X509, X509_free> x509_;
};

class VCEKCertificate : public Certificate {
 public:
  static td::Result<VCEKCertificate> create(std::string str);

 public:
  VCEKCertificate() = default;
  explicit VCEKCertificate(X509 *x509) : Certificate(x509) {
  }

 public:
  X509 *native_handle() const;
  td::Status verify_report(const AttestationReport &report, const td::UInt512 &user_claims_hash) const;

 private:
  td::Status verify_signature(const ECDSASignature &signature, td::Slice payload) const;

 public:
  td::Result<long> structVersion() const;
  td::Result<td::Slice> productName() const;
  td::Result<long> blSPL() const;
  td::Result<long> teeSPL() const;
  td::Result<long> fmcSPL() const;
  td::Result<long> spl_4() const;
  td::Result<long> spl_5() const;
  td::Result<long> spl_6() const;
  td::Result<long> spl_7() const;
  td::Result<long> snpSPL() const;
  td::Result<long> ucodeSPL() const;
  td::Result<td::Slice> hwID() const;
};
td::StringBuilder &operator<<(td::StringBuilder &sb, const VCEKCertificate &vcek);

class TrustChain {
 private:
  using Store = openssl_ptr<X509_STORE, X509_STORE_free>;

 public:
  static td::Result<TrustChain> parse(td::Slice product_name_and_path_prefix);

 public:
  TrustChain(ProductName product_name, Store store) : product_name_(product_name), store_(std::move(store)) {
  }
  TrustChain(TrustChain &&) = default;
  TrustChain(const TrustChain &) = delete;

 public:
  TrustChain &operator=(TrustChain &&) = default;
  TrustChain &operator=(const TrustChain &) = delete;

 public:
  ProductName product_name() const {
    return product_name_;
  }

  td::Status verify_cert(X509 *x509) const;

 private:
  ProductName product_name_;
  Store store_;
};

class TrustChainManager {
 public:
  static td::Result<TrustChainManager> make(td::actor::Scheduler *scheduler, td::Slice PKI_ROOT_DIR);

 public:
  TrustChainManager() = default;
  explicit TrustChainManager(td::SharedValue<std::shared_ptr<std::unordered_map<ProductName, TrustChain>>> trust_chains)
      : trust_chains_(std::move(trust_chains)) {
  }

 public:
  td::Status verify_cert(ProductName product_name, X509 *x509) const;

 private:
  td::Timestamp loaded_at_{td::Timestamp::now()};
  td::SharedValue<std::shared_ptr<std::unordered_map<ProductName, TrustChain>>> trust_chains_;
};

class TrustChainUpdater : public td::actor::Actor {
 public:
  struct Config {
    std::string PKI_ROOT_DIR;
    td::SharedValue<std::shared_ptr<std::unordered_map<ProductName, TrustChain>>> trust_chains;
    double check_interval_sec{86400.0};
  };

 public:
  explicit TrustChainUpdater(Config config) : config_(std::move(config)) {
  }

 public:
  void start_up() final;
  void alarm() final;

 private:
  void reload();

 private:
  Config config_;
};

}  // namespace sev
