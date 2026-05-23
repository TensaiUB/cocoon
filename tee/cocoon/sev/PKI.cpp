#include "tee/cocoon/sev/PKI.h"

#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/pem.h>
#include <openssl/pemerr.h>
#include <openssl/sha.h>
#include <openssl/types.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

#include "td/actor/core/SchedulerContext.h"
#include "td/utils/filesystem.h"
#include "td/utils/format.h"
#include "td/utils/misc.h"
#include "td/utils/port/Stat.h"

#include "tee/cocoon/sev/SHA384.h"

namespace sev {

constexpr td::Slice cert_chain_pem(".cert_chain.pem");
constexpr td::Slice cert_chain_crl_pem(".cert_chain_crl.pem");

td::Result<std::string> make_product_cert_chain_prefix(td::Slice SEV_PKI_ROOT_DIR, ProductName product) {
  return PSTRING() << SEV_PKI_ROOT_DIR << "/" << product;
}

td::Result<std::string> make_product_cert_chain_path(td::Slice SEV_PKI_ROOT_DIR, ProductName product) {
  return PSTRING() << SEV_PKI_ROOT_DIR << "/" << product << cert_chain_pem;
}

td::Result<std::string> make_product_cert_chain_crl_path(td::Slice SEV_PKI_ROOT_DIR, ProductName product) {
  return PSTRING() << SEV_PKI_ROOT_DIR << "/" << product << cert_chain_crl_pem;
}

td::Result<std::string> make_vcek_path(td::Slice SEV_PKI_ROOT_DIR) {
  return PSTRING() << SEV_PKI_ROOT_DIR << "/vcek.pem";
}

namespace {

td::CSlice KDS_URL_PREFIX{"https://kdsintf.amd.com/vcek/v1/"};

td::Result<std::tuple<const td::uint8*, const td::uint8*, long, ptrdiff_t, int, int>> get_asn1_object_desc(
    X509_EXTENSION* e) {
  ASN1_OCTET_STRING* v = X509_EXTENSION_get_data(e);
  if (!v) {
    return td::Status::Error("Cannot get extension data");
  }

  const unsigned char* ber_in = v->data;
  long length;
  int tag, tag_class;
  const auto rv = ASN1_get_object(&ber_in, &length, &tag, &tag_class, v->length);
  if (rv & 0x80) {
    return td::create_openssl_error(-1, "Cannot get ASN1 object");
  }
  ptrdiff_t hlength = ber_in - v->data;

  return std::make_tuple(ber_in, v->data, length, hlength, tag, tag_class);
}

td::Result<td::Slice> to_ia5string(X509_EXTENSION* e) {
  TRY_RESULT(R, get_asn1_object_desc(e));
  auto [ber_in, data, length, hlength, tag, tag_class] = R;

  ASN1_OCTET_STRING* v = X509_EXTENSION_get_data(e);
  if (!v) {
    return td::Status::Error("Cannot get extension data");
  }

  if (tag != V_ASN1_IA5STRING || tag_class != V_ASN1_UNIVERSAL) {
    return td::Status::Error("Expected V_ASN1_IA5STRING");
  }

  return td::Slice(ber_in, length);
}

td::Result<long> to_long(X509_EXTENSION* e) {
  TRY_RESULT(R, get_asn1_object_desc(e));
  auto [ber_in, data, length, hlength, tag, tag_class] = R;
  if (tag != V_ASN1_INTEGER || tag_class != V_ASN1_UNIVERSAL) {
    return td::Status::Error("Expected V_ASN1_INTEGER");
  }

  ber_in = data;
  OPENSSL_MAKE_PTR(ai, d2i_ASN1_INTEGER(nullptr, &ber_in, length + hlength), ASN1_INTEGER_free,
                   "Cannot d2i_ASN1_INTEGER");
  return ASN1_INTEGER_get(ai.get());
}

td::Result<td::Slice> to_octet_string(X509_EXTENSION* e) {
  auto v = X509_EXTENSION_get_data(e);
  if (!v) {
    return td::Status::Error("Cannot get extension data");
  }

  if (v->type != V_ASN1_OCTET_STRING) {
    return td::Status::Error(PSTRING() << "ASN1_OCTET_STRING type mismatch: " << v->type);
  }

  return td::Slice(ASN1_STRING_get0_data(v), ASN1_STRING_length(v));
}

void STACK_OF_X509_free(stack_st_X509* sk) {
  if (sk) {
    sk_X509_pop_free(sk, X509_free);
  }
}

void STACK_OF_X509_CRL_free(stack_st_X509_CRL* sk) {
  if (sk) {
    sk_X509_CRL_pop_free(sk, X509_CRL_free);
  }
}

td::Status parse_certificate(X509_STORE* store, td::Slice path) {
  using ScopedX509 = openssl_ptr<X509, X509_free>;

  TRY_RESULT(chain_pem, td::read_file_str(path.str()));
  OPENSSL_MAKE_PTR(bio, BIO_new_mem_buf(chain_pem.data(), td::narrow_cast<int>(chain_pem.size())), BIO_free,
                   "Trust Chain Certificate: cannot create BIO for chain");
  OPENSSL_MAKE_PTR(chain, sk_X509_new_null(), STACK_OF_X509_free,
                   "Trust Chain Certificate: cannot create stack of X509");

  for (;;) {
    ScopedX509 cert(PEM_read_bio_X509_AUX(bio.get(), nullptr, nullptr, nullptr));
    if (!cert) {
      auto n = ERR_peek_last_error();

      if (ERR_GET_LIB(n) == ERR_LIB_PEM && ERR_GET_REASON(n) == PEM_R_NO_START_LINE && sk_X509_num(chain.get()) == 2) {
        ERR_clear_error();
        break;
      }

      return td::create_openssl_error(-1, "Trust Chain Certificate: cannot read");
    } else {
      const auto i = sk_X509_num(chain.get());

      if (2 <= i) {
        return td::Status::Error("Trust Chain Certificate: length of 2 is expected, more found");
      }

      if (!sk_X509_push(chain.get(), cert.get())) {
        return td::create_openssl_error(-1, "Trust Chain Certificate: cannot push");
      }

      cert.release();
    }
  }
  CHECK(sk_X509_num(chain.get()) == 2);

  for (int i = 0; i < 2; ++i) {
    auto cert = sk_X509_value(chain.get(), i);

    if (!X509_STORE_add_cert(store, cert)) {
      return td::create_openssl_error(-1, "Trust Chain Certificate: cannot add certificate to store");
    }
  }

  // VCEK is signed by ASK which is signed by ARK
  if (!X509_STORE_set_depth(store, 1)) {
    return td::create_openssl_error(-1, "Trust Chain Certificate: cannot set depth");
  }

  return td::Status::OK();
}

td::Result<openssl_ptr<STACK_OF(X509_CRL), STACK_OF_X509_CRL_free>> read_crl(td::Slice path) {
  TRY_RESULT(stat, td::stat(path.str()));
  if ((stat.mtime_nsec_ + 3 * 86400) < static_cast<td::uint64>(td::Clocks::system())) {
    return td::Status::Error(PSTRING() << path << " is outdated");
  }

  TRY_RESULT(crl_bytes, td::read_file_str(path.str()));
  OPENSSL_MAKE_PTR(bio, BIO_new_mem_buf(crl_bytes.data(), td::narrow_cast<int>(crl_bytes.size())), BIO_free,
                   "Cannot create BIO for CRL");
  OPENSSL_MAKE_PTR(chain, sk_X509_CRL_new_null(), STACK_OF_X509_CRL_free, "CRL Chain: cannot create stack of X509_CRL");
  using CRL = openssl_ptr<X509_CRL, X509_CRL_free>;

  for (;;) {
    CRL crl(PEM_read_bio_X509_CRL(bio.get(), nullptr, nullptr, nullptr));
    if (!crl) {
      auto n = ERR_peek_last_error();

      if (ERR_GET_LIB(n) == ERR_LIB_PEM && ERR_GET_REASON(n) == PEM_R_NO_START_LINE && sk_X509_CRL_num(chain.get())) {
        ERR_clear_error();
        break;
      }

      return td::create_openssl_error(-1, "Trust Chain CRL: cannot read");
    } else {
      if (!sk_X509_CRL_push(chain.get(), crl.get())) {
        return td::create_openssl_error(-1, "Trust Chain CRL: cannot push");
      }
    }

    crl.release();
  }

  return chain;
}

td::Status add_crl(X509_STORE* store, STACK_OF(X509_CRL) * cert_chain_crl) {
  for (int i = 0; i < sk_X509_CRL_num(cert_chain_crl); ++i) {
    X509_CRL* crl = sk_X509_CRL_value(cert_chain_crl, i);

    if (!X509_STORE_add_crl(store, crl)) {
      return td::create_openssl_error(-1, "Trust Chain CRL: cannot add to store");
    }
  }

  if (!X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK | X509_V_FLAG_CRL_CHECK_ALL)) {
    return td::create_openssl_error(-1, "Trust Chain CRL: cannot enable CRL check");
  }

  return td::Status::OK();
}

td::Result<std::shared_ptr<std::unordered_map<ProductName, TrustChain>>> load_trust_chains(td::Slice PKI_ROOT_DIR) {
  auto trust_chains = std::make_shared<std::unordered_map<ProductName, TrustChain>>();

  TRY_STATUS(for_each_product_name([&](ProductName product_name) {
    if (product_name == ProductName::Siena) {
      // Refer to "1.5 Determining the Product Name" in "Versioned Chip
      // Endorsement Key(VCEK) Certificate and KDS Interface Specification"

      return td::Status::OK();
    }

    auto cert_chain_prefix = make_product_cert_chain_prefix(PKI_ROOT_DIR, product_name).move_as_ok();
    TRY_RESULT(trust_chain, TrustChain::parse(PSTRING () << product_name << ":" <<cert_chain_prefix));

    trust_chains->emplace(product_name, std::move(trust_chain));

    return td::Status::OK();
  }));

  return trust_chains;
}

}  // namespace

std::string make_kds_url_cert_chain(ProductName product_name) {
  return PSTRING() << KDS_URL_PREFIX << product_name_to_string(product_name) << "/cert_chain";
}

std::string make_kds_url_cert_chain_crl(ProductName product_name) {
  return PSTRING() << KDS_URL_PREFIX << product_name_to_string(product_name) << "/crl";
}

std::string make_kds_url_vcek(ProductName product_name, td::Slice hwID, TCBVersionV0 tcb) {
  return PSTRING() << KDS_URL_PREFIX << product_name_to_string(product_name) << "/" << td::format::as_hex_dump<0>(hwID)
                   << "?blSPL=" << tcb.boot_loader << "&teeSPL=" << tcb.tee << "&snpSPL=" << tcb.snp
                   << "&ucodeSPL=" << tcb.microcode;
}

std::string make_kds_url_vcek(ProductName product_name, td::Slice hwID, TCBVersionV1 tcb) {
  return PSTRING() << KDS_URL_PREFIX << product_name_to_string(product_name) << "/" << hwID << "?fmcSPL=" << tcb.fmc
                   << "&blSPL=" << tcb.boot_loader << "&teeSPL=" << tcb.tee << "&snpSPL=" << tcb.snp
                   << "&ucodeSPL=" << tcb.microcode;
}

td::Result<X509_EXTENSION*> Certificate::get_extension(td::CSlice oid, td::CSlice sn) const {
  OPENSSL_MAKE_PTR(nid, OBJ_txt2obj(oid.data(), /* no_name */ 1), ASN1_OBJECT_free,
                   PSTRING() << "Cannot create ASN1 object");
  const auto loc = X509_get_ext_by_OBJ(x509_.get(), nid.get(), -1);
  if (loc == -1) {
    return td::Status::Error(-1, PSTRING() << "Cannot get extension: " << oid);
  }

  return X509_get_ext(x509_.get(), loc);
}

X509* VCEKCertificate::native_handle() const {
  return x509_.get();
}

td::Status VCEKCertificate::verify_report(const AttestationReport& report, const td::UInt512& user_claims_hash) const {
  if (report.signature_algo != SigningAlgorithm::ECDSA_P384_with_SHA384) {
    return td::Status::Error(PSTRING() << "Unsupported Signing Algorithm: "
                                       << static_cast<std::underlying_type_t<SigningAlgorithm>>(report.signature_algo));
  }

  TRY_RESULT(signature, ECDSASignature::create(report.signature));

  td::Slice payload(reinterpret_cast<const char*>(&report), offsetof(AttestationReport, signature));
  TRY_STATUS(verify_signature(signature, payload));

  if (user_claims_hash != report.report_data) {
    return td::Status::Error("Report nonce mismatch");
  }

  return td::Status::OK();
}

td::Status VCEKCertificate::verify_signature(const ECDSASignature& signature, td::Slice body) const {
  auto sig = signature.native_handle();
  const auto md = SHA384(body);
  EVP_PKEY* pkey = X509_get_pubkey(x509_.get());
  const int rc = ECDSA_do_verify(md.raw, td::narrow_cast<int>(sizeof(md.raw)), sig, EVP_PKEY_get1_EC_KEY(pkey));

  if (rc <= 0) {
    if (!rc) {
      return td::create_openssl_error(-1, "Signature verification failed");
    }

    return td::create_openssl_error(-1, "EVP_PKEY_verify");
  }

  return td::Status::OK();
#if 0
  const auto siglen = i2d_ECDSA_SIG(signature.native_handle(), nullptr);
  std::vector<td::uint8> raw_signature (siglen);
  auto sig = raw_signature.data ();
  CHECK (siglen == i2d_ECDSA_SIG(signature.native_handle(), &sig));
  if (siglen < 0) {
    return td::Status::Error("Cannot i2d_ECDSA_SIG");
  }
  CHECK(static_cast<size_t> (siglen) <= raw_signature.size());
  LOG(INFO) << "XXX:" << td::format::as_hex_dump<0>(td::Slice(raw_signature.data(), raw_signature.size()));

  EVP_PKEY* pkey = X509_get0_pubkey(x509_.get());
  OPENSSL_MAKE_PTR (pkey_ctx, EVP_PKEY_CTX_new (pkey, nullptr), EVP_PKEY_CTX_free, "Cannot create EVP_PKEY_CTX");

  if (!EVP_PKEY_verify_init (pkey_ctx.get ())) {
    return td::create_openssl_error(-1, "Cannot EVP_PKEY_verify_init");
  }

  if (auto rc = EVP_PKEY_verify(pkey_ctx.get(), raw_signature.data(), siglen, body.ubegin(), body.size()); rc != 1) {
    if (!rc) {
      return td::Status::Error("Signature verification failed");
    }

    return td::create_openssl_error(-1, "EVP_PKEY_verify");
  }

  return td::Status::OK ();
#endif
}

td::Result<VCEKCertificate> VCEKCertificate::create(std::string str) {
  OPENSSL_MAKE_PTR(bio, BIO_new_mem_buf(str.data(), td::narrow_cast<int>(str.size())), BIO_free,
                   "VCEKCertificate: cannot create BIO");
  auto x509 = PEM_read_bio_X509_AUX(bio.get(), nullptr, nullptr, nullptr);
  if (!x509) {
    return td::create_openssl_error(-1, "Cannot PEM read VCEKCertificate");
  }

  return VCEKCertificate(x509);
}

td::Result<long> VCEKCertificate::structVersion() const {
  TRY_RESULT(e, get_extension("1.3.6.1.4.1.3704.1.1", "structVersion"));
  return to_long(e);
}

td::Result<td::Slice> VCEKCertificate::productName() const {
  TRY_RESULT(e, get_extension("1.3.6.1.4.1.3704.1.2", "productName"));
  return to_ia5string(e);
}

td::Result<long> VCEKCertificate::blSPL() const {
  TRY_RESULT(e, get_extension("1.3.6.1.4.1.3704.1.3.1", "blSPL"));
  return to_long(e);
}

td::Result<long> VCEKCertificate::teeSPL() const {
  TRY_RESULT(e, get_extension("1.3.6.1.4.1.3704.1.3.2", "teeSPL"));
  return to_long(e);
}

td::Result<long> VCEKCertificate::fmcSPL() const {
  TRY_RESULT(version, structVersion());
  if (version == 1) {
    TRY_RESULT(e, get_extension("1.3.6.1.4.1.3704.1.3.9", "fmcSPL"));
    return to_long(e);
  }

  return td::Status::Error("VCEKCertificate doesn't have fmcSPL extension");
}

td::Result<long> VCEKCertificate::spl_4() const {
  TRY_RESULT(version, structVersion());

  if (version == 1) {
    TRY_RESULT(e, get_extension("1.3.6.1.4.1.3704.1.3.4", "spl_4"));
    return to_long(e);
  }

  return td::Status::Error("VCEKCertificate doesn't have spl_4 extension");
}

td::Result<long> VCEKCertificate::spl_5() const {
  TRY_RESULT(e, get_extension("1.3.6.1.4.1.3704.1.3.5", "spl_5"));
  return to_long(e);
}

td::Result<long> VCEKCertificate::spl_6() const {
  TRY_RESULT(e, get_extension("1.3.6.1.4.1.3704.1.3.6", "spl_6"));
  return to_long(e);
}

td::Result<long> VCEKCertificate::spl_7() const {
  TRY_RESULT(e, get_extension("1.3.6.1.4.1.3704.1.3.7", "spl_7"));
  return to_long(e);
}

td::Result<long> VCEKCertificate::snpSPL() const {
  TRY_RESULT(e, get_extension("1.3.6.1.4.1.3704.1.3.3", "snpSPL"));
  return to_long(e);
}

td::Result<long> VCEKCertificate::ucodeSPL() const {
  TRY_RESULT(e, get_extension("1.3.6.1.4.1.3704.1.3.8", "ucodeSPL"));
  return to_long(e);
}

td::Result<td::Slice> VCEKCertificate::hwID() const {
  TRY_RESULT(e, get_extension("1.3.6.1.4.1.3704.1.4", "hwID"));
  return to_octet_string(e);
}

td::StringBuilder& operator<<(td::StringBuilder& sb, const VCEKCertificate& vcek) {
  const auto hwID = vcek.hwID();

  sb << "VCEKCertificate: structVersion:" << vcek.structVersion() << ", productName:" << vcek.productName() << ", blSPL"
     << vcek.blSPL() << ", teeSPL:" << vcek.teeSPL() << ", fmcSPL:" << vcek.fmcSPL() << ", spl_4:" << vcek.spl_4()
     << ", spl_5:" << vcek.spl_5() << ", spl_6:" << vcek.spl_6() << ", spl_7:" << vcek.spl_7()
     << ", snpSPL:" << vcek.snpSPL() << ", ucodeSPL:" << vcek.ucodeSPL();

  sb << ", hwID:";
  if (hwID.is_ok()) {
    sb << td::format::as_hex_dump<0>(hwID.ok());
  } else {
    sb << hwID;
  }

  return sb;
}

td::Result<TrustChain> TrustChain::parse(td::Slice product_name_and_path_prefix) {
  auto [product_name, path_prefix] = td::split(product_name_and_path_prefix, ':');

  if (product_name.empty() || path_prefix.empty()) {
    return td::Status::Error(PSTRING() << "Trust Chain format: <product_name>:<path_prefix>: "
                                       << product_name_and_path_prefix);
  }

  TRY_RESULT(product, product_name_from_name(product_name));
  TRY_RESULT(cert_chain_crl, read_crl(PSTRING () << path_prefix << cert_chain_crl_pem));
  OPENSSL_MAKE_PTR(x509, X509_STORE_new(), X509_STORE_free, "Cannot create X509_STORE");
  TRY_STATUS(parse_certificate(x509.get(), PSTRING() << path_prefix << cert_chain_pem));
  TRY_STATUS(add_crl(x509.get(), cert_chain_crl.get()));

  return TrustChain(product, std::move(x509));
}

td::Status TrustChain::verify_cert(X509* x509) const {
  OPENSSL_MAKE_PTR(store_ctx, X509_STORE_CTX_new(), X509_STORE_CTX_free, "Cannot create X509_STORE_CTX");

  if (!X509_STORE_CTX_init(store_ctx.get(), store_.get(), x509, nullptr)) {
    return td::create_openssl_error(-1, "Cannot X509_STORE_CTX_init");
  }

  auto verify_cb = [](int ok, X509_STORE_CTX* ctx) {
    // VCEK certificate doesn't have X509v3 CRL Distribution Points extension.
    // Because of X509_V_FLAG_CRL_CHECK_ALL this results in X509_V_ERR_UNABLE_TO_GET_CRL error returned from X509_verify_cert;
    // The trick is to return ok on X509_V_ERR_UNABLE_TO_GET_CRL for VCEK certificate.

    const auto err = X509_STORE_CTX_get_error(ctx);
    const auto depth = X509_STORE_CTX_get_error_depth(ctx);

    // depth 0 means VCEK certificate
    if (!ok && err == X509_V_ERR_UNABLE_TO_GET_CRL && !depth) {
      return 1;
    }

    return ok;
  };
  X509_STORE_CTX_set_verify_cb(store_ctx.get(), verify_cb);

  if (X509_verify_cert(store_ctx.get()) <= 0) {
    return td::create_openssl_error(
        -1, PSTRING() << "Cannot X509_verify_cert: "
                      << X509_verify_cert_error_string(X509_STORE_CTX_get_error(store_ctx.get())));
  }

  return td::Status::OK();
}

td::Result<TrustChainManager> TrustChainManager::make(td::actor::Scheduler* scheduler, td::Slice PKI_ROOT_DIR) {
  TRY_RESULT(trust_chains, load_trust_chains(PKI_ROOT_DIR));

  td::SharedValue<std::shared_ptr<std::unordered_map<ProductName, TrustChain>>> shared_trust_chains(
      std::move(trust_chains));

  if (scheduler) {
    LOG(INFO) << "Starting AMD SEV TrustChainUpdater";

    scheduler->run_in_context([&] {
      td::actor::create_actor<TrustChainUpdater>("TrustChainUpdater",
                                                 TrustChainUpdater::Config(PKI_ROOT_DIR.str(), shared_trust_chains))
          .release();
    });
  }

  return TrustChainManager(shared_trust_chains);
}

td::Status TrustChainManager::verify_cert(ProductName product_name, X509* x509) const {
  constexpr size_t kRefreshThreshold = 14 * 86400;
  if (td::Timestamp::in(kRefreshThreshold, loaded_at_).is_in_past()) {
    return td::Status::Error("TrustChain CRL outdated");
  }

  auto trust_chains = trust_chains_.load();
  auto found = trust_chains->find(product_name);
  if (found == trust_chains->end()) {
    return td::Status::Error(PSTRING() << "Cannot verify cert: no TrustChain for " << product_name);
  }

  auto& [_, trust_chain] = *found;
  CHECK(product_name == trust_chain.product_name());

  return trust_chain.verify_cert(x509);
}

void TrustChainUpdater::start_up() {
  alarm();
}

void TrustChainUpdater::alarm() {
  reload();
  alarm_timestamp() = td::Timestamp::in(config_.check_interval_sec);
}

void TrustChainUpdater::reload() {
  auto maybe_trust_chains = load_trust_chains(config_.PKI_ROOT_DIR);
  if (maybe_trust_chains.is_error()) {
    LOG(ERROR) << "Cannot reload trust chains: " << maybe_trust_chains.error();
    return;
  }

  config_.trust_chains.set_value(maybe_trust_chains.move_as_ok());
  LOG(INFO) << "AMD SEV TrustChains reloaded";
}

}  // namespace sev
