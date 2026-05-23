#include "td/utils/OptionParser.h"

#include "tee/cocoon/sev/ABI.h"
#include "tee/cocoon/sev/GuestDevice.h"
#include "tee/cocoon/sev/OVMF.h"
#include "tee/cocoon/sev/PKI.h"
#include "tee/cocoon/sev/RATLS.h"
#include "tee/cocoon/sev/SEVHashes.h"
#include "tee/cocoon/sev/UUID.h"
#include "tee/cocoon/sev/VMSA.h"

#include "td/utils/filesystem.h"
#include "td/utils/misc.h"

int main(int argc, char **argv) {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(DEBUG));

  sev::VCEKCertificate cert;

  td::OptionParser option_parser;
  std::unordered_map<sev::ProductName, sev::TrustChain> trust_chains;

  option_parser.add_checked_option(0, "print-this-cpu-product-name", "Print ProductName from this CPU", []() {
    TRY_RESULT(product_name, sev::product_name_from_this_cpu());
    LOG(PLAIN) << "CPU: " << product_name;

    return td::Status::OK();
  });

  option_parser.add_checked_option(0, "print-all-products", "Print all product names", []() {
    sev::for_each_product_name([&](sev::ProductName product_name) { LOG(INFO) << "ProductName: " << product_name; });

    return td::Status::OK();
  });

  option_parser.add_checked_option(0, "print-this-cpu-cert-chain-url",
                                   "Print URL at which Cert Chain on KDS for this product should reside", []() {
                                     TRY_RESULT(product_name, sev::product_name_from_this_cpu());
                                     LOG(INFO) << "URL: " << sev::make_kds_url_cert_chain(product_name);

                                     return td::Status::OK();
                                   });

  option_parser.add_checked_option(0, "print-product-cert-chain-url",
                                   "Print URL at which Cert Chain on KDS for product should reside", [](td::Slice product_name) {
                                     TRY_RESULT(product, sev::product_name_from_name (product_name));
                                     LOG(INFO) << "URL: " << sev::make_kds_url_cert_chain(product);

                                     return td::Status::OK();
                                   });

  option_parser.add_checked_option(0, "print-this-cpu-cert-chain-crl-url",
                                   "Print URL at which Cert Chain CRL on KDS for this product should reside", []() {
                                     TRY_RESULT(product_name, sev::product_name_from_this_cpu());
                                     LOG(INFO) << "URL: " << sev::make_kds_url_cert_chain_crl(product_name);

                                     return td::Status::OK();
                                   });

  option_parser.add_checked_option(0, "print-product-cert-chain-crl-url",
                                   "Print URL at which Cert Chain CRL on KDS for product should reside", [](td::Slice product_name) {
                                     TRY_RESULT(product, sev::product_name_from_name (product_name));
                                     LOG(INFO) << "URL: " << sev::make_kds_url_cert_chain_crl(product);

                                     return td::Status::OK();
                                   });

  option_parser.add_checked_option(
      0, "print-this-cpu-vcek-url", "Print URL at which VCEK on KDS for this product should reside", []() {
        TRY_RESULT(guest_device, sev::GuestDevice::open());
        td::UInt512 user_claims;
        TRY_RESULT(report, guest_device.get_report(user_claims));

        TRY_RESULT(product_name, sev::product_name_from_this_cpu());
        if (3 <= report.version) {
          TRY_RESULT_ASSIGN(product_name, sev::product_name_from_cpu(report.cpuid_fam_id, report.cpuid_mod_id));
        }

        sev::TCBVersionCastDevice tcb_version = {.as_uint64 = report.current_tcb};
        if (product_name == sev::ProductName::Turin) {
          LOG(INFO) << "URL: " << sev::make_kds_url_vcek(product_name, report.chip_id.as_slice(), tcb_version.as_v1);
        } else {
          LOG(INFO) << "URL: " << sev::make_kds_url_vcek(product_name, report.chip_id.as_slice(), tcb_version.as_v0);
        }

        return td::Status::OK();
      });

  option_parser.add_checked_option('p', "product-trust-chain", "product and trust chain path prefix",
                                   [&](td::Slice product_and_path_prefix) {
                                     TRY_RESULT(chain, sev::TrustChain::parse(product_and_path_prefix));
                                     const auto product_name = chain.product_name();
                                     trust_chains.emplace(product_name, std::move(chain));

                                     LOG(INFO) << "TrustChain for " << product_name << " loaded";

                                     return td::Status::OK();
                                   });

  option_parser.add_checked_option(0, "get-report", "get report", [&](td::Slice arg) {
    TRY_RESULT(guest_device, sev::GuestDevice::open());
    td::UInt512 user_claims;
    user_claims.as_mutable_slice().copy_from(arg);

    TRY_RESULT(report, guest_device.get_report(user_claims));
    LOG(INFO) << report;

    return td::Status::OK();
  });

  option_parser.add_checked_option(0, "print-report", "print report", [&](td::Slice path) {
    TRY_RESULT(bytes, td::read_file_str(path.str()));
    if (bytes.size() != sizeof(sev::AttestationReport)) {
      return td::Status::Error(PSTRING() << "Unexpected attestation report size: " << bytes.size());
    }
    const auto *report = reinterpret_cast<const sev::AttestationReport *>(bytes.data());
    LOG(INFO) << *report;

    return td::Status::OK();
  });

  option_parser.add_checked_option(0, "save-report", "save report", [&](td::Slice arg) {
    auto [user_claims_hex, path] = td::split(arg, ':');
    TRY_RESULT(user_claims_bytes, td::hex_decode(user_claims_hex));

    TRY_RESULT(guest_device, sev::GuestDevice::open());
    td::UInt512 user_claims;
    user_claims.as_mutable_slice().copy_from(user_claims_bytes);

    TRY_RESULT(report, guest_device.get_report(user_claims));

    return td::write_file(path.str(), td::Slice(reinterpret_cast<const char *>(&report), sizeof(report)));
  });

  option_parser.add_checked_option(0, "get-extended-report", "get report", [&](td::Slice arg) {
    TRY_RESULT(guest_device, sev::GuestDevice::open());
    td::UInt512 user_claims;
    user_claims.as_mutable_slice().copy_from(arg);

    TRY_RESULT(R, guest_device.get_extended_report(user_claims));
    const auto &[report, cert_table] = R;

    LOG(INFO) << report;
    for (const auto &entry : cert_table) {
      LOG(INFO) << "GUID: " << sev::uuid_to_string(entry.guid);
      LOG(INFO) << "Cert: " << td::format::as_hex_dump<0>(td::Slice(entry.cert));
    }

    return td::Status::OK();
  });

  option_parser.add_checked_option(0, "print-vcek-certificate", "print VCEKCertificate", [&](td::Slice path) {
    TRY_RESULT(bytes, td::read_file_str(path.str()));
    TRY_RESULT(cert, sev::VCEKCertificate::create(std::move(bytes)));

    LOG(INFO) << cert;

    return td::Status::OK();
  });

  option_parser.add_checked_option(0, "vcek-certificate", "VCEKCertificate", [&](td::Slice path) {
    TRY_RESULT(bytes, td::read_file_str(path.str()));
    TRY_RESULT_ASSIGN(cert, sev::VCEKCertificate::create(std::move(bytes)));

    return td::Status::OK();
  });

  option_parser.add_checked_option(0, "verify-vcek-certificate", "verify VCEKCertificate", [&](td::Slice path) {
    TRY_RESULT(bytes, td::read_file_str(path.str()));
    TRY_RESULT_ASSIGN(cert, sev::VCEKCertificate::create(std::move(bytes)));
    TRY_RESULT(product_name_and_stepping, cert.productName());
    TRY_RESULT(product_name, sev::product_name_from_name_and_stepping(product_name_and_stepping));

    sev::TrustChainManager manager(
        td::SharedValue<std::shared_ptr<std::unordered_map<sev::ProductName, sev::TrustChain>>>(
            std::make_shared<std::unordered_map<sev::ProductName, sev::TrustChain>>(std::move(trust_chains))));

    TRY_STATUS(manager.verify_cert(product_name, cert.native_handle()));
    LOG(INFO) << "VCEK successfully verified";

    return td::Status::OK();
  });

  option_parser.add_checked_option(0, "verify-report", "Verify report", [&](td::Slice arg) {
    auto [user_claims_hex, path] = td::split(arg, ':');
    TRY_RESULT(user_claims_bytes, td::hex_decode(user_claims_hex));

    TRY_RESULT(report, td::read_file_str(path.str()));
    if (report.size() != sizeof(sev::AttestationReport)) {
      return td::Status::Error(PSTRING() << "Unexpected AttestationReport size: " << report.size());
    }

    td::UInt512 user_claims;
    user_claims.as_mutable_slice().copy_from(user_claims_bytes);

    const auto ap = reinterpret_cast<const sev::AttestationReport *>(report.c_str());
    LOG(INFO) << "Verify report: " << cert.verify_report(*ap, user_claims);

    return td::Status::OK();
  });

  option_parser.add_checked_option(0, "print-ovfm", "Parse OVMF image", [&](td::Slice path) {
    TRY_RESULT(ovfm, sev::OVMF::open(path.str()));

    return td::Status::OK();
  });

  option_parser.add_checked_option(0, "print-sev-hashes", "Print SEV hashes", [&](td::Slice arg) {
    auto parts = td::full_split(arg, ':', 3);
    while (parts.size() < 3) {
      parts.push_back(std::string());
    }

    TRY_RESULT(sev_hashes, sev::SEVHashes::open(parts[0], parts[1], parts[2]));
    sev::SEVHashes::Table t;
    TRY_STATUS(sev_hashes.build_table(&t));
    LOG(INFO) << t;

    return td::Status::OK();
  });

  option_parser.add_checked_option(0, "print-derived-key", "Print derived key", [&](td::Slice arg) {
    auto [path, key_name] = td::split(arg, ':');

    TRY_RESULT(guest_device, sev::GuestDevice::open());
    TRY_RESULT (key, guest_device.get_derived_key (key_name));
    TRY_STATUS(td::atomic_write_file(path.str(), key.as_slice()));

    // Output the derived key hash to stdout for script consumption
    LOG(INFO) << "Derived key for '" << key_name << "': sha256=" << td::hex_encode(td::sha256(key.as_slice()));

    return td::Status::OK ();
  });

  auto r_args = option_parser.run(argc, argv);
  if (r_args.is_error()) {
    LOG(ERROR) << r_args.error();
    LOG(ERROR) << option_parser;
    return EXIT_FAILURE;
  }
}
