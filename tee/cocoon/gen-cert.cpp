#include "tee/cocoon/FwdProxy.h"
#include "tee/cocoon/Tee.h"
#include "tee/cocoon/sev/Tee.h"
#include "tee/cocoon/tdx/Tee.h"
#include "td/utils/filesystem.h"
#include "td/utils/logging.h"
#include "td/utils/OptionParser.h"
#include "td/utils/base64.h"
#include "td/utils/port/Stat.h"
#include "td/utils/port/signals.h"
#include "td/utils/port/user.h"

int main(int argc, char **argv) {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(DEBUG));
  td::set_default_failure_signal_handler().ensure();

  sev::TeeConfig sev_tee_config{};
  tdx::TeeConfig tdx_tee_config{};

  auto make_tee = [&](const std::string &tee_mode) -> td::Result<cocoon::TeeInterfaceRef> {
    if (tee_mode == "none") {
      return nullptr;
    }

    const bool fake = tee_mode == "fake_tee";
    TRY_RESULT(tee_type, cocoon::TeeInterface::this_cpu_tee_type());

    switch (tee_type) {
      case cocoon::TeeType::Sev:
        return sev::make_tee(fake, sev_tee_config);
      case cocoon::TeeType::Tdx:
        return tdx::make_tee(fake, tdx_tee_config);
    }

    UNREACHABLE();
  };

  std::string base_name = "test";
  std::string user, tee_mode;
  bool force = false;
  std::optional<td::uint32> current_time;

  td::OptionParser option_parser;
  option_parser.add_checked_option('t', "tee", "tee mode (none, fake_tee, tee)", [&](td::Slice tee_name) {
    tee_mode = tee_name.str();

    return td::Status::OK();
  });
  option_parser.add_checked_option('n', "name", "base name of cert", [&](td::Slice name) {
    base_name = name.str();
    return td::Status::OK();
  });
  option_parser.add_checked_option('u', "user", "save key under user", [&](td::Slice name) {
    user = name.str();
    return td::Status::OK();
  });
  option_parser.add_checked_option('f', "force", "rewrite key (for tests only)", [&]() {
    force = true;
    return td::Status::OK();
  });
  option_parser.add_checked_option('c', "current-time", "Unix timestamp to use for certificate generation", [&](td::Slice time_str) {
    TRY_RESULT(timestamp, td::to_integer_safe<td::uint32>(time_str));

    // Validate timestamp is not in the future (allow 60s clock skew)
    td::uint32 now = static_cast<td::uint32>(td::Clocks::system());
    if (timestamp > now + 60) {
      return td::Status::Error(PSLICE() << "Provided timestamp " << timestamp
                                        << " is in the future (current time: " << now << ")");
    }

    current_time = timestamp;
    LOG(INFO) << "Using provided timestamp: " << timestamp;
    return td::Status::OK();
  });
  option_parser.add_checked_option(0, "sev-pki-root", "Set SEV PKI root path", [&](td::Slice arg) {
    sev_tee_config.PKI_ROOT_DIR = arg.str();

    return td::Status::OK();
  });
  option_parser.add_option('h', "help", "Show this help message", [&]() {
    LOG(PLAIN) << option_parser;
    std::_Exit(0);
  });

  option_parser.set_description(
      "gen-cert: emits <name>_cert.pem, <name>_key.pem; <name>_image_hash.b64 if --tee set");

  auto r_args = option_parser.run(argc, argv, -1);
  if (r_args.is_error()) {
    LOG(ERROR) << r_args.error();
    LOG(ERROR) << option_parser;
    return 1;
  }

  auto maybe_tee = make_tee(tee_mode);
  if (maybe_tee.is_error()) {
    LOG(FATAL) << "Cannot make Tee: " << maybe_tee.error();
  }

  cocoon::TeeInterfaceRef tee = maybe_tee.move_as_ok();
  auto hash_path = PSTRING() << base_name << "_image_hash.b64";
  auto cert_path = PSTRING() << base_name << "_cert.pem";
  auto key_path = PSTRING() << base_name << "_key.pem";

  if (tee) {
    auto report = tee->make_report(td::UInt512{}).move_as_ok();
    LOG(INFO) << "TEE: " << report;
    auto image_hash = report.image_hash();
    auto hash_base64 = td::base64_encode(image_hash.as_slice());
    td::write_file(hash_path, hash_base64).ensure();
  }

  if (!force && (td::stat(cert_path).is_ok() || td::stat(key_path).is_ok())) {
    LOG(ERROR) << "Refusing to overwrite existing files";
    return 0;
  }

  // Generate certificate with optional custom time
  cocoon::TeeCertConfig config;
  if (current_time.has_value()) {
    config.current_time = current_time;
  }

  auto cert_and_key = cocoon::generate_cert_and_key(tee.get(), config).move_as_ok();

  // Change user after key generation (if needed)
  if (!user.empty()) {
    td::change_user(user).ensure();
  }
  
  td::atomic_write_file(cert_path, cert_and_key.cert_pem()).ensure();
  td::atomic_write_file(key_path, cert_and_key.key_pem()).ensure();

  return 0;
}
