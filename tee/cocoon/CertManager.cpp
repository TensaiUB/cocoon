#include "CertManager.h"
#include "td/utils/logging.h"
#include "td/utils/port/path.h"
#include "td/utils/port/Stat.h"
#include <sys/stat.h>

namespace cocoon {

void CertManager::start_up() {
  LOG(INFO) << "CertManager started, checking certificates every " << config_.check_interval_sec << " seconds";
  alarm();
}

void CertManager::alarm() {
  check_and_reload();
  alarm_timestamp() = td::Timestamp::in(config_.check_interval_sec);
}

td::Result<td::uint64> CertManager::get_file_mtime_nsec(td::CSlice path) {
  TRY_RESULT(stat, td::stat(path));
  return stat.mtime_nsec_;
}

void CertManager::check_and_reload() {
  std::string cert_path = config_.cert_base_name + "_cert.pem";
  std::string key_path = config_.cert_base_name + "_key.pem";

  auto r_cert_mtime = get_file_mtime_nsec(cert_path);
  auto r_key_mtime = get_file_mtime_nsec(key_path);

  if (r_cert_mtime.is_error() || r_key_mtime.is_error()) {
    LOG(WARNING) << "Failed to stat certificate files: "
                 << (r_cert_mtime.is_error() ? r_cert_mtime.error().message() : r_key_mtime.error().message());
    return;
  }

  td::uint64 max_mtime = std::max(r_cert_mtime.ok(), r_key_mtime.ok());

  if (max_mtime <= last_mtime_nsec_) {
    return;
  }

  LOG(INFO) << "Certificate files changed, reloading...";
  auto r_cert = load_cert_and_key(config_.cert_base_name);
  if (r_cert.is_error()) {
    LOG(ERROR) << "Failed to reload certificates: " << r_cert.error();
    return;
  }

  config_.cert_and_key.set_value(r_cert.move_as_ok());
  last_mtime_nsec_ = max_mtime;
  LOG(INFO) << "Certificates reloaded successfully";
}

}  // namespace cocoon
