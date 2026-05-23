#pragma once

#include <functional>
#include <optional>
#include <string>
#include <vector>

#include "td/e2e/Keys.h"
#include "td/utils/int_types.h"

#include "tee/cocoon/RATLS.h"

namespace cocoon {

struct TeeCertConfig {
  std::string country = "AE";  // ISO 3166-1 alpha-2 country code for UAE (must be exactly 2 characters)
  std::string state = "DUBAI";
  std::string locality = "";
  std::string organization = "TDLib Development";
  std::string organizational_unit = "Security";
  std::string common_name = "localhost";
  std::vector<std::string> san_names = {"localhost", "127.0.0.1", "::1"};
  td::uint32 validity_seconds = 86400;  // Default: 1 day
  std::vector<std::pair<std::string, std::string>> extra_extensions;
  std::optional<td::uint32> current_time;  // If set, use this time instead of system time for certificate generation
};

class TeeCertAndKey {
 public:
  TeeCertAndKey() = default;
  TeeCertAndKey(std::string cert_pem, std::string key_pem);

  const std::string& cert_pem() const;
  const std::string& key_pem() const;

 private:
  struct Impl {
    std::string cert_pem;
    std::string key_pem;
  };
  std::shared_ptr<const Impl> impl_;
};

class TeeInterface;
using TeeInterfaceRef = std::shared_ptr<const TeeInterface>;

// This is interface to local TEE implementation
class TeeInterface {
 public:
  static td::Result<TeeType> this_cpu_tee_type();

 public:
  virtual ~TeeInterface() = default;

 public:
  virtual td::Status prepare_cert_config(TeeCertConfig& config, const tde2e_core::PublicKey& public_key) const = 0;
  virtual td::Result<RATLSAttestationReport> make_report(const td::UInt512& user_claims) const = 0;
};

td::Result<TeeCertAndKey> generate_cert_and_key(const TeeInterface* tee, TeeCertConfig config = {});
td::Result<TeeCertAndKey> load_cert_and_key(td::Slice name);

struct SslCtxFree {
  void operator()(void *ptr) const;
};

// Probably it's better to split on RATLS and Tee SslCtxHolder
using SslCtxHolder = std::unique_ptr<void, SslCtxFree>;
struct SslOptions {
  enum class Mode { Server, Client } mode{Mode::Client};
  TeeCertAndKey cert_and_key;
  std::function<int(int, void*)> custom_verify;
};

td::Result<SslCtxHolder> create_ssl_ctx(SslOptions options);

}  // namespace cocoon
