#pragma once
#include "td/actor/actor.h"
#include "td/utils/SharedValue.h"
#include "td/utils/Time.h"
#include "tee/cocoon/Tee.h"

namespace cocoon {

class CertManager final : public td::actor::Actor {
 public:
  struct Config {
    std::string cert_base_name;
    td::SharedValue<TeeCertAndKey> cert_and_key;
    double check_interval_sec{60.0};
  };

  explicit CertManager(Config config) : config_(std::move(config)) {
  }

  void start_up() final;
  void alarm() final;

 private:
  void check_and_reload();
  td::Result<td::uint64> get_file_mtime_nsec(td::CSlice path);

  Config config_;
  td::uint64 last_mtime_nsec_{0};
};

}  // namespace cocoon
