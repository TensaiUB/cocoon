#pragma once
#include "td/net/TcpListener.h"
#include "td/utils/SharedValue.h"
#include "tee/cocoon/Tee.h"
#include "tee/cocoon/RATLS.h"
#include <map>

namespace cocoon {

class FwdProxy final : public td::actor::Actor {
 public:
  struct Config {
    int port_{8081};  // port to listen
    td::SharedValue<TeeCertAndKey> cert_and_key_;
    std::string default_policy_;
    std::map<std::string, RATLSPolicyRef, std::less<>> policies_;
    bool allow_policy_from_username_{false};
    bool skip_socks5{false};
    bool serialize_info{false};

    // Proof of work
    td::int32 max_pow_difficulty{28};  // Max PoW difficulty client will solve

    // For forward proxy (skip_socks5=true)
    td::IPAddress fixed_destination_;

    td::Result<RATLSPolicyRef> find_policy(td::Slice username) const;
  };
  explicit FwdProxy(Config config) : config_(std::make_shared<Config>(std::move(config))) {
  }
  void start_up() final;
  void hangup() final {
    stop();
  }

 private:
  td::actor::ActorOwn<td::TcpInfiniteListener> listener_;
  std::shared_ptr<const Config> config_;
};
}  // namespace cocoon
