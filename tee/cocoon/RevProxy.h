#pragma once
#include "td/net/TcpListener.h"
#include "td/utils/port/IPAddress.h"
#include "td/utils/SharedValue.h"
#include "tee/cocoon/RATLS.h"
#include "tee/cocoon/Tee.h"
#include "td/actor/coro_task.h"
#include "td/net/Pipe.h"

namespace cocoon {
class RevProxy final : public td::actor::Actor {
 public:
  struct Config {
    int src_port_{8081};  // port to listen
    td::IPAddress dst_;
    td::SharedValue<TeeCertAndKey> cert_and_key_;
    RATLSPolicyRef policy_;
    bool serialize_info{false};

    // Proof of work (always enabled)
    td::uint8 pow_difficulty{20};
  };
  explicit RevProxy(Config config) : config_(std::make_shared<Config>(std::move(config))) {
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
