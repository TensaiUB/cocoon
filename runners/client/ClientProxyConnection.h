#pragma once

#include "runners/BaseRunner.hpp"
#include "td/utils/buffer.h"
#include <memory>

namespace cocoon {

class ClientRunner;
class ClientProxyInfo;

class ClientProxyConnection : public ProxyOutboundConnection {
 public:
  ClientProxyConnection(BaseRunner *runner, const RemoteAppType &remote_app_type, const td::Bits256 &remote_app_hash,
                        const td::Bits256 &verified_by, TcpClient::ConnectionId connection_id,
                        TcpClient::TargetId target_id)
      : ProxyOutboundConnection(runner, remote_app_type, remote_app_hash, verified_by, connection_id, target_id) {
  }
  void send_handshake() override;
  void received_handshake_answer(td::BufferSlice answer);
  void run_authorization(std::shared_ptr<ClientProxyInfo> proxy,
                         ton::tl_object_ptr<cocoon_api::client_ProxyConnectionAuth> auth);
  void authorize_long(std::shared_ptr<ClientProxyInfo> proxy, td::uint64 nonce);
  void authorize_short(std::shared_ptr<ClientProxyInfo> proxy);
  void process_auth_answer(td::Result<td::BufferSlice> R);

  ClientRunner *runner();

  const auto &proxy() const {
    return proxy_;
  }

  auto proto_version() const {
    return proto_version_;
  }

 private:
  std::shared_ptr<ClientProxyInfo> proxy_;
  td::int32 proto_version_;
};

}  // namespace cocoon
