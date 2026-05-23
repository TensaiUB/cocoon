#pragma once

#include "runners/BaseRunner.hpp"
#include "ProxyWorkerInfo.h"
#include "ProxyWorkerConnectionInfo.h"
#include "ProxyConnectingClient.h"
#include "ProxyClientInfo.h"
#include <memory>

namespace cocoon {

class ProxyRunner;

class ProxyInboundConnection : public BaseInboundConnection {
 public:
  enum class ConnectionType { Client, Worker };
  ProxyInboundConnection(BaseRunner *runner, const RemoteAppType &remote_app_type, const td::Bits256 &remote_app_hash,
                         const td::Bits256 &verified_by, TcpClient::ConnectionId connection_id)
      : BaseInboundConnection(runner, remote_app_type, remote_app_hash, verified_by, connection_id) {
  }

  ProxyRunner *runner();

  virtual ConnectionType connection_type() const = 0;
  virtual bool handshake_is_completed() const = 0;
};

}  // namespace cocoon
