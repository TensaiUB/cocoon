#pragma once

#include "auto/tl/cocoon_api.h"
#include "block.h"
#include "runners/BaseRunner.hpp"
#include "ProxyConnectingClient.h"
#include "ProxyClientInfo.h"
#include "ProxyInboundConnection.h"
#include "td/actor/PromiseFuture.h"
#include "td/utils/buffer.h"
#include "tl/TlObject.h"
#include <memory>

namespace cocoon {

class ProxyRunner;

class ProxyInboundClientConnection : public ProxyInboundConnection {
 public:
  enum class State { None, Ok, Auth, Failed };
  ProxyInboundClientConnection(BaseRunner *runner, const RemoteAppType &remote_app_type,
                               const td::Bits256 &remote_app_hash, const td::Bits256 &verified_by,
                               TcpClient::ConnectionId connection_id)
      : ProxyInboundConnection(runner, remote_app_type, remote_app_hash, verified_by, connection_id) {
  }

  ConnectionType connection_type() const override {
    return ConnectionType::Client;
  }
  bool handshake_is_completed() const override {
    return state_ == State::Ok && is_ready();
  }

  void pre_close() override;

  auto client_info() const {
    return client_info_;
  }

  auto connecting_client_info() const {
    return connecting_client_info_;
  }
  auto proto_version() const {
    return proto_version_;
  }

  void receive_handshake_query(td::BufferSlice message, td::Promise<td::BufferSlice> promise);
  void receive_connect_to_proxy_query(td::BufferSlice message, td::Promise<td::BufferSlice> promise);

  void send_connected(ton::tl_object_ptr<cocoon_api::client_ProxyConnectionAuth> auth,
                      td::Promise<td::BufferSlice> promise);

  void receive_auth_query(td::BufferSlice message, td::Promise<td::BufferSlice> promise);
  void receive_auth_query(cocoon_api::client_authorizeWithProxyLong &auth, td::Promise<td::BufferSlice> promise);
  void receive_auth_query(cocoon_api::client_authorizeWithProxyShort &auth, td::Promise<td::BufferSlice> promise);

  void send_auth_success(td::Promise<td::BufferSlice> promise);
  void send_auth_fail(td::Status error, td::Promise<td::BufferSlice> promise);

  void received_register_message(std::shared_ptr<ProxyClientInfo> client_info);

  block::StdAddress client_sc_address() const;

  void remove_connecting_info();

 private:
  State state_{State::None};
  std::string client_owner_address_str_;
  std::shared_ptr<ProxyClientInfo> client_info_{nullptr};
  std::shared_ptr<ProxyConnectingClient> connecting_client_info_{nullptr};
  td::int32 proto_version_{0};
};

}  // namespace cocoon
