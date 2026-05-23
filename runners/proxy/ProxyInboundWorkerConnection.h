#pragma once

#include "auto/tl/cocoon_api.h"
#include "block.h"
#include "runners/BaseRunner.hpp"
#include "ProxyWorkerInfo.h"
#include "ProxyWorkerConnectionInfo.h"
#include "ProxyInboundConnection.h"
#include "td/actor/PromiseFuture.h"
#include "td/utils/buffer.h"
#include "tl/TlObject.h"
#include <memory>

namespace cocoon {

class ProxyRunner;

class ProxyInboundWorkerConnection : public ProxyInboundConnection {
 public:
  enum class State { None, Ok, Compare, CompareExt, FinishingHandshake, Failed };
  ProxyInboundWorkerConnection(BaseRunner *runner, const RemoteAppType &remote_app_type,
                               const td::Bits256 &remote_app_hash, const td::Bits256 &verified_by,
                               TcpClient::ConnectionId connection_id)
      : ProxyInboundConnection(runner, remote_app_type, remote_app_hash, verified_by, connection_id) {
  }

  ConnectionType connection_type() const override {
    return ConnectionType::Worker;
  }
  bool handshake_is_completed() const override {
    return state_ == State::Ok && is_ready();
  }

  void pre_close() override;

  auto worker_info() const {
    return worker_info_;
  }

  auto worker_connection_info() const {
    return worker_connection_info_;
  }
  auto proto_version() const {
    return proto_version_;
  }

  void receive_handshake_query(td::BufferSlice message, td::Promise<td::BufferSlice> promise);
  void receive_connect_to_proxy_query(td::BufferSlice message, td::Promise<td::BufferSlice> promise);
  void receive_compare_payment_query(td::BufferSlice message, td::Promise<td::BufferSlice> promise);
  void receive_compare_payment_ext_query(td::BufferSlice message, td::Promise<td::BufferSlice> promise);
  void receive_handshake_finish_query(td::BufferSlice message, td::Promise<td::BufferSlice> promise);

 private:
  State state_{State::None};
  std::string worker_owner_address_str_;
  std::shared_ptr<ProxyWorkerInfo> worker_info_{nullptr};
  std::shared_ptr<ProxyWorkerConnectionInfo> worker_connection_info_{nullptr};
  td::int32 proto_version_;
};

}  // namespace cocoon
