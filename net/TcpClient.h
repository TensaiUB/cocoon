/*
    This file is part of TON Blockchain Library.

    TON Blockchain Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    TON Blockchain Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with TON Blockchain Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2017-2020 Telegram Systems LLP
*/
#pragma once

#include "td/actor/PromiseFuture.h"
#include "td/utils/UInt.h"
#include "td/utils/Variant.h"
#include "td/utils/buffer.h"
#include "td/utils/common.h"
#include "td/utils/port/IPAddress.h"
#include "td/actor/actor.h"
#include "crypto/common/bitstring.h"
#include "tee/cocoon/Tee.h"
#include "tee/cocoon/RATLS.h"
#include <memory>
#include <vector>

namespace cocoon {

td::uint64 generate_unique_uint64();

struct TcpConnectionSimple {};
struct TcpConnectionSocks5 {
  TcpConnectionSocks5(td::IPAddress connect_via) : connect_via(std::move(connect_via)) {
  }
  td::IPAddress connect_via;
};
struct TcpConnectionTls {
  TcpConnectionTls(TeeCertAndKey cert_and_key, RATLSPolicyRef policy)
      : cert_and_key(std::move(cert_and_key)), policy(std::move(policy)) {
  }
  TeeCertAndKey cert_and_key;
  RATLSPolicyRef policy;
};

struct TcpConnectionType {
  td::Variant<TcpConnectionSimple, TcpConnectionSocks5, TcpConnectionTls> type;
  TcpConnectionType() : type(TcpConnectionSimple()) {
  }
  template <typename T>
  TcpConnectionType(T &&arg) : type(std::forward<T>(arg)) {
  }
};

struct RemoteAppType {
  RemoteAppType() {
    info = "";
  }
  std::string info;

  bool operator==(const RemoteAppType &other) const {
    return info == other.info;
  }
  bool operator<(const RemoteAppType &other) const {
    return info < other.info;
  }
};

class TcpClient : public td::actor::Actor {
 public:
  using ConnectionId = td::uint64;
  using TargetId = td::uint64;
  using ListeningSocketId = td::uint64;

  class Callback {
   public:
    virtual ~Callback() = default;
    virtual void on_ready_outbound(ConnectionId connection_id, TargetId target_id, const RemoteAppType &remote_app_type,
                                   const td::Bits256 &remote_app_hash, const td::Bits256 &verified_by) = 0;
    virtual void on_ready_inbound(ConnectionId connection_id, ListeningSocketId listening_socket_id,
                                  const RemoteAppType &remote_app_type, const td::Bits256 &remote_app_hash,
                                  const td::Bits256 &verified_by) = 0;
    virtual void on_stop_ready(ConnectionId connection_id) = 0;
    virtual void receive_message(ConnectionId connection_id, td::BufferSlice message) = 0;
    virtual void receive_query(ConnectionId connection_id, td::BufferSlice message,
                               td::Promise<td::BufferSlice> promise) = 0;
  };
  virtual ~TcpClient() = default;
  virtual void check_ready(ConnectionId connection_id, td::Promise<td::Unit> promise) = 0;
  virtual void send_packet(ConnectionId connection_id, td::BufferSlice data) = 0;
  virtual void send_query(std::string name, ConnectionId connection_id, td::BufferSlice data, td::Timestamp timeout,
                          td::Promise<td::BufferSlice> promise) = 0;
  virtual void fail_connection(ConnectionId connection_id) = 0;

  virtual void add_outbound_address(TargetId target_id, td::IPAddress remote_ip,
                                    const RemoteAppType &remote_app_type) = 0;
  virtual void del_outbound_address(TargetId target_id) = 0;
  virtual void add_listening_port(ListeningSocketId listening_socket_id, td::uint16 port,
                                  const RemoteAppType &remote_app_type) = 0;
  virtual void del_listening_port(ListeningSocketId listening_socket_id) = 0;
  virtual void add_connection_to_remote_app_type_rule(const RemoteAppType &remote_app_type,
                                                      std::shared_ptr<TcpConnectionType> type) = 0;

  static td::actor::ActorOwn<TcpClient> create(std::unique_ptr<Callback> callback);
};

}  // namespace cocoon
