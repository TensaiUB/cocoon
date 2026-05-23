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
#include "TcpClient.hpp"
#include "auto/tl/cocoon_api.h"
#include "common/bitstring.h"
#include "td/actor/PromiseFuture.h"
#include "td/actor/actor.h"
#include "td/net/Pipe.h"
#include "td/net/Socks5.h"
#include "td/utils/BufferedFd.h"
#include "td/utils/Random.h"
#include "td/utils/Slice-decl.h"
#include "td/utils/Status.h"
#include "td/utils/UInt.h"
#include "td/utils/overloaded.h"
#include "td/utils/port/IPAddress.h"
#include "td/utils/port/SocketFd.h"
#include "tee/cocoon/utils.h"
#include "tee/cocoon/pow.h"
#include "common/errorcode.h"
#include <memory>

namespace cocoon {

td::uint64 generate_unique_uint64() {
  static std::atomic<td::uint64> counter{999111};
  return ++counter;
}

void TcpOutboundQuery::destroy() {
  td::actor::send_closure(client_, &TcpClientImpl::unregister_query, query_id_);
}

std::unique_ptr<TcpConnection::Callback> TcpClientImpl::make_tcp_connection_callback(
    TcpClient::ConnectionId connection_id) {
  class Cb : public TcpConnection::Callback {
   private:
    td::actor::ActorId<TcpClientImpl> id_;
    ConnectionId connection_id_;

   public:
    void on_ready(td::actor::ActorId<TcpConnection> conn, const RemoteAppType &remote_app_type,
                  const td::Bits256 &remote_app_hash, const td::Bits256 &verified_by) override {
      td::actor::send_closure(id_, &TcpClientImpl::conn_ready, connection_id_, remote_app_type, remote_app_hash,
                              verified_by);
    }
    void on_close(td::actor::ActorId<TcpConnection> conn) override {
      td::actor::send_closure(id_, &TcpClientImpl::conn_stopped, connection_id_);
    }
    void on_packet(td::actor::ActorId<TcpConnection> conn, td::BufferSlice data) override {
      td::actor::send_closure(id_, &TcpClientImpl::process_packet, connection_id_, std::move(data));
    }
    void on_query(td::actor::ActorId<TcpConnection> conn, td::int64 query_id, td::BufferSlice data) override {
      td::actor::send_closure(id_, &TcpClientImpl::process_query, connection_id_, query_id, std::move(data));
    }
    void on_query_answer(td::actor::ActorId<TcpConnection> conn, td::int64 query_id, td::BufferSlice data) override {
      td::actor::send_closure(id_, &TcpClientImpl::process_query_answer, connection_id_, query_id, std::move(data));
    }
    void on_query_error(td::actor::ActorId<TcpConnection> conn, td::int64 query_id, td::Status error) override {
      td::actor::send_closure(id_, &TcpClientImpl::process_query_error, connection_id_, query_id, std::move(error));
    }
    Cb(td::actor::ActorId<TcpClientImpl> id, ConnectionId connection_id) : id_(id), connection_id_(connection_id) {
    }
  };
  return std::make_unique<Cb>(actor_id(this), connection_id);
}

void TcpClientImpl::alarm() {
  if (is_closing_) {
    return;
  }
  next_create_at_ = td::Timestamp::in(10.0);
  std::vector<ConnectionId> failed_connections;
  for (auto conn_id : failed_connections) {
    fail_connection(conn_id);
  }
  for (auto &x : targets_) {
    if (x.second->active_connections + x.second->pending_connections > 0) {
      continue;
    }

    auto it = connect_to_remote_app_type_rules_.find(x.second->remote_app_type);
    if (it == connect_to_remote_app_type_rules_.end()) {
      create_tcp_connection(x.second->remote_addr, std::make_shared<TcpConnectionType>(), x.second->target_id);
    } else {
      create_tcp_connection(x.second->remote_addr, it->second, x.second->target_id);
    }
  }

  alarm_timestamp().relax(next_create_at_);
}

void TcpClientImpl::accepted_tcp_connection(td::BufferedFd<td::SocketFd> fd, ListeningSocketId listening_socket_id) {
  auto it = listening_sockets_.find(listening_socket_id);
  if (it == listening_sockets_.end()) {
    LOG(INFO) << "tcp: dropping created outbound connection: socket already deleted";
    return;
  }
  auto connection_id = generate_unique_uint64();
  auto conn = td::actor::create_actor<TcpClientConnection>(
      td::actor::ActorOptions().with_name("inconn").with_poll(), std::move(fd), connection_id, listening_socket_id,
      it->second->remote_app_type, false, make_tcp_connection_callback(connection_id), actor_id(this));
  auto &e = active_connections_[connection_id];
  e.connection = std::move(conn);
  e.is_outbound = false;
  e.is_ready = false;
  e.remote_app_type = it->second->remote_app_type;
  e.listening_socket_id = listening_socket_id;
  it->second->pending_connections++;
}

void TcpClientImpl::create_tcp_connection(td::IPAddress connect_to, std::shared_ptr<TcpConnectionType> type,
                                          TargetId target_id) {
  auto it = targets_.find(target_id);
  if (it == targets_.end()) {
    LOG(INFO) << "tcp: dropping created outbound connection: target already deleted";
    return;
  }

  auto connection_id = generate_unique_uint64();
  auto conn = td::actor::create_actor<TcpClientConnection>(
      td::actor::ActorOptions().with_name("inconn").with_poll(), connect_to, type, connection_id, target_id,
      it->second->remote_app_type, true, make_tcp_connection_callback(connection_id), actor_id(this));
  auto &e = active_connections_[connection_id];
  e.connection = std::move(conn);
  e.is_outbound = true;
  e.is_ready = false;
  e.remote_app_type = it->second->remote_app_type;
  e.target_id = target_id;
  it->second->pending_connections++;
}

void TcpClientImpl::hangup() {
  active_connections_.clear();
  targets_.clear();
  is_closing_ = true;
  ref_cnt_--;
  for (auto &it : out_queries_) {
    td::actor::send_closure(it.second.get(), &TcpOutboundQuery::set_error,
                            td::Status::Error(ton::ErrorCode::cancelled, "hangup"));
  }
  try_stop();
}

void TcpClientImpl::try_stop() {
  if (is_closing_ && ref_cnt_ == 0 && out_queries_.empty()) {
    stop();
  }
}

void TcpClientConnection::start_up() {
  TcpConnection::start_up();
}

void TcpClientImpl::check_ready(ConnectionId connection_id, td::Promise<td::Unit> promise) {
  auto it = active_connections_.find(connection_id);
  if (it == active_connections_.end() || !it->second.is_ready) {
    promise.set_error(td::Status::Error(ton::ErrorCode::notready, "not ready"));
    return;
  }
  promise.set_value(td::Unit());
}

void TcpClientImpl::add_outbound_address(TargetId target_id, td::IPAddress remote_ip,
                                         const RemoteAppType &remote_app_type) {
  auto it = targets_.find(target_id);
  if (it != targets_.end()) {
    return;
  }
  auto target = std::make_unique<TcpTarget>(target_id, remote_ip, remote_app_type);
  CHECK(targets_.emplace(target_id, std::move(target)).second);
}

void TcpClientImpl::del_outbound_address(TargetId target_id) {
  targets_.erase(target_id);
}

void TcpClientImpl::add_listening_port(ListeningSocketId listening_socket_id, td::uint16 port,
                                       const RemoteAppType &remote_app_type) {
  auto it = listening_sockets_.find(listening_socket_id);
  if (it != listening_sockets_.end()) {
    return;
  }

  auto listening_socket = std::make_unique<TcpListeningSocket>(listening_socket_id, port, remote_app_type);

  class Callback : public td::TcpListener::Callback {
   private:
    td::actor::ActorId<TcpClientImpl> id_;
    ListeningSocketId listening_socket_id_;

   public:
    Callback(td::actor::ActorId<TcpClientImpl> id, ListeningSocketId listening_socket_id)
        : id_(id), listening_socket_id_(listening_socket_id) {
    }
    void accept(td::SocketFd fd) override {
      td::actor::send_closure(id_, &TcpClientImpl::accepted_tcp_connection, td::BufferedFd<td::SocketFd>(std::move(fd)),
                              listening_socket_id_);
    }
  };

  listening_socket->listener = td::actor::create_actor<td::TcpInfiniteListener>(
      td::actor::ActorOptions().with_name("listener").with_poll(), port,
      std::make_unique<Callback>(actor_id(this), listening_socket_id), "127.0.0.1");
  listening_sockets_.emplace(listening_socket_id, std::move(listening_socket));
}

void TcpClientImpl::del_listening_port(ListeningSocketId listening_socket_id) {
  listening_sockets_.erase(listening_socket_id);
}

td::actor::ActorOwn<TcpClient> TcpClient::create(std::unique_ptr<Callback> callback) {
  auto res = td::actor::create_actor<TcpClientImpl>("extclient", std::move(callback));
  return res;
}

void TcpClientImpl::add_connection_to_remote_app_type_rule(const RemoteAppType &remote_app_type,
                                                           std::shared_ptr<TcpConnectionType> type) {
  connect_to_remote_app_type_rules_[remote_app_type] = std::move(type);
}

}  // namespace cocoon
