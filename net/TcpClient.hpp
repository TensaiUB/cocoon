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

#include "TcpConnection.hpp"
#include "TcpClient.h"
#include "tee/cocoon/Tee.h"
#include "tee/cocoon/RATLS.h"
#include "common/bitstring.h"
#include "td/actor/ActorId.h"
#include "td/actor/ActorOwn.h"
#include "td/actor/PromiseFuture.h"
#include "td/actor/actor.h"
#include "td/actor/common.h"
#include "td/net/Pipe.h"
#include "td/utils/BufferedFd.h"
#include "td/utils/Status.h"
#include "td/utils/Time.h"
#include "td/utils/UInt.h"
#include "td/utils/Variant.h"
#include "td/utils/buffer.h"
#include "td/utils/format.h"
#include "td/utils/int_types.h"
#include "td/utils/port/IPAddress.h"
#include "td/utils/port/SocketFd.h"
#include "tl-utils/tl-utils.hpp"
#include "td/utils/Random.h"
#include "common/errorcode.h"
#include <memory>

namespace cocoon {

class TcpClientImpl;

struct TcpConnectRuleVia {
  td::IPAddress addr;
};

struct TcpConnectRuleTls {
  std::shared_ptr<TeeCertAndKey> cert_and_key;
};

struct TcpConnectRule {
  td::Variant<TcpConnectRuleVia, TcpConnectRuleTls> rule;
};

class TcpOutboundQuery : public td::actor::Actor {
 public:
  TcpOutboundQuery(td::actor::ActorId<TcpClientImpl> client, td::int64 query_id, td::Timestamp timeout,
                   td::Promise<td::BufferSlice> promise)
      : client_(std::move(client)), query_id_(query_id), timeout_(timeout), promise_(std::move(promise)) {
  }
  void start_up() override {
    alarm_timestamp() = timeout_;
  }
  void alarm() override {
    promise_.set_error(td::Status::Error(ton::ErrorCode::timeout, "Timeout"));
    destroy();
  }
  void set_error(td::Status error) {
    promise_.set_error(std::move(error));
    destroy();
  }
  void answer(td::BufferSlice data) {
    promise_.set_value(std::move(data));
    destroy();
  }
  void answer_error(td::Status error) {
    promise_.set_error(std::move(error));
    destroy();
  }
  void destroy();

 private:
  td::actor::ActorId<TcpClientImpl> client_;
  td::int64 query_id_;
  td::Timestamp timeout_;
  td::Promise<td::BufferSlice> promise_;
};

class TcpClientConnection : public TcpConnection {
 private:
  td::actor::ActorId<TcpClientImpl> tcp_client_;

 public:
  TcpClientConnection(td::IPAddress connect_to, std::shared_ptr<TcpConnectionType> type,
                      TcpClient::ConnectionId connection_id, TcpClient::ConnectionId target_id,
                      const RemoteAppType &remote_app_type, bool is_client,
                      std::unique_ptr<TcpConnection::Callback> callback, td::actor::ActorId<TcpClientImpl> tcp_client)
      : TcpConnection(std::move(connect_to), std::move(type), std::move(callback), remote_app_type, is_client)
      , tcp_client_(tcp_client)
      , connection_id_(connection_id)
      , target_id_(target_id) {
  }
  TcpClientConnection(td::SocketFd fd, TcpClient::ConnectionId connection_id, TcpClient::ConnectionId target_id,
                      const RemoteAppType &remote_app_type, bool is_client,
                      std::unique_ptr<TcpConnection::Callback> callback, td::actor::ActorId<TcpClientImpl> tcp_client)
      : TcpConnection(std::move(fd), std::move(callback), remote_app_type, is_client)
      , tcp_client_(tcp_client)
      , connection_id_(connection_id)
      , target_id_(target_id) {
  }
  void start_up() override;
  bool authorized() const override {
    return true;
  }
  auto connection_id() const {
    return connection_id_;
  }
  auto target_id() const {
    return target_id_;
  }
  auto listening_socket_id() const {
    return target_id_;
  }

 private:
  TcpClient::ConnectionId connection_id_;
  TcpClient::ConnectionId target_id_;
};

struct TcpTarget {
  TcpTarget(TcpClient::TargetId target_id, const td::IPAddress &remote_addr, const RemoteAppType &remote_app_type)
      : target_id(target_id), remote_addr(remote_addr), remote_app_type(remote_app_type) {
  }
  TcpClient::TargetId target_id;
  td::IPAddress remote_addr;
  RemoteAppType remote_app_type;
  td::int64 active_connections{0};
  td::int64 pending_connections{0};
};

struct TcpListeningSocket {
  TcpListeningSocket(TcpClient::ListeningSocketId listening_socket_id, td::uint16 remote_port,
                     const RemoteAppType &remote_app_type)
      : listening_socket_id(listening_socket_id), remote_port(remote_port), remote_app_type(remote_app_type) {
  }
  TcpClient::ListeningSocketId listening_socket_id;
  td::actor::ActorOwn<td::TcpInfiniteListener> listener;
  td::uint16 remote_port;
  RemoteAppType remote_app_type;
  td::int64 active_connections{0};
  td::int64 pending_connections{0};
};

class TcpClientImpl : public TcpClient {
 private:
  struct ConnectionDescription {
    td::actor::ActorOwn<TcpClientConnection> connection;
    RemoteAppType remote_app_type;
    union {
      TargetId target_id;
      ListeningSocketId listening_socket_id;
    };
    bool is_outbound;
    bool is_ready;
  };

 public:
  using QueryId = td::int64;
  TcpClientImpl(std::unique_ptr<Callback> callback) : callback_(std::move(callback)) {
  }

  void start_up() override {
    alarm();
  }
  void fail_connection(ConnectionId connection_id) override {
    LOG(INFO) << "tcp: failing connection " << connection_id;
    conn_stopped(connection_id);
  }
  void conn_stopped(ConnectionId conn_id) {
    auto it = active_connections_.find(conn_id);
    if (it != active_connections_.end()) {
      if (it->second.is_outbound) {
        auto t_it = targets_.find(it->second.target_id);
        if (t_it != targets_.end()) {
          if (it->second.is_ready) {
            CHECK(t_it->second->active_connections > 0);
            t_it->second->active_connections--;
          } else {
            CHECK(t_it->second->pending_connections > 0);
            t_it->second->pending_connections--;
          }
        }
      } else {
        auto t_it = listening_sockets_.find(it->second.listening_socket_id);
        if (t_it != listening_sockets_.end()) {
          if (it->second.is_ready) {
            CHECK(t_it->second->active_connections > 0);
            t_it->second->active_connections--;
          } else {
            CHECK(t_it->second->pending_connections > 0);
            t_it->second->pending_connections--;
          }
        }
      }
      it->second.is_ready = false;
      callback_->on_stop_ready(conn_id);
      active_connections_.erase(it);
      alarm_timestamp().relax(next_create_at_);
      try_stop();
    }
  }
  void conn_ready(ConnectionId conn_id, const RemoteAppType &remote_app_type, const td::Bits256 &remote_app_hash,
                  const td::Bits256 &verified_by) {
    LOG(INFO) << "tcp: created connection " << conn_id;
    auto it = active_connections_.find(conn_id);
    if (it != active_connections_.end()) {
      if (!it->second.is_ready) {
        it->second.is_ready = true;
        if (it->second.is_outbound) {
          auto t_it = targets_.find(it->second.target_id);
          if (t_it != targets_.end()) {
            CHECK(t_it->second->pending_connections > 0);
            t_it->second->pending_connections--;
            t_it->second->active_connections++;
          } else {
            LOG(ERROR) << "created connection for unknown target " << it->second.target_id;
          }
        } else {
          auto t_it = listening_sockets_.find(it->second.listening_socket_id);
          if (t_it != listening_sockets_.end()) {
            CHECK(t_it->second->pending_connections > 0);
            t_it->second->pending_connections--;
            t_it->second->active_connections++;
            LOG(ERROR) << "active_connections=" << t_it->second->active_connections;
          } else {
            LOG(ERROR) << "created connection for unknown listening socket " << it->second.listening_socket_id;
          }
        }
      }
      if (it->second.is_outbound) {
        callback_->on_ready_outbound(conn_id, it->second.target_id, it->second.remote_app_type, remote_app_hash,
                                     verified_by);
      } else {
        callback_->on_ready_inbound(conn_id, it->second.listening_socket_id, it->second.remote_app_type,
                                    remote_app_hash, verified_by);
      }
    }
  }
  void check_ready(ConnectionId connection_id, td::Promise<td::Unit> promise) override;
  void send_query(std::string name, ConnectionId connection_id, td::BufferSlice data, td::Timestamp timeout,
                  td::Promise<td::BufferSlice> promise) override {
    auto q_id = generate_next_query_id();
    auto query = td::actor::create_actor<TcpOutboundQuery>(PSTRING() << "query '" << name << "'", actor_id(this), q_id,
                                                           timeout, std::move(promise));
    out_queries_.emplace(q_id, std::move(query));
    auto it = active_connections_.find(connection_id);
    if (it != active_connections_.end()) {
      LOG(DEBUG) << "tcp: sending query to connection " << connection_id;
      td::actor::send_closure(it->second.connection, &TcpClientConnection::send_query, q_id, std::move(data));
    } else {
      LOG(WARNING) << "tcp: dropping query to connection " << connection_id << ": connection is closed";
    }
  }
  void send_query_answer(ConnectionId connection_id, td::int64 query_id, td::BufferSlice data) {
    auto it = active_connections_.find(connection_id);
    if (it != active_connections_.end()) {
      td::actor::send_closure(it->second.connection, &TcpClientConnection::send_query_answer, query_id,
                              std::move(data));
    }
  }
  void send_query_answer_error(ConnectionId connection_id, td::int64 query_id, td::Status error) {
    auto it = active_connections_.find(connection_id);
    if (it != active_connections_.end()) {
      td::actor::send_closure(it->second.connection, &TcpClientConnection::send_query_answer_error, query_id,
                              std::move(error));
    }
  }
  void send_packet(ConnectionId connection_id, td::BufferSlice data) override {
    auto it = active_connections_.find(connection_id);
    if (it != active_connections_.end()) {
      td::actor::send_closure(it->second.connection, &TcpClientConnection::send_packet, std::move(data));
    }
  }

  void process_packet(ConnectionId connection_id, td::BufferSlice data) {
    auto it = active_connections_.find(connection_id);
    if (it == active_connections_.end()) {
      return;
    }
    callback_->receive_message(connection_id, std::move(data));
  }
  void process_query_answer(ConnectionId connection_id, QueryId id, td::BufferSlice data) {
    LOG(DEBUG) << "tcp: processing query answer from " << connection_id;
    auto it = active_connections_.find(connection_id);
    if (it == active_connections_.end()) {
      return;
    }
    auto it2 = out_queries_.find(id);
    if (it2 != out_queries_.end()) {
      td::actor::send_closure(it2->second, &TcpOutboundQuery::answer, std::move(data));
    }
  }
  void process_query_error(ConnectionId connection_id, QueryId id, td::Status error) {
    auto it = active_connections_.find(connection_id);
    if (it == active_connections_.end()) {
      return;
    }
    auto it2 = out_queries_.find(id);
    if (it2 != out_queries_.end()) {
      td::actor::send_closure(it2->second, &TcpOutboundQuery::answer_error, std::move(error));
    }
  }
  void process_query(ConnectionId connection_id, QueryId id, td::BufferSlice data) {
    LOG(DEBUG) << "tcp: processing query from " << connection_id;
    auto it = active_connections_.find(connection_id);
    if (it == active_connections_.end()) {
      return;
    }
    auto P = td::PromiseCreator::lambda([self_id = actor_id(this), id, connection_id](td::Result<td::BufferSlice> R) {
      if (R.is_ok()) {
        td::actor::send_closure(self_id, &TcpClientImpl::send_query_answer, connection_id, id, R.move_as_ok());
      } else {
        td::actor::send_closure(self_id, &TcpClientImpl::send_query_answer_error, connection_id, id, R.move_as_error());
      }
    });
    callback_->receive_query(connection_id, std::move(data), std::move(P));
  }
  void unregister_query(QueryId query_id) {
    out_queries_.erase(query_id);
  }
  void alarm() override;
  void hangup() override;
  QueryId generate_next_query_id() {
    while (true) {
      QueryId q_id = td::Random::secure_uint64();
      if (out_queries_.count(q_id) == 0) {
        return q_id;
      }
    }
  }

  void outbound_connection_connected(ConnectionId target_id);

  std::unique_ptr<TcpConnection::Callback> make_tcp_connection_callback(ConnectionId connection_id);
  void accepted_tcp_connection(td::BufferedFd<td::SocketFd> fd, ListeningSocketId listening_socket_id);
  void create_tcp_connection(td::IPAddress connect_to, std::shared_ptr<TcpConnectionType> type, TargetId target_id);

  void add_outbound_address(TargetId target_id, td::IPAddress remote_ip, const RemoteAppType &remote_app_type) override;
  void del_outbound_address(TargetId target_id) override;
  void add_listening_port(ListeningSocketId listening_socket_id, td::uint16 port,
                          const RemoteAppType &remote_app_type) override;
  void del_listening_port(ListeningSocketId listening_socket_id) override;

  void add_connection_to_remote_app_type_rule(const RemoteAppType &remote_app_type,
                                              std::shared_ptr<TcpConnectionType> type) override;

 private:
  std::unique_ptr<Callback> callback_;

  td::Timestamp next_create_at_ = td::Timestamp::now_cached();

  std::map<QueryId, td::actor::ActorOwn<TcpOutboundQuery>> out_queries_;
  std::map<ConnectionId, ConnectionDescription> active_connections_;
  std::map<TargetId, std::unique_ptr<TcpTarget>> targets_;
  std::map<ListeningSocketId, std::unique_ptr<TcpListeningSocket>> listening_sockets_;
  std::map<RemoteAppType, std::shared_ptr<TcpConnectionType>> connect_to_remote_app_type_rules_;

  bool is_closing_{false};
  td::uint32 ref_cnt_{1};
  void try_stop();
};

}  // namespace cocoon
