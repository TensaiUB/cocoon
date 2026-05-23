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

#include "tee/cocoon/RATLS.h"
#include "common/bitstring.h"
#include "td/actor/PromiseFuture.h"
#include "td/actor/actor.h"
#include "td/net/TcpListener.h"
#include "TcpClient.h"
#include "td/utils/Observer.h"
#include "td/utils/UInt.h"
#include "td/utils/buffer.h"
#include "td/utils/crypto.h"
#include "td/utils/BufferedFd.h"
#include "td/utils/Random.h"

#include "td/utils/port/IPAddress.h"
#include "td/utils/port/SocketFd.h"
#include "td/net/Pipe.h"

#include "auto/tl/cocoon_api.h"

#include "cocoon-tl-utils/cocoon-tl-utils.hpp"

#include "common/errorcode.h"

#include <map>
#include <memory>
#include <set>

namespace cocoon {

class TcpConnection : public td::actor::Actor, public td::ObserverBase {
 public:
  class Callback {
   public:
    virtual ~Callback() = default;
    virtual void on_close(td::actor::ActorId<TcpConnection> conn) = 0;
    virtual void on_ready(td::actor::ActorId<TcpConnection> conn, const RemoteAppType &remote_app_type,
                          const td::Bits256 &remote_app_hash, const td::Bits256 &verified_by) = 0;
    virtual void on_packet(td::actor::ActorId<TcpConnection> conn, td::BufferSlice data) = 0;
    virtual void on_query(td::actor::ActorId<TcpConnection> conn, td::int64 query_id, td::BufferSlice data) = 0;
    virtual void on_query_answer(td::actor::ActorId<TcpConnection> conn, td::int64 query_id, td::BufferSlice data) = 0;
    virtual void on_query_error(td::actor::ActorId<TcpConnection> conn, td::int64 query_id, td::Status error) = 0;
  };

  double timeout() {
    return is_client_ ? 20.0 : 60.0;
  }

  TcpConnection(td::IPAddress connect_to, std::shared_ptr<TcpConnectionType> type, std::unique_ptr<Callback> callback,
                const RemoteAppType &remote_app_type, bool is_client)
      : connect_to_(std::move(connect_to))
      , type_(std::move(type))
      , callback_(std::move(callback))
      , remote_app_type_(remote_app_type)
      , is_client_(is_client) {
  }
  TcpConnection(td::SocketFd fd, std::unique_ptr<Callback> callback, const RemoteAppType &remote_app_type,
                bool is_client)
      : callback_(std::move(callback)), remote_app_type_(remote_app_type), is_client_(is_client) {
    connect_to_.init_peer_address(fd).ignore();
    socket_pipe_ = td::make_socket_pipe(std::move(fd));
  }
  void send(td::BufferSlice data);
  void send_packet(td::BufferSlice data);
  void send_query(td::int64 query_id, td::BufferSlice data);
  void send_query_answer(td::int64 query_id, td::BufferSlice data);
  void send_query_answer_error(td::int64 query_id, td::Status error);
  void send_uninit(td::BufferSlice data);
  td::Status receive(td::ChainBufferReader &input, bool &exit_loop);
  td::Status process_packet(td::BufferSlice data);
  td::Status process_init_packet(td::BufferSlice data);
  td::Status receive_packet(td::BufferSlice data);
  virtual bool authorized() const {
    return false;
  }
  void stop_read() {
    stop_read_ = true;
  }
  void resume_read() {
    stop_read_ = false;
  }
  bool check_ready() const {
    return received_bytes_ && inited_ && authorized() /*&& !td::can_close(buffered_fd_)*/;
  }
  void check_ready_async(td::Promise<td::Unit> promise) {
    if (check_ready()) {
      promise.set_value(td::Unit());
    } else {
      promise.set_error(td::Status::Error(ton::ErrorCode::notready, "not ready"));
    }
  }
  void send_ready() {
    LOG(DEBUG) << "tcp: sending ready";
    if (check_ready() && !sent_ready_ && callback_) {
      callback_->on_ready(self_, remote_app_type_, remote_app_hash_, verified_by_);
      sent_ready_ = true;
    }
  }

  void fail(td::Status error) {
    LOG(INFO) << "failing connection to " << connect_to_ << ": " << error;
    stop();
  }

 protected:
  td::IPAddress connect_to_;
  td::SocketPipe socket_pipe_;
  td::Pipe simple_pipe_;
  std::shared_ptr<TcpConnectionType> type_;
  td::actor::ActorId<TcpConnection> self_;
  std::unique_ptr<Callback> callback_;
  RemoteAppType remote_app_type_;
  td::Bits256 remote_app_hash_ = td::Bits256::zero();
  td::Bits256 verified_by_ = td::Bits256::zero();
  bool sent_ready_ = false;
  bool received_attestation_ = false;
  bool is_client_;

  void notify() override {
    // NB: Interface will be changed
    td::actor::send_closure_later(self_, &TcpConnection::on_net);
  }

  void start_up() override;
  void got_fd(td::Result<td::BufferedFd<td::SocketFd>> fdR);

  void tls_solved_pow(td::SocketPipe pipe);
  void tls_created_pipe(td::Pipe pipe, const RATLSAttestationReport &attestation);

  void socks5_connected(td::BufferedFd<td::SocketFd> fd);

  void process_attestation(const RATLSAttestationReport &attestation_report) {
    received_attestation_ = true;
    remote_app_hash_.as_slice().copy_from(attestation_report.image_hash().as_slice());
    verified_by_ = td::Bits256::zero();
  }

  void start();

 private:
  bool inited_ = false;
  bool stop_read_ = false;
  bool read_len_ = false;
  td::uint32 len_;
  td::uint32 received_bytes_ = 0;
  td::Timestamp fail_at_;
  td::Timestamp send_ping_at_;
  bool ping_sent_ = false;

  td::int32 in_seqno_{0};
  td::int32 out_seqno_{0};

  void on_net() {
    loop();
  }

  void tear_down() override {
    LOG(DEBUG) << "destoying connection";
    if (callback_) {
      callback_->on_close(self_);
      callback_ = nullptr;
    }
  }

  void update_timer() {
    fail_at_ = td::Timestamp::in(timeout());
    alarm_timestamp() = fail_at_;
    if (is_client_) {
      ping_sent_ = false;
      send_ping_at_ = td::Timestamp::in(timeout() / 2);
      alarm_timestamp().relax(send_ping_at_);
    }
  }

  void loop() override;

  void alarm() override {
    alarm_timestamp() = fail_at_;
    if (fail_at_.is_in_past()) {
      fail(td::Status::Error(ton::ErrorCode::timeout, "tcp: failing timedout connection"));
    } else if (is_client_ && !ping_sent_) {
      if (send_ping_at_.is_in_past() && sent_ready_) {
        auto obj = create_tl_object<cocoon_api::tcp_ping>(td::Random::fast_uint64());
        send(serialize_tl_object(obj, true));
        ping_sent_ = true;
      } else {
        alarm_timestamp().relax(send_ping_at_);
      }
    }
  }
};

}  // namespace cocoon
