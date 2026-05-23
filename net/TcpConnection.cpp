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

#include "TcpConnection.hpp"
#include "auto/tl/cocoon_api.h"
#include "auto/tl/cocoon_api.hpp"
#include "tee/cocoon/RATLS.h"
#include "tee/cocoon/Tee.h"
#include "td/net/Pipe.h"
#include "td/utils/Status.h"
#include "td/utils/buffer.h"
#include "td/utils/overloaded.h"
#include "td/utils/port/SocketFd.h"
#include "tee/cocoon/pow.h"
#include "tee/cocoon/utils.h"
#include <memory>

namespace cocoon {

void TcpConnection::start_up() {
  self_ = actor_id(this);
  update_timer();

  if (!type_) {
    CHECK(socket_pipe_);
    start();
    return;
  }

  type_->type.visit(td::overloaded(
      [&](const TcpConnectionSimple &t) {
        auto R = td::SocketFd::open(connect_to_);
        if (R.is_error()) {
          fail(R.move_as_error_prefix(PSTRING() << "tcp: failed to connect to " << connect_to_ << ": "));
          return;
        }
        socket_pipe_ = td::make_socket_pipe(R.move_as_ok());
        start();
      },
      [&](const TcpConnectionSocks5 &t) {
        auto R = td::SocketFd::open(t.connect_via);
        if (R.is_error()) {
          fail(R.move_as_error_prefix(PSTRING() << "tcp: failed to connect to " << t.connect_via << ": "));
          return;
        }
        td::connect(
            [self = actor_id(this), connect_to = connect_to_](td::Result<td::BufferedFd<td::SocketFd>> R) {
              if (R.is_ok()) {
                td::actor::send_closure(self, &TcpConnection::socks5_connected, R.move_as_ok());
              } else {
                td::actor::send_closure(
                    self, &TcpConnection::fail,
                    R.move_as_error_prefix(PSTRING() << "tcp: failed to connect to " << connect_to << " via socks5: "));
              }
            },
            socks5(R.move_as_ok(), connect_to_, "", ""));
      },
      [&](const TcpConnectionTls &t) {
        auto R = td::SocketFd::open(connect_to_);
        if (R.is_error()) {
          fail(R.move_as_error_prefix(PSTRING() << "tcp: failed to connect to " << connect_to_ << ": "));
          return;
        }
        auto pipe = td::make_socket_pipe(R.move_as_ok());
        td::connect(
            [self = actor_id(this)](td::Result<td::SocketPipe> R) {
              if (R.is_ok()) {
                td::actor::send_closure(self, &TcpConnection::tls_solved_pow, R.move_as_ok());
              } else {
                td::actor::send_closure(self, &TcpConnection::fail,
                                        R.move_as_error_prefix("tcp: failed to solve pow: "));
              }
            },
            pow::solve_pow_client(std::move(pipe), 28));
      }));
}

void TcpConnection::socks5_connected(td::BufferedFd<td::SocketFd> fd) {
  socket_pipe_ = td::make_socket_pipe(std::move(fd));
  start();
}

void TcpConnection::tls_solved_pow(td::SocketPipe pipe) {
  td::connect(
      [self = actor_id(this)](td::Result<std::pair<td::Pipe, RATLSAttestedPeerInfo>> R) {
        if (R.is_ok()) {
          auto res = R.move_as_ok();
          td::actor::send_closure(self, &TcpConnection::tls_created_pipe, std::move(res.first), res.second.report());
        } else {
          td::actor::send_closure(self, &TcpConnection::fail,
                                  R.move_as_error_prefix("tcp: failed to create tls connection: "));
        }
      },
      wrap_tls_client("conn", std::move(pipe), type_->type.get<TcpConnectionTls>().cert_and_key,
                      type_->type.get<TcpConnectionTls>().policy, td::IPAddress{}, td::IPAddress{}));
}

void TcpConnection::tls_created_pipe(td::Pipe pipe, const RATLSAttestationReport &report) {
  process_attestation(report);

  simple_pipe_ = std::move(pipe);
  start();
}

void TcpConnection::start() {
  if (socket_pipe_) {
    socket_pipe_.subscribe();
  } else {
    simple_pipe_.subscribe();
  }
  update_timer();
  notify();

  if (is_client_) {
    LOG(DEBUG) << "tcp: sending handshake";
    auto id = td::Random::secure_uint64();
    auto data = create_serialize_tl_object<cocoon_api::tcp_connect>(id);
    send_uninit(std::move(data));
  }
}

void TcpConnection::send_uninit(td::BufferSlice data) {
  send(std::move(data));
}

void TcpConnection::send(td::BufferSlice data) {
  LOG(DEBUG) << "tcp: sending packet of size " << data.size();
  auto data_size = td::narrow_cast<td::uint32>(data.size());
  if (data_size < 4 || data_size > (1 << 24)) {
    LOG(WARNING) << "tcp: bad packet size " << data_size;
    fail(td::Status::Error(ton::ErrorCode::protoviolation, "invalid packet length"));
    return;
  }

  td::BufferSlice d{data.size() + 8};
  auto S = d.as_slice();

  S.copy_from(td::Slice(reinterpret_cast<const td::uint8 *>(&data_size), 4));
  S.remove_prefix(4);
  S.copy_from(td::Slice(reinterpret_cast<const td::uint8 *>(&out_seqno_), 4));
  S.remove_prefix(4);
  S.copy_from(data.as_slice());

  if (socket_pipe_) {
    socket_pipe_.output_buffer().append(std::move(d));
  } else {
    simple_pipe_.output_buffer().append(std::move(d));
  }
  out_seqno_++;
  loop();
}

void TcpConnection::send_packet(td::BufferSlice data) {
  send(create_serialize_tl_object<cocoon_api::tcp_packet>(std::move(data)));
}

void TcpConnection::send_query(td::int64 query_id, td::BufferSlice data) {
  send(create_serialize_tl_object<cocoon_api::tcp_query>(query_id, std::move(data)));
}

void TcpConnection::send_query_answer(td::int64 query_id, td::BufferSlice data) {
  send(create_serialize_tl_object<cocoon_api::tcp_queryAnswer>(query_id, std::move(data)));
}

void TcpConnection::send_query_answer_error(td::int64 query_id, td::Status error) {
  send(create_serialize_tl_object<cocoon_api::tcp_queryError>(query_id, error.code(), error.message().str()));
}

td::Status TcpConnection::receive(td::ChainBufferReader &input, bool &exit_loop) {
  if (stop_read_) {
    exit_loop = true;
    return td::Status::OK();
  }
  if (input.size() > 0) {
    received_bytes_ = 1;
  }
  if (!read_len_) {
    if (input.size() < 4) {
      exit_loop = true;
      return td::Status::OK();
    }

    td::MutableSlice s{reinterpret_cast<td::uint8 *>(&len_), 4};
    input.advance(4, s);

    LOG(DEBUG) << "tcp: len=" << len_;
    if (len_ > (1 << 24) || len_ < 4) {
      return td::Status::Error(ton::ErrorCode::protoviolation, PSTRING() << "Too big packet " << len_);
    }
    read_len_ = true;
  }
  if (input.size() < len_ + 4) {
    exit_loop = true;
    return td::Status::OK();
  }

  td::int32 in_seqno;
  td::MutableSlice s{reinterpret_cast<td::uint8 *>(&in_seqno), 4};
  input.advance(4, s);

  if (in_seqno != in_seqno_) {
    return td::Status::Error(ton::ErrorCode::protoviolation,
                             PSTRING() << "bad seqno: expected " << in_seqno_ << " got " << in_seqno);
  }

  auto data = input.cut_head(len_).move_as_buffer_slice();
  update_timer();

  exit_loop = false;
  read_len_ = false;
  in_seqno_++;
  len_ = 0;
  if (inited_) {
    return receive_packet(std::move(data));
  } else {
    return process_init_packet(std::move(data));
  }
}

void TcpConnection::loop() {
  auto status = [&] {
    td::ChainBufferReader *input_ptr;
    if (socket_pipe_) {
      TRY_STATUS(socket_pipe_.flush_read());
      input_ptr = &socket_pipe_.input_buffer();
    } else {
      TRY_STATUS(simple_pipe_.flush_read());
      input_ptr = &simple_pipe_.input_buffer();
    }
    auto &input = *input_ptr;
    bool exit_loop = false;
    if (!received_attestation_) {
      TRY_RESULT(attested_peer_info, cocoon::framed_tl_read<RATLSAttestedPeerInfo>(input));
      if (!attested_peer_info) {
        exit_loop = true;
      } else {
        process_attestation((*attested_peer_info).report());
      }
    }
    while (!exit_loop) {
      TRY_STATUS(receive(input, exit_loop));
    }
    if (socket_pipe_) {
      TRY_STATUS(socket_pipe_.flush_write());
    } else {
      TRY_STATUS(simple_pipe_.flush_write());
    }

    /*if (td::can_close(buffered_fd_)) {
      LOG(INFO) << "tcp: stopping (can close)";
      stop();
    }*/
    return td::Status::OK();
  }();
  if (status.is_error()) {
    fail(status.move_as_error_prefix("tcp: client got error: "));
  }
}

td::Status TcpConnection::receive_packet(td::BufferSlice data) {
  LOG(DEBUG) << "tcp: received packet of size " << data.size();
  if (data.size() == 0) {
    // keepalive
    return td::Status::OK();
  }

  return process_packet(std::move(data));
}

td::Status TcpConnection::process_init_packet(td::BufferSlice data) {
  if (is_client_) {
    TRY_RESULT(r, fetch_tl_object<cocoon_api::tcp_connected>(data, true));
    inited_ = true;
    send_ready();
    return td::Status::OK();
  } else {
    TRY_RESULT(r, fetch_tl_object<cocoon_api::tcp_connect>(data, true));

    auto new_data = create_serialize_tl_object<cocoon_api::tcp_connected>(r->id_);
    send_uninit(std::move(new_data));

    inited_ = true;
    send_ready();
    return td::Status::OK();
  }
}

td::Status TcpConnection::process_packet(td::BufferSlice data) {
  TRY_RESULT(r, fetch_tl_object<cocoon_api::tcp_Packet>(data, true));
  td::Status R;
  cocoon_api::downcast_call(
      *r,
      td::overloaded(
          [&](cocoon_api::tcp_ping &obj) { send(create_serialize_tl_object<cocoon_api::tcp_pong>(obj.id_)); },
          [&](cocoon_api::tcp_pong &obj) {},
          [&](cocoon_api::tcp_packet &obj) { callback_->on_packet(self_, std::move(obj.data_)); },
          [&](cocoon_api::tcp_query &obj) { callback_->on_query(self_, obj.id_, std::move(obj.data_)); },
          [&](cocoon_api::tcp_queryAnswer &obj) { callback_->on_query_answer(self_, obj.id_, std::move(obj.data_)); },
          [&](cocoon_api::tcp_queryError &obj) {
            LOG(DEBUG) << "tcp: received error: code=" << obj.code_ << " message=" << obj.message_;
            callback_->on_query_error(self_, obj.id_, td::Status::Error(obj.code_, obj.message_));
          },
          [&](cocoon_api::tcp_connect &obj) {}, [&](cocoon_api::tcp_connected &obj) {}));
  return R;
}

}  // namespace cocoon
