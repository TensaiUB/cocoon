#pragma once
#include "tee/cocoon/RATLS.h"
#include "tee/cocoon/Tee.h"
#include "td/actor/actor.h"
#include "td/utils/as.h"
#include "td/utils/buffer.h"
#include "td/utils/BufferedFd.h"
#include "td/utils/port/SocketFd.h"
#include "td/utils/port/IPAddress.h"
#include "td/utils/Status.h"
#include "td/utils/StringBuilder.h"
#include "td/utils/format.h"
#include "td/utils/logging.h"
#include "td/utils/tl_helpers.h"
#include "td/utils/optional.h"
#include "td/actor/coro_task.h"
#include "td/net/FramedPipe.h"
#include "td/net/Pipe.h"
#include "td/net/utils.h"
#include <string>

namespace td {
class SslStream;

// Helper operator<< for UInt types
template <size_t N>
td::StringBuilder &operator<<(td::StringBuilder &sb, const td::UInt<N> &value) {
  return sb << td::hex_encode(value.as_slice());
}

template <size_t N, class T>
td::StringBuilder &operator<<(td::StringBuilder &sb, const std::array<T, N> &value) {
  return sb << td::format::as_array(value);
}

}  // namespace td

namespace cocoon {

// Binary slice helpers - convert slice to typed value
template <class T, class TT = T>
td::Result<TT> to(td::Slice s) {
  if (s.size() != sizeof(T)) {
    return td::Status::Error(PSLICE() << "Size mismatch in to(): got " << s.size() << " bytes, expected " << sizeof(T));
  }
  T result = td::as<T>(s.ubegin());
  return result;
}

// Binary slice helpers - read and consume typed value from slice
template <class T, class TT = T>
td::Result<TT> cut(td::Slice &s) {
  if (s.size() < sizeof(T)) {
    return td::Status::Error(PSLICE() << "Insufficient data in cut(): got " << s.size() << " bytes, need at least "
                                      << sizeof(T));
  }
  T result = td::as<T>(s.ubegin());
  s.remove_prefix(sizeof(T));
  return result;
}

// Create a server-side SSL stream using provided cert/key and policy verification
td::Result<td::SslStream> create_server_ssl_stream(TeeCertAndKey cert_and_key, RATLSPolicyRef policy);

// Create a client-side SSL stream for the given host using provided cert/key and policy verification
td::Result<td::SslStream> create_client_ssl_stream(td::CSlice host, TeeCertAndKey cert_and_key, RATLSPolicyRef policy,
                                                   bool enable_sni = true);

// Re-export framed I/O functions from td namespace for backward compatibility
using td::framed_read;
using td::framed_write;

/**
 * @brief Write a TL-serialized object with framing
 * @tparam T Type with store() method for TL serialization
 * @param writer Buffer to write to
 * @param object Object to serialize and write
 * @return Status indicating success or error
 */
template <class T>
td::Status framed_tl_write(td::ChainBufferWriter &writer, const T &object) {
  auto serialized = td::serialize(object);
  return td::framed_write(writer, serialized);
}

/**
 * @brief Read a TL-serialized object with framing
 * @tparam T Type with parse() method for TL deserialization
 * @param reader Buffer to read from
 * @return Optional containing the deserialized object if successful, or error status
 *         Returns empty optional if more data is needed (non-error case)
 */
template <class T>
td::Result<td::optional<T>> framed_tl_read(td::ChainBufferReader &reader) {
  td::BufferSlice message;
  TRY_RESULT(needed, td::framed_read(reader, message));

  // If needed > 0, we need more data (not an error)
  if (needed > 0) {
    return td::optional<T>{};
  }

  // Deserialize the message
  T object;
  TRY_STATUS(td::unserialize(object, message.as_slice()));
  return td::optional<T>(std::move(object));
}

// Move all available data from reader to writer
template <class L, class R>
void proxy_sockets(L &reader, R &writer) {
  // NB: do not call output_buffer() if there is nothing to write
  if (reader.input_buffer().empty()) {
    return;
  }
  writer.output_buffer().append(reader.input_buffer());
}

td::actor::StartedTask<td::BufferedFd<td::SocketFd>> socks5(td::SocketFd socket_fd, td::IPAddress dest,
                                                            td::string username, td::string password);
td::actor::StartedTask<td::Unit> proxy(td::Slice name, td::Pipe left, td::Pipe right);

td::actor::Task<std::pair<td::Pipe, RATLSAttestedPeerInfo>> wrap_tls_client(td::Slice name, td::Pipe pipe,
                                                                            TeeCertAndKey cert_and_key,
                                                                            RATLSPolicyRef policy,
                                                                            const td::IPAddress &source,
                                                                            const td::IPAddress &destination);
td::actor::Task<std::pair<td::Pipe, RATLSAttestedPeerInfo>> wrap_tls_server(td::Slice name, td::Pipe pipe,
                                                                            TeeCertAndKey cert_and_key,
                                                                            RATLSPolicyRef policy,
                                                                            const td::IPAddress &source,
                                                                            const td::IPAddress &destination);

struct ProxyState;
td::StringBuilder &operator<<(td::StringBuilder &sb, const ProxyState &state);

struct ProxyState {
  std::string state_ = "Connecting";
  td::optional<td::IPAddress> source_;
  td::optional<td::IPAddress> destination_;
  std::string attestation_;       // short image hash or empty
  std::string attestation_type_;  // "TDX", "SGX", "None", or "fake TDX"
  bool finished_ = false;
  td::Status status;

  std::string short_desc() const {
    std::string desc;
    if (source_) {
      desc += PSTRING() << source_.value().get_ip_str() << ":" << source_.value().get_port();
    } else {
      desc += "?";
    }
    desc += " -> ";
    if (destination_) {
      desc += PSTRING() << destination_.value().get_ip_str() << ":" << destination_.value().get_port();
    } else {
      desc += "?";
    }
    if (!attestation_.empty()) {
      desc += " [" + attestation_ + " " + attestation_type_ + "]";
    }
    return desc;
  }

  void set_attestation(const RATLSAttestationReport &report) {
    auto hash = report.image_hash();
    attestation_ = td::hex_encode(hash.as_slice()).substr(0, 8) + "..";
    attestation_type_ = report.short_description().str();
  }

  td::Status init_source(const td::SocketFd &socket) {
    td::IPAddress source_addr;
    TRY_STATUS(source_addr.init_peer_address(socket));
    source_ = source_addr;
    return td::Status::OK();
  }

  void update_state(td::Slice new_state) {
    state_ = new_state.str();
    LOG(INFO) << *this;
  }

  void finish(td::Status st) {
    finished_ = true;
    status = std::move(st);
    if (status.is_error()) {
      LOG(ERROR) << *this;
    } else {
      LOG(INFO) << *this;
    }
  }
};

// Helper function to parse hex string to UInt256/UInt384
template <typename UIntType>
td::Result<UIntType> parse_hex_uint(td::Slice hex_str) {
  if (hex_str.size() != sizeof(UIntType) * 2) {
    return td::Status::Error(PSLICE() << "Invalid hex string length: expected " << (sizeof(UIntType) * 2)
                                      << " chars, got " << hex_str.size());
  }

  TRY_RESULT(bytes, td::hex_decode(hex_str));
  if (bytes.size() != sizeof(UIntType)) {
    return td::Status::Error("Invalid decoded hex size");
  }

  UIntType result;
  result.as_mutable_slice().copy_from(bytes);
  return result;
}

}  // namespace cocoon
