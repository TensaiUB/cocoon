#pragma once

#include "Ed25519.h"
#include "auto/tl/cocoon_api.h"
#include "auto/tl/tonlib_api.h"
#include "checksum.h"
#include "common/bitstring.h"
#include "td/actor/ActorId.h"
#include "td/actor/ActorOwn.h"
#include "td/actor/ActorStats.h"
#include "td/actor/PromiseFuture.h"
#include "td/actor/actor.h"
#include "td/actor/common.h"
#include "td/utils/SharedSlice.h"
#include "td/utils/Status.h"
#include "td/utils/StringBuilder.h"
#include "td/utils/Time.h"
#include "td/utils/UInt.h"
#include "td/utils/buffer.h"
#include "td/utils/common.h"
#include "td/utils/format.h"
#include "td/utils/port/Clocks.h"
#include "td/utils/port/IPAddress.h"
#include "tl/TlObject.h"
#include "ton/tonlib/tonlib/TonlibClient.h"
#include "net/TcpClient.h"
#include "boost-http/http.h"
#include "crypto/block/block.h"
#include "td/utils/as.h"
#include "vm/cells/Cell.h"
#include "runners/smartcontracts/RootContractConfig.hpp"
#include "runners/smartcontracts/SmartContract.hpp"
#include "runners/smartcontracts/CocoonWallet.hpp"
#include "cocoon-tl-utils/cocoon-tl-utils.hpp"
#include "TonlibWrapper.h"
#include "helpers/Ton.h"
#include "helpers/SimpleJsonSerializer.hpp"
#include "tee/cocoon/RATLS.h"
#include "tee/cocoon/sev/Tee.h"
#include "tee/cocoon/tdx/Tee.h"

#include <algorithm>
#include <csignal>
#include <functional>
#include <memory>
#include <queue>
#include <vector>

namespace cocoon {

class BaseRunner;

enum class BaseConnectionStatus { Connected, Ready, Closing };

enum class ProxyTargetStatus { Connecting, RunningInitialHandshake, Reconnecting, RunningReconnectHandshake, Ready };

enum class ClientCheckResult { Ok, Delete };

enum class RunnerRole { Worker, Proxy, Client, KeyManager, Unknown };

RemoteAppType remote_app_type_proxy();
RemoteAppType remote_app_type_worker();
RemoteAppType remote_app_type_key_manager();
RemoteAppType remote_app_type_unknown();

using HttpHandler = std::function<void(http::HttpCallback::RequestType request_type,
                                       std::vector<std::pair<std::string, std::string>> headers, std::string path,
                                       std::vector<std::pair<std::string, std::string>> args, std::string body,
                                       std::unique_ptr<http::HttpRequestCallback> answer_callback)>;

const std::string &get_from_sorted_list(const std::vector<std::pair<std::string, std::string>> &vec,
                                        const std::string &name);

class BaseConnection {
 public:
  auto connection_id() const {
    return connection_id_;
  }
  auto runner() {
    return runner_;
  }
  bool is_ready() const {
    return status_ == BaseConnectionStatus::Ready;
  }
  bool is_connected() const {
    return status_ == BaseConnectionStatus::Connected;
  }
  auto last_status_change_at() const {
    return last_status_change_at_;
  }
  bool is_running_handshake() const {
    return status_ == BaseConnectionStatus::Connected;
  }
  const auto &remote_app_type() const {
    return remote_app_type_;
  }
  const auto &remote_app_hash() const {
    return remote_app_hash_;
  }
  const auto &verified_by() const {
    return verified_by_;
  }

  BaseConnection(BaseRunner *runner, bool is_outbound, const RemoteAppType &remote_app_type,
                 const td::Bits256 &remote_app_hash, const td::Bits256 &verified_by,
                 TcpClient::ConnectionId connection_id)
      : runner_(runner)
      , is_outbound_(is_outbound)
      , remote_app_type_(remote_app_type)
      , remote_app_hash_(remote_app_hash)
      , verified_by_(verified_by)
      , connection_id_(connection_id)
      , status_(BaseConnectionStatus::Connected) {
    last_status_change_at_ = td::Timestamp::now();
  }
  virtual ~BaseConnection() {
    close_connection();
  }
  virtual void start_up() {
  }
  virtual void post_ready() {
  }
  virtual void pre_close() {
  }

  void handshake_completed() {
    if (status_ == BaseConnectionStatus::Connected) {
      status_ = BaseConnectionStatus::Ready;
      last_status_change_at_ = td::Timestamp::now();
      post_ready();
    }
  }

  bool handshake_is_completed() const {
    return status_ == BaseConnectionStatus::Ready;
  }

  void close_connection();
  void fail_connection(td::Status error) {
    LOG(INFO) << "failing connection " << connection_id_ << ": " << error;
    close_connection();
  }

  void sent_query() {
    queries_sent_++;
  }

  void sent_message() {
    messages_sent_++;
  }

  void received_answer() {
    queries_answers_received_++;
  }

 private:
  BaseRunner *runner_;
  bool is_outbound_;
  RemoteAppType remote_app_type_;
  td::Bits256 remote_app_hash_;
  td::Bits256 verified_by_;
  TcpClient::ConnectionId connection_id_;
  BaseConnectionStatus status_;
  td::int64 queries_sent_{0};
  td::int64 messages_sent_{0};
  td::int64 queries_answers_received_{0};
  td::Timestamp last_status_change_at_;
};

class BaseInboundConnection : public BaseConnection {
 public:
  BaseInboundConnection(BaseRunner *runner, const RemoteAppType &remote_app_type, const td::Bits256 &remote_app_hash,
                        const td::Bits256 &verified_by, TcpClient::ConnectionId connection_id)
      : BaseConnection(runner, false, remote_app_type, remote_app_hash, verified_by, connection_id) {
  }
};

class BaseOutboundConnection : public BaseConnection {
 public:
  BaseOutboundConnection(BaseRunner *runner, const RemoteAppType &remote_app_type, const td::Bits256 &remote_app_hash,
                         const td::Bits256 &verified_by, TcpClient::ConnectionId connection_id)
      : BaseConnection(runner, true, remote_app_type, remote_app_hash, verified_by, connection_id) {
  }

  void start_up() override {
    send_handshake();
  }
  virtual void send_handshake() {
    handshake_completed();
  }
};

class ProxyOutboundConnection : public BaseOutboundConnection {
 public:
  ProxyOutboundConnection(BaseRunner *runner, const RemoteAppType &remote_app_type, const td::Bits256 &remote_app_hash,
                          const td::Bits256 &verified_by, TcpClient::ConnectionId connection_id,
                          TcpClient::TargetId target_id)
      : BaseOutboundConnection(runner, remote_app_type, remote_app_hash, verified_by, connection_id)
      , target_id_(target_id) {
  }

  void send_handshake() override {
    handshake_completed();
  }
  auto proxy_target_id() const {
    return target_id_;
  }
  void post_ready() override;

 private:
  TcpClient::TargetId target_id_;
};

class ProxyTarget {
 public:
  ProxyTarget(BaseRunner *runner, td::IPAddress remote_address, size_t idx)
      : runner_(runner), remote_address_(std::move(remote_address)), idx_(idx) {
    last_status_change_at_ = td::Timestamp::now();
    last_ready_at_ = td::Timestamp::now();
  }

  auto proxy_target_idx() const {
    return idx_;
  }
  bool is_ready() const {
    return status_ == ProxyTargetStatus::Ready;
  }
  bool was_in_use() const {
    return status_ == ProxyTargetStatus::Reconnecting || status_ == ProxyTargetStatus::RunningReconnectHandshake ||
           status_ == ProxyTargetStatus::Ready;
  }
  td::Timestamp disconnected_since() const {
    if (status_ == ProxyTargetStatus::Ready) {
      return td::Timestamp::now();
    } else {
      return last_ready_at_;
    }
  }
  auto connection_id() const {
    return connection_id_;
  }
  const auto &address() const {
    return remote_address_;
  }
  auto runner() {
    return runner_;
  }

  void connected(TcpClient::ConnectionId connection_id);
  void connection_is_ready(TcpClient::ConnectionId connection_id);
  void disconnected(TcpClient::ConnectionId connection_id);
  void close_connection();
  bool should_choose_another_proxy();

  void sent_query() {
    queries_sent_++;
  }
  void sent_message() {
    messages_sent_++;
  }
  void received_answer() {
    queries_answers_received_++;
  }

 private:
  BaseRunner *runner_;
  td::IPAddress remote_address_;
  size_t idx_;
  TcpClient::ConnectionId connection_id_{0};
  ProxyTargetStatus status_{ProxyTargetStatus::Connecting};
  td::int64 queries_sent_{0};
  td::int64 messages_sent_{0};
  td::int64 queries_answers_received_{0};
  td::Timestamp last_status_change_at_;
  td::Timestamp last_ready_at_;
};

class KeyManagerOutboundConnection : public BaseOutboundConnection {
 public:
  KeyManagerOutboundConnection(BaseRunner *runner, const RemoteAppType &remote_app_type,
                               const td::Bits256 &remote_app_hash, const td::Bits256 &verified_by,
                               TcpClient::ConnectionId connection_id, RunnerRole role)
      : BaseOutboundConnection(runner, remote_app_type, remote_app_hash, verified_by, connection_id)
      , role_(std::move(role)) {
  }

 private:
  RunnerRole role_;
};

class DelayedAction {
 public:
  virtual ~DelayedAction() = default;
  DelayedAction(td::Timestamp at) : at_(at) {
  }

  bool operator<(const DelayedAction &other) const {
    return at_ < other.at_;
  }

  virtual void run() = 0;

  bool is_in_past() const {
    return at_.is_in_past();
  }

  auto at() const {
    return at_;
  }

 private:
  const td::Timestamp at_;
};

template <typename F>
class DelayedActionRunnable : public DelayedAction {
 public:
  DelayedActionRunnable(td::Timestamp at, F &&run) : DelayedAction(at), run_(std::move(run)) {
  }

  void run() override {
    run_();
  }

 private:
  F run_;
};

struct RunnerConfig {
  std::shared_ptr<RootContractConfig> root_contract_config;
  td::int32 root_contract_ts;
  bool is_testnet;
  bool ton_disabled;
};

inline bool rdeserialize(block::StdAddress &addr, td::Slice s, bool is_tesnet) {
  if (!addr.rdeserialize(s)) {
    return false;
  }

  addr.testnet = is_tesnet;
  addr.bounceable = false;

  return true;
}

struct BaseRunnerPrivateKey {
  td::Bits256 private_key;
  td::Bits256 public_key;
  td::int32 expire_at;
};

class BaseRunner : public td::actor::Actor {
 private:
  template <typename T>
  auto create_tonlib_promise(td::Promise<ton::tl_object_ptr<T>> P) {
    return td::PromiseCreator::lambda([self_id = actor_id(this), P = std::move(P)](
                                          td::Result<ton::tl_object_ptr<ton::tonlib_api::Object>> R) mutable {
      td::actor::send_lambda(self_id, [R = std::move(R), P = std::move(P)]() mutable {
        if (R.is_error()) {
          P.set_error(R.move_as_error());
        } else {
          auto res = R.move_as_ok();
          if (res->get_id() == ton::tonlib_api::error::ID) {
            auto err = ton::move_tl_object_as<ton::tonlib_api::error>(std::move(res));
            P.set_error(td::Status::Error(err->code_, err->message_));
          } else {
            P.set_value(ton::move_tl_object_as<T>(std::move(res)));
          }
        }
      });
    });
  }

 public:
  static constexpr td::int64 min_wallet_balance() {
    return to_nano(2.1);
  }
  static constexpr td::int64 warning_wallet_balance() {
    return to_nano(5.0);
  }
  static td::int32 get_tl_magic(td::Slice buf) {
    if (buf.size() < 4) {
      return 0;
    }
    return td::as<td::int32>(buf.begin());
  }
  static td::int32 get_tl_magic(const td::BufferSlice &buf) {
    return get_tl_magic(buf.as_slice());
  }

  /* Getters */
  const std::string &engine_config_filename() const {
    return engine_config_filename_;
  }
  const auto &runner_config() const {
    return runner_config_;
  }
  bool is_initialized() const {
    return is_initialized_;
  }
  bool tonlib_is_synced() const {
    return tonlib_synced_;
  }
  bool is_testnet() const {
    return is_testnet_;
  }
  std::string address_link(const block::StdAddress &address) const {
    return cocoon::address_link(address.rserialize(true), is_testnet_);
  }
  const auto &root_contract_address() const {
    return root_contract_address_;
  }
  auto actual_price_per_token() const {
    return runner_config_->root_contract_config->price_per_token();
  }
  auto cocoon_wallet() const {
    return cocoon_wallet_;
  }
  const auto &cocoon_wallet_address() const {
    return cocoon_wallet_->address();
  }
  auto ton_disabled() const {
    return ton_disabled_;
  }
  bool is_test() const {
    return is_test_;
  }
  td::actor::ActorId<TcpClient> tcp_client() const {
    return client_.get();
  }
  td::int32 proxy_targets_number() const {
    return static_cast<td::int32>(proxy_targets_number_);
  }
  bool rdeserialize(block::StdAddress &addr, td::Slice s) const {
    return cocoon::rdeserialize(addr, s, is_testnet());
  }
  bool check_image_hashes() const {
    return check_image_hashes_;
  }
  bool check_image_is_verified() const {
    return false;
  }
  auto scheduler() const {
    return scheduler_;
  }
  td::Status check_verification_key(const RemoteAppType &app_type, const td::Bits256 &verified_by);

  /* Setters */
  void set_fake_tee(bool value) {
    fake_tee_ = value;
  }
  void set_http_port(td::uint16 port) {
    http_port_ = port;
  }
  void set_rpc_port(td::uint16 port, RemoteAppType remote_app_type) {
    rpc_ports_.emplace_back(port, remote_app_type);
  }
  void set_number_of_proxy_connections(size_t cnt, bool is_client) {
    proxy_targets_number_ = cnt;
    connect_to_proxy_to_client_address_ = is_client;
  }
  void set_root_contract_address(const block::StdAddress &addr) {
    root_contract_address_ = addr;
  }
  void disable_ton(std::string conf) {
    ton_disabled_ = true;
    ton_pseudo_config_ = conf;
  }
  void set_ton_config_filename(std::string new_name) {
    ton_config_filename_ = new_name;
  }
  void set_root_contract_config(std::shared_ptr<RootContractConfig> config, int ts);
  void set_root_contract_config(std::unique_ptr<RootContractConfig> config, int ts) {
    set_root_contract_config(std::shared_ptr<RootContractConfig>(std::move(config)), ts);
  }
  void set_testnet(bool value) {
    is_testnet_ = value;
  }
  void set_http_access_hash(std::string access_hash) {
    http_access_hash_ = std::move(access_hash);
  }
  td::Status connection_to_proxy_via(td::Slice addr);
  void set_tonlib_synced() {
    tonlib_synced_ = true;
  }
  void set_is_test(bool value) {
    is_test_ = value;
  }
  void set_check_image_hashes(bool value) {
    check_image_hashes_ = value;
  }

  /* main */
  BaseRunner(RunnerRole role, std::string engine_config_filename, td::actor::Scheduler *scheduler)
      : role_(std::move(role)), engine_config_filename_(std::move(engine_config_filename)), scheduler_(scheduler) {
  }

  /* initialize */
  void start_up() override;
  void initialize();
  virtual void load_config(td::Promise<td::Unit> promise);
  void load_config_completed();
  virtual void custom_initialize(td::Promise<td::Unit> promise) {
    promise.set_value(td::Unit());
  }
  void custom_initialize_completed();
  void initialize_http_server(td::Promise<td::Unit> promise);
  void http_server_initialized();
  void initialize_rpc_server(td::Promise<td::Unit> promise);
  void rpc_server_initialized();
  td::actor::Task<td::Unit> try_run_initialization_task(td::Slice name, td::actor::Task<td::Unit> task);
  td::actor::Task<td::Unit> initialize_tonlib();
  td::actor::Task<td::Unit> coro_init();
  td::actor::Task<td::Unit> get_root_contract_initial_state();
  void coro_init_done();
  void initialization_failure(td::Status error);
  void initialization_completed();

  /* tonlib */
  void tonlib_do_send_request(ton::tl_object_ptr<ton::tonlib_api::Function> func,
                              td::Promise<ton::tl_object_ptr<ton::tonlib_api::Object>> cb);
  void send_external_message(const block::StdAddress &to, td::Ref<vm::Cell> code, td::Ref<vm::Cell> data,
                             td::Promise<td::Unit> promise);
  td::actor::Task<td::Unit> send_external_message_coro(const block::StdAddress &to, td::Ref<vm::Cell> code,
                                                       td::Ref<vm::Cell> data);
  template <class T>
  inline void tonlib_send_request(ton::tl_object_ptr<T> func, td::Promise<typename T::ReturnType> P) {
    using RetType = typename T::ReturnType;
    using RetTlType = typename RetType::element_type;
    auto Q = create_tonlib_promise<RetTlType>(std::move(P));
    tonlib_do_send_request(ton::move_tl_object_as<ton::tonlib_api::Function>(std::move(func)), std::move(Q));
  }

  /* proxy target */
  virtual std::unique_ptr<ProxyTarget> allocate_proxy_target(TcpClient::TargetId target_id, const td::IPAddress &addr) {
    return nullptr;
  }
  void connect_proxy();
  void disconnect_proxy(TcpClient::TargetId idx);
  void disconnect_proxy(const td::IPAddress &addr) {
    auto idx = get_proxy_target_by_address(addr);
    if (idx != 0) {
      disconnect_proxy(idx);
    }
  }
  void cond_reconnect_to_proxy();
  TcpClient::TargetId get_proxy_target_by_address(const td::IPAddress &addr) const {
    for (auto &x : proxy_targets_) {
      if (x.second->address() == addr) {
        return x.first;
      }
    }
    return 0;
  }
  ProxyTarget *get_proxy_target(TcpClient::TargetId target_id) {
    auto it = proxy_targets_.find(target_id);
    if (it != proxy_targets_.end()) {
      return it->second.get();
    } else {
      return nullptr;
    }
  }
  ProxyTarget *get_ready_proxy_target() {
    for (auto &x : proxy_targets_) {
      if (x.second->is_ready()) {
        return x.second.get();
      }
    }
    return nullptr;
  }
  void proxy_connection_is_ready(TcpClient::ConnectionId connection_id, TcpClient::TargetId target_id) {
    auto P = get_proxy_target(target_id);
    if (P) {
      P->connection_is_ready(connection_id);
    }
  }
  template <typename F>
  void foreach_proxy_target(F &&run) {
    for (auto &p : proxy_targets_) {
      run(p.second.get());
    }
  }

  /* connections */
  virtual std::unique_ptr<ProxyOutboundConnection> allocate_proxy_outbound_connection(
      TcpClient::ConnectionId connection_id, TcpClient::TargetId target_id, const RemoteAppType &remote_app_type,
      const td::Bits256 &remote_app_hash, const td::Bits256 &verified_by) {
    return nullptr;
  }
  virtual std::unique_ptr<BaseOutboundConnection> allocate_nonproxy_outbound_connection(
      TcpClient::ConnectionId connection_id, TcpClient::TargetId target_id, const RemoteAppType &remote_app_type,
      const td::Bits256 &remote_app_hash, const td::Bits256 &verified_by) {
    return nullptr;
  }
  virtual std::unique_ptr<BaseInboundConnection> allocate_inbound_connection(
      TcpClient::ConnectionId connection_id, TcpClient::ListeningSocketId listening_socket_id,
      const RemoteAppType &remote_app_type, const td::Bits256 &remote_app_hash, const td::Bits256 &verified_by) {
    return nullptr;
  }
  //void connect_to_proxy(td::IPAddress address, td::Bits256 hash);
  void inbound_connection_ready(TcpClient::ConnectionId connection_id, TcpClient::ListeningSocketId listening_socket_id,
                                const RemoteAppType &remote_app_type, const td::Bits256 &remote_app_hash,
                                const td::Bits256 &verified_by);
  void outbound_connection_ready(TcpClient::ConnectionId connection_id, TcpClient::TargetId target_id,
                                 const RemoteAppType &remote_app_type, const td::Bits256 &remote_app_hash,
                                 const td::Bits256 &verified_by);
  void conn_stop_ready(TcpClient::ConnectionId connection_id);
  std::unique_ptr<TcpClient::Callback> make_tcp_client_callback();
  BaseConnection *get_connection(TcpClient::ConnectionId connection_id) {
    auto it = all_connections_.find(connection_id);
    if (it == all_connections_.end()) {
      return nullptr;
    }
    return it->second.get();
  }
  bool connection_is_active(TcpClient::ConnectionId connection_id) const {
    return all_connections_.count(connection_id) > 0;
  }
  void close_connection(TcpClient::ConnectionId connection_id) {
    if (connection_id > 0) {
      td::actor::send_closure(client_, &TcpClient::fail_connection, connection_id);
      auto it = all_connections_.find(connection_id);
      if (it != all_connections_.end()) {
        it->second->close_connection();
        all_connections_.erase(it);
      }
    }
  }
  void fail_connection(TcpClient::ConnectionId connection_id, td::Status error) {
    LOG(INFO) << "failing connection " << connection_id << ": " << error;
    close_connection(connection_id);
  }
  void close_all_connections() {
    for (auto &c : all_connections_) {
      td::actor::send_closure(client_, &TcpClient::fail_connection, c.first);
      c.second->close_connection();
    }
    all_connections_.clear();
  }

  /* cron */
  void alarm() override;
  td::actor::Task<td::Unit> update_root_contract_state();
  template <typename F>
  void delay_action(td::Timestamp at, F &&run) {
    if (at) {
      delayed_action_queue_.emplace(std::make_unique<DelayedActionRunnable<F>>(at, std::move(run)));
    }
  }
  void gc_cocoon_pk() {
    auto it = cocoon_pk_map_.begin();
    while (it != cocoon_pk_map_.end()) {
      if (it->second->expire_at < td::Clocks::system()) {
        it = cocoon_pk_map_.erase(it);
      } else {
        it++;
      }
    }
  }
  void get_private_keys_from_key_manager();
  void got_private_keys_from_key_manager(td::BufferSlice R);
  bool get_private_key(const td::Bits256 &pub, td::Bits256 &to) {
    auto it = cocoon_pk_map_.find(pub);
    if (it != cocoon_pk_map_.end()) {
      to = it->second->private_key;
      return true;
    } else {
      return false;
    }
  }

  /* handlers*/
  virtual void receive_message(TcpClient::ConnectionId connection_id, td::BufferSlice query) {
  }
  virtual void receive_query(TcpClient::ConnectionId connection_id, td::BufferSlice query,
                             td::Promise<td::BufferSlice> promise) {
  }
  void receive_http_request_outer(http::HttpCallback::RequestType request_type,
                                  std::vector<std::pair<std::string, std::string>> headers, std::string path,
                                  std::vector<std::pair<std::string, std::string>> args, std::string body,
                                  std::unique_ptr<http::HttpRequestCallback> answer_callback);
  virtual void receive_http_request(http::HttpCallback::RequestType request_type,
                                    std::vector<std::pair<std::string, std::string>> headers, std::string path,
                                    std::vector<std::pair<std::string, std::string>> args, std::string body,
                                    std::unique_ptr<http::HttpRequestCallback> answer_callback);

  /* http */
  static void http_send_static_answer(td::int32 code, std::string text,
                                      std::unique_ptr<http::HttpRequestCallback> answer_callback,
                                      std::string content_type = "text/html; charset=utf-8");
  static void http_send_static_answer(td::Result<td::BufferSlice> R,
                                      std::unique_ptr<http::HttpRequestCallback> answer_callback,
                                      std::string content_type = "text/html; charset=utf-8");
  td::actor::Task<td::Unit> generate_perf_stats(std::unique_ptr<http::HttpRequestCallback> answer_callback);
  void register_custom_http_handler(std::string url, HttpHandler handler) {
    CHECK(custom_http_handlers_.emplace(url, handler).second);
  }

  /* queries and messages */
  void send_query_to_proxy(std::string name, td::BufferSlice data, td::Timestamp timeout,
                           td::Promise<td::BufferSlice> promise);
  void send_query_to_connection(TcpClient::ConnectionId connection_id, std::string name, td::BufferSlice data,
                                td::Timestamp timeout, td::Promise<td::BufferSlice> promise);
  void send_handshake_query_to_connection(TcpClient::ConnectionId connection_id, std::string name, td::BufferSlice data,
                                          td::Timestamp timeout, td::Promise<td::BufferSlice> promise);
  void send_message_to_connection(TcpClient::ConnectionId connection_id, td::BufferSlice data);
  void receive_answer_from_connection(TcpClient::ConnectionId connection_id, td::Result<td::BufferSlice> result,
                                      td::Promise<td::BufferSlice> promise);

  /* SC */
  block::StdAddress generate_client_sc_address(td::Bits256 proxy_public_key,
                                               const block::StdAddress &proxy_owner_address,
                                               const block::StdAddress &proxy_sc_address,
                                               const block::StdAddress &client_owner_address,
                                               std::shared_ptr<RunnerConfig> config);
  block::StdAddress generate_worker_sc_address(td::Bits256 proxy_public_key,
                                               const block::StdAddress &proxy_owner_address,
                                               const block::StdAddress &proxy_sc_address,
                                               const block::StdAddress &worker_owner_address,
                                               std::shared_ptr<RunnerConfig> config);
  block::StdAddress generate_proxy_sc_address(td::Bits256 proxy_public_key,
                                              const block::StdAddress &proxy_owner_address,
                                              std::shared_ptr<RunnerConfig> config);
  static td::Ref<vm::Cell> generate_sc_init_data(td::Ref<vm::Cell> code, td::Ref<vm::Cell> data);
  static block::StdAddress generate_sc_address(td::Ref<vm::Cell> code, td::Ref<vm::Cell> data, bool is_test,
                                               bool is_bouncable);
  static block::StdAddress generate_sc_address(td::Ref<vm::Cell> init_data, bool is_test, bool is_bouncable);

  /* sc messages */
  static td::Ref<vm::Cell> sign_message(td::Ed25519::PrivateKey &pk, td::Ref<vm::Cell> msg);
  static td::Ref<vm::Cell> sign_and_wrap_message(td::Ed25519::PrivateKey &pk, td::Ref<vm::Cell> msg,
                                                 const block::StdAddress &return_excesses_to);

  /* sc monitor */
  void add_smartcontract(std::shared_ptr<TonScWrapper> sc);
  void del_smartcontract(TonScWrapper *sc);
  bool sc_is_alive(td::int64 id);
  void run_monitor_accounts();
  void monitored_accounts_update_completed();

  /* cocoon wallet */
  void cocoon_wallet_initialize_wait_for_balance_and_get_seqno(td::SecureString wallet_private_key,
                                                               block::StdAddress wallet_owner, td::uint64 min_balance,
                                                               td::Promise<td::Unit> promise);
  void cocoon_wallet_check_balance(td::Promise<td::Unit> promise);

  /* stat */
  void store_wallet_stat(td::StringBuilder &sb);
  void store_wallet_stat(SimpleJsonSerializer &jb);
  void store_root_contract_stat(td::StringBuilder &sb);
  void store_root_contract_stat(SimpleJsonSerializer &jb);
  void store_known_private_keys(td::StringBuilder &sb);

  void iterate_check_map(auto &map) {
    auto it = map.begin();
    while (it != map.end()) {
      auto r = it->second->check();
      if (r == ClientCheckResult::Ok) {
        it++;
      } else {
        it = map.erase(it);
      }
    }
  }

  void iterate_check_map(auto *ptr, auto &map) {
    auto it = map.begin();
    while (it != map.end()) {
      auto r = it->second->check(ptr);
      if (r == ClientCheckResult::Ok) {
        it++;
      } else {
        it = map.erase(it);
      }
    }
  }

 private:
  const RunnerRole role_;
  bool check_image_hashes_{true};

  std::shared_ptr<RunnerConfig> runner_config_;
  td::int32 root_contract_ts_{0};
  td::actor::ActorOwn<TcpClient> client_;

  std::map<TcpClient::ConnectionId, std::unique_ptr<BaseConnection>> all_connections_;
  std::map<TcpClient::TargetId, std::unique_ptr<ProxyTarget>> proxy_targets_;

  td::Timestamp try_reconnect_before_;

  td::Timestamp next_test_request_at_;
  td::uint16 http_port_{0};
  std::vector<std::pair<td::uint16, RemoteAppType>> rpc_ports_{};

  bool is_initialized_{false};
  std::string engine_config_filename_ = "config.json";
  std::string ton_config_filename_ = "testnet-global.config.json";

  block::StdAddress root_contract_address_;

  TonlibWrapper tonlib_wrapper_;
  bool tonlib_synced_{false};
  bool connect_to_proxy_to_client_address_{false};
  bool root_contract_state_updating_{false};
  td::Timestamp next_root_contract_state_update_at_;
  size_t proxy_targets_number_{0};
  td::actor::ActorOwn<td::actor::ActorStats> actor_stats_;

  class Compare {
   public:
    bool operator()(const std::unique_ptr<DelayedAction> &l, const std::unique_ptr<DelayedAction> &r) const {
      return *r < *l;
    }
  };

  std::priority_queue<std::unique_ptr<DelayedAction>, std::vector<std::unique_ptr<DelayedAction>>, Compare>
      delayed_action_queue_;

  bool monitored_accounts_update_running_{false};
  td::Timestamp next_monitor_at_;
  std::vector<std::shared_ptr<TonScWrapper>> monitored_accounts_;
  std::shared_ptr<CocoonWallet> cocoon_wallet_;
  td::IPAddress connection_to_proxy_via_;
  bool is_test_{false};
  bool is_testnet_{true};
  bool ton_disabled_{false};
  bool fake_tee_{false};
  tdx::TeeConfig tdx_tee_config_{};
  sev::TeeConfig sev_tee_config_{};
  RATLSInterface::Config ratls_config_{};
  std::string ton_pseudo_config_;
  std::string http_access_hash_;

  td::Timestamp next_key_manager_request_at_;
  td::IPAddress key_manager_addr_;
  TcpClient::ListeningSocketId key_manager_socket_id_{0};
  TcpClient::ConnectionId key_manager_connection_id_{0};
  std::map<td::Bits256, std::shared_ptr<BaseRunnerPrivateKey>> cocoon_pk_map_;
  std::unique_ptr<KeyManagerOutboundConnection> key_manager_connection_;

  std::map<std::string, HttpHandler> custom_http_handlers_;

  td::actor::Scheduler *scheduler_;
};

}  // namespace cocoon
