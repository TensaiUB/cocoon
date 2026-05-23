#pragma once

#include "Ed25519.h"
#include "auto/tl/cocoon_api.h"
#include "common/bigint.hpp"
#include "common/bitstring.h"
#include "runners/BaseRunner.hpp"
#include "td/actor/ActorId.h"
#include "td/utils/SharedSlice.h"
#include "tl/TlObject.h"
#include "ton/ton-types.h"
#include "vm/cells/CellBuilder.h"
#include <list>
#include <memory>

namespace cocoon {

struct PrivateKey {
  td::Bits256 private_key;
  td::Bits256 public_key;
  td::uint8 key_type_;
  td::int32 valid_since_config_version_;
  td::int32 valid_since_;
  td::int32 valid_until_;

  void serialize(vm::CellBuilder &cb) {
    cb.store_bytes(public_key.as_slice());
    cb.store_long(key_type_, 8);
    cb.store_long(valid_until_, 32);
  }
};

class KeyManagerRunner : public BaseRunner {
 public:
  KeyManagerRunner(std::string engine_config_filename, td::actor::Scheduler *scheduler)
      : BaseRunner(RunnerRole::KeyManager, std::move(engine_config_filename), scheduler) {
  }

  /* CONST PARAMS */

  static constexpr td::int32 key_ttl() {
    return 86400;
  }
  static constexpr td::int32 key_generate_period() {
    return 3600;
  }

  /* SIMPLE GETTERS */
  bool check_hashes() const {
    return check_hashes_;
  }
  const auto &owner_address() const {
    return owner_address_;
  }

  /* SIMPLE SETTERS */
  void enable_check_hashes() {
    check_hashes_ = true;
  }
  void set_owner_address(block::StdAddress owner_address) {
    owner_address_ = std::move(owner_address);
  }

  /* ALLOCATORS */
  std::unique_ptr<BaseInboundConnection> allocate_inbound_connection(TcpClient::ConnectionId connection_id,
                                                                     TcpClient::ListeningSocketId listening_socket_id,
                                                                     const RemoteAppType &remote_app_type,
                                                                     const td::Bits256 &remote_app_hash,
                                                                     const td::Bits256 &verified_by) override {
    LOG(ERROR) << "accepted inbound connection";
    if (!is_initialized()) {
      return nullptr;
    }
    return std::make_unique<BaseInboundConnection>(this, remote_app_type, remote_app_hash, verified_by, connection_id);
  }

  /* INITIALIZATION */
  void load_config(td::Promise<td::Unit> promise) override;
  void custom_initialize(td::Promise<td::Unit> promise) override;

  /* DB */
  void process_db_key(td::Slice key, td::Slice value);
  void config_to_db();
  td::UniqueSlice get_from_db(td::Slice key);
  void set_to_db(td::Slice key, td::Slice value);
  void del_from_db(td::Slice key) {
    kv_->erase(key).ensure();
  }
  void flush_db() {
    kv_->flush().ensure();
  }
  template <typename F>
  void db_transaction(F &&run) {
    kv_->begin_transaction();
    run();
    kv_->commit_transaction();
  }

  /* CRON */
  void alarm() override;

  /* INBOUND MESSAGE HANDLERS */
  void receive_message(TcpClient::ConnectionId connection_id, td::BufferSlice query) override;
  void receive_query(TcpClient::ConnectionId connection_id, td::BufferSlice query,
                     td::Promise<td::BufferSlice> promise) override;

  /* CONTROL */
  void remove_key(td::Bits256 public_key);
  PrivateKey *generate_key(td::uint8 key_type);
  void add_static_private_key();

  /* HTTP HANDLING */

  std::string wrap_short_answer_to_http(std::string text) {
    td::StringBuilder sb;
    sb << "<!DOCTYPE html>\n";
    sb << "<html><body>\n";
    sb << text << "<br/>\n";
    sb << "<a href=\"/stats\">return to stats</a>\n";
    sb << "</html></body>\n";
    return sb.as_cslice().str();
  };
  std::string http_generate_main();
  std::string http_generate_json_stats();
  std::string http_remove_key(std::string pub_key);
  std::string http_generate_key(std::string key_type);

 private:
  block::StdAddress owner_address_;

  std::list<std::unique_ptr<PrivateKey>> private_keys_;
  bool check_hashes_{false};

  std::string db_path_;
  std::shared_ptr<td::KeyValue> kv_;

  std::unique_ptr<td::Ed25519::PrivateKey> private_key_;
  td::Bits256 public_key_;
  std::unique_ptr<td::Ed25519::PublicKey> public_key_obj_;

  std::unique_ptr<td::Ed25519::PrivateKey> wallet_private_key_;
  td::Bits256 wallet_public_key_;

  td::Bits256 local_image_hash_unverified_;

  td::uint32 active_config_version_{0};
};

}  // namespace cocoon
