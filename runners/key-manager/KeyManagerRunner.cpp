#include "KeyManagerRunner.hpp"

#include "Ed25519.h"
#include "common/bitstring.h"
#include "errorcode.h"
#include "td/actor/actor.h"
#include "td/utils/Random.h"
#include "td/utils/SharedSlice.h"
#include "td/utils/base64.h"
#include "td/utils/common.h"
#include "td/utils/filesystem.h"
#include "td/db/RocksDb.h"
#include "td/utils/misc.h"
#include "td/utils/overloaded.h"
#include "runners/smartcontracts/Opcodes.hpp"

#include "cocoon-tl-utils/cocoon-tl-utils.hpp"
#include "git.h"

#include "auto/tl/cocoon_api_json.h"
#include "auto/tl/cocoon_api.h"
#include "auto/tl/cocoon_api.hpp"
#include "td/utils/port/Clocks.h"
#include "tl/TlObject.h"
#include "vm/cells/CellBuilder.h"
#include <memory>

namespace cocoon {

void KeyManagerRunner::load_config(td::Promise<td::Unit> promise) {
  auto S = [&]() -> td::Status {
    TRY_RESULT_PREFIX(conf_data, td::read_file(engine_config_filename()), "failed to read: ");
    TRY_RESULT_PREFIX(conf_json, td::json_decode(conf_data.as_slice()), "failed to parse json: ");

    cocoon::cocoon_api::keyStorageRunner_config conf;
    TRY_STATUS_PREFIX(cocoon::cocoon_api::from_json(conf, conf_json.get_object()), "json does not fit TL scheme: ");
    set_testnet(conf.is_testnet_);
    if (conf.http_port_) {
      set_http_port((td::uint16)conf.http_port_);
    }
    set_rpc_port((td::uint16)conf.rpc_port_, remote_app_type_unknown());

    TRY_RESULT_PREFIX(owner_address, block::StdAddress::parse(conf.owner_address_), "failed to parse owner address: ");
    owner_address.testnet = is_testnet();
    owner_address.bounceable = false;
    set_owner_address(owner_address);

    TRY_RESULT_PREFIX(rc_address, block::StdAddress::parse(conf.root_contract_address_),
                      "cannot parse root contract address: ");
    rc_address.testnet = is_testnet();
    set_root_contract_address(rc_address);

    if (conf.ton_config_filename_.size() > 0) {
      set_ton_config_filename(conf.ton_config_filename_);
    }

    wallet_private_key_ = std::make_unique<td::Ed25519::PrivateKey>(td::SecureString(conf.node_wallet_key_.as_slice()));
    wallet_public_key_.as_slice().copy_from(wallet_private_key_->get_public_key().move_as_ok().as_octet_string());

    private_key_ =
        std::make_unique<td::Ed25519::PrivateKey>(td::SecureString(conf.machine_specific_private_key_.as_slice()));
    public_key_.as_slice().copy_from(private_key_->get_public_key().move_as_ok().as_octet_string());

    public_key_obj_ = std::make_unique<td::Ed25519::PublicKey>(
        td::Ed25519::PublicKey::from_slice(public_key_.as_slice()).move_as_ok());

    if (conf.check_hashes_ || !conf.is_test_) {
      set_fake_tee(false);
      enable_check_hashes();
    } else {
      set_fake_tee(true);
      add_static_private_key();
    }
    set_http_access_hash(conf.http_access_hash_);
    set_is_test(conf.is_test_);

    db_path_ = conf.db_path_;
    if (!is_test()) {
      CHECK(!is_testnet());
    }

    return td::Status::OK();
  }();
  if (S.is_error()) {
    promise.set_error(std::move(S));
  } else {
    promise.set_value(td::Unit());
  }
}

void KeyManagerRunner::custom_initialize(td::Promise<td::Unit> promise) {
  kv_ = std::make_shared<td::RocksDb>(td::RocksDb::open(db_path_).move_as_ok());

  {
    td::UniqueSlice value = get_from_db("config");

    if (value.size() > 0) {
      auto obj = cocoon::fetch_tl_object<cocoon_api::keyManagerDb_Config>(value.as_slice(), true).move_as_ok();

      cocoon_api::downcast_call(*obj, td::overloaded([&](cocoon_api::keyManagerDb_configEmpty &c) { UNREACHABLE(); },
                                                     [&](cocoon_api::keyManagerDb_configV1 &c) {
                                                       CHECK(runner_config()->root_contract_config->version() >=
                                                             (td::uint32)c.root_contract_version_);
                                                       active_config_version_ = c.root_contract_version_;
                                                     }));
    } else {
      active_config_version_ = 0;
    }
  }

  auto snap = kv_->snapshot();
  snap->for_each([&](td::Slice key, td::Slice value) -> td::Status {
    process_db_key(key, value);
    return td::Status::OK();
  });

  register_custom_http_handler("/stats", [&](http::HttpCallback::RequestType request_type,
                                             std::vector<std::pair<std::string, std::string>> headers, std::string path,
                                             std::vector<std::pair<std::string, std::string>> args, std::string body,
                                             std::unique_ptr<http::HttpRequestCallback> answer_callback) {
    http_send_static_answer(http_generate_main(), std::move(answer_callback));
  });
  register_custom_http_handler(
      "/jsonstats",
      [&](http::HttpCallback::RequestType request_type, std::vector<std::pair<std::string, std::string>> headers,
          std::string path, std::vector<std::pair<std::string, std::string>> args, std::string body,
          std::unique_ptr<http::HttpRequestCallback> answer_callback) {
        http_send_static_answer(http_generate_json_stats(), std::move(answer_callback), "application/json");
      });
  register_custom_http_handler(
      "/request/removekey",
      [&](http::HttpCallback::RequestType request_type, std::vector<std::pair<std::string, std::string>> headers,
          std::string path, std::vector<std::pair<std::string, std::string>> args, std::string body,
          std::unique_ptr<http::HttpRequestCallback> answer_callback) {
        if (request_type == http::HttpCallback::RequestType::Post) {
          http_send_static_answer(http_remove_key(get_from_sorted_list(args, "key")), std::move(answer_callback));
        } else {
          http_send_static_answer(404, "not found", std::move(answer_callback));
        }
      });
  register_custom_http_handler(
      "/request/generatekey",
      [&](http::HttpCallback::RequestType request_type, std::vector<std::pair<std::string, std::string>> headers,
          std::string path, std::vector<std::pair<std::string, std::string>> args, std::string body,
          std::unique_ptr<http::HttpRequestCallback> answer_callback) {
        if (request_type == http::HttpCallback::RequestType::Post) {
          http_send_static_answer(http_generate_key(get_from_sorted_list(args, "type")), std::move(answer_callback));
        } else {
          http_send_static_answer(404, "not found", std::move(answer_callback));
        }
      });

  cocoon_wallet_initialize_wait_for_balance_and_get_seqno(
      wallet_private_key_->as_octet_string(), owner_address_, min_wallet_balance(),
      [self_id = actor_id(this), promise = std::move(promise)](td::Result<td::Unit> R) mutable {
        if (R.is_error()) {
          promise.set_error(R.move_as_error());
          return;
        }
        promise.set_value(td::Unit());
      });
}

void KeyManagerRunner::process_db_key(td::Slice key, td::Slice value) {
  auto key_parts = td::split(key, '_');
  auto key_type = key_parts.first;
  key = key_parts.second;

  CHECK(value.size() >= 64);
  auto signature = value.copy().remove_prefix(value.size() - 64);
  value.remove_suffix(64);

  public_key_obj_->verify_signature(value, signature).ensure();

  if (key_type == "key") {
    auto obj = cocoon::fetch_tl_object<cocoon_api::keyManagerDb_key>(value, true).move_as_ok();

    auto P = std::make_unique<PrivateKey>();
    P->private_key = obj->private_key_;

    P->public_key.as_slice().copy_from(td::Ed25519::PrivateKey(td::SecureString(P->private_key.as_slice()))
                                           .get_public_key()
                                           .move_as_ok()
                                           .as_octet_string());
    CHECK(P->public_key.to_hex() == key);
    P->key_type_ = (td::uint8)obj->key_type_;
    P->valid_since_ = obj->valid_since_utime_;
    P->valid_until_ = obj->valid_until_utime_;
    P->valid_since_config_version_ = obj->valid_since_config_version_;
    CHECK(active_config_version_ >= (td::uint32)P->valid_since_config_version_);

    if ((td::uint32)P->valid_until_ > td::Clocks::system()) {
      private_keys_.push_back(std::move(P));
    }
  } else if (key_type == "config") {
  } else {
    LOG(FATAL) << "unknown key type in db: " << key;
  }
}

void KeyManagerRunner::config_to_db() {
  auto conf = cocoon::create_serialize_tl_object<cocoon_api::keyManagerDb_configV1>(
      runner_config()->root_contract_config->version());
  set_to_db("config", std::move(conf));
}

td::UniqueSlice KeyManagerRunner::get_from_db(td::Slice key) {
  std::string config_value;
  auto k = kv_->get(key, config_value);
  k.ensure();

  if (k.move_as_ok() == td::KeyValue::GetStatus::Ok) {
    auto value = td::Slice(config_value);
    CHECK(value.size() >= 64);
    auto signature = value.copy().remove_prefix(value.size() - 64);
    value.remove_suffix(64);

    public_key_obj_->verify_signature(value, signature).ensure();

    return td::UniqueSlice(value);
  } else {
    return td::UniqueSlice();
  }
}

void KeyManagerRunner::set_to_db(td::Slice key, td::Slice value) {
  td::UniqueSlice signed_value(value.size() + 64);
  auto signature = private_key_->sign(value).move_as_ok();
  auto S = signed_value.as_mutable_slice();
  S.copy_from(value);
  S.remove_prefix(value.size());
  S.copy_from(signature.as_slice());
  S.remove_prefix(signature.size());
  CHECK(!S.size());
  kv_->set(key, signed_value.as_slice()).ensure();
}

void KeyManagerRunner::alarm() {
  BaseRunner::alarm();

  if (!is_initialized()) {
    return;
  }

  kv_->begin_transaction().ensure();
  if (runner_config()->root_contract_config->version() > active_config_version_) {
    active_config_version_ = runner_config()->root_contract_config->version();
    config_to_db();
  }
  td::int32 p_cnt = 0;
  td::int32 last_generated_at = 0;
  for (auto it = private_keys_.begin(); it != private_keys_.end();) {
    if ((*it)->valid_until_ < td::Clocks::system()) {
      kv_->erase(PSTRING() << "key_" << (*it)->public_key.to_hex());
      it = private_keys_.erase(it);
    } else {
      if ((*it)->key_type_ == 1) {
        p_cnt++;
        last_generated_at = std::max(last_generated_at, (*it)->valid_since_);
      }
      it++;
    }
  }
  if (p_cnt == 0 || (last_generated_at + key_generate_period()) < td::Clocks::system()) {
    generate_key(1);
  }
  kv_->commit_transaction().ensure();
  kv_->flush().ensure();
}

void KeyManagerRunner::receive_message(TcpClient::ConnectionId connection_id, td::BufferSlice query) {
}

void KeyManagerRunner::receive_query(TcpClient::ConnectionId connection_id, td::BufferSlice query,
                                     td::Promise<td::BufferSlice> promise) {
  if (!is_initialized()) {
    return;
  }
  auto conn = static_cast<BaseInboundConnection *>(get_connection(connection_id));
  if (!conn) {
    return;
  }

  auto magic = get_tl_magic(query);
  switch (magic) {
    case cocoon_api::keyManager_getProxyPrivateKeys::ID: {
      if (check_hashes_ && !runner_config()->root_contract_config->has_proxy_hash(conn->remote_app_hash())) {
        return promise.set_error(td::Status::Error(ton::ErrorCode::error, "unknown proxy hash"));
      }
      {
        auto S = check_verification_key(remote_app_type_proxy(), conn->verified_by());
        if (S.is_error()) {
          return promise.set_error(std::move(S));
        }
      }
      std::vector<ton::tl_object_ptr<cocoon_api::keyManager_privateKey>> pks;
      for (auto &k : private_keys_) {
        pks.push_back(ton::create_tl_object<cocoon_api::keyManager_privateKey>(k->valid_until_, k->private_key));
      }
      promise.set_value(cocoon::create_serialize_tl_object<cocoon_api::keyManager_privateKeys>(std::move(pks)));
      return;
    }
    case cocoon_api::keyManager_getWorkerPrivateKeys::ID: {
      if (check_hashes_ && !runner_config()->root_contract_config->has_worker_hash(conn->remote_app_hash())) {
        return promise.set_error(td::Status::Error(ton::ErrorCode::error, "unknown worker hash"));
      }
      {
        auto S = check_verification_key(remote_app_type_worker(), conn->verified_by());
        if (S.is_error()) {
          return promise.set_error(std::move(S));
        }
      }
      std::vector<ton::tl_object_ptr<cocoon_api::keyManager_privateKey>> pks;
      for (auto &k : private_keys_) {
        pks.push_back(ton::create_tl_object<cocoon_api::keyManager_privateKey>(k->valid_until_, k->private_key));
      }
      promise.set_value(cocoon::create_serialize_tl_object<cocoon_api::keyManager_privateKeys>(std::move(pks)));
      return;
    }
    default:
      LOG(ERROR) << "received query with unknown magic " << td::format::as_hex(magic);
      promise.set_error(td::Status::Error(ton::ErrorCode::failure, "unknown query magic"));
  }
}

void KeyManagerRunner::remove_key(td::Bits256 public_key) {
  for (auto it = private_keys_.begin(); it != private_keys_.end(); it++) {
    if ((*it)->public_key == public_key) {
      kv_->erase(PSTRING() << "key_" << (*it)->public_key.to_hex());
      private_keys_.erase(it);
      return;
    }
  }
}

void KeyManagerRunner::add_static_private_key() {
  auto P = std::make_unique<PrivateKey>();
  P->key_type_ = 1;
  P->private_key.as_slice().copy_from(td::base64_decode("BwrYLmEy2rMgZ/tyCv0AYFVaZPkFu+wNwoSQiJUbOmM=").move_as_ok());
  P->public_key.as_slice().copy_from(td::base64_decode("+2fQ/NM48g4NSVfZ6CrcEB0uNROkSKOrRgUu4biMWBg=").move_as_ok());
  P->valid_since_ = (td::int32)td::Clocks::system();
  P->valid_until_ = 2000000000;
  P->valid_since_config_version_ = active_config_version_;
  private_keys_.push_back(std::move(P));
}

PrivateKey *KeyManagerRunner::generate_key(td::uint8 key_type) {
  td::SecureString s(32);
  td::Random::secure_bytes(s.as_mutable_slice());
  td::Ed25519::PrivateKey pk(std::move(s));
  auto pub = pk.get_public_key().move_as_ok();

  auto P = std::make_unique<PrivateKey>();
  P->key_type_ = key_type;
  P->private_key.as_slice().copy_from(pk.as_octet_string().as_slice());
  P->public_key.as_slice().copy_from(pub.as_octet_string().as_slice());
  P->valid_since_ = (td::int32)td::Clocks::system();
  P->valid_until_ = P->valid_since_ + key_ttl();
  P->valid_since_config_version_ = active_config_version_;

  auto ptr = P.get();

  set_to_db(PSTRING() << "key_" << P->public_key.to_hex(),
            cocoon::create_serialize_tl_object<cocoon_api::keyManagerDb_key>(
                P->private_key, P->key_type_, P->valid_since_config_version_, P->valid_since_, P->valid_until_));

  private_keys_.push_back(std::move(P));

  if (ptr) {
    vm::CellBuilder cb;
    cb.store_long(opcodes::root_add_public_key_signed, 32).store_long(td::Random::fast_uint64());
    ptr->serialize(cb);

    auto msg = sign_and_wrap_message(*private_key_, cb.finalize(), cocoon_wallet()->address());
    cocoon_wallet()->send_transaction(root_contract_address(), to_nano(0.4), {}, std::move(msg), {});
  }

  return ptr;
}

std::string KeyManagerRunner::http_generate_main() {
  td::StringBuilder sb;
  sb << "<!DOCTYPE html>\n";
  sb << "<html><body>\n";
  {
    sb << "<h1>STATUS</h1>\n";
    sb << "<table>\n";
    if (cocoon_wallet()) {
      sb << "<tr><td>wallet</td><td>";
      if (cocoon_wallet()->balance() < min_wallet_balance()) {
        sb << "<span style=\"background-color:Crimson;\">balance too low on "
           << address_link(cocoon_wallet()->address()) << "</span>";
      } else if (cocoon_wallet()->balance() < warning_wallet_balance()) {
        sb << "<span style=\"background-color:Gold;\">balance low on " << address_link(cocoon_wallet()->address())
           << "</span>";
      } else {
        sb << "<span style=\"background-color:Green;\">balance ok on " << address_link(cocoon_wallet()->address())
           << "</span>";
      }
      sb << "</td></tr>\n";
    }
    {
      sb << "<tr><td>image</td><td>";
      sb << "<span style=\"background-color:Gold;\">cannot check our hash " << local_image_hash_unverified_.to_hex()
         << "</span>";
      sb << "</td></tr>\n";
    }
    auto r = runner_config();
    if (r) {
      auto ts = (int)std::time(0);
      sb << "<tr><td>ton</td><td>";
      if (ts - r->root_contract_ts < 600) {
        sb << "<span style=\"background-color:Green;\">synced</span>";
      } else if (ts - r->root_contract_ts < 3600) {
        sb << "<span style=\"background-color:Gold;\">late</span>";
      } else {
        sb << "<span style=\"background-color:Crimson;\">out of sync</span>";
      }
      sb << "</td></tr>\n";
    }
    sb << "<tr><td>enabled</td><td>";
    sb << "</td></tr>\n";
    sb << "<tr><td>version</td><td>commit " << GitMetadata::CommitSHA1() << " at " << GitMetadata::CommitDate()
       << "</td></tr>\n";
    sb << "</table>\n";
  }
  {
    sb << "<h1>LOCAL CONFIG</h1>\n";
    sb << "<table>\n";
    sb << "<tr><td>root address</td><td>" << address_link(root_contract_address()) << "</td></tr>\n";
    sb << "<tr><td>owner address</td><td>" << address_link(owner_address()) << "</td></tr>\n";
    sb << "<tr><td>check hashes</td><td>" << (check_hashes_ ? "YES" : "NO") << "</td></tr>\n";
    sb << "<tr><td>public key</td><td>" << public_key_.to_hex() << "</td></tr>\n";
    sb << "</table>\n";
  }
  store_wallet_stat(sb);
  store_root_contract_stat(sb);
  {
    sb << "<h1>KEYS</h1>\n";
    sb << "<table>\n";
    sb << "<tr><td>key</td><td>key type</td><td>valid since config version</td><td>valid "
          "since</td><td>valid until</td></tr>\n";
    for (auto &it : private_keys_) {
      const auto &k = *it;
      sb << "<tr><td>" << k.public_key.to_hex() << "</td><td>" << k.key_type_ << "</td><td>"
         << k.valid_since_config_version_ << "</td><td>" << k.valid_since_ << "</td><td>" << k.valid_until_
         << "</td></tr>\n";
    }
    sb << "</table>\n";
  }
  sb << "</body></html>\n";
  return sb.as_cslice().str();
}

std::string KeyManagerRunner::http_generate_json_stats() {
  SimpleJsonSerializer jb;

  jb.start_object();
  {
    jb.start_object("status");
    jb.add_element("actual_image_hash", true);
    auto r = runner_config();
    if (r) {
      jb.add_element("ton_last_synced_at", r->root_contract_ts);
    }
    jb.add_element("git_commit", GitMetadata::CommitSHA1());
    jb.add_element("git_commit_data", GitMetadata::CommitDate());
    jb.stop_object();
  }
  {
    jb.start_object("localconfig");
    jb.add_element("check_hashes", check_hashes_);
    jb.stop_object();
  }
  store_root_contract_stat(jb);

  jb.stop_object();

  return jb.as_cslice().str();
}

std::string KeyManagerRunner::http_remove_key(std::string pub_key) {
  auto R = td::hex_decode(pub_key);
  if (R.is_error()) {
    return wrap_short_answer_to_http(PSTRING() << "cannot decode hex: " << R.move_as_error());
  }
  auto r = R.move_as_ok();
  if (r.size() != 32) {
    return wrap_short_answer_to_http(PSTRING() << "cannot decode hex: public key must be 32 bytes long");
  }
  td::Bits256 p;
  p.as_slice().copy_from(r);
  remove_key(p);
  return wrap_short_answer_to_http(PSTRING() << "key removed");
}

std::string KeyManagerRunner::http_generate_key(std::string key_type) {
  if (key_type == "") {
    key_type = "1";
  }
  auto R = td::to_integer_safe<td::uint8>(key_type);
  if (R.is_error()) {
    return wrap_short_answer_to_http(PSTRING() << "failed to parse integer: " << key_type);
  }
  generate_key(R.move_as_ok());
  kv_->flush().ensure();
  return wrap_short_answer_to_http(PSTRING() << "key generated");
}

}  // namespace cocoon
