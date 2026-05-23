// Build guard: this target is only added when SGX is found in CMake.
#if __has_include(<sgx_urts.h>)

//
//
// Created by Arseny Smirnov  on 30/07/2025.
//

#include "tee/cocoon/tdx/tdx.h"
#include "tee/cocoon/utils.h"
#include "common.h"
#include "td/actor/actor.h"
#include "td/net/TcpListener.h"
#include "td/utils/algorithm.h"
#include "td/utils/as.h"
#include "td/utils/BufferedFd.h"
#include "td/utils/filesystem.h"
#include "td/utils/logging.h"
#include "td/utils/OptionParser.h"
#include "td/utils/tl_helpers.h"
#include "td/e2e/MessageEncryption.h"
#include <algorithm>
#include <openssl/core_names.h>
#include <openssl/ec.h>
#include <openssl/err.h>

#include "cocoon/openssl_utils.h"
#include "td/net/Pipe.h"
#include "td/net/utils.h"

#include <openssl/evp.h>

namespace cocoon {

// Constants for cryptographic operations
static constexpr size_t EC_POINT_SIZE = 32;  // Size of each coordinate in EC point
static constexpr size_t SHA256_SIZE = 32;    // SHA-256 hash size

// Client: make TDX report, request key, verify quote, ECDH-decrypt secret
class GetPersistentKeyClient {
  static constexpr size_t POINT_SIZE = EC_POINT_SIZE;
  static constexpr size_t DH_SIZE = EC_POINT_SIZE;

 public:
  struct Config {
    std::vector<td::UInt256> allowed_mr_enclave;  ///< Allowed MR_ENCLAVE values (empty = any)
    bool skip_mr_enclave_validation{};
    std::string key_name;  ///< Key name for derivation
  };

  explicit GetPersistentKeyClient(Config config)
      : config_(std::move(config)) {
  }
  /**
   * Generates a request for a persistent key.
   * 
   * @return Serialized GetPersistentKey request containing TDX report and public key
   */
  td::Result<std::string> get_request() {
    // Generate EC key pair for ECDH
    TRY_RESULT_ASSIGN(public_key_, gen_public_key());

    // Create report data with public key hash
    td::UInt512 report_data;
    td::sha256(public_key_, report_data.as_mutable_slice().substr(0, SHA256_SIZE));
    report_data.as_mutable_slice().substr(SHA256_SIZE).fill_zero();

    // Generate TDX report
    TRY_RESULT(report, tdx::tdx_make_report(report_data));

    return td::serialize(
        GetPersistentKey{.tdx_report = report.raw_report, .public_key = public_key_, .key_name = config_.key_name});
  }

  /**
   * Processes the response from the SGX enclave and decrypts the persistent key.
   *
   * @param response_slice Serialized PersistentKey response
   * @return Decrypted persistent key
   */
  td::Result<std::string> process_response(td::Slice response_slice) {
    // Deserialize response
    PersistentKey response;
    TRY_STATUS(td::unserialize(response, response_slice));

    // Validate SGX quote
    TRY_RESULT(attestation_data, validate_sgx_quote(response));

    // Decrypt the secret using ECDH
    return decrypt_secret(response, attestation_data);
  }

 private:
  /**
   * Validates the SGX quote and checks report data integrity.
   */
  td::Result<tdx::SgxAttestationData> validate_sgx_quote(const PersistentKey &response) {
    TRY_RESULT(p, tdx::sgx_validate_quote(tdx::Quote{response.sgx_quote}));

    const auto& [sgx_attestation_data, _] = p;

    // Verify report data integrity
    td::UInt512 expected_report_data;
    td::sha256(public_key_, expected_report_data.as_mutable_slice().substr(0, SHA256_SIZE));
    td::sha256(response.encrypted_secret, expected_report_data.as_mutable_slice().substr(SHA256_SIZE, SHA256_SIZE));

    if (expected_report_data != sgx_attestation_data.reportdata) {
      LOG(ERROR) << "SGX attestation data mismatch:";
      LOG(ERROR) << "Expected: " << td::format::as_hex_dump<0>(expected_report_data.as_slice());
      LOG(ERROR) << "Got:      " << td::format::as_hex_dump<0>(sgx_attestation_data.reportdata.as_slice());
      return td::Status::Error("SGX attestation data verification failed");
    }

    // Validate MR_ENCLAVE if configured
    if (!config_.skip_mr_enclave_validation) {
      bool mr_enclave_valid = false;
      for (const auto &allowed : config_.allowed_mr_enclave) {
        if (sgx_attestation_data.mr_enclave == allowed) {
          mr_enclave_valid = true;
          break;
        }
      }
      if (!mr_enclave_valid) {
        //TODO: LOG_LAMBDA
        LOG(ERROR) << "MR_ENCLAVE validation failed:";
        LOG(ERROR) << "Got: " << td::hex_encode(sgx_attestation_data.mr_enclave.as_slice());
        LOG(ERROR) << "Allowed values:";
        for (const auto &allowed : config_.allowed_mr_enclave) {
          LOG(ERROR) << "  " << td::hex_encode(allowed.as_slice());
        }
        return td::Status::Error("MR_ENCLAVE validation failed");
      }
      LOG(INFO) << "MR_ENCLAVE validation passed";
    } else {
      LOG(INFO) << "MR_ENCLAVE validation skipped: MR_ENCLAVE="
                << td::hex_encode(sgx_attestation_data.mr_enclave.as_slice());
    }

    LOG(INFO) << "SGX attestation data validated successfully:\n" << sgx_attestation_data;
    return sgx_attestation_data;
  }

  /**
   * Decrypts the encrypted secret using ECDH key exchange.
   */
  td::Result<std::string> decrypt_secret(const PersistentKey &response,
                                         const tdx::SgxAttestationData &attestation_data) {
    // Validate encrypted secret size
    // Expect enclave public key (64) + ciphertext (32)
    static constexpr size_t ENCLAVE_PUBKEY_SIZE = POINT_SIZE * 2;
    if (response.encrypted_secret.size() < ENCLAVE_PUBKEY_SIZE + 32) {
      return td::Status::Error(PSLICE() << "Encrypted secret too small: " << response.encrypted_secret.size()
                                        << " bytes, expected at least " << (ENCLAVE_PUBKEY_SIZE + 32));
    }

    const unsigned char *ptr = td::Slice(response.encrypted_secret).ubegin();
    const unsigned char *peer_pub = ptr;
    const unsigned char *ciphertext = ptr + ENCLAVE_PUBKEY_SIZE;
    size_t ciphertext_size = response.encrypted_secret.size() - ENCLAVE_PUBKEY_SIZE;
    if (ciphertext_size != 32) {
      // Protocol currently produces 32-byte persistent key
      return td::Status::Error("Unexpected ciphertext size");
    }
    size_t decrypted_key_size = ciphertext_size;

    auto make_uncompressed_p256_point = [](const unsigned char *little_endian_xy) {
      static_assert(POINT_SIZE == 32, "P-256 coordinate size");
      td::UInt256 x_le = td::as<td::UInt256>(little_endian_xy);
      td::UInt256 y_le = td::as<td::UInt256>(little_endian_xy + POINT_SIZE);
      std::reverse(x_le.raw, x_le.raw + POINT_SIZE);
      std::reverse(y_le.raw, y_le.raw + POINT_SIZE);
      std::vector<unsigned char> out(1 + POINT_SIZE + POINT_SIZE);
      out[0] = 0x04;
      td::as<td::UInt256>(out.data() + 1) = x_le;
      td::as<td::UInt256>(out.data() + 1 + POINT_SIZE) = y_le;
      return out;
    };
    auto pub_point = make_uncompressed_p256_point(peer_pub);

    OPENSSL_MAKE_PTR(kctx, EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free, "EVP_PKEY_CTX_new_id failed");

    OPENSSL_CHECK_OK(EVP_PKEY_fromdata_init(kctx.get()), "EVP_PKEY_fromdata_init failed");

    OSSL_PARAM params[] = {OSSL_PARAM_utf8_string("group", (char *)"prime256v1", 0),
                           OSSL_PARAM_octet_string("pub", pub_point.data(), pub_point.size()), OSSL_PARAM_END};

    EVP_PKEY *peerkey = nullptr;
    OPENSSL_CHECK_OK(EVP_PKEY_fromdata(kctx.get(), &peerkey, EVP_PKEY_PUBLIC_KEY, params), "EVP_PKEY_fromdata failed");
    CHECK(peerkey);
    SCOPE_EXIT {
      EVP_PKEY_free(peerkey);
    };

    td::UInt256 dh;
    size_t dh_len = sizeof(dh);

    CHECK(private_key_);
    OPENSSL_MAKE_PTR(dctx, EVP_PKEY_CTX_new(private_key_.get(), nullptr), EVP_PKEY_CTX_free, "EVP_PKEY_CTX_new failed");
    OPENSSL_CHECK_OK(EVP_PKEY_derive_init(dctx.get()), "EVP_PKEY_derive_init failed");
    OPENSSL_CHECK_OK(EVP_PKEY_derive_set_peer(dctx.get(), peerkey), "EVP_PKEY_derive_set_peer failed");
    OPENSSL_CHECK_OK(EVP_PKEY_derive(dctx.get(), dh.raw, &dh_len), "EVP_PKEY_derive failed");
    if (dh_len != sizeof(dh)) {
      return td::Status::Error("Unexpected size of the shared key");
    }

    std::reverse(dh.raw, dh.raw + dh_len);

    // Derive AES key and IV from SHA-256(shared_secret)
    unsigned char key_iv_hash[32];
    td::sha256(td::Slice(dh.raw, sizeof(dh)), td::MutableSlice(key_iv_hash, 32));
    const unsigned char *aes_key = key_iv_hash;
    const unsigned char *iv = key_iv_hash + 16;
    OPENSSL_MAKE_PTR(ctx, EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free, "EVP_CIPHER_CTX_new failed");
    OPENSSL_CHECK_OK(EVP_DecryptInit_ex2(ctx.get(), EVP_aes_128_ctr(), aes_key, iv, nullptr),
                     "EVP_DecryptInit_ex2 failed");

    int outl = 0, tmplen = 0;
    std::string decrypted_key(decrypted_key_size, '\0');
    OPENSSL_CHECK_OK(
        EVP_DecryptUpdate(ctx.get(), td::MutableSlice(decrypted_key).ubegin(), &outl, ciphertext, decrypted_key_size),
        "EVP_DecryptUpdate failed");
    OPENSSL_CHECK_OK(EVP_DecryptFinal_ex(ctx.get(), td::MutableSlice(decrypted_key).ubegin() + outl, &tmplen),
                     "EVP_DecryptFinal_ex failed");

    return decrypted_key;
  }

 private:
  Config config_;
  struct EvpPkeyFree {
    void operator()(EVP_PKEY *key) const {
      EVP_PKEY_free(key);
    }
  };
  std::unique_ptr<EVP_PKEY, EvpPkeyFree> private_key_;
  std::string public_key_;

  td::Result<std::string> gen_public_key() {
    OPENSSL_MAKE_PTR(pctx, EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr), EVP_PKEY_CTX_free, "EVP_PKEY_CTX_new_id failed");
    OPENSSL_CHECK_OK(EVP_PKEY_keygen_init(pctx.get()), "Can't init keygen");
    OPENSSL_CHECK_OK(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx.get(), NID_X9_62_prime256v1),
                     "Can't set ec_paramgen_curve_nid");

    EVP_PKEY *pkey = nullptr;
    OPENSSL_CHECK_OK(EVP_PKEY_keygen(pctx.get(), &pkey), "Can't generate random private_key");
    private_key_.reset(pkey);

    BIGNUM *x = nullptr, *y = nullptr;
    OPENSSL_CHECK_OK(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_X, &x), "Can't extract pub X from private key");
    SCOPE_EXIT {
      BN_free(x);
    };
    OPENSSL_CHECK_OK(EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_EC_PUB_Y, &y), "Can't extract pub Y from private key");
    SCOPE_EXIT {
      BN_free(y);
    };

    td::UInt256 pubX;
    td::UInt256 pubY;
    if (BN_bn2binpad(x, pubX.raw, POINT_SIZE) <= 0) {
      return td::Status::Error("Failed to convert X coordinate to bytes");
    }

    if (BN_bn2binpad(y, pubY.raw, POINT_SIZE) <= 0) {
      return td::Status::Error("Failed to convert Y coordinate to bytes");
    }

    // Convert from big-endian (OpenSSL) to little-endian (expected by enclave)
    std::reverse(pubX.raw, pubX.raw + POINT_SIZE);
    std::reverse(pubY.raw, pubY.raw + POINT_SIZE);

    return pubX.as_slice().str() + pubY.as_slice().str();
  }
};

/**
 * TCP client actor for communicating with the SGX enclave server.
 *
 * This actor:
 * 1. Connects to the enclave server via VSOCK
 * 2. Sends a key request
 * 3. Receives and processes the response
 * 4. Exits with the decrypted key
 */

class Client : public td::actor::Actor {
 public:
  struct Config {
    GetPersistentKeyClient::Config client_config;
    std::string key_name;
    std::string output_file;
  };

  explicit Client(td::BufferedFd<td::SocketFd> fd, Config config)
      : fd_(td::make_socket_pipe(std::move(fd)))
      , config_(std::move(config))
      , client_(config_.client_config) {
  }

 private:
  td::SocketPipe fd_;
  Config config_;
  GetPersistentKeyClient client_;
  bool sent_request_{false};
  // framed I/O helpers are used directly via utils.h

  void loop() override {
    auto status = do_loop();
    if (status.is_error()) {
      LOG(ERROR) << "Client error: " << status;
      std::_Exit(1);
    }
  }

  void start_up() override {
    fd_.subscribe();
  }

  td::Status do_loop() {
    if (!sent_request_) {
      sent_request_ = true;
      TRY_RESULT(request, client_.get_request());
      TRY_STATUS(cocoon::framed_write(fd_.output_buffer(), request));
      LOG(INFO) << "Sent key request to enclave server";
    }
    TRY_STATUS(loop_read("enclave_connection", fd_));
    TRY_STATUS(process_response());
    TRY_STATUS(loop_write("enclave_connection", fd_));
    return td::Status::OK();
  }

  /**
   * Processes response from the enclave server.
   */
  td::Status process_response() {
    td::BufferSlice response;
    TRY_RESULT(bytes_needed, cocoon::framed_read(fd_.input_buffer(), response));

    // Wait for more data if response is incomplete
    if (bytes_needed != 0) {
      return td::Status::OK();
    }

    LOG(INFO) << "Received response from enclave server";
    TRY_RESULT(decrypted_key, client_.process_response(response.as_slice()));

    // Do not log the key material; only log success and size
    LOG(INFO) << "Successfully received derived key (" << decrypted_key.size()
              << " bytes) sha256=" << td::hex_encode(td::sha256(decrypted_key));

    // The key is already derived in the SGX enclave based on key_name
    // Save the derived key to file if output file is specified
    if (!config_.output_file.empty()) {
      TRY_STATUS(td::write_file(config_.output_file, decrypted_key));
      LOG(INFO) << "Derived key saved to: " << config_.output_file;
    }

    // Output the derived key hash to stdout for script consumption
    auto derived_key_hash = td::hex_encode(td::sha256(decrypted_key));

    LOG(INFO) << "Derived key for '" << config_.key_name << "': sha256=" << derived_key_hash;

    std::_Exit(0);  // Exit with success
  }
};
}  // namespace cocoon

/**
 * Main entry point for the persistent key client.
 *
 * Connects to the SGX enclave server via VSOCK and requests a persistent key.
 */
int main(int argc, char **argv) {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(DEBUG));

  constexpr td::int32 DEFAULT_VSOCK_PORT = 12345;
  constexpr int SCHEDULER_THREADS = 1;
  constexpr int SCHEDULER_TIMEOUT_MS = 10;

  // Parse command line arguments
  td::int32 vsock_port = DEFAULT_VSOCK_PORT;
  cocoon::Client::Config client_config;
  std::string key_name = "default";
  std::string output_file;

  td::OptionParser option_parser;
  option_parser.add_checked_option('p', "port", "VSOCK port to connect to", [&](td::Slice port_str) {
    TRY_RESULT(port, td::to_integer_safe<td::int32>(port_str));
    if (port <= 0 || port > 65535) {
      return td::Status::Error("Invalid port number");
    }
    vsock_port = port;
    return td::Status::OK();
  });

  option_parser.add_checked_option('m', "mr-enclave", "Allowed MR_ENCLAVE value (hex)", [&](td::Slice hex_str) {
    if (hex_str.size() != 64) {  // 32 bytes * 2 hex chars
      return td::Status::Error("MR_ENCLAVE must be 64 hex characters (32 bytes)");
    }
    TRY_RESULT(mr_enclave_str, td::hex_decode(hex_str));
    td::UInt256 mr_enclave;
    mr_enclave.as_mutable_slice().copy_from(mr_enclave_str);
    client_config.client_config.allowed_mr_enclave.push_back(mr_enclave);
    return td::Status::OK();
  });

  option_parser.add_checked_option('s', "skip-validation", "Skip MR_ENCLAVE validation", [&]() {
    client_config.client_config.skip_mr_enclave_validation = true;
    return td::Status::OK();
  });

  option_parser.add_checked_option('k', "key-name", "Key name for HMAC derivation (cocoon:<key-name>)",
                                   [&](td::Slice name) {
                                     key_name = name.str();
                                     return td::Status::OK();
                                   });

  option_parser.add_checked_option('o', "output", "Output file for persistent key", [&](td::Slice filename) {
    output_file = filename.str();
    return td::Status::OK();
  });

  option_parser.add_option('h', "help", "Show this help message", [&]() {
    LOG(PLAIN) << option_parser;
    std::_Exit(0);
  });

  option_parser.set_description(
      "seal-client: connect via vsock, request persistent key. Optionally derive named key with HMAC.");

  auto r_args = option_parser.run(argc, argv, -1);
  if (r_args.is_error()) {
    LOG(ERROR) << r_args.error();
    LOG(ERROR) << option_parser;
    return 1;
  }

  LOG(INFO) << "seal-client port=" << vsock_port;
  if (!client_config.client_config.skip_mr_enclave_validation) {
    LOG(INFO) << "mr_enclave validation enabled (" << client_config.client_config.allowed_mr_enclave.size() << ")";
  } else {
    LOG(INFO) << "mr_enclave validation disabled";
  }

  td::actor::Scheduler sched({SCHEDULER_THREADS});

  // Set up client config with new options
  client_config.client_config.key_name = key_name;
  client_config.key_name = key_name;
  client_config.output_file = output_file;

  sched.run_in_context([&] {
    // Connect to enclave server via VSOCK
    auto socket_result = td::SocketFd::open_vsock(vsock_port);
    if (socket_result.is_error()) {
      LOG(FATAL) << socket_result.error();
    }
    LOG(INFO) << "connected";

    // Create client actor
    td::actor::create_actor<cocoon::Client>(
        "PersistentKeyClient", td::BufferedFd<td::SocketFd>(socket_result.move_as_ok()), std::move(client_config))
        .release();
  });

  sched.start();

  // Run scheduler until completion
  while (sched.run(SCHEDULER_TIMEOUT_MS)) {
    // Continue processing
  }

  LOG(INFO) << "done";
  return 0;
}
#else
int main(int, char **) {
  return 0;
}
#endif
