// Build guard: this target is only added when SGX is found in CMake.
#if __has_include(<sgx_urts.h>)

//
// Created by Arseny Smirnov  on 30/07/2025.
//
#include "tee/cocoon/tdx/tdx.h"
#include "cocoon/utils.h"
#include "common.h"
#include "Enclave_u.h"
#include "sgx_utils.h"
#include "td/actor/actor.h"
#include "td/net/Pipe.h"
#include "td/net/TcpListener.h"
#include "td/net/utils.h"
#include "td/utils/BufferedFd.h"
#include "td/utils/logging.h"
#include "td/utils/OptionParser.h"
#include "td/utils/base64.h"
#include "td/utils/tl_helpers.h"
#include <memory>
#include <sgx_dcap_ql_wrapper.h>
#include <sgx_default_quote_provider.h>
#include <sgx_report2.h>
#include <sgx_urts.h>

void ocall_print(const char* str) {
  fprintf(stderr, "[ENCLAVE] %s\n", str);
}

namespace cocoon {

// SGX server for persistent key TL protocol

// Constants for SGX operations
static constexpr size_t MAX_ENCRYPTED_SECRET_SIZE = 128;
static constexpr size_t ENCLAVE_PUBKEY_SIZE = sizeof(sgx_ec256_public_t);
static constexpr char DEFAULT_ENCLAVE_PATH[] = "tee/cocoon/tdx/sgx-enclave/enclave.signed.so";

class SharedEnclave {
 public:
  static td::Result<std::shared_ptr<SharedEnclave>> create(td::CSlice enclave_path) {
    auto ptr = std::shared_ptr<SharedEnclave>(new SharedEnclave());
    ptr->path_ = enclave_path.str();
    SGX_CHECK_OK(sgx_create_enclave(ptr->path_.c_str(), 0, nullptr, nullptr, &ptr->enclave_id_, nullptr),
                 "Failed to create SGX enclave");
    QL_CHECK_OK(sgx_qe_get_target_info(&ptr->target_info_), "Failed to get SGX target info");
    QL_CHECK_OK(sgx_qe_get_quote_size(&ptr->quote_size_), "Failed to get SGX quote size");
    LOG(INFO) << "SGX enclave created: path='" << ptr->path_ << "' quote_size=" << ptr->quote_size_;
    return ptr;
  }
  ~SharedEnclave() {
    if (enclave_id_ != 0) {
      sgx_destroy_enclave(enclave_id_);
      LOG(INFO) << "SGX enclave destroyed";
    }
  }
  sgx_enclave_id_t enclave_id() const {
    return enclave_id_;
  }
  const sgx_target_info_t& target_info() const {
    return target_info_;
  }
  td::uint32 quote_size() const {
    return quote_size_;
  }

 private:
  SharedEnclave() = default;
  std::string path_;
  sgx_enclave_id_t enclave_id_{0};
  sgx_target_info_t target_info_{};
  td::uint32 quote_size_{};
};

class GetPersistentKeyServer {
 public:
  explicit GetPersistentKeyServer(std::shared_ptr<SharedEnclave> enclave)
      : enclave_(std::move(enclave)) {
    if (!enclave_) {
      LOG(FATAL) << "SharedEnclave cannot be null";
    }
  }
  /**
   * Processes a persistent key request from a client.
   *
   * @param request_slice Serialized GetPersistentKey request
   * @return Serialized PersistentKey response
   */
  td::Result<std::string> process_request(td::Slice request_slice) {
    GetPersistentKey request;
    TRY_STATUS(td::unserialize(request, request_slice));

    LOG(INFO) << "Processing persistent key request";
    TRY_RESULT(result, generate_persistent_key(request));

    return td::serialize(result);
  }

 private:
  std::shared_ptr<SharedEnclave> enclave_;

  /**
   * Generates a persistent key using SGX enclave.
   *
   * @param query The persistent key request containing TDX report and public key
   * @return PersistentKey response with SGX quote and encrypted secret
   */
  td::Result<PersistentKey> generate_persistent_key(const GetPersistentKey& query) {
    // Reuse shared enclave and cached QE info
    const auto enclave_id = enclave_->enclave_id();
    const auto& target_info = enclave_->target_info();
    const auto quote_size = enclave_->quote_size();

    // Prepare TDX report
    TRY_RESULT(tdx_report, extract_tdx_report(query));

    sgx_report_t sgx_report;
    // no-op

    // Call enclave to generate the key
    TRY_RESULT(encrypted_secret, call_enclave_generate_key(enclave_id, target_info, tdx_report, query.public_key,
                                                           query.key_name, sgx_report));

    // Generate SGX quote
    TRY_RESULT(sgx_quote, generate_sgx_quote(sgx_report, quote_size));

    // Validate the generated quote
    TRY_RESULT(p, tdx::sgx_validate_quote(tdx::Quote{sgx_quote}));
    LOG(INFO) << "quote ok";

    // Do not log secret material

    return PersistentKey{.sgx_quote = std::move(sgx_quote), .encrypted_secret = std::move(encrypted_secret)};
  }

  /**
   * Extracts TDX report from the request.
   */
  td::Result<sgx_report2_t> extract_tdx_report(const GetPersistentKey& query) {
    sgx_report2_t tdx_report;

    if (query.tdx_report.size() != sizeof(tdx_report)) {
      return td::Status::Error(PSLICE() << "Invalid TDX report size: expected " << sizeof(tdx_report) << " bytes, got "
                                        << query.tdx_report.size());
    }

    memcpy(&tdx_report, query.tdx_report.data(), query.tdx_report.size());
    LOG(INFO) << "TDX report extracted";

    return tdx_report;
  }

  /**
   * Calls the SGX enclave to generate an encrypted key.
   */
  td::Result<std::string> call_enclave_generate_key(sgx_enclave_id_t enclave_id, const sgx_target_info_t& target_info,
                                                    const sgx_report2_t& tdx_report, const std::string& public_key,
                                                    const std::string& key_name, sgx_report_t& sgx_report) {
    std::string encrypted_secret_buffer(MAX_ENCRYPTED_SECRET_SIZE, '\0');
    size_t encrypted_secret_size = 0;
    sgx_status_t ecall_result;

    if (public_key.size() != sizeof(sgx_ec256_public_t)) {
      return td::Status::Error(PSLICE() << "Invalid public key size: expected " << sizeof(sgx_ec256_public_t)
                                        << " bytes, got " << public_key.size());
    }

    sgx_status_t call_status =
        ecall_gen_key(enclave_id, &ecall_result, &target_info, &tdx_report, public_key.c_str(), public_key.size(),
                      key_name.c_str(), key_name.size(), &encrypted_secret_buffer[0], encrypted_secret_buffer.size(),
                      &encrypted_secret_size, &sgx_report);

    if (call_status != SGX_SUCCESS) {
      return td::Status::Error(PSLICE() << "Enclave call failed: " << td::format::as_hex(call_status));
    }

    if (ecall_result != SGX_SUCCESS) {
      return td::Status::Error(PSLICE() << "Enclave function failed: " << td::format::as_hex(ecall_result));
    }

    if (encrypted_secret_size > encrypted_secret_buffer.size()) {
      return td::Status::Error("Encrypted secret size exceeds buffer capacity");
    }

    if (encrypted_secret_size < ENCLAVE_PUBKEY_SIZE + 32) {
      return td::Status::Error("Encrypted secret too small (missing enclave public key or ciphertext)");
    }

    encrypted_secret_buffer.resize(encrypted_secret_size);
    LOG(INFO) << "Enclave generated encrypted secret (" << encrypted_secret_size << " bytes)";

    return encrypted_secret_buffer;
  }

  /**
   * Generates an SGX quote from the SGX report.
   */
  td::Result<std::string> generate_sgx_quote(const sgx_report_t& sgx_report, td::uint32 quote_size) {
    std::string quote_buffer(quote_size, '\0');

    QL_CHECK_OK(sgx_qe_get_quote(&sgx_report, quote_size, td::MutableSlice(quote_buffer).ubegin()),
                "Failed to generate SGX quote");

    LOG(DEBUG) << "quote generated";
    return quote_buffer;
  }
};

/**
 * TCP server for handling persistent key requests.
 *
 * This server:
 * 1. Listens on a VSOCK port for client connections
 * 2. Spawns worker actors for each connection
 * 3. Each worker processes one persistent key request
 */
class Server : public td::actor::Actor {
 public:
  struct Config {
    td::int32 port_{12345};  // Default VSOCK port
    std::string enclave_path{DEFAULT_ENCLAVE_PATH};
  };

  /**
   * Worker actor that handles a single client connection.
   */
  class Worker : public td::actor::Actor {
   public:
    explicit Worker(td::BufferedFd<td::SocketFd> fd, std::shared_ptr<const Config> config,
                    std::shared_ptr<SharedEnclave> enclave)
        : fd_(td::make_socket_pipe(std::move(fd)))
        , config_(std::move(config))
        , enclave_(std::move(enclave))
        , server_(enclave_) {
    }

   private:
    td::SocketPipe fd_;
    std::shared_ptr<const Config> config_;
    std::shared_ptr<SharedEnclave> enclave_;
    GetPersistentKeyServer server_;

    void start_up() override {
      fd_.subscribe();
    }

    void loop() override {
      auto status = do_loop();
      if (status.is_error()) {
        LOG(ERROR) << "Worker error: " << status;
        stop();
      }
    }

    td::Status do_loop() {
      TRY_STATUS(loop_read("client_connection", fd_));
      TRY_STATUS(process_client_request());
      TRY_STATUS(loop_write("client_connection", fd_));
      return td::Status::OK();
    }

    /**
     * Processes a single client request for a persistent key.
     */
    td::Status process_client_request() {
      td::BufferSlice query;
      TRY_RESULT(bytes_needed, cocoon::framed_read(fd_.input_buffer(), query));

      // Wait for complete request
      if (bytes_needed != 0) {
        return td::Status::OK();
      }

      LOG(INFO) << "Received persistent key request from client";

      TRY_RESULT(response, server_.process_request(query.as_slice()));

      TRY_STATUS(cocoon::framed_write(fd_.output_buffer(), response));
      LOG(INFO) << "Sent persistent key response to client";

      return td::Status::OK();
    }
  };

  void start_up() override {
    LOG(INFO) << "seal-server port=" << config_->port_ << " enclave='" << config_->enclave_path << "'";
    auto res = SharedEnclave::create(config_->enclave_path);
    if (res.is_error()) {
      LOG(FATAL) << res.error();
      return;
    }
    enclave_ = res.move_as_ok();

    struct Callback : public td::TcpListener::Callback {
      std::shared_ptr<const Config> config_;
      std::shared_ptr<SharedEnclave> enclave_;
      explicit Callback(std::shared_ptr<const Config> config, std::shared_ptr<SharedEnclave> enclave)
          : config_(std::move(config)), enclave_(std::move(enclave)) {
      }
      void accept(td::SocketFd fd) override {
        auto options = td::actor::ActorOptions().with_name("Socks5Connection").with_poll(true);
        td::actor::create_actor<Worker>(options, td::BufferedFd<td::SocketFd>(std::move(fd)), config_, enclave_)
            .release();
      }
    };
    auto options = td::actor::ActorOptions().with_name("Listener").with_poll(true);
    listener_ = td::actor::create_actor<td::TcpListener>(options, config_->port_,
                                                         std::make_unique<Callback>(config_, enclave_), "@vsock");
    auto server = GetPersistentKeyServer(enclave_);
  }
  explicit Server(Config config) : config_(std::make_shared<Config>(std::move(config))) {
    LOG(DEBUG) << "server init";
  }

 private:
  td::actor::ActorOwn<td::TcpListener> listener_;
  std::shared_ptr<const Config> config_;
  std::shared_ptr<SharedEnclave> enclave_;
};

}  // namespace cocoon

/**
 * Main entry point for the persistent key server.
 *
 * Starts an SGX enclave server that processes persistent key requests from clients.
 */
int main(int argc, char** argv) {
  SET_VERBOSITY_LEVEL(VERBOSITY_NAME(INFO));

  constexpr int SCHEDULER_THREADS = 1;
  constexpr int SCHEDULER_TIMEOUT_MS = 10;
  constexpr td::int32 DEFAULT_VSOCK_PORT = 12345;

  // Parse command line arguments
  td::int32 vsock_port = DEFAULT_VSOCK_PORT;
  std::string enclave_path = cocoon::DEFAULT_ENCLAVE_PATH;

  td::OptionParser option_parser;
  option_parser.add_checked_option('p', "port", "VSOCK port to listen on", [&](td::Slice port_str) {
    TRY_RESULT(port, td::to_integer_safe<td::int32>(port_str));
    if (port <= 0 || port > 65535) {
      return td::Status::Error("Invalid port number");
    }
    vsock_port = port;
    return td::Status::OK();
  });

  option_parser.add_option('h', "help", "Show this help message", [&]() {
    LOG(PLAIN) << option_parser;
    std::_Exit(0);
  });

  option_parser.add_checked_option('e', "enclave-path", "Path to enclave signed shared object", [&](td::Slice p) {
    if (p.empty()) {
      return td::Status::Error("enclave path cannot be empty");
    }
    enclave_path = p.str();
    return td::Status::OK();
  });

  option_parser.set_description("seal-server: listen on vsock and answer persistent key requests");

  auto r_args = option_parser.run(argc, argv, -1);
  if (r_args.is_error()) {
    LOG(ERROR) << r_args.error();
    LOG(ERROR) << option_parser;
    return 1;
  }

  LOG(INFO) << "seal-server port=" << vsock_port << " enclave='" << enclave_path << "'";

  td::actor::Scheduler sched({SCHEDULER_THREADS});

  sched.run_in_context([&] {
    cocoon::Server::Config server_config{.port_ = vsock_port, .enclave_path = enclave_path};
    td::actor::create_actor<cocoon::Server>("PersistentKeyServer", std::move(server_config)).release();
  });

  sched.start();
  LOG(INFO) << "started";

  // Run scheduler until interrupted
  while (sched.run(SCHEDULER_TIMEOUT_MS)) {
    // Continue processing
  }

  LOG(INFO) << "done";
  return 0;
}
#else
int main(int, char**) {
  return 0;
}
#endif
