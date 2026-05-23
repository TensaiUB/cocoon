#pragma once
#include "td/utils/tl_parsers.h"
#include "td/utils/tl_storers.h"

/**
 * Common data structures for persistent key management protocol.
 * 
 * This file defines the TL (Type Language) schema for communication
 * between the client and SGX enclave server:
 * 
 * ```
 * persistentKey#163a179a sgx_quote:bytes encrypted_secret:bytes = PersistentKey;
 * getPersistentKey#317a821c tdx_report:bytes public_key:bytes key_name:string = PersistentKey;
 * ```
 */

namespace cocoon {
// Magic numbers for TL serialization
static constexpr td::uint32 PERSISTENT_KEY_MAGIC = 0x163a179a;
static constexpr td::uint32 GET_PERSISTENT_KEY_MAGIC = 0x317a821c;

/**
 * Request structure for persistent key generation.
 * 
 * Contains:
 * - tdx_report: Raw TDX report from the client (validates client's TEE state)
 * - public_key: Client's EC public key for ECDH key exchange (64 bytes: X||Y coordinates)
 * - key_name: Name for key derivation (e.g., "disk_encryption")
 */
struct GetPersistentKey {
  std::string tdx_report;  // TDX report (fixed size, typically ~1KB)
  std::string public_key;  // EC public key (64 bytes: 32-byte X + 32-byte Y)
  std::string key_name;    // Key name for derivation

  template <class StorerT>
  void store(StorerT &storer) const {
    using td::store;
    store(GET_PERSISTENT_KEY_MAGIC, storer);
    store(tdx_report, storer);
    store(public_key, storer);
    store(key_name, storer);
  }
  template <class ParserT>
  void parse(ParserT &parser) {
    using td::parse;
    td::uint32 magic;
    parse(magic, parser);
    if (magic != GET_PERSISTENT_KEY_MAGIC) {
      parser.set_error("Unexpected magic");
      return;
    }
    parse(tdx_report, parser);
    parse(public_key, parser);
    parse(key_name, parser);
  }
};

/**
 * Response structure containing the persistent key.
 * 
 * Contains:
 * - sgx_quote: SGX quote that proves the key was generated in a genuine SGX enclave
 * - encrypted_secret: The persistent key encrypted with ECDH-derived AES key
 *                    Format: enclave_public_key (64) || ciphertext (32)
 */
struct PersistentKey {
  std::string sgx_quote;         // SGX quote for attestation (variable size, ~3-5KB)
  std::string encrypted_secret;  // Encrypted persistent key (96 bytes total)
  template <class StorerT>
  void store(StorerT &storer) const {
    using td::store;
    store(PERSISTENT_KEY_MAGIC, storer);
    store(sgx_quote, storer);
    store(encrypted_secret, storer);
  }
  template <class ParserT>
  void parse(ParserT &parser) {
    using td::parse;
    td::uint32 magic;
    parse(magic, parser);
    if (magic != PERSISTENT_KEY_MAGIC) {
      parser.set_error("Unexpected magic");
      return;
    }
    parse(sgx_quote, parser);
    parse(encrypted_secret, parser);
  }
};
}  // namespace cocoon