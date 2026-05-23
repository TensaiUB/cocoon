#pragma once
#include "td/utils/Status.h"
#include "td/utils/UInt.h"
#include "tee/cocoon/RATLS.h"
#include <memory>
#include <optional>

namespace cocoon {

// Thread-safe synchronous interface for caching attestation verification results
// Used during SSL verification callback (which is synchronous)
class AttestationCache {
 public:
  virtual ~AttestationCache() = default;

  struct CacheEntry {
    RATLSAttestationReport report;
  };

  struct Config {
    size_t max_entries{10000};
  };

  // Query cache by quote hash (thread-safe)
  // Returns: empty optional if not found
  virtual std::optional<CacheEntry> get(const td::UInt256& quote_hash) = 0;

  // Store attestation result in cache (thread-safe)
  virtual void put(const td::UInt256& quote_hash, RATLSAttestationReport) = 0;

  // Create default in-memory cache
  static std::shared_ptr<AttestationCache> create(Config config);
};

}  // namespace cocoon
