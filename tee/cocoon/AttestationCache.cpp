#include "AttestationCache.h"
#include "td/utils/LRUCache.h"
#include "td/utils/Time.h"
#include "td/utils/logging.h"
#include "td/utils/misc.h"
#include <mutex>

namespace cocoon {
namespace {

class InMemoryAttestationCache final : public AttestationCache {
 public:
  explicit InMemoryAttestationCache(Config config) : config_(std::move(config)), cache_(config_.max_entries) {
  }

  std::optional<CacheEntry> get(const td::UInt256& quote_hash) override {
    std::lock_guard<std::mutex> lock(mutex_);

    auto* entry = cache_.get_if_exists(quote_hash);
    if (!entry) {
      return std::nullopt;
    }

    return *entry;
  }

  void put(const td::UInt256& quote_hash, RATLSAttestationReport report) override {
    std::lock_guard<std::mutex> lock(mutex_);

    cache_.put(quote_hash, CacheEntry{std::move(report)});

    LOG(DEBUG) << "Cached attestation for quote hash " << td::hex_encode(quote_hash.as_slice());
  }

 private:
  Config config_;
  std::mutex mutex_;
  td::LRUCache<td::UInt256, CacheEntry> cache_;
};

}  // namespace

std::shared_ptr<AttestationCache> AttestationCache::create(Config config) {
  return std::make_shared<InMemoryAttestationCache>(std::move(config));
}

}  // namespace cocoon
