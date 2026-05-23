#pragma once

#include <type_traits>

#include "td/utils/Slice-decl.h"
#include "td/utils/Status.h"
#include "td/utils/StringBuilder.h"
#include "td/utils/UInt.h"

namespace sev {

// AMD SEV-SNP ABI Specification (PDF)
// Chapter 10 APPENDIX: Digital Signatures
enum class SigningAlgorithm : td::uint32 {
  ECDSA_P384_with_SHA384 = 1,
};
td::StringBuilder &operator<<(td::StringBuilder &sb, SigningAlgorithm algo);

enum class ECCCurve : td::uint32 {
  P384 = 2,
};
td::StringBuilder &operator<<(td::StringBuilder &sb, ECCCurve curve);

struct ECDSAP384withSHA384Signature {
  td::UInt<576> R;
  td::UInt<576> S;
  td::uint8 reserved[368];
};
static_assert(sizeof(ECDSAP384withSHA384Signature) == 512);
td::StringBuilder &operator<<(td::StringBuilder &sb, const ECDSAP384withSHA384Signature &signature);

struct ECDSAP384PublicKey {
  ECCCurve curve;
  td::UInt<576> QX;
  td::UInt<576> QY;
  td::uint8 reserved[880];
};
static_assert(sizeof(ECDSAP384PublicKey) == 1028);
td::StringBuilder &operator<<(td::StringBuilder &sb, const ECDSAP384PublicKey &public_key);

// Chapter 4.3 Guest Policy
struct GuestPolicy {
  td::uint64 reserved_must_be_zero : 38;
  td::uint64 page_swap_disable : 1;
  td::uint64 ciphertext_hiding_dram : 1;
  td::uint64 rapl_dis : 1;
  td::uint64 mem_aes_256_xts : 1;
  td::uint64 cxl_allow : 1;
  td::uint64 single_socket : 1;
  td::uint64 debug : 1;
  td::uint64 migrate_ma : 1;
  td::uint64 reserved_must_be_one : 1;
  td::uint64 smt : 1;
  td::uint64 abi_major : 8;
  td::uint64 abi_minor : 8;
};
static_assert(sizeof(GuestPolicy) == sizeof(td::uint64));
td::StringBuilder &operator<<(td::StringBuilder &sb, GuestPolicy guest_policy);

union GuestPolicyCastDevice {
  GuestPolicy as_guest_policy;
  td::uint64 as_uint64;
};
static_assert(sizeof(GuestPolicyCastDevice) == sizeof(GuestPolicy));

struct GuestFieldSelect {
  td::uint64 launch_mit_vector : 1;
  td::uint64 tcb_version : 1;
  td::uint64 guest_svn : 1;
  td::uint64 measurement : 1;
  td::uint64 family_id : 1;
  td::uint64 image_id : 1;
  td::uint64 guest_policy : 1;
  td::uint64 reserved : 57;
};
static_assert(sizeof(GuestFieldSelect) == sizeof(td::uint64));

union GuestFieldSelectCastDevice {
  GuestFieldSelect as_guest_field_select;
  td::uint64 as_uint64;
};
static_assert(sizeof(GuestFieldSelectCastDevice) == sizeof(GuestFieldSelect));

struct PlatformInfo {
  td::uint64 reserved : 56;
  td::uint64 tio_en : 1;
  td::uint64 reserved2 : 1;
  td::uint64 alias_check_complete : 1;
  td::uint64 ciphertext_hiding_dram_en : 1;
  td::uint64 rapl_dis : 1;
  td::uint64 ecc_en : 1;
  td::uint64 tsme_en : 1;
  td::uint64 smt_en : 1;
};
static_assert(sizeof(PlatformInfo) == sizeof(td::uint64));
td::StringBuilder &operator<<(td::StringBuilder &sb, PlatformInfo platform_info);

// Chapter 2 Data Structures and Encodings
// 2.2 TCB_VERSION
enum class TCBVersion {
  V0,
  V1,
};

struct TCBVersionV1 {
  td::uint64 fmc : 8;
  td::uint64 boot_loader : 8;
  td::uint64 tee : 8;
  td::uint64 snp : 8;
  td::uint64 reserved : 24;
  td::uint64 microcode : 8;
};
static_assert(sizeof(TCBVersionV1) == sizeof(td::uint64));
td::StringBuilder &operator<<(td::StringBuilder &sb, TCBVersionV1 tcb_version);

struct TCBVersionV0 {
  td::uint64 boot_loader : 8;
  td::uint64 tee : 8;
  td::uint64 reserved : 32;
  td::uint64 snp : 8;
  td::uint64 microcode : 8;
};
static_assert(sizeof(TCBVersionV0) == sizeof(td::uint64));
td::StringBuilder &operator<<(td::StringBuilder &sb, TCBVersionV0 tcb_version);

union TCBVersionCastDevice {
  TCBVersionV0 as_v0;
  TCBVersionV1 as_v1;
  td::uint64 as_uint64;
};
static_assert(sizeof(TCBVersionCastDevice) == sizeof(td::uint64));

// Chapter 7.3 Attestation
// Table 23. ATTESTATION_REPORT Structure
struct AttestationReport {
  td::uint32 version;
  td::uint32 guest_svn;
  GuestPolicy policy;
  td::UInt128 family_id;
  td::UInt128 image_id;
  td::uint32 vmpl;
  SigningAlgorithm signature_algo;
  td::uint64 current_tcb;
  PlatformInfo platform_info;

  td::uint32 reserved_must_be_zero_0 : 27;
  td::uint32 signing_key : 3;
  td::uint32 mask_chip_key : 1;
  td::uint32 author_key_en : 1;

  td::uint32 reserved_must_be_zero_1;
  td::UInt512 report_data;
  td::UInt384 measurement;
  td::UInt256 host_data;
  td::UInt384 id_key_digest;
  td::UInt384 author_key_digest;
  td::UInt256 report_id;
  td::UInt256 report_id_ma;
  td::uint64 reported_tcb;
  // Added in version 3
  td::uint8 cpuid_fam_id;
  td::uint8 cpuid_mod_id;
  td::uint8 cpuid_step;
  td::uint8 reserved_1[21];
  td::UInt512 chip_id;
  td::uint64 commited_tcb;
  td::uint8 current_build;
  td::uint8 current_minor;
  td::uint8 current_major;
  td::uint8 reserved_2;
  td::uint8 committed_build;
  td::uint8 committed_minor;
  td::uint8 committed_major;
  td::uint8 reserved_3;
  td::uint64 launch_tcb;
  td::uint64 launch_mit_vector;
  td::uint64 current_mit_vector;
  td::uint8 reserved_4[152];
  ECDSAP384withSHA384Signature signature;
};
static_assert(sizeof(AttestationReport) == 1184);
static_assert(std::is_trivially_copyable_v<AttestationReport>);
td::StringBuilder &operator<<(td::StringBuilder &sb, const AttestationReport &report);

// Versioned Chip Endorsement
// Key (VCEK) Certificate and
// KDS Interface Specification
enum class ProductName {
  Milan,
  Genoa,
  Siena,
  Turin,
};

template <typename F>
auto for_each_product_name(F f) {
  if constexpr (std::is_same_v<decltype(f(ProductName::Milan)), td::Status>) {
    TRY_STATUS(f(ProductName::Milan));
    TRY_STATUS(f(ProductName::Genoa));
    TRY_STATUS(f(ProductName::Siena));
    TRY_STATUS(f(ProductName::Turin));

    return td::Status::OK();
  } else {
    static_assert(std::is_same_v<decltype(f(ProductName::Milan)), void>);

    f(ProductName::Milan);
    f(ProductName::Genoa);
    f(ProductName::Siena);
    f(ProductName::Turin);
  }
}

static inline bool operator<(ProductName x, ProductName y) {
  return static_cast<std::underlying_type_t<ProductName>>(x) < static_cast<std::underlying_type_t<ProductName>>(y);
}

td::CSlice product_name_to_string(ProductName product_name);
td::Result<ProductName> product_name_from_name(td::Slice n);
td::Result<ProductName> product_name_from_name_and_stepping(td::Slice nas);
td::StringBuilder &operator<<(td::StringBuilder &sb, ProductName product_name);
td::Result<ProductName> product_name_from_cpu(int cpu_fam_id, int cpu_mod_id);
td::Result<ProductName> product_name_from_this_cpu();
td::uint32 make_cpu_signature(int cpu_fam_id, int cpu_mod_id, int cpu_stepping);

}  // namespace sev
