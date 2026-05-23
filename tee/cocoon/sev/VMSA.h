#pragma once

#include <array>

#include "td/utils/int_types.h"
#include "td/utils/Slice-decl.h"

#include "tee/cocoon/sev/ABI.h"

namespace sev {

class VMSA {
 public:
  struct GuestFeatures {
    td::uint64 SNPActive : 1;
    td::uint64 vTOM : 1;
    td::uint64 ReflectVC : 1;
    td::uint64 RestrictedInjection : 1;
    td::uint64 AlternateInjection : 1;
    td::uint64 DebugVirtualization : 1;
    td::uint64 PreventHostIBS : 1;
    td::uint64 BTBIsolation : 1;
    td::uint64 VmplSSS : 1;
    td::uint64 SecureTSC : 1;
    td::uint64 VmgexitParameter : 1;
    td::uint64 PmcVirtualization : 1;
    td::uint64 IbsVirtualization : 1;
    td::uint64 GuestInterceptCtl : 1;
    td::uint64 VmsaRegProt : 1;
    td::uint64 SecureAvic : 1;
    td::uint64 reserved : 4;
    td::uint64 IbpbOnEntry : 1;
    td::uint64 reserved2 : 43;
  };

  static_assert(sizeof(GuestFeatures) == sizeof(td::uint64));

 public:
  VMSA(td::uint64 ap_ip, td::uint32 cpu_signature, GuestFeatures guest_features);

 private:
  static constexpr size_t kPageSize{4096};

 private:
  struct vmcb_seg {
    td::uint16 selector;
    td::uint16 attrib;
    td::uint32 limit;
    td::uint64 base;
  } __attribute__((__packed__));

  /* Save area definition for SEV-ES and SEV-SNP guests */
  struct sev_es_save_area {
    struct vmcb_seg es;
    struct vmcb_seg cs;
    struct vmcb_seg ss;
    struct vmcb_seg ds;
    struct vmcb_seg fs;
    struct vmcb_seg gs;
    struct vmcb_seg gdtr;
    struct vmcb_seg ldtr;
    struct vmcb_seg idtr;
    struct vmcb_seg tr;
    td::uint64 pl0_ssp;
    td::uint64 pl1_ssp;
    td::uint64 pl2_ssp;
    td::uint64 pl3_ssp;
    td::uint64 u_cet;
    td::uint8 reserved_0xc8[2];
    td::uint8 vmpl;
    td::uint8 cpl;
    td::uint8 reserved_0xcc[4];
    td::uint64 efer;
    td::uint8 reserved_0xd8[104];
    td::uint64 xss;
    td::uint64 cr4;
    td::uint64 cr3;
    td::uint64 cr0;
    td::uint64 dr7;
    td::uint64 dr6;
    td::uint64 rflags;
    td::uint64 rip;
    td::uint64 dr0;
    td::uint64 dr1;
    td::uint64 dr2;
    td::uint64 dr3;
    td::uint64 dr0_addr_mask;
    td::uint64 dr1_addr_mask;
    td::uint64 dr2_addr_mask;
    td::uint64 dr3_addr_mask;
    td::uint8 reserved_0x1c0[24];
    td::uint64 rsp;
    td::uint64 s_cet;
    td::uint64 ssp;
    td::uint64 isst_addr;
    td::uint64 rax;
    td::uint64 star;
    td::uint64 lstar;
    td::uint64 cstar;
    td::uint64 sfmask;
    td::uint64 kernel_gs_base;
    td::uint64 sysenter_cs;
    td::uint64 sysenter_esp;
    td::uint64 sysenter_eip;
    td::uint64 cr2;
    td::uint8 reserved_0x248[32];
    td::uint64 g_pat;
    td::uint64 dbgctl;
    td::uint64 br_from;
    td::uint64 br_to;
    td::uint64 last_excp_from;
    td::uint64 last_excp_to;
    td::uint8 reserved_0x298[80];
    td::uint32 pkru;
    td::uint32 tsc_aux;
    td::uint64 tsc_scale;
    td::uint64 tsc_offset;
    td::uint8 reserved_0x300[8];
    td::uint64 rcx;
    td::uint64 rdx;
    td::uint64 rbx;
    td::uint64 reserved_0x320; /* rsp already available at 0x01d8 */
    td::uint64 rbp;
    td::uint64 rsi;
    td::uint64 rdi;
    td::uint64 r8;
    td::uint64 r9;
    td::uint64 r10;
    td::uint64 r11;
    td::uint64 r12;
    td::uint64 r13;
    td::uint64 r14;
    td::uint64 r15;
    td::uint8 reserved_0x380[16];
    td::uint64 guest_exit_info_1;
    td::uint64 guest_exit_info_2;
    td::uint64 guest_exit_int_info;
    td::uint64 guest_nrip;
    td::uint64 sev_features;
    td::uint64 vintr_ctrl;
    td::uint64 guest_exit_code;
    td::uint64 virtual_tom;
    td::uint64 tlb_id;
    td::uint64 pcpu_id;
    td::uint64 event_inj;
    td::uint64 xcr0;
    td::uint8 reserved_0x3f0[16];
    /* Floating point area */
    td::uint64 x87_dp;
    td::uint32 mxcsr;
    td::uint16 x87_ftw;
    td::uint16 x87_fsw;
    td::uint16 x87_fcw;
    td::uint16 x87_fop;
    td::uint16 x87_ds;
    td::uint16 x87_cs;
    td::uint64 x87_rip;
    td::uint8 fpreg_x87[80];
    td::uint8 fpreg_xmm[256];
    td::uint8 fpreg_ymm[256];
  } __attribute__((__packed__));
  static_assert(sizeof(sev_es_save_area) == 1648);

 public:
  td::Slice bsp_page() const {
    return td::Slice(bsp_.data(), bsp_.size());
  }

  td::Slice ap_page() const {
    return td::Slice(ap_.data(), ap_.size());
  }

 private:
  void build_save_area(sev_es_save_area *area, td::uint64 ip, td::uint32 cpu_signature, GuestFeatures guest_features);

 private:
  std::array<td::uint8, 4096> bsp_;
  std::array<td::uint8, 4096> ap_;
};


}  // namespace sev
