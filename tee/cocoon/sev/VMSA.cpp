#include "tee/cocoon/sev/VMSA.h"

namespace sev {

VMSA::VMSA(td::uint64 ap_ip, td::uint32 cpu_signature, GuestFeatures guest_features) {
  bsp_.fill(0);
  ap_.fill(0);

  build_save_area(reinterpret_cast<sev_es_save_area*>(bsp_.data()), 0xfffffff0, cpu_signature, guest_features);
  if (ap_ip) {
    build_save_area(reinterpret_cast<sev_es_save_area*>(ap_.data()), ap_ip, cpu_signature, guest_features);
  }
}

void VMSA::build_save_area(sev_es_save_area* area, td::uint64 ip, td::uint32 cpu_signature,
                           GuestFeatures guest_features) {
  area->es = {0, 0x93, 0xffff, 0};
  area->cs = {0xf000, 0x9b, 0xffff, ip & 0xffff0000};
  area->ss = {0, 0x93, 0xffff, 0};
  area->ds = {0, 0x93, 0xffff, 0};
  area->fs = {0, 0x93, 0xffff, 0};
  area->gs = {0, 0x93, 0xffff, 0};
  area->gdtr = {0, 0, 0xffff, 0};
  area->idtr = {0, 0, 0xffff, 0};
  area->ldtr = {0, 0x82, 0xffff, 0};
  area->tr = {0, 0x8b, 0xffff, 0};
  area->efer = 0x1000;
  area->cr4 = 0x40;
  area->cr0 = 0x10;
  area->dr7 = 0x400;
  area->dr6 = 0xffff0ff0;
  area->rflags = 0x2;
  area->rip = ip & 0xffff;
  area->g_pat = 0x7040600070406ULL;

  area->rdx = cpu_signature;
  area->sev_features = guest_features.SNPActive;
  area->xcr0 = 0x1;
  area->mxcsr = 0x1f80;
  area->x87_fcw = 0x37f;
}

}  // namespace sev
