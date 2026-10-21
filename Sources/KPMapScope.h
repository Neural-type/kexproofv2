//
//  KPMapScope.h
//  KexProofV2
//
//  R5e: read-only scope recon for the retype path.
//  Dumps kernel_pmap entries, page-mgmt flags, and the FTE oracle for our
//  ucred page. NEVER writes kernel memory.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface KPMapScope : NSObject

// R5e scope report (read-only):
//  1. page-mgmt flags at 0x7aa258a (promote-0x21) and 0x7aa2a31
//  2. kernel_pmap header + linked-list range walk (start/end/flags)
//  3. our ucred VA/PA + FTE type/refcount oracle
//  4. verdict: does any walked range cover ucred's VA?
+ (NSString *)kernelPmapScopeReport;
+ (NSString *)necpCalibReport;
+ (NSString *)glyphGriftProbeReport;
+ (NSString *)glyphSprayReport;
+ (NSString *)glyphSprayReportVariant:(nullable NSString *)forceName;
+ (NSString *)glyphTypedSprayReport:(nullable NSString *)forceName;

@end

NS_ASSUME_NONNULL_END
