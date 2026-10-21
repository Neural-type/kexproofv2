#import "KPAppDelegate.h"
#import "KPViewController.h"
#import "exploit/kexploit_opa334.h"

@implementation KPAppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    NSLog(@"[KexProofV2] didFinishLaunching");
    self.window = [[UIWindow alloc] initWithFrame:[UIScreen mainScreen].bounds];

    KPViewController *main = [[KPViewController alloc] init];
    UINavigationController *nav = [[UINavigationController alloc] initWithRootViewController:main];

    UINavigationBarAppearance *appearance = [[UINavigationBarAppearance alloc] init];
    [appearance configureWithOpaqueBackground];
    appearance.backgroundColor = [UIColor colorWithRed:0.07 green:0.07 blue:0.09 alpha:1.0];
    appearance.titleTextAttributes = @{NSForegroundColorAttributeName: [UIColor whiteColor]};
    nav.navigationBar.standardAppearance = appearance;
    nav.navigationBar.scrollEdgeAppearance = appearance;

    self.window.rootViewController = nav;
    [self.window makeKeyAndVisible];
    return YES;
}

// PEV1-CLEANUP: pe_v1 (CVE-2025-43520) leaves control.icmp6filt corrupted on
// purpose (it IS the KRW primitive). soclose → rip6_detach → kfree_type of that
// pointer is the zalloc.c:829 panic. so_usecount leaking does NOT stop the free.
// Restore/NULL the pointer before the process dies. atexit() covers normal exit;
// this covers the app-shell teardown path.
- (void)applicationWillTerminate:(UIApplication *)application {
    NSLog(@"[KexProofV2] applicationWillTerminate — disarming icmp6filt");
    kexploit_disarm_for_close();
}

@end
