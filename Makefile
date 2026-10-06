ARCHS = arm64e
TARGET = iphone:clang:latest:15.0
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

APPLICATION_NAME = KexProofV2

KP_CHOMA_DIR = Sources/xpf/external/ChOma
KP_IMG4_DIR = Sources/xpf/external/img4lib

KexProofV2_FILES = \
	$(wildcard Sources/*.m) \
	$(wildcard Sources/TaskRop/*.m) \
	$(wildcard Sources/shim/*.c) \
	$(wildcard Sources/exploit/*.c) \
	$(wildcard Sources/exploit/*.m) \
	$(wildcard Sources/xpf/src/*.c) \
	$(wildcard $(KP_CHOMA_DIR)/src/*.c) \
	$(KP_IMG4_DIR)/lzss.c \
	$(filter-out $(KP_IMG4_DIR)/libvfs/vfs_lzvn.c, $(wildcard $(KP_IMG4_DIR)/libvfs/*.c)) \
	$(wildcard $(KP_IMG4_DIR)/libDER/*.c)

KexProofV2_FRAMEWORKS = UIKit Foundation CoreFoundation Security QuartzCore CoreLocation Metal
KexProofV2_PRIVATE_FRAMEWORKS = IOSurface IOKit
KexProofV2_LIBRARIES = compression

# -Wall -Wextra stay on, but no -Werror: third-party exploit/patchfinder code.
KexProofV2_CFLAGS = \
	-fobjc-arc -O2 -Wall -Wextra -Wno-error -Wno-deprecated-declarations \
	-include stdio.h \
	-ISources \
	-ISources/shim \
	-ISources/include \
	-ISources/TaskRop \
	-ISources/xpf/src \
	-I$(KP_CHOMA_DIR)/include \
	-I$(KP_IMG4_DIR) \
	-DUSE_COMMONCRYPTO -DUSE_LIBCOMPRESSION -DiOS10 \
	-DDER_MULTIBYTE_TAGS=1 "-D__unused=__attribute__((unused))" -DDER_TAG_SIZE=8 \
	-Wno-variadic-macros -Wno-multichar -Wno-four-char-constants -Wno-unused-parameter

# clang 11's arm64e chained fixups crash dyld4 on iOS 18 ("Address size fault"
# in _dyld_lookup_section_info) — emit the legacy fixup format instead.
KexProofV2_LDFLAGS =

KexProofV2_INSTALL_PATH = /Applications
KexProofV2_RESOURCE_DIRS = Resources
KexProofV2_CODESIGN_FLAGS = -SResources/entitlements.plist

include $(THEOS_MAKE_PATH)/application.mk
