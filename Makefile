TARGET := iphone:clang:latest:16.0
THEOS_PACKAGE_SCHEME=rootless
THEOS_PACKAGE_INSTALL_PREFIX=/var/jb

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = Relic2Demo

Relic2Demo_FILES = tweak.mm
Relic2Demo_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
#SUBPROJECTS += librelic2
#include $(THEOS_MAKE_PATH)/aggregate.mk