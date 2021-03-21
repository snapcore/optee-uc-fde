ifeq ($O,)
out-dir := $(CURDIR)/out
else
include scripts/common.mk
out-dir := $(call strip-trailing-slashes-and-dots,$(O))
ifeq ($(out-dir),)
$(error invalid output directory (O=$(O)))
endif
endif

-include $(TA_DEV_KIT_DIR)/host_include/conf.mk

ifneq ($V,1)
	q := @
	echo := @echo
else
	q :=
	echo := @:
endif
# export 'q', used by sub-makefiles.
export q

# If _HOST or _TA specific compilers are not specified, then use CROSS_COMPILE
CROSS_COMPILE_HOST ?= $(CROSS_COMPILE)
CROSS_COMPILE_TA ?= $(CROSS_COMPILE)

.PHONY: all
all: ta fde-reveal-key fde-setup fde-key-manager

.PHONY: fde-reveal-key
fde-reveal-key:
	$(q)$(MAKE) -C host/fde_key_manager CROSS_COMPILE="$(CROSS_COMPILE_HOST)" \
			     --no-builtin-variables \
			     O=$(out-dir) \
			     $@

.PHONY: fde-setup
fde-setup:
	$(q)$(MAKE) -C host/fde_key_manager CROSS_COMPILE="$(CROSS_COMPILE_HOST)" \
			     --no-builtin-variables \
			     O=$(out-dir) \
			     $@

.PHONY: fde-key-manager
fde-key-manager:
	$(q)$(MAKE) -C host/fde_key_manager CROSS_COMPILE="$(CROSS_COMPILE_HOST)" \
			     --no-builtin-variables \
			     O=$(out-dir) \
			     $@

.PHONY: ta
ta:
	$(q)$(MAKE) -C ta CROSS_COMPILE="$(CROSS_COMPILE_TA)" \
			  O=$(out-dir) \
			  $@

.PHONY: clean
clean:
	$(q)$(MAKE) -C host/fde_key_manager O=$(out-dir) $@
	$(q)$(MAKE) -C ta O=$(out-dir) $@

install:
	$(echo) '  INSTALL ${DESTDIR}/lib/optee_armtz'
	$(q)mkdir -p ${DESTDIR}/lib/optee_armtz
	$(q)find $(out-dir)/ta -name \*.ta -exec cp -a {} ${DESTDIR}/lib/optee_armtz \;
	$(echo) '  INSTALL ${DESTDIR}/usr/bin'
	$(q)mkdir -p ${DESTDIR}/usr/bin
	$(q)cp -a $(out-dir)/fde_key_manager/fde-key-manager ${DESTDIR}/usr/bin
	$(q)cp -a $(out-dir)/fde_key_manager/fde-reveal-key ${DESTDIR}/usr/bin
	$(q)cp -a $(out-dir)/fde_key_manager/fde-setup ${DESTDIR}/usr/bin
