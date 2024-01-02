include $(TOPDIR)/rules.mk
include $(INCLUDE_DIR)/kernel.mk
include $(TOPDIR)/.config
 
PKG_NAME:=spectrum_scan
PKG_RELEASE:=1.0
 
PKG_BUILD_DIR := $(BUILD_DIR)/$(PKG_NAME)
PKG_CONFIG_DEPENDS :=
 
include $(INCLUDE_DIR)/package.mk

define Package/$(PKG_NAME)
	SUBMENU:=Utilities
	CATEGORY:=Ruijie Properties
	TITLE:=spectrum_scan utility
	DEPENDS:= +liblua +libuci +libubus +libubox +libdebug +libpthread +libjson-c +rg_unified_framework +rg_crypto +libopenssl
ifeq ($(CONFIG_PACKAGE_fredis), y)
	DEPENDS += +rg_proto +fredis
endif
endef

define Package/$(PKG_NAME)/description
	This is spectrum_scan.
endef

define Package/$(PKG_NAME)/config
menu "Configuration"
	config SPECTRUM_SCAN_2G
		bool "SPECTRUM_SCAN_2G"
		default n
		help
			SPECTRUM_SCAN_2G.
	config SPECTRUM_SCAN_REDBS_ENABLE
		bool "SPECTRUM_SCAN_REDBS_ENABLE"
		default y
		help
			SPECTRUM_SCAN_REDBS_ENABLE.
	config SPECTRUM_SCAN_TEST_ENABLE
		bool "SPECTRUM_SCAN_TEST_ENABLE"
		default n
		help
			SPECTRUM_SCAN_TEST_ENABLE.
	config SPECTRUM_SCAN_DEBUG_ENABLE
		bool "SPECTRUM_SCAN_DEBUG_ENABLE"
		default n
		help
			SPECTRUM_SCAN_DEBUG_ENABLE.
	config SPECTRUM_SCAN_5G
		bool "SPECTRUM_SCAN_5G"
		default y
		help
			SPECTRUM_SCAN_5G.
endmenu
endef

 
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./spectrum_scan_2g/src/* $(PKG_BUILD_DIR)/
	$(CP) ./src/* $(PKG_BUILD_DIR)/
	$(CP) ./libs/* $(PKG_BUILD_DIR)/

	mkdir -p $(PKG_BUILD_DIR)/show_apcli_enable/
	$(CP) ./show_apcli_enable/* $(PKG_BUILD_DIR)/show_apcli_enable/
	$(CP) ./src/spctrm_scn_* $(PKG_BUILD_DIR)/show_apcli_enable/
	$(CP) ./spectrum_scan_2g/src/* $(PKG_BUILD_DIR)/show_apcli_enable/
	$(CP) ./libs/* $(PKG_BUILD_DIR)/show_apcli_enable/

	mkdir -p $(PKG_BUILD_DIR)/ufplug/
	$(CP) ./ufplug/* $(PKG_BUILD_DIR)/ufplug/
	$(CP) ./libs/* $(PKG_BUILD_DIR)/ufplug/
ifeq ($(CONFIG_SPECTRUM_SCAN_TEST_ENABLE),y)
	mkdir -p $(PKG_BUILD_DIR)/test/
	$(CP) ./test/* $(PKG_BUILD_DIR)/test/
	$(CP) ./libs/* $(PKG_BUILD_DIR)/test/
endif

endef

define Build/Configure
endef



define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="$(TARGET_CPPFLAGS)"\ 
		LDFLAGS="$(TARGET_LDFLAGS)"

	$(MAKE) -C $(PKG_BUILD_DIR)/show_apcli_enable/ \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="$(TARGET_CPPFLAGS)"\ 
		LDFLAGS="$(TARGET_LDFLAGS)"

	$(MAKE) -C $(PKG_BUILD_DIR)/ufplug/ \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="$(TARGET_CPPFLAGS)"\ 
		LDFLAGS="$(TARGET_LDFLAGS)"
ifeq ($(CONFIG_SPECTRUM_SCAN_TEST_ENABLE),y)	
	$(MAKE) -C $(PKG_BUILD_DIR)/test/ \
		$(TARGET_CONFIGURE_OPTS) \
		CFLAGS="$(TARGET_CFLAGS)" \
		CPPFLAGS="$(TARGET_CPPFLAGS)"\ 
		LDFLAGS="$(TARGET_LDFLAGS)"
endif

endef


define Package/$(PKG_NAME)/install	
	$(INSTALL_DIR) $(1)/usr/local/schedule/1_min_crontab_task
	$(INSTALL_DIR) $(1)/tmp/spectrum_scan/
	$(INSTALL_DIR) $(1)/etc/spectrum_scan/
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) ./files/spectrum_scan.init $(1)/etc/init.d/spectrum_scan
	$(INSTALL_DIR) $(1)/usr/local/lua/dev_sta/
	$(INSTALL_BIN) ./files/spectrumScan.lua $(1)/etc/spectrum_scan/spectrumScan.lua
	$(INSTALL_DIR) $(1)/usr/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/spectrum_scan.elf $(1)/usr/sbin/spectrum_scan.elf
	$(INSTALL_DIR) $(1)/sbin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/show_apcli_enable/show_apcli_enable.elf $(1)/sbin/
	$(INSTALL_DIR) $(1)/usr/lib/ufplugins
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ufplug/spectrumScan.so $(1)/usr/lib/ufplugins
ifeq ($(CONFIG_SPECTRUM_SCAN_TEST_ENABLE),y)	
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/test/test.elf $(1)/usr/sbin/
endif

ifeq ($(CONFIG_SPECTRUM_SCAN_DEBUG_ENABLE),y)
	sed -i '/# debug code start/,/# debug code end/c\# debug code start\n\
	killall -9 unifyframe-sgi.elf\n\
	/etc/init.d/unifyframe-sgi restart\n\
	ubus call spectrum_scan.debug set '\''{"level":"INFO","module":"all","status":"open","tty":"/dev/tty"}'\''\n\
	# debug code end' $(1)/etc/init.d/spectrum_scan
else
	sed -i '/# debug code start/,/# debug code end/c\# debug code start\n# debug code end' $(1)/etc/init.d/spectrum_scan
endif

endef

$(eval $(call BuildPackage,$(PKG_NAME)))
