# Copyright (C) 2012 Nils Schneider <nils at nilsschneider.net>
# This is free software, licensed under the Apache 2.0 license.

include $(TOPDIR)/rules.mk

PKG_NAME:=gluon-setup-mode
PKG_VERSION:=1

include ../gluon.mk

define Package/gluon-setup-mode
  TITLE:=Our setup mode has dhcp client on setup_ifname (WAN), and 203.0.113.1/24 on lan_ifname (LAN)
  DEPENDS:=+gluon-core +gluon-lock-password +ubus +dnsmasq
endef

define Package/gluon-setup-mode/description
	Mode to perform basic setup in a connected way (i. e. with Internet access)
endef

$(eval $(call BuildPackageGluon,gluon-setup-mode))
