#
# Makefile for the netlink driver.
#

obj-y  				:= af_netlink.o genetlink.o

obj-$(CONFIG_NETLINK_DIAG)	+= netlink_diag.o
obj-$(CONFIG_NETLINK_SHIM)	+= af_shim.o
netlink_diag-y			:= diag.o
