include $(RTE_SDK)/mk/rte.vars.mk

#
# library name
#
LIB = librte_pmd_xdpzc.a

+CFLAGS += -I/usr/src/linux-headers-`uname -r`/include

CFLAGS += -O3
CFLAGS += $(WERROR_FLAGS)
LDLIBS += -lpcap
LDLIBS += -lrte_eal -lrte_mbuf -lrte_mempool -lrte_ring
LDLIBS += -lrte_ethdev -lrte_net -lrte_kvargs
LDLIBS += -lrte_bus_vdev
LDLIBS += -L/usr/src/linux-headers-`uname -r`/tools/bpf/ -lbpf 

EXPORT_MAP := rte_pmd_xdpzc_version.map

LIBABIVER := 1

#
# all source are stored in SRCS-y
#
SRCS-$(CONFIG_RTE_LIBRTE_PMD_XDPZC) += rte_eth_xdpzc.c

#
# Export include files
#
SYMLINK-y-include +=

include $(RTE_SDK)/mk/rte.lib.mk
