#include <asm/uaccess.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/path.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/namei.h>
#include <linux/slab.h>
#include <linux/kthread.h>
#include <linux/delay.h>
#include <linux/mm.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>
#include <linux/netdevice.h>

#include <linux/mm_types.h>
#include <linux/pagemap.h>
#include <asm/pgtable.h>

#include <linux/proc_fs.h>
#include <linux/ethtool.h>
#include <linux/etherdevice.h>

#include <linux/hypercall.h>
#include <linux/dyndev.h>
#include <linux/netdev_features.h>
#include <linux/if_arp.h>
#include <linux/ethtool.h>

#include "hyperutils.h"
#include "dyndev_netdev.h"

static int num_net_devices = 0;
static struct net_device **netdevs = NULL;

static char *nulltermdevnames = NULL;
static char **device_names = NULL;

static u32 always_on(struct net_device *dev)
{
	return 1;
}

static const struct ethtool_ops netdev_ethtool_ops = {
	.get_link		= always_on,
};

static void netdev_dev_free(struct net_device *dev)
{
	int i;
	for (i = 0; i < num_net_devices; i++){
		if (netdevs[i] == dev){
			free_netdev(netdevs[i]);
			netdevs[i] = NULL;
			return;
		}
	}
	printk(KERN_ERR "netdev_dev_free: netdev not found\n");
}

static int netdev_dev_init(struct net_device *dev){
	return 0;
}

static netdev_tx_t netdev_xmit(struct sk_buff *skb, struct net_device *dev)
{
	return NETDEV_TX_OK;
}

static struct rtnl_link_stats64 *netdev_get_stats64(struct net_device *dev,
						      struct rtnl_link_stats64 *stats){
	return stats;
}

static const struct net_device_ops netdev_ops = {
	.ndo_init      = netdev_dev_init,
	.ndo_start_xmit= netdev_xmit,
	.ndo_get_stats64 = netdev_get_stats64,
	.ndo_set_mac_address = eth_mac_addr,
};

static void netdev_setup(struct net_device *dev)
{
	dev->mtu		= 64 * 1024;
	dev->hard_header_len	= ETH_HLEN;	/* 14	*/
	dev->min_header_len	= ETH_HLEN;	/* 14	*/
	dev->addr_len		= ETH_ALEN;	/* 6	*/
	dev->type		= ARPHRD_ETHER;
	dev->flags		= IFF_LOOPBACK;
	dev->priv_flags		|= IFF_LIVE_ADDR_CHANGE | IFF_NO_QUEUE;
	netif_keep_dst(dev);
	dev->hw_features	= NETIF_F_GSO_SOFTWARE;
	dev->features 		= NETIF_F_SG | NETIF_F_FRAGLIST
		| NETIF_F_GSO_SOFTWARE
		| NETIF_F_HW_CSUM
		| NETIF_F_RXCSUM
		| NETIF_F_SCTP_CRC
		| NETIF_F_HIGHDMA
		| NETIF_F_LLTX
		| NETIF_F_NETNS_LOCAL
		| NETIF_F_VLAN_CHALLENGED
		| NETIF_F_LOOPBACK;
	dev->ethtool_ops	= &netdev_ethtool_ops;
	dev->header_ops		= &eth_header_ops;
	dev->netdev_ops		= &netdev_ops;
	dev->destructor		= netdev_dev_free;
}

int dyndev_init_netdevs(char *devnames) {
	char *str, *it;
	int i, err;

	if (!devnames || !(*devnames)){
		printk(KERN_ERR "dyndev: no netdev names provided\n");
		return 0;
	}

	// First, count the number of devices to allocate memory
	for (str = devnames;; str++) {
		if (*str == '\0'){
			num_net_devices++;
			break;
		}else if (*str == ',') {
            num_net_devices++;
        }
    }
	printk(KERN_ERR "dyndev: found %d netdev names\n", num_net_devices);

	nulltermdevnames = kmalloc(strlen(devnames) + 1, GFP_KERNEL);

	strcpy(nulltermdevnames, devnames);
	// Next, turn the devices into a null terminated memory area
	for (str = nulltermdevnames; *str; str++) {
        if (*str == ',') {
			*str = '\0';
		}
	}

	// Next, make each member point to the start of the device name
	device_names = kmalloc(sizeof(char*) * num_net_devices, GFP_KERNEL);
	it = nulltermdevnames;
	for (i = 0; i < num_net_devices; i++){
		device_names[i] = it;
		it += strlen(it) + 1;
	}

	// Finally, allocate the netdevs
	netdevs = kmalloc(sizeof(struct net_device*) * num_net_devices, GFP_KERNEL);
	for (i = 0; i < num_net_devices; i++){
		netdevs[i] = alloc_netdev(0, device_names[i], NET_NAME_UNKNOWN, netdev_setup);
		err = register_netdev(netdevs[i]);
		if (err){
			printk(KERN_ERR "dyndev: Failed to register netdev %s\n", device_names[i]);
		}
	}
	return 0;
}

void dyndev_free_netdevs(void) {
	int i;
	for (i = 0; i < num_net_devices; i++){
		if (netdevs[i] != NULL){
			free_netdev(netdevs[i]);
		}
	}
}