/*
 * netfilter module for userspace packet logging daemons
 *
 * (C) 2000-2002 by Harald Welte <laforge@gnumonks.org>
 *
 * Modified for compatibility with Linux kernel 4.10
 */

#define EXPORT_SYMTAB

#include <linux/netlink.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/module.h>
#include <linux/netfilter_bridge.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/br_netfilter.h>

MODULE_AUTHOR("Harald Welte <laforge@gnumonks.org>");
MODULE_DESCRIPTION("IP tables userspace logging module");

static struct sock *igloolognl;    /* our socket */

void igloo_rcv(struct sk_buff *skb){
    printk(KERN_INFO "igloo: received netlink message\n");
}

static int __init igloo_netlink_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = igloo_rcv,
    };

    igloolognl = netlink_kernel_create(&init_net, 0x1a, &cfg);
    if (!igloolognl)
        return -ENOMEM;

    return 0;
}

static void __exit igloo_netlink_exit(void)
{
    netlink_kernel_release(igloolognl);
}

module_init(igloo_netlink_init);
module_exit(igloo_netlink_exit);
