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

#include "ulog.h"

EXPORT_SYMBOL(ulog_target);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Harald Welte <laforge@gnumonks.org>");
MODULE_DESCRIPTION("IP tables userspace logging module");

#define ULOG_NL_EVENT       111     /* Harald's favorite number */
#define ULOG_MAXNLGROUPS    32      /* number of nlgroups */

#if 1
#define DEBUGP(format, args...) printk(KERN_INFO __FILE__ ":%s: " format, __FUNCTION__, ##args)
#else
#define DEBUGP(format, args...)
#endif


#define PRINTR(format, args...) do { if (net_ratelimit()) printk(format, ## args); } while (0)

static int nlbufsiz = 4096;
module_param(nlbufsiz, int, 0);
MODULE_PARM_DESC(nlbufsiz, "netlink buffer size");

static int flushtimeout = HZ / 10;
module_param(flushtimeout, int, 0);
MODULE_PARM_DESC(flushtimeout, "buffer flush timeout");

/* global data structures */

typedef struct {
    unsigned int qlen;       /* number of nlmsgs' in the skb */
    struct nlmsghdr *lastnlh;    /* netlink header of last msg in skb */
    struct sk_buff *skb;     /* the pre-allocated skb */
    struct timer_list timer; /* the timer function */
} ulog_buff_t;

static ulog_buff_t ulog_buffers[ULOG_MAXNLGROUPS]; /* array of buffers */

static struct sock *nflognl;    /* our socket */
static size_t qlen;     /* current length of multipart-nlmsg */
static DEFINE_SPINLOCK(ulog_lock);  /* spinlock */

/* send one ulog_buff_t to userspace */
static void ulog_send(unsigned int nlgroupnum)
{
    ulog_buff_t *ub = &ulog_buffers[nlgroupnum];

    if (timer_pending(&ub->timer)) {
        DEBUGP("ULOG: ulog_send: timer was pending, deleting\n");
        del_timer(&ub->timer);
    }

    /* last nlmsg needs NLMSG_DONE */
    if (ub->qlen > 1)
        ub->lastnlh->nlmsg_type = NLMSG_DONE;

    NETLINK_CB(ub->skb).dst_group = nlgroupnum + 1;
    DEBUGP("ULOG: throwing %d packets to netlink mask %u\n",
    	ub->qlen, nlgroupnum);
    netlink_broadcast(nflognl, ub->skb, 0, nlgroupnum + 1, GFP_ATOMIC);

    ub->qlen = 0;
    ub->skb = NULL;
    ub->lastnlh = NULL;
}

/* timer function to flush queue in ULOG_FLUSH_INTERVAL time */
static void ulog_timer(unsigned long data)
{
    ulog_buff_t *ub = (ulog_buff_t *)data;
    DEBUGP("ULOG: timer function called, calling ulog_send\n");

    /* lock to protect against somebody modifying our structure
     * from ulog_target at the same time */
    spin_lock_bh(&ulog_lock);
    ulog_send(ub - &ulog_buffers[0]);
    spin_unlock_bh(&ulog_lock);
}

struct sk_buff *ulog_alloc_skb(unsigned int size)
{
    struct sk_buff *skb;

    /* alloc skb which should be big enough for a whole
     * multipart message. WARNING: has to be <= 131000
     * due to slab allocator restrictions */

    skb = alloc_skb(nlbufsiz, GFP_ATOMIC);
    if (!skb) {
        PRINTR("ULOG: can't alloc whole buffer %ub!\n",
            nlbufsiz);

        /* try to allocate only as much as we need for
         * current packet */

        skb = alloc_skb(size, GFP_ATOMIC);
        if (!skb)
            PRINTR("ULOG: can't even allocate %ub\n", size);
    }

    return skb;
}

void ulog_target(const struct sk_buff *skb, const struct net_device *in,
         const struct net_device *out,
         struct ulog_info *loginfo, char type) {
    ulog_buff_t *ub;
    ulog_packet_msg_t *pm;
    size_t size, copy_len;
    struct nlmsghdr *nlh;
    enum ip_conntrack_info ctinfo;
    const struct nf_bridge_info *nf_bridge;
    struct nf_conn *ct = nf_ct_get(skb, &ctinfo);

    /* ffs == find first bit set, necessary because userspace
     * is already shifting groupnumber, but we need unshifted.
     * ffs() returns [1..32], we need [0..31] */
    unsigned int groupnum = ffs(loginfo->nl_group) - 1;

    /* calculate the size of the skb needed */
    if ((loginfo->copy_range == 0) ||
        (loginfo->copy_range > skb->len)) {
        copy_len = skb->len;
    } else {
        copy_len = loginfo->copy_range;
    }

    size = NLMSG_SPACE(sizeof(*pm) + copy_len);

    ub = &ulog_buffers[groupnum];

    spin_lock_bh(&ulog_lock);

    if (!ub->skb) {
        if (!(ub->skb = ulog_alloc_skb(size)))
            goto alloc_failure;
    } else if (ub->qlen >= loginfo->qthreshold ||
           size > skb_tailroom(ub->skb)) {
        /* either the queue len is too high or we don't have
         * enough room in nlskb left. send it to userspace. */

        ulog_send(groupnum);

        if (!(ub->skb = ulog_alloc_skb(size)))
            goto alloc_failure;
    }

    DEBUGP("ULOG: qlen %d, qthreshold %d\n", ub->qlen,
        loginfo->qthreshold);

    nlh = nlmsg_put(ub->skb, 0, ub->qlen, ULOG_NL_EVENT,
            size - sizeof(*nlh), 0);
    if( !nlh)
        goto nlmsg_failure;
    ub->qlen++;

    pm = NLMSG_DATA(nlh);
    memset(pm, 0, sizeof(*pm));

    /* copy prefix, payload, etc. */
    if (loginfo->prefix[0] != '\0')
        strncpy(pm->prefix, loginfo->prefix, sizeof(pm->prefix));

    if (skb_network_header(skb) - skb_mac_header(skb) ==
        sizeof(struct ethhdr)) {
        memcpy(pm->mac, eth_hdr(skb)->h_source, ETH_ALEN);
    }

    if (in) pm->indev_idx = in->ifindex;

    if (out) pm->outdev_idx = out->ifindex;

    pm->ingress_prio = skb->ingress_priority;
    pm->egress_prio = skb->priority;

    pm->type = type;

    pm->inphysdev_idx = -1;
    pm->outphysdev_idx = -1;

    nf_bridge = nf_bridge_info_get(skb);
    if (nf_bridge) {
        if (nf_bridge->physindev) {
            pm->inphysdev_idx = nf_bridge->physindev->ifindex;
        }
        if (nf_bridge->physoutdev) {
            pm->outphysdev_idx = nf_bridge->physoutdev->ifindex;
        }
    }

    if (ct) {
        struct nf_conntrack_tuple *src = &ct->tuplehash[IP_CT_DIR_ORIGINAL].tuple;
        struct nf_conntrack_tuple *dst = &ct->tuplehash[IP_CT_DIR_REPLY].tuple;
        pm->ct = true;
        if (ctinfo < IP_CT_IS_REPLY) {
            memcpy(pm->ct_src1, &src->src.u3, sizeof(pm->ct_src1));
            memcpy(pm->ct_src2, &dst->dst.u3, sizeof(pm->ct_src2));
            memcpy(pm->ct_dst1, &src->dst.u3, sizeof(pm->ct_dst1));
            memcpy(pm->ct_dst2, &dst->src.u3, sizeof(pm->ct_dst2));
            pm->ct_src1_port = src->src.u.all;
            pm->ct_src2_port = dst->dst.u.all;
            pm->ct_dst1_port = src->dst.u.all;
            pm->ct_dst2_port = dst->src.u.all;
        }
        else {
            memcpy(pm->ct_src1, &dst->src.u3, sizeof(pm->ct_src1));
            memcpy(pm->ct_src2, &src->dst.u3, sizeof(pm->ct_src2));
            memcpy(pm->ct_dst1, &dst->dst.u3, sizeof(pm->ct_dst1));
            memcpy(pm->ct_dst2, &src->src.u3, sizeof(pm->ct_dst2));
            pm->ct_src1_port = dst->src.u.all;
            pm->ct_src2_port = src->dst.u.all;
            pm->ct_dst1_port = dst->dst.u.all;
            pm->ct_dst2_port = src->src.u.all;
        }
    }

    if (copy_len) {
        if (type == 0) {
            memcpy(pm->payload, skb_mac_header(skb), copy_len);
        }
        else if (type == 1) {
            memcpy(pm->payload, ip_hdr(skb), copy_len);
        }
        else if (type == 2) {
            memcpy(pm->payload, ipv6_hdr(skb), copy_len);
        }
    }

    /* check if we are building multi-part messages */
    if (ub->qlen > 1) {
        ub->lastnlh->nlmsg_flags |= NLM_F_MULTI;
    }

    /* if threshold is reached, send message to userspace */
    if (qlen >= loginfo->qthreshold) {
        if (loginfo->qthreshold > 1)
            nlh->nlmsg_type = NLMSG_DONE;
    }

    ub->lastnlh = nlh;

    /* if timer isn't already running, start it */
    if (!timer_pending(&ub->timer)) {
        mod_timer(&ub->timer, jiffies + flushtimeout);
    }

    spin_unlock_bh(&ulog_lock);

    return;

nlmsg_failure:
    PRINTR("ULOG: error during NLMSG_PUT\n");

alloc_failure:
    PRINTR("ULOG: Error building netlink message\n");

    spin_unlock_bh(&ulog_lock);
}

static int __init ulog_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .groups = ULOG_MAXNLGROUPS,
    };
    int i;

    DEBUGP("ULOG: init module\n");

    if (nlbufsiz >= 128*1024) {
        printk("Netlink buffer has to be <= 128kB\n");
        return -EINVAL;
    }

    /* initialize ulog_buffers */
    for (i = 0; i < ULOG_MAXNLGROUPS; i++) {
        setup_timer(&ulog_buffers[i].timer, ulog_timer, (unsigned long)&ulog_buffers[i]);
    }

    nflognl = netlink_kernel_create(&init_net, NETLINK_NFLOG, &cfg);
    if (!nflognl)
        return -ENOMEM;

    return 0;
}

static void __exit ulog_exit(void)
{
    ulog_buff_t *ub;
    int i;

    DEBUGP("ULOG: cleanup_module\n");

    netlink_kernel_release(nflognl);

    /* remove pending timers and free allocated skb's */
    for (i = 0; i < ULOG_MAXNLGROUPS; i++) {
        ub = &ulog_buffers[i];
        if (timer_pending(&ub->timer)) {
            DEBUGP("timer was pending, deleting\n");
            del_timer(&ub->timer);
        }

        if (ub->skb) {
            kfree_skb(ub->skb);
            ub->skb = NULL;
        }
    }
}

module_init(ulog_init);
module_exit(ulog_exit);
