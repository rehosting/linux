#include <linux/module.h>
#include <linux/netlink.h>
#include <net/net_namespace.h>
#include <net/sock.h>
#include "af_netlink.h"

//#define RESPONSE "hello world\0"

static struct sock *nl_sk = NULL;

static void nl_catch_all_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    int pid;
    struct sk_buff *skb_out;
    int msg_size = 512;
    int res;
    int i;

    nlh = (struct nlmsghdr*)skb->data;
    pid = nlh->nlmsg_pid; // PID of sending process

    // Printk the message
    printk(KERN_INFO "Received message from PID %d:\n", pid);
    for (i = 0; i < nlh->nlmsg_len; i++) {
        printk(KERN_CONT "%02x ", ((unsigned char *)nlh)[i]);
    }
    printk(KERN_CONT "\n");

    skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out)
    {
        printk(KERN_ERR "Failed to allocate new skb\n");
        return;
    } 

    // Add the message to the skb
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);  
    //strncpy(nlmsg_data(nlh), RESPONSE, msg_size);
    // Write 0xff * msg_size to the message
    memset(nlmsg_data(nlh), 0xff, msg_size);

    // Send the message back
    res = nlmsg_unicast(nl_sk, skb_out, pid);
    if (res < 0)
        printk(KERN_INFO "Error while sending back to user\n");
}

static int __init nl_catch_all_init(void)
{
    struct netlink_kernel_cfg cfg = {
        .input = nl_catch_all_recv_msg,
    };

    printk(KERN_INFO "Initializing catch-all Netlink protocol\n");

    nl_sk = netlink_kernel_create(&init_net, NETLINK_SHIM, &cfg);
    if (!nl_sk) {
        printk(KERN_ALERT "Error creating socket.\n");
        return -10;
    }

    return 0;
}

static void __exit nl_catch_all_exit(void)
{
    printk(KERN_INFO "Exiting catch-all Netlink protocol module\n");
    netlink_kernel_release(nl_sk);
}

module_init(nl_catch_all_init);
module_exit(nl_catch_all_exit);

MODULE_LICENSE("GPL");