#include <linux/netlink.h>
#include <linux/skbuff.h>

#include "portal_internal.h"

static void handle_netlink_recv(struct sk_buff *skb)
{
	igloo_portal(IGLOO_HYP_NETLINK_RECV, skb->protocol, (unsigned long)skb);
}

static struct netlink_kernel_cfg cfg = {
.input = handle_netlink_recv,
};

void igloo_netlink_init(void)
{
	bool protocol_ids[32] = { 0 };
	igloo_portal(IGLOO_HYP_NETLINK_INIT, (unsigned long) &protocol_ids, 0);
}

void handle_op_reg_netlink(portal_region *mem_region)
{
	igloo_pr_debug("igloo: Handling HYPER_OP_REG_NETLINK\n");

	int protocol_id = le64_to_cpu(mem_region->header.addr);
	if (protocol_id < 17 || protocol_id > 31) {
		igloo_pr_debug("igloo: netlink: protocol ID must be between 17-31\n");
		mem_region->header.op = cpu_to_le64(HYPER_RESP_WRITE_FAIL);
		return;
	}
	struct sock *sock = netlink_kernel_create(&init_net, protocol_id, &cfg);
	if (!sock) {
		igloo_pr_debug("igloo: netlink: failed creating socket\n");
		mem_region->header.op = cpu_to_le64(HYPER_RESP_WRITE_FAIL);
		return;
	}

	igloo_pr_debug("igloo: netlink: created socket\n");
	mem_region->header.op = cpu_to_le64(HYPER_RESP_WRITE_OK);
}
