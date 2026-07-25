/*
 * bridge_fdb_stp - FDB churn helpers.
 *
 * Netlink RTM_DELNEIGH builder for a single FDB entry (races the
 * receive-path learning re-installing the same lladdr) plus the
 * random-unicast MAC generator that feeds both the traffic burst's
 * per-frame source and the RTM_DELNEIGH target.
 */

#include <errno.h>
#include <stddef.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <linux/neighbour.h>
#include <linux/rtnetlink.h>

#include "childops-netlink.h"
#include "random.h"

#include "bridge-fdb-stp-internal.h"

/*
 * RTM_DELNEIGH for a fdb entry: family=AF_BRIDGE, ndm_ifindex=port,
 * NDA_LLADDR=mac.  Races the receive-path learning that may be
 * re-installing the same entry concurrently — the targeted
 * learn-vs-delete window.
 */
int build_fdb_del(struct nl_ctx *ctx, int port_ifindex,
		  const unsigned char *mac)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct ndmsg *ndm;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = RTM_DELNEIGH;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = nl_seq_next(ctx);

	ndm = (struct ndmsg *)NLMSG_DATA(nlh);
	ndm->ndm_family  = AF_BRIDGE;
	ndm->ndm_ifindex = port_ifindex;
	ndm->ndm_state   = NUD_REACHABLE;
	ndm->ndm_flags   = NTF_MASTER;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*ndm));
	off = nla_put(buf, off, sizeof(buf), NDA_LLADDR, mac, 6);
	if (!off)
		return -EIO;

	nlh->nlmsg_len = (__u32)off;
	return nl_send_recv(ctx, buf, off);
}

/*
 * Generate a random unicast, locally-administered MAC.  Bit 0 of the
 * first byte is the multicast bit (must be 0); bit 1 is the
 * locally-administered bit (set so we don't collide with any host
 * OUI).  br_fdb_update accepts any unicast lladdr.
 */
void random_unicast_lla(unsigned char *mac)
{
	generate_rand_bytes(mac, 6);
	mac[0] = (unsigned char)((mac[0] & 0xfc) | 0x02);
}
