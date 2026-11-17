/*
 * Self-check for the tun group's sanitiser (ioctls/tun.c), held to what
 * __tun_chr_ioctl() (drivers/net/tun.c) takes: TUNSETLINK's link type,
 * which it refuses for IEEE 802.15.4, its monitor type and 6LoWPAN,
 * compared as an unsigned short; and TUNSETOFFLOAD's features, UDP
 * tunnel GSO among them, with a vnet header size that has a write carry
 * the tunnel header.
 */

#include <stdbool.h>
#include <string.h>
#include <linux/if_arp.h>
#include <linux/if_tun.h>

#include "debug.h"		/* BUG */
#include "fake_ioctls.h"
#include "ioctls.h"		/* struct ioctl_group */
#include "kernel/if_tun.h"	/* TUN_F_* */
#include "syscall.h"		/* struct syscallrecord */

#define ROUNDS		4000

/* sizeof(struct virtio_net_hdr_v1_hash_tunnel) */
#define TUN_VNET_TNL_SIZE	24

static const struct ioctl_group *tun_grp;

static bool in_table(unsigned long request)
{
	unsigned int i;

	for (i = 0; i < tun_grp->ioctls_cnt; i++) {
		if (tun_grp->ioctls[i].request == request)
			return true;
	}
	return false;
}

/* The arg the sanitiser leaves for @request. */
static unsigned long tun_arg(unsigned long request)
{
	static struct syscallrecord rec;

	memset(&rec, 0, sizeof(rec));
	fake_ioctl_request = request;
	tun_grp->sanitise(tun_grp, &rec);
	return rec.a3;
}

static void draws_link_types(void)
{
	unsigned int i, refused = 0, high = 0;

	if (!in_table(TUNSETLINK))
		BUG("tun: TUNSETLINK is not in the group's table");
	for (i = 0; i < ROUNDS; i++) {
		unsigned long arg = tun_arg(TUNSETLINK);
		unsigned short type = (unsigned short) arg;

		if (type == ARPHRD_IEEE802154 ||
		    type == ARPHRD_IEEE802154_MONITOR ||
		    type == ARPHRD_6LOWPAN)
			refused++;
		if (arg > 0xffff)
			high++;
	}
	if (refused == 0 || refused > ROUNDS / 4)
		BUG("tun: TUNSETLINK's link types are not mostly ones it takes, with the refused ones among them");
	if (high == 0)
		BUG("tun: no TUNSETLINK type has a bit set past the low 16");
}

/*
 * What set_offload() leaves of @arg once it has taken every feature it
 * can, 0 when it takes them all; *@tunnel says whether UDP tunnel GSO,
 * which it takes only beside CSUM and a plain GSO, was among them.
 */
static unsigned long offload_left(unsigned long arg, bool *tunnel)
{
	bool plain = false;

	*tunnel = false;
	if (!(arg & TUN_F_CSUM))
		return arg;
	arg &= ~TUN_F_CSUM;
	if (arg & (TUN_F_TSO4 | TUN_F_TSO6)) {
		plain = true;
		arg &= ~(TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_TSO_ECN);
	}
	arg &= ~TUN_F_UFO;
	if ((arg & TUN_F_USO4) && (arg & TUN_F_USO6)) {
		plain = true;
		arg &= ~(TUN_F_USO4 | TUN_F_USO6);
	}
	if (plain && (arg & TUN_F_UDP_TUNNEL_GSO)) {
		*tunnel = true;
		arg &= ~(TUN_F_UDP_TUNNEL_GSO | TUN_F_UDP_TUNNEL_GSO_CSUM);
	}
	return arg;
}

static void draws_tunnel_offloads(void)
{
	unsigned int i, taken = 0, tunnel = 0, sized = 0;

	for (i = 0; i < ROUNDS; i++) {
		unsigned long arg;
		bool tnl;

		if (offload_left(tun_arg(TUNSETOFFLOAD), &tnl) == 0) {
			taken++;
			tunnel += tnl;
		}
		arg = tun_arg(TUNSETVNETHDRSZ);
		if (arg != FAKE_IOCTL_JUNK_ARG &&
		    *(const int *) arg == TUN_VNET_TNL_SIZE)
			sized++;
	}
	if (taken < ROUNDS / 2 || tunnel == 0)
		BUG("tun: TUNSETOFFLOAD's features are not mostly ones set_offload() takes, with UDP tunnel GSO among them");
	if (sized == 0)
		BUG("tun: no TUNSETVNETHDRSZ is as long as the UDP tunnel header");
}

void tun_ioctl_self_check(void);
void tun_ioctl_self_check(void)
{
	tun_grp = fake_ioctl_group("tun");
	if (tun_grp == NULL)
		BUG("tun: the group did not register");
	draws_link_types();
	draws_tunnel_offloads();
}
