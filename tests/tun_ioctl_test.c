/*
 * Self-check for the tun group's sanitiser (ioctls/tun.c), held to what
 * __tun_chr_ioctl() (drivers/net/tun.c) takes: TUNSETLINK's link type,
 * which it refuses for IEEE 802.15.4, its monitor type and 6LoWPAN,
 * compared as an unsigned short; TUNSETOFFLOAD's features, UDP tunnel
 * GSO among them, with a vnet header size that has a write carry the
 * tunnel header; and TUNSETQUEUE's flags, which tun_set_queue() takes
 * only as a queue attach or detach.  And the fd it acts on: the ioctl
 * checks CAP_NET_ADMIN against the netns the fd was opened in, so a lane
 * child sends most calls to a /dev/net/tun of its own netns.
 */

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_tun.h>

#include "debug.h"		/* BUG */
#include "fake_ioctls.h"
#include "ioctls.h"		/* struct ioctl_group */
#include "kernel/if_tun.h"	/* TUN_F_* */
#include "syscall.h"		/* struct syscallrecord */
#include "utils.h"		/* waitpid_eintr */

extern bool fake_lane_active;	/* lane_socket_test.c */

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

static void draws_queue_attach_and_detach(void)
{
	unsigned int i, attach = 0, detach = 0;

	for (i = 0; i < ROUNDS; i++) {
		unsigned long arg = tun_arg(TUNSETQUEUE);
		short flags;

		if (arg == FAKE_IOCTL_JUNK_ARG)
			continue;
		flags = ((const struct ifreq *) arg)->ifr_flags;
		if (flags & IFF_ATTACH_QUEUE)
			attach++;
		else if (flags & IFF_DETACH_QUEUE)
			detach++;
	}
	if (attach == 0 || detach == 0)
		BUG("tun: TUNSETQUEUE does not both attach and detach a queue, all tun_set_queue() takes");
}

/* How the lane helper exits: it could not set up, the swap was not seven
 * calls in eight, or the fd it swapped in is not of the child's netns. */
#define LANE_NO_SETUP	77
#define LANE_RATE	1
#define LANE_NOT_OWN	2

/* TUNSETIFF of a tun device on @fd: 0, or the errno. */
static int setiff(int fd)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
	strcpy(ifr.ifr_name, "trinity%d");
	return ioctl(fd, TUNSETIFF, &ifr) == 0 ? 0 : errno;
}

/*
 * A helper opens /dev/net/tun as the parent does, in the netns it starts
 * in, then unshares a user and a network namespace as a lane child does
 * and draws the group's calls onto that fd.  Seven in eight go to another
 * tun fd, the same one each time, on which TUNSETIFF makes a device,
 * where on the drawn fd it is refused.  Returns the helper's status.
 */
static int lane_swap_status(void)
{
	pid_t pid = fork();
	int status;

	if (pid < 0)
		BUG("tun: fork failed");
	if (pid == 0) {
		unsigned int i, swapped = 0;
		int drawn, own = -1;

		/* Don't outlive the test binary if the check aborts. */
		prctl(PR_SET_PDEATHSIG, SIGKILL);
		drawn = open("/dev/net/tun", O_RDWR);
		if (drawn < 0 || unshare(CLONE_NEWUSER | CLONE_NEWNET) != 0)
			_exit(LANE_NO_SETUP);
		fake_lane_active = true;
		for (i = 0; i < ROUNDS; i++) {
			struct syscallrecord rec;

			memset(&rec, 0, sizeof(rec));
			rec.a1 = (unsigned long) drawn;
			fake_ioctl_request = TUNGETFEATURES;
			tun_grp->sanitise(tun_grp, &rec);
			if ((int) rec.a1 == drawn)
				continue;
			if (own < 0)
				own = (int) rec.a1;
			if ((int) rec.a1 != own)
				_exit(LANE_NOT_OWN);
			swapped++;
		}
		if (swapped < ROUNDS * 0.84 || swapped > ROUNDS * 0.91)
			_exit(LANE_RATE);
		if (setiff(drawn) != EPERM || setiff(own) != 0)
			_exit(LANE_NOT_OWN);
		_exit(0);
	}
	if (waitpid_eintr(pid, &status, 0) != pid)
		BUG("tun: cannot reap the lane helper");
	if (!WIFEXITED(status))
		BUG("tun: the lane helper died");
	return WEXITSTATUS(status);
}

static void lane_child_uses_its_own_tun(void)
{
	struct syscallrecord rec;
	unsigned int i;
	int status;

	/* Outside the lane the drawn fd stands. */
	for (i = 0; i < ROUNDS; i++) {
		memset(&rec, 0, sizeof(rec));
		rec.a1 = 5;
		fake_ioctl_request = TUNGETFEATURES;
		tun_grp->sanitise(tun_grp, &rec);
		if (rec.a1 != 5)
			BUG("tun: a child outside the lane had its fd swapped");
	}

	status = lane_swap_status();
	if (status == LANE_NO_SETUP) {
		printf("(SKIP: no /dev/net/tun or no user namespaces, the lane swap was not checked) ");
		return;
	}
	if (status == LANE_RATE)
		BUG("tun: a lane child does not swap seven calls in eight onto its own tun fd");
	if (status != 0)
		BUG("tun: the fd a lane child swaps in is not one of its own netns");
}

void tun_ioctl_self_check(void);
void tun_ioctl_self_check(void)
{
	tun_grp = fake_ioctl_group("tun");
	if (tun_grp == NULL)
		BUG("tun: the group did not register");
	draws_link_types();
	draws_tunnel_offloads();
	draws_queue_attach_and_detach();
	lane_child_uses_its_own_tun();
}
