/*
 * Self-check for the tun group's sanitiser (ioctls/tun.c), held to what
 * __tun_chr_ioctl() (drivers/net/tun.c) takes: TUNSETLINK's link type,
 * which it refuses for IEEE 802.15.4, its monitor type and 6LoWPAN,
 * compared as an unsigned short, and takes otherwise.
 */

#include <stdbool.h>
#include <string.h>
#include <linux/if_arp.h>
#include <linux/if_tun.h>

#include "debug.h"		/* BUG */
#include "fake_ioctls.h"
#include "ioctls.h"		/* struct ioctl_group */
#include "syscall.h"		/* struct syscallrecord */

#define ROUNDS		4000

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

void tun_ioctl_self_check(void);
void tun_ioctl_self_check(void)
{
	tun_grp = fake_ioctl_group("tun");
	if (tun_grp == NULL)
		BUG("tun: the group did not register");
	draws_link_types();
}
