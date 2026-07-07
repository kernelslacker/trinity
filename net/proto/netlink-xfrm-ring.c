/*
 * netlink-xfrm-ring.c -- per-process SA + policy tracking rings
 * for the NETLINK_XFRM grammar.  Storage and ring operations live
 * here; the rest of the grammar consumes them through the externs in
 * include/proto-netlink-xfrm-internal.h.
 */

#include <stdbool.h>
#include <string.h>

#include "proto-netlink-xfrm-internal.h"
#include "random.h"

#include "kernel/netlink.h"
static struct xfrm_sa_track sa_ring[NR_SA_RING_SLOTS];
static unsigned int sa_ring_next;	/* next-write cursor */

static struct xfrm_policy_track policy_ring[NR_POLICY_RING_SLOTS];
static unsigned int policy_ring_next;

/*
 * SA ring management.  Push acquires the next slot; if the slot was
 * already occupied, evict by DELSA before overwriting.  Random pick
 * draws from used slots; returns false when the ring is empty.  Drop
 * clears a single slot.  Drain clears every slot (called after FLUSHSA).
 */
unsigned int sa_ring_count(void)
{
	unsigned int i, n = 0;

	for (i = 0; i < NR_SA_RING_SLOTS; i++)
		if (sa_ring[i].used)
			n++;
	return n;
}

/* Build XFRM_MSG_DELSA targeting one ring entry.  Used both for direct
 * DELSA rotation and for ring eviction. */
int xfrm_emit_delsa_for(int fd, const struct xfrm_sa_track *t)
{
	unsigned char buf[256];
	struct nlmsghdr *nlh;
	struct xfrm_usersa_id *uid;
	size_t off;

	memset(buf, 0, sizeof(buf));
	nlh = (struct nlmsghdr *)buf;
	nlh->nlmsg_type  = XFRM_MSG_DELSA;
	nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlh->nlmsg_seq   = xfrm_next_seq();

	uid = (struct xfrm_usersa_id *)NLMSG_DATA(nlh);
	uid->daddr  = t->daddr;
	uid->spi    = t->spi;
	uid->family = t->family;
	uid->proto  = t->proto;

	off = NLMSG_HDRLEN + NLMSG_ALIGN(sizeof(*uid));
	nlh->nlmsg_len = (__u32)off;
	return xfrm_send_recv(fd, buf, off);
}

int sa_ring_push(int fd, const struct xfrm_sa_track *entry)
{
	struct xfrm_sa_track *slot = &sa_ring[sa_ring_next];

	if (slot->used) {
		int rc = xfrm_emit_delsa_for(fd, slot);

		/* Eviction failed.  Give the SA a few ticks to become
		 * deletable before clobbering the slot -- a transient
		 * -EBUSY / -ESRCH window is normal.  After three
		 * consecutive failures the slot is wedged forever and
		 * the ring loses that coverage permanently, so
		 * force-overwrite; the kernel SAD is reset on netns
		 * teardown anyway. */
		if (rc != 0) {
			slot->evict_fail++;
			if (slot->evict_fail < 3)
				return rc;
			/* fall through to force-overwrite */
		}
	}

	*slot = *entry;
	slot->used = true;
	slot->evict_fail = 0;
	sa_ring_next = (sa_ring_next + 1) % NR_SA_RING_SLOTS;
	return 0;
}

bool sa_ring_pick(struct xfrm_sa_track *out, unsigned int *idx_out)
{
	unsigned int i, count = sa_ring_count();
	unsigned int pick, seen = 0;

	if (count == 0)
		return false;

	pick = rnd_modulo_u32(count);
	for (i = 0; i < NR_SA_RING_SLOTS; i++) {
		if (!sa_ring[i].used)
			continue;
		if (seen == pick) {
			*out = sa_ring[i];
			if (idx_out)
				*idx_out = i;
			return true;
		}
		seen++;
	}
	return false;
}

void sa_ring_drop(unsigned int idx)
{
	if (idx < NR_SA_RING_SLOTS)
		sa_ring[idx].used = false;
}

void sa_ring_drain(void)
{
	unsigned int i;

	for (i = 0; i < NR_SA_RING_SLOTS; i++)
		sa_ring[i].used = false;
}

unsigned int policy_ring_count(void)
{
	unsigned int i, n = 0;

	for (i = 0; i < NR_POLICY_RING_SLOTS; i++)
		if (policy_ring[i].used)
			n++;
	return n;
}

void policy_ring_push(const struct xfrm_policy_track *entry)
{
	struct xfrm_policy_track *slot = &policy_ring[policy_ring_next];

	*slot = *entry;
	slot->used = true;
	policy_ring_next = (policy_ring_next + 1) % NR_POLICY_RING_SLOTS;
}

bool policy_ring_pick(struct xfrm_policy_track *out, unsigned int *idx_out)
{
	unsigned int i, count = policy_ring_count();
	unsigned int pick, seen = 0;

	if (count == 0)
		return false;

	pick = rnd_modulo_u32(count);
	for (i = 0; i < NR_POLICY_RING_SLOTS; i++) {
		if (!policy_ring[i].used)
			continue;
		if (seen == pick) {
			*out = policy_ring[i];
			if (idx_out)
				*idx_out = i;
			return true;
		}
		seen++;
	}
	return false;
}

void policy_ring_drain(void)
{
	unsigned int i;

	for (i = 0; i < NR_POLICY_RING_SLOTS; i++)
		policy_ring[i].used = false;
}
