/*
 * xfrm-churn-pfkey - PF_KEYv2 flush alt path for the xfrm_churn
 * childop.  Carved out of childops/net/xfrm/xfrm-churn.c so the
 * AF_KEY dispatch driver compiles as its own TU alongside the
 * netlink builders and inner-traffic drivers.
 *
 * Pure relocation: every function body is byte-for-byte the same as
 * the original.  pfkey_flush_burst widens from file-static to
 * external linkage so the xfrm-churn.c teardown phase can reach it
 * across the TU boundary; pfkey_flush_one, the per-child
 * ns_unsupported_pfkey latch and the g_pfkey_seq counter stay
 * file-static because they have no cross-TU callers.
 */

#include "xfrm-churn-internal.h"

/* Latched on first EAFNOSUPPORT / EPROTONOSUPPORT (kernel without
 * CONFIG_NET_KEY) so subsequent iterations don't burn a socket()
 * syscall for nothing. */
static bool ns_unsupported_pfkey;

/*
 * Sequence counter for the PF_KEYv2 alt path only.  PF_KEY is not
 * netlink so the shared nl_ctx counter doesn't apply; this monotonic
 * counter keeps sadb_msg_seq values varying across calls without
 * pretending the kernel needs them to match request/response pairs
 * (we never read the reply).
 */
static __u32 g_pfkey_seq;

/*
 * Build and send one SADB_FLUSH for the given satype on an already-open
 * PF_KEYv2 socket.  PF_KEYv2 is not netlink, so the bumped g_pfkey_seq
 * keeps message seq values varying without pretending to match
 * request/response pairs (we never read the reply).
 */
static void pfkey_flush_one(int s, __u8 satype)
{
	struct sadb_msg msg;

	memset(&msg, 0, sizeof(msg));
	msg.sadb_msg_version  = PF_KEY_V2;
	msg.sadb_msg_type     = SADB_FLUSH;
	msg.sadb_msg_satype   = satype;
	msg.sadb_msg_len      = sizeof(msg) / 8;
	msg.sadb_msg_seq      = ++g_pfkey_seq;
	msg.sadb_msg_pid      = (__u32)mypid();
	if (send(s, &msg, sizeof(msg), MSG_DONTWAIT) > 0)
		__atomic_add_fetch(&shm->stats.xfrm_churn.pfkey_send_ok,
				   1, __ATOMIC_RELAXED);
}

/*
 * PF_KEYv2 alt path: open AF_KEY socket and emit a SADB_FLUSH for
 * ESP and AH.  Drives net/key/af_key.c dispatch + flush paths that
 * share the SAD / SPD with the netlink_xfrm side.  Latched on first
 * EAFNOSUPPORT / EPROTONOSUPPORT (kernel without CONFIG_NET_KEY).
 */
void pfkey_flush_burst(struct childdata *child)
{
	int s;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op latch slot.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the latch
	 * store entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (ns_unsupported_pfkey)
		return;

	s = socket(AF_KEY, SOCK_RAW | SOCK_CLOEXEC, PF_KEY_V2);
	if (s < 0) {
		if (errno == EAFNOSUPPORT || errno == EPROTONOSUPPORT) {
			ns_unsupported_pfkey = true;
			if (valid_op)
				__atomic_store_n(&shm->stats.childop.latch_reason[op],
						 CHILDOP_LATCH_NS_UNSUPPORTED,
						 __ATOMIC_RELAXED);
		}
		return;
	}

	pfkey_flush_one(s, SADB_SATYPE_ESP);
	pfkey_flush_one(s, SADB_SATYPE_AH);

	close(s);
}
