/*
 * SYSCALL_DEFINE5(setsockopt, int, fd, int, level, int, optname, char __user *, optval, int, optlen)
 */

#include <stdlib.h>
#include <linux/filter.h>
#include "arch.h"
#include "bpf.h"
#include "deferred-free.h"
#include "net.h"
#include "compat.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "utils.h"	// RAND_ARRAY

static const unsigned int socket_opts[] = {
	SO_DEBUG, SO_REUSEADDR, SO_TYPE, SO_ERROR,
	SO_DONTROUTE, SO_BROADCAST, SO_SNDBUF, SO_RCVBUF,
	SO_SNDBUFFORCE, SO_RCVBUFFORCE, SO_KEEPALIVE, SO_OOBINLINE,
	SO_NO_CHECK, SO_PRIORITY, SO_LINGER, SO_BSDCOMPAT,
	SO_REUSEPORT, SO_PASSCRED, SO_PEERCRED, SO_RCVLOWAT, SO_SNDLOWAT,
	SO_RCVTIMEO, SO_SNDTIMEO, SO_SECURITY_AUTHENTICATION, SO_SECURITY_ENCRYPTION_TRANSPORT,
	SO_SECURITY_ENCRYPTION_NETWORK, SO_BINDTODEVICE, SO_ATTACH_FILTER, SO_DETACH_FILTER,
	SO_PEERNAME, SO_TIMESTAMP, SO_ACCEPTCONN, SO_PEERSEC,
	SO_PASSSEC, SO_TIMESTAMPNS, SO_MARK, SO_TIMESTAMPING,
	SO_PROTOCOL, SO_DOMAIN, SO_RXQ_OVFL, SO_WIFI_STATUS,
	SO_PEEK_OFF, SO_NOFCS, SO_LOCK_FILTER, SO_SELECT_ERR_QUEUE,
	SO_BUSY_POLL, SO_MAX_PACING_RATE, SO_BPF_EXTENSIONS, SO_INCOMING_CPU,
	SO_ATTACH_BPF, SO_ATTACH_REUSEPORT_CBPF, SO_ATTACH_REUSEPORT_EBPF,
	SO_CNX_ADVICE, SCM_TIMESTAMPING_OPT_STATS, SO_MEMINFO, SO_INCOMING_NAPI_ID,
	SO_COOKIE, SCM_TIMESTAMPING_PKTINFO, SO_PEERGROUPS, SO_ZEROCOPY,
	SO_TXTIME, SO_BINDTOIFINDEX, SO_TIMESTAMP_NEW, SO_TIMESTAMPNS_NEW,
	SO_TIMESTAMPING_NEW, SO_RCVTIMEO_NEW, SO_SNDTIMEO_NEW,
	SO_DETACH_REUSEPORT_BPF, SO_PREFER_BUSY_POLL, SO_BUSY_POLL_BUDGET,
	SO_NETNS_COOKIE, SO_BUF_LOCK,
	SO_RESERVE_MEM, SO_TXREHASH, SO_RCVMARK,
	SO_PASSPIDFD, SO_PEERPIDFD,
	SO_DEVMEM_LINEAR, SO_DEVMEM_DMABUF, SO_DEVMEM_DONTNEED,
	SO_RCVPRIORITY, SO_PASSRIGHTS, SO_INQ,
#ifdef SCM_TS_OPT_ID
	SCM_TS_OPT_ID,
#endif
};

static void socket_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_SOCKET;

	so->optname = RAND_ARRAY(socket_opts);

	/* Adjust length according to operation set. */
	switch (so->optname) {

	case SO_LINGER:
		so->optlen = sizeof(struct linger);
		break;

	case SO_RCVTIMEO:
	case SO_SNDTIMEO:
		so->optlen = sizeof(struct timeval);
		break;

	case SO_ATTACH_FILTER: {
		unsigned long *optval = NULL, optlen = 0;

		/* Free any optval allocated by the caller (do_setsockopt)
		 * before we replace it with the BPF filter. */
		free((void *) so->optval);
		so->optval = 0;

#ifdef USE_BPF
		bpf_gen_filter(&optval, &optlen);
#endif

		so->optval = (unsigned long) optval;
		so->optlen = optlen;
		break;
	}

	case SO_ATTACH_BPF:
	case SO_ATTACH_REUSEPORT_EBPF:
	case SO_DETACH_REUSEPORT_BPF: {
#ifdef USE_BPF
		int prog_fd = get_rand_bpf_prog_fd();
		if (prog_fd >= 0) {
			int *buf = zmalloc_tracked(sizeof(int));
			*buf = prog_fd;
			free((void *) so->optval);
			so->optval = (unsigned long) buf;
			so->optlen = sizeof(int);
		}
#endif
		break;
	}

	default:
		break;
	}
}
/*
 * If we have a .len set, use it.
 * If not, pick some random size.
 */
unsigned int sockoptlen(unsigned int len)
{
	if (len != 0)
		return len;

	if (RAND_BOOL())
		return sizeof(char);
	else
		return sizeof(int);
}

/*
 * We do this if for eg, we've ended up being passed
 * an fd that isn't a socket (ie, triplet==NULL).
 * It can also happen if we land on an sso func that
 * isn't implemented for a particular family yet.
 */
static void do_random_sso(struct sockopt *so, struct socket_triplet *triplet)
{
	unsigned int i;
	const struct netproto *proto;

retry:
	switch (rnd_modulo_u32(4)) {
	case 0:	/* do a random protocol, even if it doesn't match this socket. */
		i = rnd_modulo_u32(TRINITY_PF_MAX);
		proto = net_protocols[i].proto;
		if (proto != NULL) {
			if (proto->setsockopt != NULL) {
				proto->setsockopt(so, triplet);
				return;
			}
		}
		goto retry;

	case 1:	/* protocol-specific setsockopt for this socket's family. */
		if (triplet->family < TRINITY_PF_MAX) {
			proto = net_protocols[triplet->family].proto;
			if (proto != NULL && proto->setsockopt != NULL)
				proto->setsockopt(so, triplet);
		}
		break;

	case 2:	/* Last resort: Generic socket options. */
		socket_setsockopt(so, triplet);
		break;

	case 3:	/* completely random operation. */
		so->level = rnd_u32();
		so->optname = RAND_BYTE();
		break;
	}
}

static void call_sso_ptr(struct sockopt *so, struct socket_triplet *triplet)
{
	const struct netproto *proto;

	proto = net_protocols[triplet->family].proto;

	if (proto != NULL) {
		if (proto->setsockopt != NULL) {
			proto->setsockopt(so, triplet);
			return;
		}
	}

	do_random_sso(so, triplet);
}

/*
 * Call a proto specific setsockopt routine from the table above.
 *
 * Called from random setsockopt() syscalls, and also during socket
 * creation on startup from sso_socket()
 *
 */
void do_setsockopt(struct sockopt *so, struct socket_triplet *triplet)
{
	so->optname = 0;

	/* Sometimes just do generic options */
	if (ONE_IN(10)) {
		socket_setsockopt(so, triplet);
		return;
	}

	if (triplet == NULL)
		return;

	/* get a page for the optval to live in.
	 * Pushing this into per-proto .setsockopt calls is deferred because
	 * each protocol would need its own function pointer and allocation
	 * strategy, and most protocols are fine with a single page.
	 */
	/* Mostly released via deferred_freeptr(&rec->post_state) in
	 * post_setsockopt(); a RAND_BOOL fallback below may direct-free.
	 * Opt in to the alloc tracker: the rare direct-free path leaves
	 * a stale slot to be evicted (benign leak), which is the safer
	 * failure mode per the 2026-05-19 alloc-tracking audit. */
	so->optval = (unsigned long) zmalloc_tracked(page_size);

	/* At the minimum, we want len to be a char or int.
	 * It gets (overridden below in the per-proto sso->func, so this
	 * is just for the unannotated protocols.
	 */
	so->optlen = sockoptlen(0);

	if (ONE_IN(100))
		do_random_sso(so, triplet);
	else
		call_sso_ptr(so, triplet);

	/*
	 * 10% of the time, mangle the options.
	 * This should catch new options we don't know about, and also maybe some missing bounds checks.
	 */
	if (ONE_IN(10))
		so->optname |= (1UL << (rnd_modulo_u32(32)));

	/* optval should be nonzero to enable a boolean option, or zero if the option is to be disabled.
	 * Let's disable it half the time.
	 */
	if (RAND_BOOL()) {
		free((void *) so->optval);
		so->optval = 0;
	}
}

/*
 * Snapshot of the optname alongside the heap optval the post handler
 * frees.  rec->a3 (optname) and rec->a4 (optval) are both ABI-exposed
 * and a sibling syscall can scribble either between syscall return and
 * post entry; the old post handler treated post_state as a bare optval
 * and dispatched freeing through a single path, so a scribble of a4
 * had to be defended against by the snapshot and a scribble of a3 was
 * irrelevant because no per-optname dispatch existed.  The classic-BPF
 * SO_ATTACH_FILTER path needs that dispatch: its optval is a
 * two-tier sock_fprog wrapper (outer + inner filter) and a plain
 * deferred_freeptr() on the wrapper leaks the inner buffer.  Store
 * optname here so the post handler picks the right cleanup independent
 * of a3 corruption, and keep a magic cookie to reject foreign
 * allocations that pose as a snap via post_state stomp.
 */
#define SETSOCKOPT_POST_STATE_MAGIC	0x534F505453544154UL	/* "SOPTSTAT" */
struct setsockopt_post_state {
	unsigned long magic;
	int optname;
	void *optval;
};

static void sanitise_setsockopt(struct syscallrecord *rec)
{
	struct sockopt so = { 0, 0, 0, 0 };
	struct setsockopt_post_state *snap;
	struct socketinfo *si;
	struct socket_triplet *triplet = NULL;
	int fd;

	rec->post_state = 0;

	si = (struct socketinfo *) rec->a1;
	if (si == NULL) {
		rec->a1 = get_random_fd();
		rec->a4 = 0;
		return;
	}

	if (ONE_IN(1000)) {
		fd = get_random_fd();
	} else {
		fd = si->fd;
		triplet = &si->triplet;
	}

	rec->a1 = fd;

	do_setsockopt(&so, triplet);

	/* copy the generated values to the shm. */
	rec->a2 = so.level;
	rec->a3 = so.optname;
	rec->a4 = so.optval;
	rec->a5 = so.optlen;

	/* Snap only when there is a heap optval to free.  The RAND_BOOL
	 * disable path in do_setsockopt() already freed and zeroed optval,
	 * so post_state stays NULL and the post handler returns early. */
	if (so.optval == 0)
		return;

	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = SETSOCKOPT_POST_STATE_MAGIC;
	snap->optname = so.optname;
	snap->optval = (void *) so.optval;
	rec->post_state = (unsigned long) snap;
}

static void post_setsockopt(struct syscallrecord *rec)
{
	struct setsockopt_post_state *snap = (void *) rec->post_state;

	rec->a4 = 0;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_setsockopt: rejected suspicious post_state=%p "
			  "(pid-scribbled?)\n", snap);
		rec->post_state = 0;
		return;
	}

	/*
	 * Magic-cookie check: a sibling scribble of rec->post_state with a
	 * heap-shaped pointer to a foreign allocation would survive the
	 * shape gate above and let post_setsockopt parse arbitrary bytes
	 * as a setsockopt_post_state, then route the optname dispatch into
	 * bpf_free_filter() with a wild sock_fprog *.  Abandon without
	 * freeing on mismatch; the pointer is suspect and may not be heap.
	 */
	if (snap->magic != SETSOCKOPT_POST_STATE_MAGIC) {
		outputerr("post_setsockopt: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->post_state = 0;
		return;
	}

	/*
	 * Defense in depth: snap survived the gates but the inner optval
	 * pointer may have been scribbled.  Leak rather than hand garbage
	 * to free() / bpf_free_filter().  Snap itself is still safe to
	 * release through the post_state slot.
	 */
	if (looks_like_corrupted_ptr(rec, snap->optval)) {
		outputerr("post_setsockopt: rejected suspicious snap optval=%p (post_state-scribbled?)\n",
			  snap->optval);
		deferred_freeptr(&rec->post_state);
		return;
	}

#ifdef USE_BPF
	if (snap->optname == SO_ATTACH_FILTER) {
		bpf_free_filter((struct sock_fprog *) snap->optval);
	} else
#endif
	{
		deferred_free_enqueue(snap->optval);
	}

	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_setsockopt = {
	.name = "setsockopt",
	.num_args = 5,
	.argtype = { [0] = ARG_SOCKETINFO },
	.argname = { [0] = "fd", [1] = "level", [2] = "optname", [3] = "optval", [4] = "optlen" },
	.sanitise = sanitise_setsockopt,
	.post = post_setsockopt,
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.rettype = RET_ZERO_SUCCESS,
};
