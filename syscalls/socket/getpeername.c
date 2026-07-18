/*
 * SYSCALL_DEFINE3(getpeername, int, fd, struct sockaddr __user *, usockaddr, int __user *, usockaddr_len)
 */
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include "deferred-free.h"
#include "net.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "valresult.h"

#if defined(SYS_getpeername) || defined(__NR_getpeername)
#ifndef SYS_getpeername
#define SYS_getpeername __NR_getpeername
#endif
#define HAVE_SYS_GETPEERNAME 1
#endif

#ifdef HAVE_SYS_GETPEERNAME
/*
 * Snapshot of the three getpeername input args read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot retarget the re-issue at a different fd or
 * redirect the source memcpy at a foreign user buffer.
 *
 * Even with the magic-cookie gate on snap, a heap-shaped redirect to a
 * foreign chunk could in principle carry the matching cookie by
 * coincidence -- the snap holds inner pointers (usockaddr, usockaddr_len)
 * that the post handler dereferences for the equality oracle, so a
 * cookie-collision foreign chunk would feed garbage inner pointers into
 * the source memcpy.  Register the snap address in the post-state
 * ownership table at sanitise time so the post handler can confirm the
 * snap it is about to dereference is one we actually allocated, not a
 * coincidental match on a foreign chunk.
 */
#define GETPEERNAME_POST_STATE_MAGIC	0x47504E4DUL	/* "GPNM" */
struct getpeername_post_state {
	unsigned long magic;
	unsigned long fd;
	unsigned long usockaddr;
	unsigned long usockaddr_len;
	struct valresult_buf vrb;
};
#endif

static void sanitise_getpeername(struct syscallrecord *rec)
{
#ifdef HAVE_SYS_GETPEERNAME
	struct getpeername_post_state *snap;

	rec->post_state = 0;
#endif
	struct sockaddr_storage *addr;
	struct valresult_buf vrb;

	rec->a1 = fd_from_socketinfo((struct socketinfo *) rec->a1);

	/*
	 * ARG_SOCKADDR hands back generate_sockaddr()'s natural per-family
	 * allocation -- as small as sockaddr_in (16 bytes) when the random
	 * draw picks AF_INET, smaller still on the unknown-protocol fallback
	 * paths that publish a rnd_modulo_u32(page_size - 1) + 1 length.  The
	 * kernel fills the peer address up to *addrlen bytes, where *addrlen
	 * is the value-result slot below seeded at sockaddr_storage capacity.
	 * When the fd at a1 is a connected AF_UNIX socket whose peer carries
	 * a long sun_path the kernel writes ~110 bytes into a 16-byte zmalloc
	 * chunk and glibc's heap-overflow detector aborts the child.  Override
	 * a2 with a sockaddr_storage-sized writable buffer so the kernel has
	 * room for the largest legitimate address.  Mirrors sanitise_recvfrom
	 * in recv.c.
	 */
	addr = (struct sockaddr_storage *) get_writable_address(sizeof(*addr));
	if (addr != NULL)
		rec->a2 = (unsigned long) addr;
	else
		/* On pool exhaustion / mincore failure, leaving the original
		 * undersized ARG_SOCKADDR buffer would preserve the very
		 * overflow shape this routine exists to prevent.  Force NULL
		 * so the kernel returns -EFAULT cleanly. */
		rec->a2 = 0;

	/*
	 * usockaddr_len is a value-result socklen_t pointer. ARG_SOCKADDRLEN
	 * published a scalar into the slot, which the kernel reads as a
	 * __user pointer and EFAULTs every call -- the post oracle below
	 * was effectively never reachable. Route the addrlen slot through
	 * valresult_alloc() so the shape catalogue (EXACT / UNDER /
	 * EXACT_PLUS_ONE / HUGE / ZERO) mutates *lenp around the natural
	 * sockaddr_storage capacity. Mirrors recv.c (81a1271bc2a1) and
	 * getsockopt.c (38e1b000092d). EXACT (~88%) preserves the
	 * stable-equality oracle for the happy path; the other shapes are
	 * new fuzz coverage that the oracle will mostly short-circuit via
	 * the retval and recheck_len != first_len gates.
	 */
	vrb = valresult_alloc(sizeof(struct sockaddr_storage),
			      valresult_pick_shape());
	rec->a3 = (unsigned long) vrb.len_io;
	avoid_shared_buffer_inout(&rec->a3, sizeof(socklen_t));

#ifdef HAVE_SYS_GETPEERNAME
	/*
	 * magic-cookie / private post_state: see post_state_register().
	 * Gated on HAVE_SYS_GETPEERNAME to mirror the .post registration --
	 * without the post handler a snap that only the post path frees
	 * would leak.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic         = GETPEERNAME_POST_STATE_MAGIC;
	snap->fd            = rec->a1;
	snap->usockaddr     = rec->a2;
	snap->usockaddr_len = rec->a3;
	snap->vrb           = vrb;
	rec->post_state = (unsigned long) snap;
	post_state_register(snap);
#endif
}

/*
 * Oracle: getpeername(fd, addr, addrlen) writes the connected peer's
 * sockaddr for fd into *addr and the resulting length into *addrlen.
 * The fd table is per-process, so no sibling trinity child can rebind or
 * reconnect the underlying socket beneath us within the sample window --
 * for any already-connected socket two back-to-back calls for the same
 * fd must produce a byte-identical peer address (modulo families with
 * intentionally-volatile fields, see below).  This is the textbook
 * stable-equality oracle: snapshot the result, re-issue the syscall
 * against fresh private buffers, and compare.
 *
 * Divergence shapes the oracle catches:
 *   - copy_to_user mis-write inside the sockaddr (wrong slot, torn write).
 *   - 32-bit-on-64-bit compat sign-extension on the socklen_t value-result
 *     word landing in addrlen.
 *   - struct layout mismatch between userspace and kernel headers for
 *     sockaddr_un / sockaddr_in / sockaddr_in6 (inserted field, padding
 *     drift).
 *   - sibling-thread scribble of the user addr buffer at rec->a2 or the
 *     addrlen word at rec->a3 between the original syscall return and our
 *     re-issue, via alloc_shared in another trinity child task.
 *
 * TOCTOU defeat: the three input args (fd, usockaddr, usockaddr_len)
 * are snapshotted at sanitise time into a heap struct in rec->post_state,
 * so a sibling that scribbles rec->aN between syscall return and post
 * entry cannot steer the re-issue against a different fd or redirect the
 * source memcpy at a foreign user buffer.  The addr and addrlen payloads
 * pointed to by the snapshot are then snapshotted into stack-locals
 * before re-issuing, with fresh private stack buffers handed to the
 * re-call (do NOT pass the snapshot's usockaddr/usockaddr_len -- a
 * sibling could mutate the user buffers themselves mid-syscall and forge
 * a clean compare).
 *
 * Family-aware compare:
 *   - AF_UNIX: full sockaddr bytes (sun_family + sun_path) are stable, so
 *     a straight memcmp over first_len bytes is the right cross-check.
 *   - AF_INET: sin_family + sin_addr.s_addr are stable; sin_port is
 *     deliberately excluded.  The peer port the kernel reports back is
 *     the remote endpoint's port, which in normal use is fixed for the
 *     life of the connection -- but skipping it costs us nothing and
 *     defeats any ephemeral-source-port surprise leaking in via odd
 *     protocol corners (e.g. unconnected DGRAM sockets the syscall layer
 *     would reject before we get here, but better safe).
 *   - AF_INET6: sin6_family + sin6_addr (the 16-byte s6_addr) are stable;
 *     sin6_port, sin6_flowinfo and sin6_scope_id are deliberately
 *     excluded.  Flow label and scope-id can legitimately differ across
 *     re-reads on certain v6 socket types and we'd rather miss those than
 *     drown the channel in FPs.
 *   - All other families (AF_PACKET, AF_NETLINK, ...) are silently
 *     skipped: each has its own volatility profile and is left for a
 *     follow-up pass.
 *
 * Sample one in a hundred to stay in line with the rest of the oracle
 * family.  rc != 0 on the re-call (fd closed by sibling between return
 * and re-call, or other transient failure) is treated as 'give up' and
 * silently skipped.  recheck_len != first_len is also treated as benign
 * size-class drift rather than corruption.
 */
#ifdef HAVE_SYS_GETPEERNAME
/*
 * Phase 1 (snap ownership): shape -> ownership -> magic gate on the
 * post_state pointer.  Returns true when snap is proven to be the
 * snapshot this attempt installed and is safe to dereference and
 * release; false when any gate rejected it, in which case the helper
 * has already emitted the diagnostic, bumped the corrupt_ptr counter
 * where appropriate, and cleared rec->post_state so the caller must
 * return without touching snap.  Mirrors prctl.c / recv.c
 * post_recvmsg for the canonical ordering and the rationale for each
 * gate.
 */
static bool getpeername_validate_snap(struct syscallrecord *rec,
				      struct getpeername_post_state *snap)
{
	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_getpeername: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		rec->post_state = 0;
		return false;
	}

	/*
	 * Ownership-table check: must be the FIRST gate that touches snap
	 * after the shape check, BEFORE any field read.  A foreign chunk
	 * could carry a matching magic cookie by coincidence (another
	 * in-flight getpeername child's snap, or a stale snap a sibling
	 * stomp resurrected by redirecting rec->post_state at it), in
	 * which case reading snap->magic touches the wrong struct.  The
	 * subsequent oracle path dereferences snap->usockaddr and
	 * snap->usockaddr_len, so a coincidental same-magic match would
	 * feed garbage inner pointers into the source memcpy.  Verify
	 * against the ownership table -- a value not registered cannot be
	 * one we produced.  Mirrors prctl.c.
	 */
	if (!post_state_is_owned(snap)) {
		outputerr("post_getpeername: rejected post_state=%p not in ownership table "
			  "(post_state-redirected?)\n", snap);
		rec->post_state = 0;
		return false;
	}

	/*
	 * Magic-cookie check: ownership table confirmed this is our snap,
	 * so reading snap->magic is now safe.  A mismatch here means the
	 * snapshot itself was wholesale-scribbled in place -- abandon
	 * rather than feed wild bytes into the inner-field deref.
	 * Mirrors recv.c post_recvmsg.
	 */
	if (snap->magic != GETPEERNAME_POST_STATE_MAGIC) {
		outputerr("post_getpeername: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->post_state = 0;
		return false;
	}

	return true;
}

/*
 * Phase 3 (divergence report): hex-dump the first 8 bytes of each
 * sockaddr and emit the [oracle:getpeername] line, then bump the
 * anomaly counter.  Family is derived from first_addr->ss_family --
 * the recheck phase only invokes this on the AF_UNIX / AF_INET /
 * AF_INET6 paths whose family field is byte-equal across re-reads.
 */
static void getpeername_report_divergence(socklen_t first_len,
					  const struct sockaddr_storage *first_addr,
					  const struct sockaddr_storage *recheck_addr)
{
	const unsigned char *first_bytes = (const unsigned char *) first_addr;
	const unsigned char *recheck_bytes = (const unsigned char *) recheck_addr;
	char first_hex[8 * 3 + 1];
	char recheck_hex[8 * 3 + 1];
	size_t off;
	unsigned int nbytes;
	unsigned int i;

	nbytes = first_len < 8 ? first_len : 8;

	off = 0;
	for (i = 0; i < nbytes; i++)
		off += snprintf(first_hex + off, sizeof(first_hex) - off,
				"%02x ", first_bytes[i]);
	first_hex[off > 0 ? off - 1 : 0] = '\0';

	off = 0;
	for (i = 0; i < nbytes; i++)
		off += snprintf(recheck_hex + off, sizeof(recheck_hex) - off,
				"%02x ", recheck_bytes[i]);
	recheck_hex[off > 0 ? off - 1 : 0] = '\0';

	output(0,
	       "[oracle:getpeername] family=%u len=%u [%s] vs [%s]\n",
	       (unsigned int) first_addr->ss_family, (unsigned int) first_len,
	       first_hex, recheck_hex);
	__atomic_add_fetch(&shm->stats.oracle.getpeername_oracle_anomalies,
			   1, __ATOMIC_RELAXED);
}

/*
 * Phase 2 (recheck oracle): ABI-validate the retval, sample 1/100,
 * snapshot the user-side post-call address/length, re-issue
 * getpeername against fresh private buffers, and run the family-aware
 * compare.  Every gate-fail / sibling-stomp / sample-miss path returns
 * silently and lets the caller's release phase run.  On divergence
 * dispatches to getpeername_report_divergence() for the log/stats.
 */
static void getpeername_recheck(struct syscallrecord *rec,
				struct getpeername_post_state *snap)
{
	unsigned long retval = rec->retval;
	struct sockaddr_storage first_addr;
	struct sockaddr_storage recheck_addr;
	socklen_t first_len;
	socklen_t recheck_len;
	sa_family_t family;
	bool diverged;
	int fd;
	int rc;

	/*
	 * Kernel ABI: getpeername returns 0 on success and -1UL (errno style)
	 * on failure — those are the only two legitimate retval shapes. Any
	 * other value is a structural ABI regression: a sign-extension tear
	 * across the 32/64 boundary, a torn copy-out of the status code, or a
	 * sibling thread scribbling rec->retval between syscall return and
	 * post-hook entry. Reject before the ONE_IN(100) sample gate, which
	 * would otherwise miss a corrupted retval 99% of the time, and before
	 * the != 0 early-return that today silently absorbs both -1 and any
	 * wild value into the same "give up quietly" branch.
	 */
	if (retval != 0 && retval != (unsigned long)-1L) {
		outputerr("post_getpeername: rejected retval 0x%lx outside {0, -1} (kernel ABI: status code only)\n",
			  retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
		return;
	}

	if (!ONE_IN(100))
		return;

	if ((long) retval != 0)
		return;

	if (snap->usockaddr == 0 || snap->usockaddr_len == 0)
		return;

	fd = (int) snap->fd;

	{
		void *len_p = (void *)(unsigned long) snap->usockaddr_len;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner pointer
		 * fields.  Reject pid-scribbled usockaddr_len before deref.
		 */
		if (looks_like_corrupted_ptr(rec, len_p)) {
			outputerr("post_getpeername: rejected suspicious usockaddr_len=%p (post_state-scribbled?)\n",
				  len_p);
			return;
		}
	}

	/*
	 * Copy the length word through the TOCTOU-guarded helper.  The
	 * shape-only guard above lets a non-NULL but stale/unmapped
	 * snap->usockaddr_len through; post_snapshot_or_skip range-proves
	 * the socklen_t window and recovers from a sibling mprotect/munmap
	 * fault instead of crashing the child mid-sample.
	 */
	if (!post_snapshot_or_skip(&first_len, (const void *) snap->usockaddr_len,
				   sizeof(socklen_t)))
		return;
	if (first_len == 0 || first_len > sizeof(struct sockaddr_storage))
		return;

	memset(&first_addr, 0, sizeof(first_addr));
	if (!post_snapshot_or_skip(&first_addr,
				   (const void *) snap->usockaddr, first_len))
		return;

	recheck_len = sizeof(struct sockaddr_storage);
	memset(&recheck_addr, 0, sizeof(recheck_addr));
	rc = syscall(SYS_getpeername, fd, (struct sockaddr *) &recheck_addr,
		     &recheck_len);
	if (rc != 0)
		return;

	if (recheck_len != first_len)
		return;

	family = first_addr.ss_family;
	diverged = false;

	switch (family) {
	case AF_UNIX:
		if (memcmp(&first_addr, &recheck_addr, first_len) != 0)
			diverged = true;
		break;
	case AF_INET: {
		const struct sockaddr_in *fa = (const struct sockaddr_in *) &first_addr;
		const struct sockaddr_in *ra = (const struct sockaddr_in *) &recheck_addr;

		if (fa->sin_family != ra->sin_family ||
		    fa->sin_addr.s_addr != ra->sin_addr.s_addr)
			diverged = true;
		break;
	}
	case AF_INET6: {
		const struct sockaddr_in6 *fa = (const struct sockaddr_in6 *) &first_addr;
		const struct sockaddr_in6 *ra = (const struct sockaddr_in6 *) &recheck_addr;

		if (fa->sin6_family != ra->sin6_family ||
		    memcmp(&fa->sin6_addr, &ra->sin6_addr, sizeof(fa->sin6_addr)) != 0)
			diverged = true;
		break;
	}
	default:
		return;
	}

	if (diverged)
		getpeername_report_divergence(first_len, &first_addr, &recheck_addr);
}

/*
 * Phase 4 (release): unregister the ownership-table slot then queue
 * the snap for deferred free.  Unregister-before-free is load-bearing
 * -- a registered-but-freed slot poisons the next allocation that
 * hashes to the same bucket and post_state_is_owned() would then
 * return true for memory that is no longer ours.
 */
static void getpeername_release(struct syscallrecord *rec,
				struct getpeername_post_state *snap)
{
	valresult_free(&snap->vrb);
	post_state_release(rec, snap);
}

static void post_getpeername(struct syscallrecord *rec)
{
	struct getpeername_post_state *snap =
		(struct getpeername_post_state *) rec->post_state;

	if (snap == NULL)
		return;

	if (!getpeername_validate_snap(rec, snap))
		return;

	getpeername_recheck(rec, snap);

	getpeername_release(rec, snap);
}
#endif

struct syscallentry syscall_getpeername = {
	.name = "getpeername",
	.num_args = 3,
	.argtype = { [0] = ARG_SOCKETINFO, [1] = ARG_SOCKADDR, [2] = ARG_SOCKADDRLEN },
	.argname = { [0] = "fd", [1] = "usockaddr", [2] = "usockaddr_len" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.sanitise = sanitise_getpeername,
#ifdef HAVE_SYS_GETPEERNAME
	.post = post_getpeername,
#endif
};
