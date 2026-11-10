/*
 * The re-call oracle getsockname() and getpeername() share: the sanitiser
 * snapshots the address buffers it hands the kernel, and the post handler
 * re-issues the call into private buffers and compares the two answers.
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
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "sockname-recall.h"
#include "trinity.h"
#include "utils.h"
#include "valresult.h"

/*
 * Snapshot of the address buffers read by the post oracle, captured at
 * sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect the source memcpy at a foreign user
 * buffer.  The fd the re-issue asks is read from the slot the kernel was
 * handed instead.
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
#define SOCKNAME_POST_STATE_MAGIC	0x534B4E4DUL	/* "SKNM" */
struct sockname_post_state {
	unsigned long magic;
	unsigned long usockaddr;
	unsigned long usockaddr_len;
	struct valresult_buf vrb;
};

void sockname_recall_sanitise(struct syscallrecord *rec)
{
	struct sockname_post_state *snap;
	struct sockaddr_storage *addr;
	struct valresult_buf vrb;

	rec->post_state = 0;
	rec->a1 = fd_from_socketinfo((struct socketinfo *) rec->a1);

	/*
	 * ARG_SOCKADDR hands back generate_sockaddr()'s natural per-family
	 * allocation -- as small as sockaddr_in (16 bytes) when the random
	 * draw picks AF_INET, smaller still on the unknown-protocol fallback
	 * paths that publish a rnd_modulo_u32(page_size - 1) + 1 length.  The
	 * kernel fills the address up to *addrlen bytes, where *addrlen is
	 * the value-result slot below seeded at sockaddr_storage capacity.
	 * When the fd at a1 is an AF_UNIX socket whose name (or, for
	 * getpeername, whose peer's) carries a long sun_path the kernel
	 * writes ~110 bytes into a 16-byte zmalloc chunk and glibc's
	 * heap-overflow detector aborts the child.  Override a2 with a
	 * sockaddr_storage-sized writable buffer so the kernel has room for
	 * the largest legitimate address.  Mirrors sanitise_recvfrom in
	 * recv.c.
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
	 * sockaddr_storage capacity. Mirrors recv.c and getsockopt.c.
	 * EXACT (~88%) preserves the stable-equality oracle for the happy
	 * path; the other shapes are new fuzz coverage that the oracle will
	 * mostly short-circuit via the retval and recheck_len != first_len
	 * gates.
	 */
	vrb = valresult_alloc(sizeof(struct sockaddr_storage),
			      valresult_pick_shape());
	rec->a3 = (unsigned long) vrb.len_io;
	avoid_shared_buffer_inout(&rec->a3, sizeof(socklen_t));

	/* magic-cookie / private post_state: see post_state_register(). */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic         = SOCKNAME_POST_STATE_MAGIC;
	snap->usockaddr     = rec->a2;
	snap->usockaddr_len = rec->a3;
	snap->vrb           = vrb;
	rec->post_state = (unsigned long) snap;
	post_state_register(snap);
}

/*
 * Oracle: both calls write an address for fd into *addr and the resulting
 * length into *addrlen, and two back-to-back calls for the same fd must
 * produce a byte-identical address (modulo families with
 * intentionally-volatile fields; each call's file says which, and why).
 * This is the textbook stable-equality oracle: snapshot the result,
 * re-issue the syscall against fresh private buffers, and compare.
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
 * TOCTOU defeat: the usockaddr and usockaddr_len pointers are snapshotted
 * at sanitise time into a heap struct in rec->post_state, so a sibling
 * that scribbles rec->aN between syscall return and post entry cannot
 * redirect the source memcpy at a foreign user buffer, and the re-issue
 * asks the fd the kernel was handed.  The addr and addrlen payloads
 * pointed to by the snapshot are then snapshotted into stack-locals
 * before re-issuing, with fresh private stack buffers handed to the
 * re-call (do NOT pass the snapshot's usockaddr/usockaddr_len -- a
 * sibling could mutate the user buffers themselves mid-syscall and forge
 * a clean compare).
 *
 * Family-aware compare: AF_UNIX compares the whole sockaddr, AF_INET and
 * AF_INET6 the family and the address with the port left out, and every
 * other family is skipped.  So is a socket outside the child's own pool
 * (see sockname_recheck()).
 *
 * Sample one in a hundred to stay in line with the rest of the oracle
 * family.  rc != 0 on the re-call (fd closed by sibling between return
 * and re-call, or other transient failure) is treated as 'give up' and
 * silently skipped.  recheck_len != first_len is also treated as benign
 * size-class drift rather than corruption.
 */
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
static bool sockname_validate_snap(struct syscallrecord *rec,
				   struct sockname_post_state *snap,
				   const char *name)
{
	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(rec, snap)) {
		outputerr("post_%s: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  name, snap);
		rec->post_state = 0;
		return false;
	}

	/*
	 * Ownership-table check: must be the FIRST gate that touches snap
	 * after the shape check, BEFORE any field read.  A foreign chunk
	 * could carry a matching magic cookie by coincidence (another
	 * in-flight child's snap, or a stale snap a sibling stomp
	 * resurrected by redirecting rec->post_state at it), in which case
	 * reading snap->magic touches the wrong struct.  The subsequent
	 * oracle path dereferences snap->usockaddr and snap->usockaddr_len,
	 * so a coincidental same-magic match would feed garbage inner
	 * pointers into the source memcpy.  Verify against the ownership
	 * table -- a value not registered cannot be one we produced.
	 * Mirrors prctl.c.
	 */
	if (!post_state_is_owned(snap)) {
		outputerr("post_%s: rejected post_state=%p not in ownership table "
			  "(post_state-redirected?)\n", name, snap);
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
	if (snap->magic != SOCKNAME_POST_STATE_MAGIC) {
		outputerr("post_%s: rejected snap with bad magic 0x%lx "
			  "(post_state-stomped to foreign allocation?)\n",
			  name, snap->magic);
		post_handler_corrupt_ptr_bump(rec, NULL);
		rec->post_state = 0;
		return false;
	}

	return true;
}

/*
 * Phase 3 (divergence report): hex-dump the first 8 bytes of each
 * sockaddr and emit the [oracle:<name>] line, then bump *anomalies.
 * Family is derived from first_addr->ss_family -- the recheck phase
 * only invokes this on the AF_UNIX / AF_INET / AF_INET6 paths whose
 * family field is byte-equal across re-reads.
 */
static void sockname_report_divergence(const char *name,
				       unsigned long *anomalies,
				       socklen_t first_len,
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
	       "[oracle:%s] family=%u len=%u [%s] vs [%s]\n",
	       name, (unsigned int) first_addr->ss_family,
	       (unsigned int) first_len, first_hex, recheck_hex);
	__atomic_add_fetch(anomalies, 1, __ATOMIC_RELAXED);
}

/*
 * Phase 2 (recheck oracle): ABI-validate the retval, sample 1/100,
 * snapshot the user-side post-call address/length, re-issue syscall nr
 * against fresh private buffers, and run the family-aware compare.
 * Every gate-fail / sibling-stomp / sample-miss path returns silently
 * and lets the caller's release phase run.  On divergence dispatches to
 * sockname_report_divergence() for the log/stats.
 */
static void sockname_recheck(struct syscallrecord *rec,
			     struct sockname_post_state *snap,
			     const char *name, long nr,
			     unsigned long *anomalies)
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
	 * Kernel ABI: both calls return 0 on success and -1UL on failure
	 * (with errno set on the libc side). The syscall return path has no
	 * other legitimate value -- anything outside {0, -1UL} is a
	 * structural ABI violation (sign-extension tear of the int return,
	 * sibling-thread scribble of rec->retval between syscall return and
	 * post entry, or a torn copy_to_user of the result word landing in
	 * the syscall return slot). Reject before the ONE_IN(100) sample
	 * gate below: the existing oracle short-circuits on retval != 0 and
	 * would silently swallow a wild value 100% of the time, leaving the
	 * corruption invisible.
	 */
	if (retval != 0 && retval != (unsigned long)-1L) {
		outputerr("post_%s: rejected returned status 0x%lx outside {0, -1UL} (kernel ABI violation)\n",
			  name, retval);
		post_handler_corrupt_ptr_bump(rec, NULL);
		return;
	}

	if (!ONE_IN(100))
		return;

	if ((long) retval != 0)
		return;

	if (snap->usockaddr == 0 || snap->usockaddr_len == 0)
		return;

	/* The socket the kernel answered for. */
	fd = (int) get_arg_snapshot(rec, 1);

	/*
	 * A sibling holding the socket can bind, connect or disconnect it
	 * between the two calls, which moves the name or the peer, so only
	 * a socket of this child's own pool is judged.  ARG_SOCKETINFO hands
	 * out the parent's, which every child inherited, so most calls are
	 * not; a dup of one joins the pool too, the rare shared case left.
	 */
	if (find_local_object_by_fd(OBJ_FD_SOCKET, fd) == NULL)
		return;

	{
		void *len_p = (void *)(unsigned long) snap->usockaddr_len;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner pointer
		 * fields.  Reject pid-scribbled usockaddr_len before deref.
		 */
		if (looks_like_corrupted_ptr(rec, len_p)) {
			outputerr("post_%s: rejected suspicious usockaddr_len=%p (post_state-scribbled?)\n",
				  name, len_p);
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
	rc = syscall(nr, fd, (struct sockaddr *) &recheck_addr, &recheck_len);
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
		sockname_report_divergence(name, anomalies, first_len,
					   &first_addr, &recheck_addr);
}

/*
 * Phase 4 (release): unregister the ownership-table slot then queue
 * the snap for deferred free.  Unregister-before-free is load-bearing
 * -- a registered-but-freed slot poisons the next allocation that
 * hashes to the same bucket and post_state_is_owned() would then
 * return true for memory that is no longer ours.
 */
static void sockname_release(struct syscallrecord *rec,
			     struct sockname_post_state *snap)
{
	valresult_free(&snap->vrb);
	post_state_release(rec, snap);
}

void sockname_recall_post(struct syscallrecord *rec, const char *name,
			  long nr, unsigned long *anomalies)
{
	struct sockname_post_state *snap =
		(struct sockname_post_state *) rec->post_state;

	if (snap == NULL)
		return;

	if (!sockname_validate_snap(rec, snap, name))
		return;

	sockname_recheck(rec, snap, name, nr, anomalies);

	sockname_release(rec, snap);
}
