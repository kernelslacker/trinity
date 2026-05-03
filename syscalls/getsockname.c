/*
 * SYSCALL_DEFINE3(getsockname, int, fd, struct sockaddr __user *, usockaddr, int __user *, usockaddr_len)
 */
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <unistd.h>
#include "net.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

static void sanitise_getsockname(struct syscallrecord *rec)
{
	rec->a1 = fd_from_socketinfo((struct socketinfo *) rec->a1);
}

/*
 * Oracle: getsockname(fd, addr, addrlen) writes the bound local address
 * for fd into *addr and the resulting length into *addrlen.  The fd table
 * is per-process, so no sibling trinity child can rebind the underlying
 * socket beneath us within the sample window -- two back-to-back calls
 * for the same fd must produce a byte-identical address (modulo families
 * with intentionally-volatile fields, see below).  This is the textbook
 * stable-equality oracle: snapshot the result, re-issue the syscall
 * against fresh private buffers, and compare.
 *
 * Divergence shapes the oracle catches:
 *   - copy_to_user mis-write inside the sockaddr (wrong slot, torn write).
 *   - 32-bit-on-64-bit compat sign-extension on the socklen_t value-result
 *     word landing in addrlen.
 *   - struct layout mismatch between userspace and kernel headers for
 *     sockaddr_un / sockaddr_in (inserted field, padding drift).
 *   - sibling-thread scribble of the user addr buffer at rec->a2 or the
 *     addrlen word at rec->a3 between the original syscall return and our
 *     re-issue, via alloc_shared in another trinity child task.
 *
 * TOCTOU defeat: a sibling thread in the same trinity child can scribble
 * either the addr buffer at rec->a2 or the addrlen word at rec->a3
 * between the syscall return and our post-hook.  Snapshot both into
 * stack-locals immediately, then re-issue with fresh private stack
 * buffers (do NOT pass rec->a2/rec->a3 -- a sibling could mutate them
 * mid-syscall and we want a clean compare).
 *
 * Family-aware compare:
 *   - AF_UNIX: full sockaddr bytes (sun_family + sun_path) are stable.
 *   - AF_INET: sin_family + sin_addr.s_addr are stable; sin_port is
 *     deliberately excluded -- a UDP DGRAM socket with an ephemeral
 *     autobind can legitimately surface a different port across the two
 *     re-reads in rare corner cases, and we'd rather miss those than
 *     drown the channel in autobind FPs.
 *   - All other families (AF_INET6, AF_PACKET, AF_NETLINK, ...) are
 *     silently skipped: each has its own volatility profile and is left
 *     for a follow-up pass.
 *
 * Sample one in a hundred to stay in line with the rest of the oracle
 * family.  rc != 0 on the re-call (fd closed by sibling between return
 * and re-call, or other transient failure) is treated as 'give up' and
 * silently skipped.  recheck_len != first_len is also treated as benign
 * size-class drift rather than corruption.
 */
static void post_getsockname(struct syscallrecord *rec)
{
	struct sockaddr_storage first_addr;
	struct sockaddr_storage recheck_addr;
	socklen_t first_len;
	socklen_t recheck_len;
	sa_family_t family;
	bool diverged;
	int fd;
	int rc;

	if (!ONE_IN(100))
		return;

	if ((long) rec->retval != 0)
		return;

	if (rec->a2 == 0 || rec->a3 == 0)
		return;

	fd = (int) rec->a1;

	{
		void *addr_p = (void *)(unsigned long) rec->a2;
		void *len_p = (void *)(unsigned long) rec->a3;

		/* Cluster-1/2/3 guard: reject pid-scribbled rec->a2/a3. */
		if (looks_like_corrupted_ptr(addr_p) ||
		    looks_like_corrupted_ptr(len_p)) {
			outputerr("post_getsockname: rejected suspicious usockaddr=%p usockaddr_len=%p (pid-scribbled?)\n",
				  addr_p, len_p);
			shm->stats.post_handler_corrupt_ptr++;
			return;
		}
	}

	memcpy(&first_len, (const void *) rec->a3, sizeof(socklen_t));
	if (first_len == 0 || first_len > sizeof(struct sockaddr_storage))
		return;

	memset(&first_addr, 0, sizeof(first_addr));
	memcpy(&first_addr, (const void *) rec->a2, first_len);

	recheck_len = sizeof(struct sockaddr_storage);
	memset(&recheck_addr, 0, sizeof(recheck_addr));
	rc = syscall(SYS_getsockname, fd, (struct sockaddr *) &recheck_addr,
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
	default:
		return;
	}

	if (diverged) {
		const unsigned char *first_bytes = (const unsigned char *) &first_addr;
		const unsigned char *recheck_bytes = (const unsigned char *) &recheck_addr;
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
		       "[oracle:getsockname] family=%u len=%u [%s] vs [%s]\n",
		       (unsigned int) family, (unsigned int) first_len,
		       first_hex, recheck_hex);
		__atomic_add_fetch(&shm->stats.getsockname_oracle_anomalies,
				   1, __ATOMIC_RELAXED);
	}
}

struct syscallentry syscall_getsockname = {
	.name = "getsockname",
	.num_args = 3,
	.argtype = { [0] = ARG_SOCKETINFO, [1] = ARG_SOCKADDR, [2] = ARG_SOCKADDRLEN },
	.argname = { [0] = "fd", [1] = "usockaddr", [2] = "usockaddr_len" },
	.flags = NEED_ALARM,
	.group = GROUP_NET,
	.sanitise = sanitise_getsockname,
	.post = post_getsockname,
};
