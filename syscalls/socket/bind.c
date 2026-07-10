/*
 * SYSCALL_DEFINE3(bind, int, fd, struct sockaddr __user *, umyaddr, int, addrlen)
 *
 * On success, zero is returned.
 * On error, -1 is returned, and errno is set appropriately.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include "net.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

/*
 * Random ARG_SOCKADDR draws steered at bind() are dominated by shapes
 * the per-family bind hook never sees.  generate_sockaddr() has a 50%
 * PF_UNSPEC-over-sockaddr_un arm that bounces at copy_from_sockaddr's
 * family reject, and the rest of the time picks a family with no
 * relation to the fd's own -- another early EINVAL that never reaches
 * inet_bind / unix_bind / ...  Steer (addr, addrlen) so the fd's own
 * bind hook is what the kernel actually executes.
 *
 * Buckets:
 *
 *   (a) NULL address, zero length -- exercises __sys_bind's early
 *       copy_from_sockaddr reject arm cleanly rather than falling
 *       through the family-mismatch path.
 *
 *   (b) Struct-size boundary length bias -- keep the generic-layer
 *       address bytes but publish addrlen at one of the common
 *       sizeof() edges (sockaddr_in / sockaddr_in6 / sockaddr_un /
 *       sockaddr_storage / bare sa_family_t) so per-family bind hooks
 *       hit their own short-copy and truncation edges instead of the
 *       uniform-noise length ARG_SOCKADDRLEN would otherwise draw.
 *
 *   (c) INET/INET6 ephemeral-port bind -- sockaddr_in{,6} at loopback
 *       or wildcard with sin{,6}_port = 0, letting the kernel pick a
 *       free port via inet_csk_get_port / inet6_bind_sk.  Feeds the
 *       auto-bind / port-reuse paths that a random-port draw only
 *       lands on under an EADDRINUSE bounce.
 *
 *   (d) AF_UNIX abstract-namespace bind -- sun_path with a leading
 *       NUL byte, hitting unix_bind_bsd's abstract branch that a
 *       generic sockaddr_un with random bytes almost never lines up
 *       for cleanly.
 *
 *   (e) AF_UNIX real-filesystem-path bind -- sun_path steered at one
 *       of a small parent-owned pool of paths under a per-pid /tmp
 *       directory, driving unix_bind_bsd through vfs_mknod.  The
 *       .cleanup hook unlink()s the specific path used so the next
 *       draw from the same slot does not bounce on EADDRINUSE.
 *
 * When the socket family is anything else, or the bucket falls in the
 * per-family gap, the generic-layer (addr, addrlen) is left in place --
 * still fuzz-useful and cheap.
 */

#define NR_BIND_UNIX_PATHS	8
static char bind_unix_dir[64];
static char bind_unix_paths[NR_BIND_UNIX_PATHS][64];
static unsigned int nr_bind_unix_paths;

static void bind_unix_paths_teardown(void)
{
	unsigned int i;

	for (i = 0; i < nr_bind_unix_paths; i++)
		(void) unlink(bind_unix_paths[i]);
	if (bind_unix_dir[0] != '\0')
		(void) rmdir(bind_unix_dir);
}

/*
 * Parent-only constructor: create /tmp/trinity-bind-<pid>/ and a bank
 * of candidate socket-file paths under it.  Children fork after the
 * constructor and never re-run it, so every child sees the same paths
 * via COW.  The atexit teardown runs only in the parent -- children
 * exit via _exit() and skip atexit -- so a per-call .cleanup unlink is
 * still required to keep back-to-back binds against the same slot from
 * bouncing on EADDRINUSE.
 */
static void __attribute__((constructor)) bind_unix_paths_init(void)
{
	unsigned int i;
	int n;

	n = snprintf(bind_unix_dir, sizeof(bind_unix_dir),
		     "/tmp/trinity-bind-%d", (int) getpid());
	if (n <= 0 || n >= (int) sizeof(bind_unix_dir)) {
		bind_unix_dir[0] = '\0';
		return;
	}
	if (mkdir(bind_unix_dir, 0700) != 0 && errno != EEXIST) {
		bind_unix_dir[0] = '\0';
		return;
	}

	for (i = 0; i < NR_BIND_UNIX_PATHS; i++) {
		n = snprintf(bind_unix_paths[i], sizeof(bind_unix_paths[i]),
			     "%s/s%u", bind_unix_dir, i);
		if (n <= 0 || n >= (int) sizeof(bind_unix_paths[i]))
			break;
		nr_bind_unix_paths = i + 1;
	}

	if (nr_bind_unix_paths > 0)
		atexit(bind_unix_paths_teardown);
}

/*
 * Common addrlen values the per-family bind hook actually compares
 * against.  RAND_ARRAY draws from these instead of the uniform-noise
 * length ARG_SOCKADDRLEN would otherwise pull, so short-copy and
 * truncation edges inside per-family sockaddr parsers see coverage.
 */
static const socklen_t bind_boundary_lens[] = {
	sizeof(sa_family_t),
	sizeof(struct sockaddr),
	sizeof(struct sockaddr_in),
	sizeof(struct sockaddr_in6),
	sizeof(struct sockaddr_un),
	sizeof(struct sockaddr_storage),
};

/*
 * The specific-shape builders below all publish their sockaddr through
 * zmalloc_tracked() and overwrite rec->a2.  The generic-layer's
 * ARG_SOCKADDR buffer already lives in the alloc_track ring and is left
 * to LRU rotation; the new buffer is what cleanup_deferred_free for
 * ARG_SOCKADDR frees at dispatch tail via deferred_free_enqueue.  This
 * is the same tracked-allocation shape generate_sockaddr() itself hands
 * back, so no reject noise is introduced.
 */
static void bind_build_inet(struct syscallrecord *rec)
{
	struct sockaddr_in *sin;

	sin = (struct sockaddr_in *) zmalloc_tracked(sizeof(*sin));
	if (sin == NULL)
		return;
	sin->sin_family = AF_INET;
	sin->sin_port = 0;
	sin->sin_addr.s_addr = RAND_BOOL()
		? htonl(INADDR_LOOPBACK)
		: htonl(INADDR_ANY);
	rec->a2 = (unsigned long) sin;
	rec->a3 = sizeof(*sin);
}

static void bind_build_inet6(struct syscallrecord *rec)
{
	struct sockaddr_in6 *sin6;

	sin6 = (struct sockaddr_in6 *) zmalloc_tracked(sizeof(*sin6));
	if (sin6 == NULL)
		return;
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = 0;
	sin6->sin6_addr = RAND_BOOL() ? in6addr_loopback : in6addr_any;
	rec->a2 = (unsigned long) sin6;
	rec->a3 = sizeof(*sin6);
}

static void bind_build_abstract_unix(struct syscallrecord *rec)
{
	struct sockaddr_un *sun;
	unsigned int len;

	sun = (struct sockaddr_un *) zmalloc_tracked(sizeof(*sun));
	if (sun == NULL)
		return;
	sun->sun_family = AF_UNIX;
	sun->sun_path[0] = '\0';
	len = (unsigned int) RAND_RANGE((size_t) 1, sizeof(sun->sun_path) - 1);
	generate_rand_bytes((unsigned char *) sun->sun_path + 1, len);
	rec->a2 = (unsigned long) sun;
	rec->a3 = (socklen_t) (sizeof(sa_family_t) + 1 + len);
}

static void bind_build_pathname_unix(struct syscallrecord *rec)
{
	struct sockaddr_un *sun;
	const char *src;
	size_t plen;

	if (nr_bind_unix_paths == 0)
		return;
	sun = (struct sockaddr_un *) zmalloc_tracked(sizeof(*sun));
	if (sun == NULL)
		return;
	sun->sun_family = AF_UNIX;
	src = bind_unix_paths[rnd_modulo_u32(nr_bind_unix_paths)];
	plen = strnlen(src, sizeof(sun->sun_path) - 1);
	memcpy(sun->sun_path, src, plen);
	sun->sun_path[plen] = '\0';
	rec->a2 = (unsigned long) sun;
	rec->a3 = (socklen_t) (sizeof(sa_family_t) + plen + 1);
	/* Stash the pool path so cleanup_bind unlinks the exact slot
	 * this call bound.  Pool paths live in a file-static array, so
	 * post_state holds an interior pointer -- cleanup treats it as
	 * a read-only string and never free()s it. */
	rec->post_state = (unsigned long) src;
}

static void sanitise_bind(struct syscallrecord *rec)
{
	struct socketinfo *si = (struct socketinfo *) rec->a1;
	unsigned int family = 0;
	unsigned int bucket;

	/* Read the family off socketinfo before we overwrite a1 with
	 * the fd, so the family-biased buckets below can steer the
	 * (addr, addrlen) pair at the socket's own bind hook. */
	if (si != NULL)
		family = si->triplet.family;

	rec->a1 = fd_from_socketinfo(si);

	if (si == NULL)
		return;

	bucket = rnd_modulo_u32(100);

	/* Family-agnostic buckets first: both are shape probes that
	 * exercise the syscall-layer reject and truncation arms. */
	if (bucket < 8) {
		rec->a2 = 0;
		rec->a3 = 0;
		return;
	}
	if (bucket < 22) {
		rec->a3 = RAND_ARRAY(bind_boundary_lens);
		return;
	}

	/* From here on, buckets synthesise a per-family sockaddr steered
	 * at the fd's own bind hook.  Families we don't specialise for
	 * fall through with the generic-layer (addr, addrlen). */
	switch (family) {
	case AF_INET:
		if (bucket < 70)
			bind_build_inet(rec);
		return;
	case AF_INET6:
		if (bucket < 70)
			bind_build_inet6(rec);
		return;
	case AF_UNIX:
		if (bucket < 50)
			bind_build_abstract_unix(rec);
		else if (bucket < 80)
			bind_build_pathname_unix(rec);
		return;
	default:
		return;
	}
}

static void cleanup_bind(struct syscallrecord *rec)
{
	const char *path = (const char *) rec->post_state;
	const char *base = (const char *) bind_unix_paths;
	const char *end = base + sizeof(bind_unix_paths);

	rec->post_state = 0;
	/* Only unlink a path that points into our own pool.  post_state
	 * lives in the shm-resident syscallrecord and can be scribbled
	 * by a sibling; a shape gate against the file-static array
	 * range rejects any foreign value cheaply before it reaches
	 * unlink(). */
	if (path < base || path >= end)
		return;
	(void) unlink(path);
}

struct syscallentry syscall_bind = {
	.name = "bind",
	.num_args = 3,
	.argtype = { [0] = ARG_SOCKETINFO, [1] = ARG_SOCKADDR, [2] = ARG_SOCKADDRLEN },
	.argname = { [0] = "fd", [1] = "umyaddr", [2] = "addrlen" },
	.rettype = RET_ZERO_SUCCESS,
	.flags = NEED_ALARM | KCOV_REMOTE_HEAVY,
	.group = GROUP_NET,
	.sanitise = sanitise_bind,
	.cleanup = cleanup_bind,
};
