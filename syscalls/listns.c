/*
 * SYSCALL_DEFINE4(listns, const struct ns_id_req __user *, req,
 *		u64 __user *, ns_ids, size_t, nr_ns_ids,
 *		unsigned int, flags)
 */
#include <linux/types.h>
#include <sched.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "csfu.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * struct ns_id_req from include/uapi/linux/nsfs.h.
 * Define locally to build against older kernel headers.
 */
#ifndef NS_ID_REQ_SIZE_VER0
struct ns_id_req {
	__u32 size;
	__u32 spare;
	__u64 ns_id;
	__u32 ns_type;
	__u32 spare2;
	__u64 user_ns_id;
};
#define NS_ID_REQ_SIZE_VER0	32
#endif

#ifndef LISTNS_CURRENT_USER
#define LISTNS_CURRENT_USER	0xffffffffffffffffULL
#endif

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP		0x02000000
#endif

#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME		0x00000080
#endif

static const unsigned long ns_types[] = {
	CLONE_NEWNS,
	CLONE_NEWUTS,
	CLONE_NEWIPC,
	CLONE_NEWUSER,
	CLONE_NEWPID,
	CLONE_NEWNET,
	CLONE_NEWCGROUP,
	CLONE_NEWTIME,
};

/*
 * Output buffer sized for the largest nr_ns_ids bucket.  We always
 * allocate the maximum; the syscall arg picks a smaller value from
 * the bucket below.  A kernel-side bound bug cannot then scribble
 * past the allocation -- the post oracle still catches a retval that
 * exceeds the snapshotted nr_ns_ids cap.
 */
#define LISTNS_BUF_SLOTS	1024

#define LISTNS_NS_ID_POOL_SIZE	8

/*
 * Per-process cache of real namespace ids harvested from
 * /proc/self/ns/{cgroup,ipc,mnt,net,pid,time,user,uts}.  Each symlink
 * target has the form "<type>:[<inum>]" where <inum> is the namespace
 * id usable by listns.  Random 64-bit values almost never match a
 * live namespace and the find_ns_id() arm short-circuits before any
 * iteration runs; pulling real ids from /proc steers the bias into
 * the lookup-hit arm.  Per-process static survives the fork-per-child
 * model via inheritance.  Lazy-loaded on first call -- no fileops in
 * the syscall hot path.
 */
static __u64 listns_ns_id_pool[LISTNS_NS_ID_POOL_SIZE];
static unsigned int listns_ns_id_pool_n;
static bool listns_ns_id_pool_loaded;

static void load_listns_ns_id_pool(void)
{
	static const char *const ns_names[] = {
		"cgroup", "ipc", "mnt", "net",
		"pid", "time", "user", "uts",
	};
	char path[64];
	char link[64];
	const char *p;
	unsigned long long id;
	unsigned int i;
	ssize_t n;

	if (listns_ns_id_pool_loaded)
		return;
	listns_ns_id_pool_loaded = true;

	for (i = 0; i < ARRAY_SIZE(ns_names); i++) {
		if (listns_ns_id_pool_n >= ARRAY_SIZE(listns_ns_id_pool))
			break;

		snprintf(path, sizeof(path), "/proc/self/ns/%s",
			 ns_names[i]);
		n = readlink(path, link, sizeof(link) - 1);
		if (n <= 0)
			continue;
		link[n] = '\0';

		p = strchr(link, '[');
		if (p == NULL)
			continue;
		if (sscanf(p + 1, "%llu", &id) != 1)
			continue;

		listns_ns_id_pool[listns_ns_id_pool_n++] = (__u64) id;
	}
}

/*
 * ns_type picker.  Real callers pass exactly one CLONE_NEW* bit;
 * uniform pick across the eight defined types covers each iterator
 * codepath equally.  A small zero arm exercises the "missing type"
 * EINVAL gate; a rand32 tail keeps the validator warm against
 * unmodelled high-bit garbage.
 */
static __u32 pick_listns_ns_type(void)
{
	unsigned int bucket = rnd_modulo_u32(20);

	if (bucket < 16)
		return (__u32) ns_types[rnd_modulo_u32(ARRAY_SIZE(ns_types))];
	if (bucket < 18)
		return 0;
	return rnd_u32();
}

/*
 * ns_id picker.  Zero means "list the whole tree for ns_type" -- the
 * dominant real-world shape and the bulk of the iterator work.  Pool
 * picks hit the find_ns_id() lookup arm with a live id.  Raw u64
 * keeps the lookup-miss path warm.
 */
static __u64 pick_listns_ns_id(void)
{
	unsigned int bucket;

	load_listns_ns_id_pool();

	bucket = rnd_modulo_u32(10);

	if (bucket < 5)
		return 0;
	if (bucket < 8 && listns_ns_id_pool_n > 0)
		return listns_ns_id_pool[
			rnd_modulo_u32(listns_ns_id_pool_n)];
	return (__u64) rnd_u64();
}

/*
 * user_ns_id picker.  Almost always zero (use the caller's user
 * namespace); occasional pool / random arms exercise the explicit
 * user-ns resolution path.
 */
static __u64 pick_listns_user_ns_id(void)
{
	unsigned int bucket;

	load_listns_ns_id_pool();

	bucket = rnd_modulo_u32(10);

	if (bucket < 7)
		return 0;
	if (bucket < 9 && listns_ns_id_pool_n > 0)
		return listns_ns_id_pool[
			rnd_modulo_u32(listns_ns_id_pool_n)];
	return (__u64) rnd_u64();
}

/*
 * nr_ns_ids bucket.  0 trips the early EINVAL gate; 8 / 64 / 1024
 * give the iterator a small / typical / large output bound to honor.
 * The underlying allocation is LISTNS_BUF_SLOTS regardless, so a
 * kernel-side over-write cannot scribble past our buffer.
 */
static unsigned long pick_listns_nr(void)
{
	switch (rnd_modulo_u32(4)) {
	case 0:  return 0;
	case 1:  return 8;
	case 2:  return 64;
	default: return LISTNS_BUF_SLOTS;
	}
}

/*
 * Flags bucket.  Most callers pass zero; LISTNS_CURRENT_USER is the
 * only defined alt-flag; the rand32 arm keeps the flag validator
 * warm against unmodelled high-bit garbage.
 */
static unsigned long pick_listns_flags(void)
{
	unsigned int bucket = rnd_modulo_u32(20);

	if (bucket < 16)
		return 0;
	if (bucket < 19)
		return LISTNS_CURRENT_USER;
	return rnd_u32();
}

/*
 * Snapshot of the listns input args read by the post oracle, captured at
 * sanitise time and consumed by the post handler.  Lives in rec->post_state,
 * a slot the syscall ABI does not expose, so a sibling syscall scribbling
 * rec->aN between the syscall returning and the post handler running cannot
 * smear the size bound used to validate the retval.
 *
 * Wired into the post_state ownership table by post_state_install() at
 * sanitise time; post_listns() gates the snap through
 * post_state_claim_owned() before any field deref, so a sibling stomp that
 * redirects rec->post_state at a foreign heap chunk is rejected by the
 * ownership lookup before the leading-word magic compare ever runs.
 */
#define LISTNS_POST_STATE_MAGIC	0x4C4E5321UL	/* "LNS!" */
struct listns_post_state {
	unsigned long magic;
	unsigned long req;
	unsigned long nr_ns_ids;
};

static const struct csfu_desc desc_listns = {
	.name = "ns_id_req",
	.ksize = sizeof(struct ns_id_req),
	.size_field_off = offsetof(struct ns_id_req, size),
	.size_field_width = sizeof(((struct ns_id_req *) 0)->size),
};

static void sanitise_listns(struct syscallrecord *rec)
{
	struct csfu_buf csfu;
	struct ns_id_req *req;
	__u64 *ns_ids;
	struct listns_post_state *snap;
	unsigned long nr;

	csfu = build_csfu_struct(&desc_listns);
	req = csfu.ptr;
	if (req == NULL)
		return;

	req->ns_type = pick_listns_ns_type();
	req->ns_id = pick_listns_ns_id();
	req->user_ns_id = pick_listns_user_ns_id();

	ns_ids = (__u64 *) get_writable_address(
		LISTNS_BUF_SLOTS * sizeof(*ns_ids));
	if (ns_ids == NULL) {
		/*
		 * get_writable_address() can legally return NULL when the
		 * per-child mapping pool is exhausted.  req was allocated
		 * via zmalloc_tracked above; without the enqueue here the
		 * tracked allocation lingers in the alloc-track ring until
		 * LRU eviction.  Hand it off so the deferred-free path
		 * reclaims it on the next flush.
		 */
		deferred_free_enqueue(req);
		return;
	}

	nr = pick_listns_nr();

	rec->a1 = (unsigned long) req;
	rec->a2 = (unsigned long) ns_ids;
	rec->a3 = nr;
	rec->a4 = pick_listns_flags();

	avoid_shared_buffer_inout(&rec->a1, csfu.usize);
	avoid_shared_buffer_out(&rec->a2, nr * sizeof(*ns_ids));

	/* Snapshot for the post handler -- a1 / a3 may be scribbled by a
	 * sibling syscall before post_listns() runs. */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = LISTNS_POST_STATE_MAGIC;
	snap->req = rec->a1;
	snap->nr_ns_ids = rec->a3;
	post_state_install(rec, snap);
}

static void post_listns(struct syscallrecord *rec)
{
	struct listns_post_state *snap;
	unsigned long retval = rec->retval;
	long ret = (long) retval;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, LISTNS_POST_STATE_MAGIC, __func__);
	if (snap == NULL) {
		rec->a1 = 0;
		return;
	}

	/*
	 * Kernel ABI: sys_listns writes at most nr_ns_ids u64 namespace IDs
	 * to the user buffer and returns the count written, capped at the
	 * snapshotted nr_ns_ids arg.  Failure returns -1UL.  Anything >
	 * snap->nr_ns_ids on a non-(-1UL) return is structural ABI
	 * corruption: a sign-extension tear in the syscall return path, a
	 * kernel-side write that spilled past the user-supplied bound, or a
	 * torn read of the namespace iterator counter.  Fall through to
	 * out_free so the deferred req / post_state buffers are still
	 * released.
	 */
	if (ret != -1L && retval > snap->nr_ns_ids) {
		outputerr("post_listns: retval %lu exceeds requested nr_ns_ids %lu\n",
			  retval, snap->nr_ns_ids);
		post_handler_corrupt_ptr_bump(rec, NULL);
		goto out_free;
	}

out_free:
	rec->a1 = 0;
	deferred_freeptr(&snap->req);
	post_state_release(rec, snap);
}

struct syscallentry syscall_listns = {
	.name = "listns",
	.num_args = 4,
	.argname = { [0] = "req", [1] = "ns_ids", [2] = "nr_ns_ids", [3] = "flags" },
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_ADDRESS, [2] = ARG_LEN },
	.sanitise = sanitise_listns,
	.post = post_listns,
	.group = GROUP_PROCESS,
	.bound_arg = 3,
	.rettype = RET_NUM_BYTES,
	.flags = REEXEC_SANITISE_OK,
};
