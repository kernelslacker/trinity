/*
 * SYSCALL_DEFINE4(listns, const struct ns_id_req __user *, req,
 *		u64 __user *, ns_ids, size_t, nr_ns_ids,
 *		unsigned int, flags)
 */
#include <linux/types.h>
#include <sched.h>
#include "random.h"
#include "sanitise.h"
#include "utils.h"

/*
 * struct ns_id_req from include/uapi/linux/nsfs.h.
 * Define locally to build against older kernel headers.
 */
#ifndef NS_ID_REQ_SIZE_VER0
struct ns_id_req {
	__u32 size;
	__u32 ns_type;
	__u64 ns_id;
	__u64 user_ns_id;
};
#define NS_ID_REQ_SIZE_VER0	24
#endif

#ifndef LISTNS_CURRENT_USER
#define LISTNS_CURRENT_USER	(1 << 0)
#endif

#ifndef CLONE_NEWCGROUP
#define CLONE_NEWCGROUP		0x02000000
#endif

static unsigned long listns_flags[] = {
	LISTNS_CURRENT_USER,
};

static unsigned long ns_types[] = {
	CLONE_NEWNS,
	CLONE_NEWUTS,
	CLONE_NEWIPC,
	CLONE_NEWUSER,
	CLONE_NEWPID,
	CLONE_NEWNET,
	CLONE_NEWCGROUP,
};

static void sanitise_listns(struct syscallrecord *rec)
{
	struct ns_id_req *req;

	req = zmalloc(sizeof(struct ns_id_req));
	req->size = NS_ID_REQ_SIZE_VER0;
	req->ns_type = ns_types[rand() % ARRAY_SIZE(ns_types)];

	rec->a1 = (unsigned long) req;
	rec->a3 = RAND_RANGE(1, 512);
}

static void post_listns(struct syscallrecord *rec)
{
	freeptr(&rec->a1);
}

struct syscallentry syscall_listns = {
	.name = "listns",
	.num_args = 4,
	.arg1name = "req",
	.arg1type = ARG_ADDRESS,
	.arg2name = "ns_ids",
	.arg2type = ARG_ADDRESS,
	.arg3name = "nr_ns_ids",
	.arg3type = ARG_LEN,
	.arg4name = "flags",
	.arg4type = ARG_LIST,
	.arg4list = ARGLIST(listns_flags),
	.rettype = RET_ZERO_SUCCESS,
	.sanitise = sanitise_listns,
	.post = post_listns,
};
