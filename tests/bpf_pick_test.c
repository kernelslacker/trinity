/*
 * Self-check for the bpf object pickers (fds/bpf.c): init seeds no link,
 * btf or token into the global pool, and a child's add to it is a no-op,
 * so their fds live only in the pool of the child whose syscall post made
 * them, and a picker hands one out on every call while the global pool is
 * empty, as the map picker does when no map was seeded; an object whose
 * fd is gone is never handed out.  The pools come through
 * fake_objects.c's get_objhead() hook, and the pickers are reached through
 * __real_, past the fake_fds.c stand-ins.
 */

#include <stdio.h>
#include <string.h>

#include "bpf.h"		/* struct bpfobj */
#include "debug.h"		/* BUG */
#include "objects.h"
#include "utils-macros.h"	/* ARRAY_SIZE */

#ifdef USE_BPF
extern struct objhead *(*fake_get_objhead)(enum obj_scope scope,
					   enum objecttype type);	/* fake_objects.c */

bool __real_get_rand_bpf_map(struct bpfobj *map);
int __real_get_rand_bpf_fd(void);
int __real_get_rand_bpf_link_fd(void);
int __real_get_rand_bpf_btf_fd(void);
int __real_get_rand_bpf_token_fd(void);

/* Calls per picker, each of which a lost coin flip used to cost. */
#define PICKS	64

static struct objhead local_head, global_head;
static struct object pooled;
static struct object *local_array[1];

static struct objhead *head_hook(enum obj_scope scope, enum objecttype type)
{
	(void)type;
	return scope == OBJ_LOCAL ? &local_head : &global_head;
}
#endif

void bpf_pick_self_check(void);
void bpf_pick_self_check(void)
{
#ifdef USE_BPF
	static const struct {
		const char *what;
		enum objecttype type;
		int (*pick)(void);
		int *fd;
	} pickers[] = {
		{ "map", OBJ_FD_BPF_MAP, __real_get_rand_bpf_fd,
		  &pooled.bpfobj.map_fd },
		{ "link", OBJ_FD_BPF_LINK, __real_get_rand_bpf_link_fd,
		  &pooled.bpflinkobj.fd },
		{ "btf", OBJ_FD_BPF_BTF, __real_get_rand_bpf_btf_fd,
		  &pooled.bpfbtfobj.fd },
		{ "token", OBJ_FD_BPF_TOKEN, __real_get_rand_bpf_token_fd,
		  &pooled.bpftokenobj.fd },
	};
	struct bpfobj map;
	unsigned int i, k;

	fake_get_objhead = head_hook;
	local_array[0] = &pooled;
	local_head.array = local_array;
	local_head.num_entries = 1;
	for (i = 0; i < ARRAY_SIZE(pickers); i++) {
		memset(&pooled, 0, sizeof(pooled));
		pooled.obj_type = pickers[i].type;
		*pickers[i].fd = 42;
		for (k = 0; k < PICKS; k++) {
			if (pickers[i].pick() == 42)
				continue;
			fprintf(stderr, "bpf %s: pick %u missed the child's own\n",
				pickers[i].what, k);
			BUG("bpf pick: a picker passed over the child's pool");
		}
	}

	memset(&pooled, 0, sizeof(pooled));
	pooled.obj_type = OBJ_FD_BPF_MAP;
	pooled.bpfobj.map_fd = -1;
	for (k = 0; k < PICKS; k++) {
		if (__real_get_rand_bpf_map(&map))
			BUG("bpf pick: a map whose fd is gone was handed out");
	}
	fake_get_objhead = NULL;
	memset(&local_head, 0, sizeof(local_head));
#endif
}
