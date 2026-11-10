/*
 * Self-check for the bpf object pickers (fds/bpf.c): init seeds no
 * link, btf or token into the global pool, and a child's add to it is a
 * no-op, so their fds live only in the pool of the child whose syscall
 * post made them, and a picker hands one out on every call while the
 * global pool is empty, as the map and program pickers do when init
 * seeded none; an object whose fd is gone is never handed out.  A pick of
 * a program or a map by type draws from both pools.  The pools come
 * through fake_objects.c's get_objhead() hook, and the pickers are reached
 * through __real_, past the fake_fds.c stand-ins.
 */

#include <stdio.h>
#include <string.h>

#include "bpf.h"		/* struct bpfobj, struct bpfprogobj */
#include "debug.h"		/* BUG */
#include "objects.h"
#include "utils-macros.h"	/* ARRAY_SIZE */

#ifdef USE_BPF
extern struct objhead *(*fake_get_objhead)(enum obj_scope scope,
					   enum objecttype type);	/* fake_objects.c */

bool __real_get_rand_bpf_map(struct bpfobj *map);
int __real_get_rand_bpf_fd(void);
bool __real_get_rand_bpf_prog(struct bpfprogobj *prog);
int __real_get_rand_bpf_prog_fd(void);
int __real_get_rand_bpf_prog_fd_of_type(unsigned int prog_type);
int __real_get_rand_bpf_map_fd_of_types(const unsigned int *map_types,
					unsigned int n_types);
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

/*
 * The child's LWT_XMIT program and the global one each come back from a
 * pick of that type, and neither the global program of another type nor a
 * matching one whose fd is gone ever does.  A type no pool holds is -1.
 */
static void typed_prog_pick_check(void)
{
	static struct object progs[4];
	static struct object *global_array[3];
	bool seen_local = false, seen_global = false;
	unsigned int k;

	memset(progs, 0, sizeof(progs));
	for (k = 0; k < ARRAY_SIZE(progs); k++) {
		progs[k].obj_type = OBJ_FD_BPF_PROG;
		progs[k].bpfprogobj.prog_type = BPF_PROG_TYPE_LWT_XMIT;
		progs[k].bpfprogobj.fd = 42 + k;
	}
	progs[1].bpfprogobj.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
	progs[3].bpfprogobj.fd = -1;
	local_array[0] = &progs[0];
	local_head.array = local_array;
	local_head.num_entries = 1;
	global_array[0] = &progs[1];
	global_array[1] = &progs[2];
	global_array[2] = &progs[3];
	global_head.array = global_array;
	global_head.num_entries = ARRAY_SIZE(global_array);

	for (k = 0; k < PICKS; k++) {
		int fd = __real_get_rand_bpf_prog_fd_of_type(BPF_PROG_TYPE_LWT_XMIT);

		if (fd == 42) {
			seen_local = true;
		} else if (fd == 44) {
			seen_global = true;
		} else {
			fprintf(stderr, "bpf typed pick: pick %u gave fd %d\n", k, fd);
			BUG("bpf pick: a typed pick gave a program of another type or a closed one");
		}
	}
	if (!seen_local || !seen_global)
		BUG("bpf pick: a typed pick passed over one of the pools");
	if (__real_get_rand_bpf_prog_fd_of_type(BPF_PROG_TYPE_LWT_IN) != -1)
		BUG("bpf pick: a typed pick found a type no pool holds");
	memset(&global_head, 0, sizeof(global_head));
}

/*
 * A pick of a map by type goes the program pick's way over the maps, by
 * their map type: one of a sockmap or a sockhash gives back the child's
 * sockmap and the global sockhash, never the global hash.
 */
static void typed_map_pick_check(void)
{
	static const unsigned int sockmaps[] = {
		BPF_MAP_TYPE_SOCKMAP, BPF_MAP_TYPE_SOCKHASH,
	};
	static const unsigned int devmap[] = { BPF_MAP_TYPE_DEVMAP };
	static struct object maps[3];
	static struct object *global_array[2];
	bool seen_local = false, seen_global = false;
	unsigned int k;

	memset(maps, 0, sizeof(maps));
	for (k = 0; k < ARRAY_SIZE(maps); k++) {
		maps[k].obj_type = OBJ_FD_BPF_MAP;
		maps[k].bpfobj.map_fd = 52 + k;
	}
	maps[0].bpfobj.map_type = BPF_MAP_TYPE_SOCKMAP;
	maps[1].bpfobj.map_type = BPF_MAP_TYPE_HASH;
	maps[2].bpfobj.map_type = BPF_MAP_TYPE_SOCKHASH;
	local_array[0] = &maps[0];
	local_head.array = local_array;
	local_head.num_entries = 1;
	global_array[0] = &maps[1];
	global_array[1] = &maps[2];
	global_head.array = global_array;
	global_head.num_entries = ARRAY_SIZE(global_array);

	for (k = 0; k < PICKS; k++) {
		int fd = __real_get_rand_bpf_map_fd_of_types(sockmaps,
							     ARRAY_SIZE(sockmaps));

		if (fd == 52) {
			seen_local = true;
		} else if (fd == 54) {
			seen_global = true;
		} else {
			fprintf(stderr, "bpf typed map pick: pick %u gave fd %d\n", k, fd);
			BUG("bpf pick: a typed map pick gave a map of another type");
		}
	}
	if (!seen_local || !seen_global)
		BUG("bpf pick: a typed map pick passed over one of the pools");
	if (__real_get_rand_bpf_map_fd_of_types(devmap, ARRAY_SIZE(devmap)) != -1)
		BUG("bpf pick: a typed map pick found a type no pool holds");
	memset(&global_head, 0, sizeof(global_head));
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
		{ "prog", OBJ_FD_BPF_PROG, __real_get_rand_bpf_prog_fd,
		  &pooled.bpfprogobj.fd },
		{ "link", OBJ_FD_BPF_LINK, __real_get_rand_bpf_link_fd,
		  &pooled.bpflinkobj.fd },
		{ "btf", OBJ_FD_BPF_BTF, __real_get_rand_bpf_btf_fd,
		  &pooled.bpfbtfobj.fd },
		{ "token", OBJ_FD_BPF_TOKEN, __real_get_rand_bpf_token_fd,
		  &pooled.bpftokenobj.fd },
	};
	struct bpfprogobj prog;
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
	memset(&pooled, 0, sizeof(pooled));
	pooled.obj_type = OBJ_FD_BPF_PROG;
	pooled.bpfprogobj.fd = -1;
	for (k = 0; k < PICKS; k++) {
		if (__real_get_rand_bpf_prog(&prog))
			BUG("bpf pick: a program whose fd is gone was handed out");
	}
	typed_prog_pick_check();
	typed_map_pick_check();
	fake_get_objhead = NULL;
	memset(&local_head, 0, sizeof(local_head));
#endif
}
