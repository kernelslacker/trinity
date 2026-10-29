/*
 * Environment for linking fds/fds.c and fds/fds-registry.c into the test
 * binary: the allocator and list validator the registry needs, and a stub
 * for the object-pool lookup the fd-to-provider walk reaches.  The stub
 * aborts unless a test has installed a pool, so a test that wanders into
 * that walk fails loudly instead of quietly seeing an untracked fd.  Also
 * the pickers of fds/bpf.c, which the bpf sanitisers draw from.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bpf.h"
#include "cgroup.h"
#include "perf.h"
#include "list.h"
#include "objects.h"
#include "utils.h"

/* Owned by utils/zmalloc.c in production.  The registry relies on zeroed nodes. */
void *__zmalloc(size_t size, const char *func)
{
	void *p = calloc(1, size);

	if (p == NULL) {
		fprintf(stderr, "fake __zmalloc: calloc(%zu) failed in %s\n",
			size, func);
		abort();
	}
	return p;
}

/*
 * Owned by utils/debug.c in production, where it checks the links around
 * an insertion.  The lists the tests build come from the registry itself.
 */
void __list_add_valid_or_die(struct list_head *new, struct list_head *prev,
			     struct list_head *next, const char *file,
			     const char *func, unsigned int line)
{
	(void)new; (void)prev; (void)next;
	(void)file; (void)func; (void)line;
}

/*
 * What find_object_by_fd() answers.  A test that drives code reaching the
 * lookup sets this for the duration of the call and clears it after.
 */
struct object *(*fake_find_object_by_fd)(int fd);

struct object *find_object_by_fd(int fd)
{
	if (fake_find_object_by_fd == NULL) {
		fprintf(stderr, "fake find_object_by_fd called unexpectedly\n");
		abort();
	}
	return fake_find_object_by_fd(fd);
}

/*
 * The pickers of fds/bpf.c, whose pools no test provides: the sanitisers of
 * syscalls/bpf*.c and the perf ioctl group take -1 from each, as they do
 * from an empty pool, but for the map picker, which answers with the map a
 * test installs a hook to name, and the program picker, which answers with
 * the program a test's hook names or, unhooked, a program of no particular
 * type at the fd a test sets.
 */
bool (*fake_get_rand_bpf_map)(struct bpfobj *map);
bool (*fake_get_rand_bpf_prog)(struct bpfprogobj *prog);
int fake_bpf_prog_fd = -1;

bool get_rand_bpf_map(struct bpfobj *map)
{
	return fake_get_rand_bpf_map != NULL && fake_get_rand_bpf_map(map);
}

int get_rand_bpf_fd(void)
{
	struct bpfobj map;

	return get_rand_bpf_map(&map) ? map.map_fd : -1;
}

bool get_rand_bpf_prog(struct bpfprogobj *prog)
{
	if (fake_get_rand_bpf_prog != NULL)
		return fake_get_rand_bpf_prog(prog);
	memset(prog, 0, sizeof(*prog));
	prog->fd = fake_bpf_prog_fd;
	return fake_bpf_prog_fd >= 0;
}

int get_rand_bpf_prog_fd(void)
{
	struct bpfprogobj prog;

	return get_rand_bpf_prog(&prog) ? prog.fd : -1;
}

int get_rand_bpf_link_fd(void)
{
	return -1;
}

/* The pickers of fds/perf.c and fds/cgroup.c, which answer with the fd a
 * test sets, -1 from an empty pool. */
int fake_perf_fd = -1;
int fake_cgroup_fd = -1;

int get_rand_perf_fd(void)
{
	return fake_perf_fd;
}

int get_rand_cgroup_fd(void)
{
	return fake_cgroup_fd;
}

int get_rand_bpf_btf_fd(void)
{
	return -1;
}

int get_rand_bpf_token_fd(void)
{
	return -1;
}
