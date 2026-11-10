/*
 * Environment for linking fds/fds.c and fds/fds-registry.c into the test
 * binary: the allocator and list validator the registry needs, and a stub
 * for the object-pool lookup the fd-to-provider walk reaches.  The stub
 * aborts unless a test has installed a pool, so a test that wanders into
 * that walk fails loudly instead of quietly seeing an untracked fd.  Also
 * the pickers of fds/bpf.c, which the bpf sanitisers draw from, the ring
 * picker of fds/io_uring.c, which io_uring_register's draws from, and an
 * unlink() that can plant a symlink under the name it removes.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bpf.h"
#include "cgroup.h"
#include "perf.h"
#include "list.h"
#include "objects.h"
#include "utils.h"

/*
 * For the providers that unlink a name in the run's cwd, then create it:
 * armed with that name, the next unlink() of it leaves a symlink to
 * fake_unlink_target in its place, as a local user who wins the race in
 * a world-writable tmp/ would, and disarms.  Unarmed, the real call.
 */
const char *fake_unlink_plant;
const char *fake_unlink_target;

int __real_unlink(const char *path);
int __wrap_unlink(const char *path);
int __wrap_unlink(const char *path)
{
	int ret = __real_unlink(path);

	if (fake_unlink_plant != NULL && strcmp(path, fake_unlink_plant) == 0) {
		fake_unlink_plant = NULL;
		if (symlink(fake_unlink_target, path) != 0) {
			fprintf(stderr, "fake unlink: cannot plant %s\n", path);
			abort();
		}
	}
	return ret;
}

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
 * Owned by utils/debug.c in production, where they check the links around
 * an insertion and a removal.  The lists the tests build come from the
 * registry and the pathname pool themselves.
 */
void __list_add_valid_or_die(struct list_head *new, struct list_head *prev,
			     struct list_head *next, const char *file,
			     const char *func, unsigned int line)
{
	(void)new; (void)prev; (void)next;
	(void)file; (void)func; (void)line;
}

void __list_del_entry_valid_or_die(struct list_head *entry, const char *file,
				   const char *func, unsigned int line)
{
	(void)entry;
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
 * Stand-ins for the pickers of fds/bpf.c, which bpf_pick_test.c runs
 * through __real_: every other caller, the sanitisers of syscalls/bpf*.c
 * and the perf ioctl group among them, gets these, which read no pool.
 * Each answers -1, as an empty pool does, but for the map picker, which
 * answers with the map a test installs a hook to name, the program picker,
 * which answers with the program a test's hook names or, unhooked, a
 * program of no particular type at the fd a test sets, and the pick of a
 * program by type, which answers with the fd a test's hook gives the type.
 */
bool (*fake_get_rand_bpf_map)(struct bpfobj *map);
bool (*fake_get_rand_bpf_prog)(struct bpfprogobj *prog);
int fake_bpf_prog_fd = -1;

bool __wrap_get_rand_bpf_map(struct bpfobj *map);
bool __wrap_get_rand_bpf_map(struct bpfobj *map)
{
	return fake_get_rand_bpf_map != NULL && fake_get_rand_bpf_map(map);
}

int __wrap_get_rand_bpf_fd(void);
int __wrap_get_rand_bpf_fd(void)
{
	struct bpfobj map;

	return __wrap_get_rand_bpf_map(&map) ? map.map_fd : -1;
}

bool __wrap_get_rand_bpf_prog(struct bpfprogobj *prog);
bool __wrap_get_rand_bpf_prog(struct bpfprogobj *prog)
{
	if (fake_get_rand_bpf_prog != NULL)
		return fake_get_rand_bpf_prog(prog);
	memset(prog, 0, sizeof(*prog));
	prog->fd = fake_bpf_prog_fd;
	return fake_bpf_prog_fd >= 0;
}

int __wrap_get_rand_bpf_prog_fd(void);
int __wrap_get_rand_bpf_prog_fd(void)
{
	struct bpfprogobj prog;

	return __wrap_get_rand_bpf_prog(&prog) ? prog.fd : -1;
}

int (*fake_get_rand_bpf_prog_fd_of_type)(unsigned int prog_type);

int __wrap_get_rand_bpf_prog_fd_of_type(unsigned int prog_type);
int __wrap_get_rand_bpf_prog_fd_of_type(unsigned int prog_type)
{
	if (fake_get_rand_bpf_prog_fd_of_type != NULL)
		return fake_get_rand_bpf_prog_fd_of_type(prog_type);
	return -1;
}

int __wrap_get_rand_bpf_link_fd(void);
int __wrap_get_rand_bpf_link_fd(void)
{
	return -1;
}

int __wrap_get_rand_bpf_btf_fd(void);
int __wrap_get_rand_bpf_btf_fd(void)
{
	return -1;
}

int __wrap_get_rand_bpf_token_fd(void);
int __wrap_get_rand_bpf_token_fd(void)
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

/* No ring is set up here, so the pool is empty. */
struct io_uringobj *get_io_uring_ring(void)
{
	return NULL;
}
