/*
 * bpf_lifecycle: end-to-end BPF program lifecycle with map mutation.
 *
 * Trinity already fuzzes individual bpf() commands well, but the kernel
 * paths reached by random isolated calls miss the most interesting one:
 * a verifier-passing program that gets attached to a real hook, has its
 * referenced map mutated under it, then runs against the live map state.
 * Almost every BPF CVE in the past few years (verifier reasoning flaws,
 * map UAFs, attach/detach refcount bugs, helper boundary errors) requires
 * this full chain, not random isolated commands.
 *
 * This childop drives the chain in one self-contained sequence:
 *
 *   1. bpf(MAP_CREATE)                — array map (predictable keys 0..N-1)
 *   2. bpf(PROG_LOAD)                  — minimal program that references
 *                                        the map via BPF_LD_MAP_FD and
 *                                        does a bounds-checked
 *                                        bpf_map_lookup_elem call
 *   3. attach to a hook                — combo-specific:
 *                                          SOCKET_FILTER ↦ setsockopt
 *                                                          (SO_ATTACH_BPF)
 *                                          CGROUP_SKB    ↦ bpf(PROG_ATTACH)
 *   4. bpf(MAP_UPDATE_ELEM) × N        — mutate live map values while the
 *                                        program is attached
 *   5. trigger via syscall             — combo-specific:
 *                                          SOCKET_FILTER: send/recv on
 *                                                         the attached
 *                                                         socket plus
 *                                                         BPF_PROG_TEST_RUN
 *                                          CGROUP_SKB:    UDP loopback
 *                                                         packet to drive
 *                                                         the cgroup
 *                                                         INET_INGRESS hook
 *   6. detach                          — SO_DETACH_BPF or bpf(PROG_DETACH)
 *   7. bpf(MAP_DELETE_ELEM) × N        — drain the map
 *   8. close prog/map fds              — explicit cleanup, BPF fds aren't
 *                                        in trinity's object catalog
 *
 * The program is a small (~9 insn) verifier-passing template chosen to
 * pass on every modern kernel without privileges:
 *
 *     r2 = 0
 *     *(u32 *)(r10 - 4) = r2          ; key = 0 on the stack
 *     r2 = r10
 *     r2 += -4                        ; r2 = &key
 *     r1 = map_fd                     ; LD_MAP_FD (two slots)
 *     call bpf_map_lookup_elem        ; r0 = lookup result (may be NULL)
 *     r0 = 0                          ; SOCKET_FILTER drop / CGROUP_SKB
 *                                       drop, both safe defaults
 *     exit
 *
 * The lookup result is intentionally ignored — what we want is the
 * verifier-validated map access path running with mutating contents.
 *
 * Two combos are dispatched stochastically per call:
 *   - SOCKET_FILTER (~70%) — works without privileges on essentially any
 *     kernel.  Attach is via setsockopt on a socketpair; trigger is a
 *     send()/recv() pair plus a BPF_PROG_TEST_RUN to definitively run
 *     the program under the verifier-blessed runtime.
 *   - CGROUP_SKB (~30%) — exercises the canonical bpf(PROG_ATTACH) path.
 *     Requires CAP_BPF + CAP_NET_ADMIN
 *     plus a writable cgroup directory; on the first failure with
 *     EPERM/EACCES (or no cgroup) we latch the combo off for the rest of
 *     the child's life so we don't spin retrying.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <linux/bpf.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include "arch.h"
#include "bpf.h"
#include "bpf-syscall.h"
#include "child.h"
#include "childops-util.h"
#include "objects.h"
#include "publish_resource.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"

#include "kernel/fcntl.h"
#include "kernel/mman.h"
#include "kernel/socket.h"
#ifndef SO_DETACH_BPF
#define SO_DETACH_BPF		SO_DETACH_FILTER
#endif
#ifndef BPF_F_ALLOW_MULTI
#define BPF_F_ALLOW_MULTI	(1U << 1)
#endif
#ifndef BPF_MAP_TYPE_ARENA
#define BPF_MAP_TYPE_ARENA	33
#endif
#ifndef BPF_F_MMAPABLE
#define BPF_F_MMAPABLE		(1U << 10)
#endif

#define MAP_ENTRIES		8

/*
 * Build and load the verifier-passing template program for prog_type.
 * The map fd is patched into the BPF_LD_MAP_FD instruction's imm field
 * after the array is initialised so we can use a runtime-known fd.
 *
 * Returns the loaded program fd on success, or -1 with errno set.
 */
static int load_template_prog(unsigned int prog_type, int map_fd)
{
	struct bpf_insn insns[] = {
		/* r2 = 0 */
		EBPF_MOV64_IMM(BPF_REG_2, 0),
		/* *(u32 *)(r10 - 4) = r2 */
		EBPF_STX_MEM(BPF_W, BPF_REG_10, BPF_REG_2, -4),
		/* r2 = r10 */
		EBPF_MOV64_REG(BPF_REG_2, BPF_REG_10),
		/* r2 += -4   (r2 now points to the on-stack key) */
		EBPF_ALU64_IMM(BPF_ADD, BPF_REG_2, -4),
		/*
		 * BPF_LD_MAP_FD is a 64-bit immediate load that occupies
		 * two instruction slots; src_reg=1 tells the verifier the
		 * imm is a map fd to be resolved.  The macro in bpf.h uses
		 * the comma operator, which would only emit one slot inside
		 * an initializer-list, so we open-code both slots here.
		 */
		{ .code = BPF_LD | BPF_DW | BPF_IMM,
		  .dst_reg = BPF_REG_1, .src_reg = BPF_PSEUDO_MAP_FD,
		  .off = 0, .imm = 0 },		/* imm patched below */
		{ .code = 0,
		  .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0 },
		/* call bpf_map_lookup_elem */
		EBPF_CALL(BPF_FUNC_map_lookup_elem),
		/* r0 = 0 — drop/return path that's safe for both combos */
		EBPF_MOV64_IMM(BPF_REG_0, 0),
		/* exit */
		EBPF_EXIT(),
	};
	union bpf_attr attr;
	char license[] = "GPL";

	insns[4].imm = map_fd;

	memset(&attr, 0, sizeof(attr));
	attr.prog_type = prog_type;
	attr.insn_cnt = ARRAY_SIZE(insns);
	attr.insns = (uintptr_t)insns;
	attr.license = (uintptr_t)license;

	return sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

static int create_array_map(void)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_ARRAY;
	attr.key_size = sizeof(uint32_t);
	attr.value_size = sizeof(uint32_t);
	attr.max_entries = MAP_ENTRIES;

	return sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

static void update_elem(int map_fd, uint32_t key, uint32_t value)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = map_fd;
	attr.key = (uintptr_t)&key;
	attr.value = (uintptr_t)&value;
	attr.flags = 0;

	(void)sys_bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

static void delete_elem(int map_fd, uint32_t key)
{
	union bpf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.map_fd = map_fd;
	attr.key = (uintptr_t)&key;

	(void)sys_bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

/*
 * Run the loaded program through the BPF_PROG_TEST_RUN command with a
 * fixed 64-byte buffer.  TEST_RUN works for SOCKET_FILTER without any
 * privileges on modern kernels and gives us a deterministic execution
 * of the program against the just-mutated map state.
 */
static void test_run(int prog_fd)
{
	unsigned char data_in[64];
	unsigned char data_out[64];
	union bpf_attr attr;

	generate_rand_bytes(data_in, sizeof(data_in));

	memset(&attr, 0, sizeof(attr));
	attr.test.prog_fd = prog_fd;
	attr.test.data_in = (uintptr_t)data_in;
	attr.test.data_size_in = sizeof(data_in);
	attr.test.data_out = (uintptr_t)data_out;
	attr.test.data_size_out = sizeof(data_out);
	attr.test.repeat = 1;

	(void)sys_bpf(BPF_PROG_TEST_RUN, &attr, sizeof(attr));
}

/*
 * Latches set after first irrecoverable failure for a combo, so we don't
 * keep re-failing for the rest of this child's life.  Per-child static —
 * each forked child has its own copy.
 */
static bool socket_filter_disabled;
static bool cgroup_disabled;
static bool arena_unsupported;

/*
 * Publish a freshly-created BPF map fd into the per-child object pool
 * so subsequent get_rand_bpf_fd() calls see the live mutating map
 * alongside the static templates the bpf-map provider seeded.  Returns
 * the obj* for use with destroy_object during teardown.
 *
 * Ownership transfers to the pool — the destructor wired up by the
 * bpf-map provider closes the fd when destroy_object runs.  Caller
 * must NOT close the fd directly after publishing.
 */
static struct object *publish_map_fd(int fd, uint32_t map_type)
{
	return publish_resource(OBJ_FD_BPF_MAP, fd,
				&(struct resource_meta){.subtype = map_type});
}

static struct object *publish_prog_fd(int fd, uint32_t prog_type)
{
	return publish_resource(OBJ_FD_BPF_PROG, fd,
				&(struct resource_meta){.subtype = prog_type});
}

/*
 * Combo A — SOCKET_FILTER, the unprivileged-friendly path.
 *
 * Returns true if the full chain ran (even with non-fatal in-flight
 * errors), false if a structural failure means we should not retry this
 * combo for this child.
 */
static bool combo_socket_filter(struct childdata *child)
{
	int sv[2] = { -1, -1 };
	int map_fd = -1;
	int prog_fd = -1;
	struct object *map_obj = NULL;
	struct object *prog_obj = NULL;
	uint32_t key;
	char buf[16];
	int i;
	bool ok = false;

	if (socket_filter_disabled)
		return false;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	map_fd = create_array_map();
	if (map_fd < 0)
		goto out;
	map_obj = publish_map_fd(map_fd, BPF_MAP_TYPE_ARRAY);

	prog_fd = load_template_prog(BPF_PROG_TYPE_SOCKET_FILTER, map_fd);
	if (prog_fd < 0) {
		if (errno == EPERM || errno == EACCES) {
			__atomic_add_fetch(&shm->stats.bpf_lifecycle.eperm,
					   1, __ATOMIC_RELAXED);
			socket_filter_disabled = true;
		} else {
			__atomic_add_fetch(&shm->stats.bpf_lifecycle.verifier_rejects,
					   1, __ATOMIC_RELAXED);
		}
		goto out;
	}
	__atomic_add_fetch(&shm->stats.bpf_lifecycle.progs_loaded, 1,
			   __ATOMIC_RELAXED);
	prog_obj = publish_prog_fd(prog_fd, BPF_PROG_TYPE_SOCKET_FILTER);

	if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
		sv[0] = sv[1] = -1;
		goto out;
	}

	/* Populate map before attach so first execution sees live entries. */
	for (key = 0; key < MAP_ENTRIES; key++)
		update_elem(map_fd, key, rand32());

	if (setsockopt(sv[0], SOL_SOCKET, SO_ATTACH_BPF,
		       &prog_fd, sizeof(prog_fd)) < 0) {
		__atomic_add_fetch(&shm->stats.bpf_lifecycle.attach_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	__atomic_add_fetch(&shm->stats.bpf_lifecycle.attached, 1,
			   __ATOMIC_RELAXED);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	/*
	 * Mutate-then-trigger interleaved.  Each iteration writes a fresh
	 * random value into a key, then drives the program both via the
	 * socket-layer hook (send/recv) and via PROG_TEST_RUN.  The latter
	 * is the most reliable trigger across socket implementations that
	 * may or may not invoke sk_filter on AF_UNIX dgram.
	 */
	for (i = 0; i < 4; i++) {
		ssize_t r;

		update_elem(map_fd, (uint32_t)(i & (MAP_ENTRIES - 1)),
			    rand32());
		(void)send(sv[1], "trig", 4, MSG_DONTWAIT);
		r = recv(sv[0], buf, sizeof(buf), MSG_DONTWAIT);
		(void)r;
		test_run(prog_fd);
	}
	__atomic_add_fetch(&shm->stats.bpf_lifecycle.triggered, 1,
			   __ATOMIC_RELAXED);

	(void)setsockopt(sv[0], SOL_SOCKET, SO_DETACH_BPF, NULL, 0);

	for (key = 0; key < MAP_ENTRIES; key++)
		delete_elem(map_fd, key);

	ok = true;

out:
	if (sv[0] >= 0)
		close(sv[0]);
	if (sv[1] >= 0)
		close(sv[1]);
	/*
	 * The prog/map fds were published into the local pool above and
	 * the destructor wired up by the bpf-{prog,map} provider closes
	 * them when destroy_object runs.  Manual close stays only for the
	 * pre-publish error paths where create_array_map() succeeded but
	 * load_template_prog() failed before publish_prog_fd() ran (and
	 * the symmetric early-create-failure path where map_obj is also
	 * NULL).
	 */
	if (prog_obj)
		destroy_object(prog_obj, OBJ_LOCAL, OBJ_FD_BPF_PROG);
	else if (prog_fd >= 0)
		close(prog_fd);
	if (map_obj)
		destroy_object(map_obj, OBJ_LOCAL, OBJ_FD_BPF_MAP);
	else if (map_fd >= 0)
		close(map_fd);
	return ok;
}

/*
 * Trigger CGROUP_SKB INET_INGRESS by emitting one UDP packet to the
 * loopback interface.  Anything that reaches the local socket layer in
 * our cgroup will run the attached program; we don't care if a recv()
 * actually returns the byte.
 */
static void cgroup_trigger(void)
{
	struct sockaddr_in sin;
	int s;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons((uint16_t)RAND_RANGE(1024, 65535));
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	(void)sendto(s, "x", 1, MSG_DONTWAIT,
		     (const struct sockaddr *)&sin, sizeof(sin));
	close(s);
}

/*
 * Combo B — CGROUP_SKB via the literal bpf(PROG_ATTACH) path.
 * Best-effort: needs CAP_BPF + CAP_NET_ADMIN plus
 * one of the trinity{0..7} cgroup directories that munge_process()
 * already uses.  Latches off on EPERM/EACCES or missing cgroup.
 */
static bool combo_cgroup_skb(struct childdata *child)
{
	int cgroup_fd = -1;
	int map_fd = -1;
	int prog_fd = -1;
	struct object *map_obj = NULL;
	struct object *prog_obj = NULL;
	union bpf_attr attr;
	char path[64];
	uint32_t key;
	bool attached = false;
	bool ok = false;

	if (cgroup_disabled)
		return false;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	snprintf(path, sizeof(path), "/sys/fs/cgroup/trinity%u",
		 rnd_modulo_u32(8));
	cgroup_fd = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
	if (cgroup_fd < 0) {
		cgroup_disabled = true;
		return false;
	}

	map_fd = create_array_map();
	if (map_fd < 0)
		goto out;
	map_obj = publish_map_fd(map_fd, BPF_MAP_TYPE_ARRAY);

	prog_fd = load_template_prog(BPF_PROG_TYPE_CGROUP_SKB, map_fd);
	if (prog_fd < 0) {
		if (errno == EPERM || errno == EACCES) {
			__atomic_add_fetch(&shm->stats.bpf_lifecycle.eperm,
					   1, __ATOMIC_RELAXED);
			cgroup_disabled = true;
		} else {
			__atomic_add_fetch(&shm->stats.bpf_lifecycle.verifier_rejects,
					   1, __ATOMIC_RELAXED);
		}
		goto out;
	}
	__atomic_add_fetch(&shm->stats.bpf_lifecycle.progs_loaded, 1,
			   __ATOMIC_RELAXED);
	prog_obj = publish_prog_fd(prog_fd, BPF_PROG_TYPE_CGROUP_SKB);

	for (key = 0; key < MAP_ENTRIES; key++)
		update_elem(map_fd, key, rand32());

	memset(&attr, 0, sizeof(attr));
	attr.target_fd = cgroup_fd;
	attr.attach_bpf_fd = prog_fd;
	attr.attach_type = BPF_CGROUP_INET_INGRESS;
	attr.attach_flags = (uint32_t)RAND_NEGATIVE_OR(BPF_F_ALLOW_MULTI);
	if (sys_bpf(BPF_PROG_ATTACH, &attr, sizeof(attr)) < 0) {
		if (errno == EPERM || errno == EACCES) {
			__atomic_add_fetch(&shm->stats.bpf_lifecycle.eperm,
					   1, __ATOMIC_RELAXED);
			cgroup_disabled = true;
		} else {
			__atomic_add_fetch(&shm->stats.bpf_lifecycle.attach_failed,
					   1, __ATOMIC_RELAXED);
		}
		goto out;
	}
	attached = true;
	__atomic_add_fetch(&shm->stats.bpf_lifecycle.attached, 1,
			   __ATOMIC_RELAXED);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	for (key = 0; key < MAP_ENTRIES; key++) {
		update_elem(map_fd, key, rand32());
		cgroup_trigger();
	}
	__atomic_add_fetch(&shm->stats.bpf_lifecycle.triggered, 1,
			   __ATOMIC_RELAXED);

	for (key = 0; key < MAP_ENTRIES; key++)
		delete_elem(map_fd, key);

	ok = true;

out:
	if (attached) {
		memset(&attr, 0, sizeof(attr));
		attr.target_fd = cgroup_fd;
		attr.attach_bpf_fd = prog_fd;
		attr.attach_type = BPF_CGROUP_INET_INGRESS;
		(void)sys_bpf(BPF_PROG_DETACH, &attr, sizeof(attr));
	}
	if (cgroup_fd >= 0)
		close(cgroup_fd);
	/* See combo_socket_filter() for why prog_obj/map_obj cleanup
	 * goes through destroy_object — the destructors close the fds. */
	if (prog_obj)
		destroy_object(prog_obj, OBJ_LOCAL, OBJ_FD_BPF_PROG);
	else if (prog_fd >= 0)
		close(prog_fd);
	if (map_obj)
		destroy_object(map_obj, OBJ_LOCAL, OBJ_FD_BPF_MAP);
	else if (map_fd >= 0)
		close(map_fd);
	return ok;
}

/*
 * Combo C — exercise the BPF arena map mmap() teardown across two mms.
 *
 * Arena maps (BPF_MAP_TYPE_ARENA, added in v6.9) expose a sparse 4 GiB
 * region as a mmap()-able fd.  The kernel marks arena VMAs VM_DONTCOPY,
 * so the mapping is NOT inherited across fork; exercising arena teardown
 * across multiple mms means each task that wants the mapping must mmap
 * the fd itself.  No other childop creates an arena map or drives such
 * a two-mm mapping, so the arena map_vm_close() path under concurrent
 * teardown was unreached.
 *
 * Sequence:
 *   1. BPF_MAP_CREATE arena with BPF_F_MMAPABLE, key_size = value_size = 0,
 *      max_entries = small page count (the arena's max grow size).
 *   2. mmap(MAP_SHARED) the arena fd for a few pages worth; the kernel
 *      records user_vm_start/end on this first mapping.
 *   3. fork().  Grandchild re-mmaps the arena fd at the same virtual
 *      address with MAP_FIXED_NOREPLACE — the arena requires the same
 *      addr+len once user_vm_start/end are set, and the parent's VMA is
 *      absent in the child mm so MAP_FIXED_NOREPLACE will not collide.
 *      The grandchild then touches each page to force population,
 *      munmap()s, and _exit(0)s.  Parent concurrently munmap()s and
 *      close()s its own copies, racing the arena vm-close teardown
 *      across the two address spaces.
 *   4. Parent reaps the grandchild via waitpid_eintr() (child.c installs
 *      SIGALRM/SIGXCPU without SA_RESTART, so a plain waitpid() can
 *      return EINTR mid-syscall) and only counts the run when the
 *      grandchild reached its clean exit — a SIGSEGV or non-zero exit
 *      means the multi-mm teardown path was not actually exercised.
 *
 * If BPF_MAP_CREATE fails (older kernel without arena support, or
 * CONFIG_BPF_SYSCALL=n / arena disabled), latch arena_unsupported and
 * bail cleanly — we must not crash trinity over a missing feature.
 */
static bool combo_arena_fork(struct childdata *child)
{
	union bpf_attr attr;
	unsigned int npages;
	long page_sz;
	size_t map_len;
	int map_fd;
	void *map;
	pid_t pid;
	pid_t rc;
	int status = 0;

	if (arena_unsupported)
		return false;

	/* Snapshot child->op_type once and bounds-check before indexing
	 * the per-op stats arrays.  The field lives in shared memory and
	 * can be scribbled by a poisoned-arena write from a sibling; the
	 * child.c dispatch loop already gates its dispatch + alt-op
	 * accounting on the same valid_op snapshot.  Skip the stats
	 * writes entirely when the snapshot is out of range. */
	const enum child_op_type op = child->op_type;
	const bool valid_op = ((int) op >= 0 && op < NR_CHILD_OP_TYPES);

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.setup_accepted[op],
				   1, __ATOMIC_RELAXED);

	npages = rnd_modulo_u32(4) + 1;

	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_ARENA;
	attr.map_flags = BPF_F_MMAPABLE;
	attr.key_size = 0;
	attr.value_size = 0;
	attr.max_entries = npages;

	map_fd = sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
	if (map_fd < 0) {
		arena_unsupported = true;
		__atomic_add_fetch(&shm->stats.bpf_lifecycle.eperm,
				   1, __ATOMIC_RELAXED);
		return false;
	}

	page_sz = sysconf(_SC_PAGESIZE);
	if (page_sz <= 0)
		page_sz = 4096;
	map_len = (size_t)npages * (size_t)page_sz;

	map = mmap(NULL, map_len, PROT_READ | PROT_WRITE, MAP_SHARED, map_fd, 0);
	if (map == MAP_FAILED) {
		close(map_fd);
		return false;
	}

	if (valid_op)
		__atomic_add_fetch(&shm->stats.childop.data_path[op],
				   1, __ATOMIC_RELAXED);

	pid = fork();
	if (pid < 0) {
		(void)munmap(map, map_len);
		close(map_fd);
		return false;
	}
	if (pid == 0) {
		/*
		 * Grandchild: arena VMAs are VM_DONTCOPY, so the parent's
		 * mapping is absent here.  Re-mmap the inherited fd at the
		 * same address (the arena enforces same addr+len once
		 * user_vm_start/end are set), touch each page to fault them
		 * in, drop the mapping, and exit.  Race window is the gap
		 * between the parent's munmap+close below and our exit's mm
		 * teardown.
		 */
		volatile unsigned char *p;
		void *child_map;
		size_t off;

		child_map = mmap(map, map_len, PROT_READ | PROT_WRITE,
				 MAP_SHARED | MAP_FIXED_NOREPLACE, map_fd, 0);
		if (child_map == MAP_FAILED)
			_exit(1);
		p = child_map;
		for (off = 0; off < map_len; off += (size_t)page_sz)
			p[off] = (unsigned char)(off & 0xffU);
		(void)munmap(child_map, map_len);
		_exit(0);
	}

	/* Parent: race the grandchild's vma teardown with our own. */
	(void)munmap(map, map_len);
	close(map_fd);

	rc = waitpid_eintr(pid, &status, 0);

	/*
	 * Only count the run when the grandchild actually drove the
	 * multi-mm arena teardown: its mmap+touch succeeded and it exited
	 * cleanly.  A SIGSEGV (e.g. address/length mismatch against
	 * user_vm_start/end) or a non-zero exit means we tested a
	 * userspace error path, not the kernel teardown we care about.
	 */
	if (rc == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0)
		__atomic_add_fetch(&shm->stats.bpf_lifecycle.triggered, 1,
				   __ATOMIC_RELAXED);
	return true;
}

bool bpf_lifecycle(struct childdata *child)
{
	__atomic_add_fetch(&shm->stats.bpf_lifecycle.runs, 1, __ATOMIC_RELAXED);

	/*
	 * 20% arena+fork combo when arena is supported.  Falls through to
	 * the existing cgroup/socket dispatch if arena isn't built into
	 * the running kernel or the combo decides not to run this turn.
	 */
	if (!arena_unsupported && RAND_RANGE(0, 9) < 2) {
		if (combo_arena_fork(child))
			return true;
		/* fall through */
	}

	/*
	 * 30% cgroup combo when it isn't latched off, otherwise socket.
	 * If the socket combo is also disabled the call becomes a noop —
	 * cheap, and avoids busy-failing on a kernel without BPF support.
	 */
	if (!cgroup_disabled && RAND_RANGE(0, 9) < 3) {
		if (combo_cgroup_skb(child))
			return true;
		/* fall through to socket combo on failure */
	}

	(void)combo_socket_filter(child);
	return true;
}
