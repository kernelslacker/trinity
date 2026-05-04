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
 *   - CGROUP_SKB (~30%) — exercises the canonical bpf(PROG_ATTACH) path
 *     described in the Trinity TODO.  Requires CAP_BPF + CAP_NET_ADMIN
 *     plus a writable cgroup directory; on the first failure with
 *     EPERM/EACCES (or no cgroup) we latch the combo off for the rest of
 *     the child's life so we don't spin retrying.
 *
 * Trinity-todo #1.4.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <unistd.h>

#include "arch.h"
#include "bpf.h"
#include "child.h"
#include "objects.h"
#include "random.h"
#include "shm.h"
#include "trinity.h"

#ifndef SO_ATTACH_BPF
#define SO_ATTACH_BPF		50
#endif
#ifndef SO_DETACH_BPF
#define SO_DETACH_BPF		SO_DETACH_FILTER
#endif
#ifndef BPF_F_ALLOW_MULTI
#define BPF_F_ALLOW_MULTI	(1U << 1)
#endif

#define MAP_ENTRIES		8

static int sys_bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
	return (int)syscall(__NR_bpf, cmd, attr, size);
}

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
	struct object *obj;

	obj = alloc_object();
	obj->bpfobj.map_fd = fd;
	obj->bpfobj.map_type = map_type;
	add_object(obj, OBJ_LOCAL, OBJ_FD_BPF_MAP);
	return obj;
}

static struct object *publish_prog_fd(int fd, uint32_t prog_type)
{
	struct object *obj;

	obj = alloc_object();
	obj->bpfprogobj.fd = fd;
	obj->bpfprogobj.prog_type = prog_type;
	add_object(obj, OBJ_LOCAL, OBJ_FD_BPF_PROG);
	return obj;
}

/*
 * Combo A — SOCKET_FILTER, the unprivileged-friendly path.
 *
 * Returns true if the full chain ran (even with non-fatal in-flight
 * errors), false if a structural failure means we should not retry this
 * combo for this child.
 */
static bool combo_socket_filter(void)
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

	map_fd = create_array_map();
	if (map_fd < 0)
		goto out;
	map_obj = publish_map_fd(map_fd, BPF_MAP_TYPE_ARRAY);

	prog_fd = load_template_prog(BPF_PROG_TYPE_SOCKET_FILTER, map_fd);
	if (prog_fd < 0) {
		if (errno == EPERM || errno == EACCES) {
			__atomic_add_fetch(&shm->stats.bpf_lifecycle_eperm,
					   1, __ATOMIC_RELAXED);
			socket_filter_disabled = true;
		} else {
			__atomic_add_fetch(&shm->stats.bpf_lifecycle_verifier_rejects,
					   1, __ATOMIC_RELAXED);
		}
		goto out;
	}
	__atomic_add_fetch(&shm->stats.bpf_lifecycle_progs_loaded, 1,
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
		__atomic_add_fetch(&shm->stats.bpf_lifecycle_attach_failed,
				   1, __ATOMIC_RELAXED);
		goto out;
	}
	__atomic_add_fetch(&shm->stats.bpf_lifecycle_attached, 1,
			   __ATOMIC_RELAXED);

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
	__atomic_add_fetch(&shm->stats.bpf_lifecycle_triggered, 1,
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
 * Combo B — CGROUP_SKB via the literal bpf(PROG_ATTACH) path described
 * in the Trinity TODO.  Best-effort: needs CAP_BPF + CAP_NET_ADMIN plus
 * one of the trinity{0..7} cgroup directories that munge_process()
 * already uses.  Latches off on EPERM/EACCES or missing cgroup.
 */
static bool combo_cgroup_skb(void)
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

	snprintf(path, sizeof(path), "/sys/fs/cgroup/trinity%u",
		 (unsigned int)(rand() % 8));
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
			__atomic_add_fetch(&shm->stats.bpf_lifecycle_eperm,
					   1, __ATOMIC_RELAXED);
			cgroup_disabled = true;
		} else {
			__atomic_add_fetch(&shm->stats.bpf_lifecycle_verifier_rejects,
					   1, __ATOMIC_RELAXED);
		}
		goto out;
	}
	__atomic_add_fetch(&shm->stats.bpf_lifecycle_progs_loaded, 1,
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
			__atomic_add_fetch(&shm->stats.bpf_lifecycle_eperm,
					   1, __ATOMIC_RELAXED);
			cgroup_disabled = true;
		} else {
			__atomic_add_fetch(&shm->stats.bpf_lifecycle_attach_failed,
					   1, __ATOMIC_RELAXED);
		}
		goto out;
	}
	attached = true;
	__atomic_add_fetch(&shm->stats.bpf_lifecycle_attached, 1,
			   __ATOMIC_RELAXED);

	for (key = 0; key < MAP_ENTRIES; key++) {
		update_elem(map_fd, key, rand32());
		cgroup_trigger();
	}
	__atomic_add_fetch(&shm->stats.bpf_lifecycle_triggered, 1,
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

bool bpf_lifecycle(struct childdata *child)
{
	(void)child;

	__atomic_add_fetch(&shm->stats.bpf_lifecycle_runs, 1, __ATOMIC_RELAXED);

	/*
	 * 30% cgroup combo when it isn't latched off, otherwise socket.
	 * If the socket combo is also disabled the call becomes a noop —
	 * cheap, and avoids busy-failing on a kernel without BPF support.
	 */
	if (!cgroup_disabled && RAND_RANGE(0, 9) < 3) {
		if (combo_cgroup_skb())
			return true;
		/* fall through to socket combo on failure */
	}

	(void)combo_socket_filter();
	return true;
}
