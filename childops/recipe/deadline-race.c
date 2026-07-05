/*
 * Part of the recipe_runner catalogue; see recipe-runner.c for the
 * design rationale and recipe-runner-internal.h for the shared
 * declarations and macros.
 */

#include <errno.h>
#include <poll.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/bpf.h>
#include <linux/keyctl.h>
#include <linux/perf_event.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "arch.h"
#include "syscall-gate.h"
#include "name-pool.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"
#include "trinity.h"
#include "pids.h"

#include "childops/recipe/internal.h"

/*
 * Racer thread for recipe_bpf_htab_iter_del.  Walks the hash map's keyspace
 * issuing BPF_MAP_DELETE_ELEM against each pre-populated key, with a
 * deadline check between iterations so the racer self-bounds even under
 * heavy contention.  Re-populates and re-deletes in a loop until the
 * deadline elapses, so the iteration side has a continuously-mutating
 * bucket walk to step through.
 *
 * Each bpf() syscall is unbounded only by the kernel's per-call work,
 * which for a single-element hash op is effectively trivial.  The
 * deadline gate ensures pthread_join() returns within ~100ms regardless
 * of how the iteration side schedules.
 */
struct bpf_htab_racer_arg {
	int		map_fd;
	uint32_t	max_entries;
	struct timespec	deadline;
};

static bool bpf_htab_deadline_passed(const struct timespec *deadline)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return true;
	if (now.tv_sec > deadline->tv_sec)
		return true;
	if (now.tv_sec == deadline->tv_sec && now.tv_nsec >= deadline->tv_nsec)
		return true;
	return false;
}

static void *bpf_htab_racer_thread(void *arg)
{
	struct bpf_htab_racer_arg *ra = arg;
	union bpf_attr attr;
	uint32_t key, value;

	while (!bpf_htab_deadline_passed(&ra->deadline)) {
		for (key = 0; key < ra->max_entries; key++) {
			if (bpf_htab_deadline_passed(&ra->deadline))
				return NULL;
			memset(&attr, 0, sizeof(attr));
			attr.map_fd = ra->map_fd;
			attr.key    = (uintptr_t)&key;
			(void)trinity_raw_syscall(__NR_bpf, BPF_MAP_DELETE_ELEM,
				      &attr, sizeof(attr));
		}
		for (key = 0; key < ra->max_entries; key++) {
			if (bpf_htab_deadline_passed(&ra->deadline))
				return NULL;
			value = key ^ 0xa5a5a5a5;
			memset(&attr, 0, sizeof(attr));
			attr.map_fd = ra->map_fd;
			attr.key    = (uintptr_t)&key;
			attr.value  = (uintptr_t)&value;
			attr.flags  = 0;	/* BPF_ANY */
			(void)trinity_raw_syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM,
				      &attr, sizeof(attr));
		}
	}
	return NULL;
}

/*
 * Recipe 30: BPF hash-map iterate vs delete cross-thread race.
 *
 * Per cycle (1..MAX_CYCLES):
 *
 *   bpf(BPF_MAP_CREATE, BPF_MAP_TYPE_HASH, key=u32, value=u32,
 *       max_entries=N) -> populate N entries via BPF_MAP_UPDATE_ELEM ->
 *   spawn racer thread that loops {DELETE_ELEM × N -> UPDATE_ELEM × N}
 *   under a 100ms deadline -> main thread walks the keyspace via
 *   BPF_MAP_GET_NEXT_KEY (chained from a NULL prev_key) up to N+8
 *   iterations or until -ENOENT -> usleep 0..100us race-window jitter
 *   -> pthread_join -> close map_fd.
 *
 * Targets the htab_map_get_next_key RCU-walk in kernel/bpf/hashtab.c
 * concurrent with htab_map_delete_elem.  The bug class: htab uses RCU
 * for the bucket lists but the iterator's "next" pointer can dangle if
 * the element it just observed is deleted before the next dereference,
 * and the bucket-lock acquisition order between iterate and delete has
 * to keep the chain walk consistent under concurrent prepend/remove.
 *
 * Distinct from recipe_bpf_lifecycle (childops/misc/bpf-lifecycle.c) which
 * drives BPF_MAP_TYPE_ARRAY (no chain walk, no per-bucket lock) plus a
 * loaded program; this recipe drives the *concurrent* iterate-vs-delete
 * window on a real hash map's bucket chain.  Random callers of bpf()
 * almost never construct a populated hash map and walk it from one
 * thread while another thread mutates it; the path stays cold without
 * a deliberate driver.
 *
 * Bounded racer (deadline-gated bpf() ops, no blocking calls) means
 * plain pthread_join always returns within ~100ms.  THREAD_SPAWN_LATCH=3
 * consecutive pthread_create failures bails for the rest of the
 * invocation.
 *
 * Latch shape covers the ways the feature can be absent on the very
 * first probe:
 *   - bpf() ENOSYS                   (CONFIG_BPF_SYSCALL off)
 *   - BPF_MAP_CREATE EPERM           (kernel.unprivileged_bpf_disabled
 *                                     and we lack CAP_BPF)
 *   - BPF_MAP_CREATE EINVAL          (BPF_MAP_TYPE_HASH unsupported on
 *                                     a stripped kernel build)
 */
#define RECIPE_BPF_HTAB_MAX_CYCLES	4
#define RECIPE_BPF_HTAB_ENTRIES		16

bool recipe_bpf_htab_iter_del(bool *unsupported)
{
	unsigned int cycles;
	unsigned int i;
	unsigned int spawn_fail_streak = 0;
	unsigned int completed = 0;
	bool spawn_latched = false;

	cycles = 1 + rnd_modulo_u32(RECIPE_BPF_HTAB_MAX_CYCLES);

	for (i = 0; i < cycles; i++) {
		struct bpf_htab_racer_arg ra;
		union bpf_attr attr;
		pthread_t tid;
		uint32_t key, value, next_key;
		int map_fd;
		int rc;
		unsigned int walked;

		memset(&attr, 0, sizeof(attr));
		attr.map_type    = BPF_MAP_TYPE_HASH;
		attr.key_size    = sizeof(uint32_t);
		attr.value_size  = sizeof(uint32_t);
		attr.max_entries = RECIPE_BPF_HTAB_ENTRIES;
		map_fd = (int)trinity_raw_syscall(__NR_bpf, BPF_MAP_CREATE,
				      &attr, sizeof(attr));
		if (map_fd < 0) {
			if (i == 0 && (errno == ENOSYS || errno == EPERM ||
				       errno == EINVAL)) {
				*unsupported = true;
				__atomic_add_fetch(&shm->stats.recipe_unsupported,
						   1, __ATOMIC_RELAXED);
				return false;
			}
			continue;
		}

		/* Pre-populate so the racer's first DELETE pass has work and
		 * the iterate path has a non-empty keyspace to walk. */
		for (key = 0; key < RECIPE_BPF_HTAB_ENTRIES; key++) {
			value = key ^ 0xa5a5a5a5;
			memset(&attr, 0, sizeof(attr));
			attr.map_fd = map_fd;
			attr.key    = (uintptr_t)&key;
			attr.value  = (uintptr_t)&value;
			attr.flags  = 0;	/* BPF_ANY */
			(void)trinity_raw_syscall(__NR_bpf, BPF_MAP_UPDATE_ELEM,
				      &attr, sizeof(attr));
		}

		ra.map_fd      = map_fd;
		ra.max_entries = RECIPE_BPF_HTAB_ENTRIES;
		if (clock_gettime(CLOCK_MONOTONIC, &ra.deadline) < 0) {
			close(map_fd);
			continue;
		}
		ra.deadline.tv_nsec += RECIPE_RACER_TIMEOUT_MS * 1000000L;
		while (ra.deadline.tv_nsec >= 1000000000L) {
			ra.deadline.tv_nsec -= 1000000000L;
			ra.deadline.tv_sec  += 1;
		}

		rc = pthread_create(&tid, NULL, bpf_htab_racer_thread, &ra);
		if (rc != 0) {
			close(map_fd);
			if (++spawn_fail_streak >= RECIPE_THREAD_SPAWN_LATCH) {
				spawn_latched = true;
				break;
			}
			continue;
		}
		spawn_fail_streak = 0;

		/* Variable race window -- 0..100us picks a random sub-window
		 * of the racer's loop to begin our iteration in. */
		if ((rnd_u32() & 0xff) != 0)
			usleep((useconds_t)rnd_modulo_u32(101));

		/* Walk the keyspace with chained GET_NEXT_KEY, starting from
		 * NULL (returns the first key in iteration order).  Bounded
		 * by 2*N+8 iterations: under a racing populator we can revisit
		 * keys, so an unbounded loop could spin if the racer keeps
		 * re-inserting.  -ENOENT terminates iteration normally. */
		{
			uint32_t *prev = NULL;
			uint32_t prev_key = 0;
			unsigned int cap = 2 * RECIPE_BPF_HTAB_ENTRIES + 8;

			for (walked = 0; walked < cap; walked++) {
				memset(&attr, 0, sizeof(attr));
				attr.map_fd = map_fd;
				attr.key    = (uintptr_t)prev;
				attr.next_key = (uintptr_t)&next_key;
				if ((int)trinity_raw_syscall(__NR_bpf, BPF_MAP_GET_NEXT_KEY,
						 &attr, sizeof(attr)) < 0)
					break;
				prev_key = next_key;
				prev = &prev_key;
			}
		}

		(void)pthread_join(tid, NULL);
		close(map_fd);

		completed++;
	}

	/* If every cycle was lost to pthread_create EAGAIN under sibling
	 * thread pressure, that's transient nproc/thread exhaustion -- not
	 * a recipe failure.  Skip rather than score a partial, which would
	 * keep the picker re-selecting us against a kernel path we never
	 * actually exercised. */
	if (completed == 0 && spawn_latched)
		return true;

	return completed > 0;
}

/*
 * Racer thread for recipe_perf_mmap_close.  Loops short poll(POLLIN)
 * + non-blocking read() of the perf counter value across the
 * RECIPE_RACER_TIMEOUT_MS window so the racer is consistently inside
 * either perf_poll() or perf_read() on the file when the main thread
 * closes it.  Both calls have hard ceilings: poll's via its timeout
 * argument; read short-circuits to -EBADF / -ESRCH after the file or
 * context is torn down.
 *
 * EBADF on either call is the fdget-vs-close lookup race we are
 * hunting; success on read is the close-after-counter-read sub-window
 * where the syscall completed before close landed.
 */
struct perf_mmap_close_racer_arg {
	int		perf_fd;
	struct timespec	deadline;
};

static bool perf_mmap_close_deadline_passed(const struct timespec *deadline)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return true;
	if (now.tv_sec > deadline->tv_sec)
		return true;
	if (now.tv_sec == deadline->tv_sec && now.tv_nsec >= deadline->tv_nsec)
		return true;
	return false;
}

static void *perf_mmap_close_racer_thread(void *arg)
{
	struct perf_mmap_close_racer_arg *ra = arg;
	struct pollfd pfd;
	uint64_t value;
	ssize_t r __unused__;

	while (!perf_mmap_close_deadline_passed(&ra->deadline)) {
		pfd.fd = ra->perf_fd;
		pfd.events = POLLIN;
		pfd.revents = 0;
		(void)poll(&pfd, 1, 5);

		r = read(ra->perf_fd, &value, sizeof(value));
	}
	return NULL;
}

/*
 * Recipe 31: perf_event mmap close-vs-read race.
 *
 * Per cycle (1..MAX_CYCLES):
 *
 *   perf_event_open(PERF_TYPE_SOFTWARE/PERF_COUNT_SW_CPU_CLOCK,
 *                   sample_period=1ms, sample_type=TID|TIME,
 *                   pid=0/cpu=-1, disabled=1) -> mmap (1 + N) pages
 *   SHARED -> PERF_EVENT_IOC_ENABLE -> spawn racer that loops
 *   poll(POLLIN, 5ms) + read(perf_fd) under a 100ms deadline ->
 *   usleep 0..100us race-window jitter -> close(perf_fd) (the race)
 *   -> pthread_join -> munmap.
 *
 * Targets perf_release / perf_event_release_kernel and the ring-
 * buffer teardown reachable when a perf event with an active mmap
 * is closed concurrently with another task in perf_poll() or
 * perf_read() on the same fd.  The bug class lives on:
 *   - the fdget-vs-close lookup race in perf_poll/perf_read
 *   - the wait-queue cleanup vs poll_wait() on the event's poll head
 *   - the rb (ring buffer) refcount machinery -- mmap holds an rb
 *     ref that survives close() until munmap, so perf_release sees
 *     the rb still attached while the racer's syscalls hold a file
 *     ref
 *
 * Threads share the fdtable, which is the bug class -- a sibling
 * process closing the same numeric fd in its own table never races
 * with our fdget.  Distinct from childops/misc/perf-event-chains.c which
 * exercises the group/multiplex surface single-threaded; this recipe
 * drives the *concurrent* close-vs-read window on the file lifetime
 * with an active sampling mmap.
 *
 * Bounded racer (deadline-gated poll(5ms) + read on a counter file
 * that returns immediately once the event is gone) means plain
 * pthread_join always returns within ~100ms.  Sidesteps the wedge
 * problem where pthread_cancel against a thread mid-poll is
 * unreliable and detached threads leak state.  Mirrors the 2-thread
 * shape from recipe_timerfd_xclose and recipe_bpf_htab_iter_del,
 * sharing RECIPE_RACER_TIMEOUT_MS and RECIPE_THREAD_SPAWN_LATCH.
 *
 * THREAD_SPAWN_LATCH=3 consecutive pthread_create failures bails
 * for the rest of the invocation -- under nproc/thread limits the
 * EAGAIN won't lift mid-op while fork_storm or cgroup_churn are
 * competing for the budget.
 *
 * Latch shape covers every way the feature can be absent on the
 * very first probe:
 *   - perf_event_open ENOSYS         (CONFIG_PERF_EVENTS off)
 *   - perf_event_open EACCES / EPERM (kernel.perf_event_paranoid
 *                                     restricts even SW events)
 *   - perf_event_open EOPNOTSUPP     (no software PMU available)
 *   - perf_event_open EINVAL         (PERF_TYPE_SOFTWARE config
 *                                     unsupported on stripped builds)
 *   - mmap MAP_FAILED EPERM/EACCES   (mmap of perf rings disabled)
 *
 * Once latched, the dispatcher stops siblings from re-probing the
 * unsupported feature on every recipe pick.
 */
#define RECIPE_PERF_MMAP_MAX_CYCLES	4
#define RECIPE_PERF_MMAP_DATA_PAGES	4U	/* power of two */

bool recipe_perf_mmap_close(bool *unsupported)
{
	struct perf_event_attr attr;
	unsigned int cycles;
	unsigned int i;
	unsigned int spawn_fail_streak = 0;
	unsigned int completed = 0;
	bool spawn_latched = false;
	size_t mmap_sz;

	mmap_sz = (size_t)(1U + RECIPE_PERF_MMAP_DATA_PAGES) *
		  (size_t)page_size;
	cycles = 1 + rnd_modulo_u32(RECIPE_PERF_MMAP_MAX_CYCLES);

	for (i = 0; i < cycles; i++) {
		struct perf_mmap_close_racer_arg ra;
		pthread_t tid;
		void *ring;
		int perf_fd;
		int rc;

		memset(&attr, 0, sizeof(attr));
		attr.type           = PERF_TYPE_SOFTWARE;
		attr.size           = sizeof(attr);
		attr.config         = PERF_COUNT_SW_CPU_CLOCK;
		attr.sample_period  = 1000000ULL;	/* 1 ms */
		attr.sample_type    = PERF_SAMPLE_TID | PERF_SAMPLE_TIME;
		attr.disabled       = 1;
		attr.exclude_kernel = 1;
		attr.exclude_hv     = 1;

		perf_fd = (int)trinity_raw_syscall(__NR_perf_event_open, &attr,
				       0 /* this thread */,
				       -1 /* any cpu */,
				       -1 /* no group leader */,
				       0UL /* flags */);
		if (perf_fd < 0) {
			if (i == 0 && (errno == ENOSYS || errno == EACCES ||
				       errno == EPERM ||
				       errno == EOPNOTSUPP ||
				       errno == EINVAL)) {
				*unsupported = true;
				__atomic_add_fetch(&shm->stats.recipe_unsupported,
						   1, __ATOMIC_RELAXED);
				return false;
			}
			continue;
		}

		ring = mmap(NULL, mmap_sz, PROT_READ | PROT_WRITE,
			    MAP_SHARED, perf_fd, 0);
		if (ring == MAP_FAILED) {
			if (i == 0 && (errno == EPERM || errno == EACCES)) {
				close(perf_fd);
				*unsupported = true;
				__atomic_add_fetch(&shm->stats.recipe_unsupported,
						   1, __ATOMIC_RELAXED);
				return false;
			}
			close(perf_fd);
			continue;
		}

		/* Activate sampling so the ring has a chance to fill while
		 * the racer is poll/read-ing. */
		(void)ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0);

		ra.perf_fd = perf_fd;
		if (clock_gettime(CLOCK_MONOTONIC, &ra.deadline) < 0) {
			munmap(ring, mmap_sz);
			close(perf_fd);
			continue;
		}
		ra.deadline.tv_nsec += RECIPE_RACER_TIMEOUT_MS * 1000000L;
		while (ra.deadline.tv_nsec >= 1000000000L) {
			ra.deadline.tv_nsec -= 1000000000L;
			ra.deadline.tv_sec  += 1;
		}

		rc = pthread_create(&tid, NULL,
				    perf_mmap_close_racer_thread, &ra);
		if (rc != 0) {
			munmap(ring, mmap_sz);
			close(perf_fd);
			if (++spawn_fail_streak >= RECIPE_THREAD_SPAWN_LATCH) {
				spawn_latched = true;
				break;
			}
			continue;
		}
		spawn_fail_streak = 0;

		/* Variable race window -- 0..100us picks a random sub-
		 * window of the racer's poll/read loop to land the close
		 * in. */
		if ((rnd_u32() & 0xff) != 0)
			usleep((useconds_t)rnd_modulo_u32(101));

		(void)close(perf_fd);

		(void)pthread_join(tid, NULL);

		/* Drop the mmap reference last -- the rb refcount survives
		 * close() until the final munmap, exercising the
		 * perf_mmap_close vm_op teardown after the close race has
		 * completed. */
		munmap(ring, mmap_sz);

		completed++;
	}

	/* If every cycle was lost to pthread_create EAGAIN under sibling
	 * thread pressure, that's transient nproc/thread exhaustion -- not
	 * a recipe failure.  Skip rather than score a partial, which would
	 * keep the picker re-selecting us against a kernel path we never
	 * actually exercised. */
	if (completed == 0 && spawn_latched)
		return true;

	return completed > 0;
}

/*
 * Racer thread for recipe_keys_revoke_race.  Loops keyctl(KEYCTL_READ)
 * against a freshly-created "user" key under a 100ms deadline.  keyctl
 * is not poll()-able, so the deadline-loop shape mirrors recipe_perf_
 * mmap_close rather than the poll-then-read shape used by recipe_
 * timerfd_xclose -- maximises the chance the racer is consistently
 * inside keyctl_read / key_validate / type->read on the keyring data
 * when the main thread lands keyctl_revoke.
 *
 * EKEYREVOKED on read is the post-revoke success path; EACCES /
 * ENOKEY is the lookup-after-unlink window; success is the
 * read-completed-before-revoke sub-window.  All terminate the
 * syscall in well under one alarm tick.
 */
struct keys_revoke_racer_arg {
	int32_t		key_id;		/* key_serial_t */
	struct timespec	deadline;
};

static bool keys_revoke_deadline_passed(const struct timespec *deadline)
{
	struct timespec now;

	if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
		return true;
	if (now.tv_sec > deadline->tv_sec)
		return true;
	if (now.tv_sec == deadline->tv_sec && now.tv_nsec >= deadline->tv_nsec)
		return true;
	return false;
}

static void *keys_revoke_racer_thread(void *arg)
{
	struct keys_revoke_racer_arg *ra = arg;
	unsigned char buf[64];
	long r __unused__;

	/* Tight-spin keyctl_read.  user-type payloads are tiny so each
	 * call returns almost immediately; no usleep between iterations
	 * keeps the racer maximally inside the kernel-side validate /
	 * type->read window when revoke lands. */
	while (!keys_revoke_deadline_passed(&ra->deadline)) {
		r = trinity_raw_syscall(__NR_keyctl, (unsigned long)KEYCTL_READ,
			    (unsigned long)ra->key_id,
			    (unsigned long)buf,
			    (unsigned long)sizeof(buf), 0UL);
	}
	return NULL;
}

/*
 * Recipe 32: keyring key revoke-vs-read race.
 *
 * Per cycle (1..MAX_CYCLES):
 *
 *   keyctl(KEYCTL_JOIN_SESSION_KEYRING, NULL) (once per recipe call) ->
 *   add_key("user", "trinity-keys-revoke-race-NN", payload, 16,
 *           KEY_SPEC_SESSION_KEYRING) -> spawn racer that loops
 *   keyctl(KEYCTL_READ) under a 100ms deadline -> usleep 0..100us
 *   race-window jitter -> keyctl(KEYCTL_REVOKE) (the race) ->
 *   pthread_join -> keyctl(KEYCTL_UNLINK).
 *
 * Targets the kernel paths key_revoke / type->revoke vs keyctl_read /
 * key_validate / type->read, plus the RCU teardown of struct
 * user_key_payload on user_revoke().  Both threads share the same
 * key_serial_t, which is the bug class -- a sibling process operating
 * on a separate keyring never races with our key_validate.  Distinct
 * from random keyctl callers in the syscall fuzzer that target a
 * key in isolation; this recipe drives the *concurrent* read-vs-
 * revoke window on a key with an active reader.
 *
 * Bounded racer (deadline-gated keyctl_read returning immediately on
 * EKEYREVOKED / ENOKEY / EACCES) means plain pthread_join always
 * returns within ~100ms.  Sidesteps the wedge problem where pthread_
 * cancel against a thread mid-syscall is unreliable and detached
 * threads leak state.  Mirrors the deadline-loop shape from recipe_
 * perf_mmap_close, sharing RECIPE_RACER_TIMEOUT_MS and RECIPE_THREAD_
 * SPAWN_LATCH.
 *
 * THREAD_SPAWN_LATCH=3 consecutive pthread_create failures bails
 * for the rest of the invocation -- under nproc/thread limits the
 * EAGAIN won't lift mid-op while fork_storm or cgroup_churn are
 * competing for the budget.
 *
 * Latch shape covers every way the feature can be absent on the
 * very first probe:
 *   - keyctl ENOSYS                 (CONFIG_KEYS off)
 *   - keyctl JOIN EPERM / EACCES    (LSM denies session keyring)
 *   - add_key ENOSYS / EPERM        (key type "user" disabled / LSM)
 *   - add_key EDQUOT                (kernel.keys.maxkeys exhausted)
 *
 * Once latched, the dispatcher stops siblings from re-probing the
 * unsupported feature on every recipe pick.
 *
 * Per-cycle add_key failures mid-loop are tolerated (one bad cycle,
 * e.g. ephemeral EDQUOT under sibling load, shouldn't penalise the
 * whole recipe).  Cleanup unlinks the key from the session keyring
 * after revoke so gc_works can progress promptly; EKEYREVOKED on the
 * unlink itself is fine and intentionally ignored.
 */
#define RECIPE_KEYS_REVOKE_MAX_CYCLES	4
#define RECIPE_KEYS_REVOKE_PAYLOAD_LEN	16

bool recipe_keys_revoke_race(bool *unsupported)
{
	unsigned char payload[RECIPE_KEYS_REVOKE_PAYLOAD_LEN];
	char desc[64];
	unsigned int cycles;
	unsigned int i;
	unsigned int spawn_fail_streak = 0;
	unsigned int completed = 0;
	bool spawn_latched = false;
	long jr;

	/* Anchor a session keyring up-front so add_key has somewhere to
	 * link.  Each call creates a fresh anonymous session keyring;
	 * no other recipe touches keyrings, so this does not clobber
	 * sibling state inside the trinity child. */
	jr = trinity_raw_syscall(__NR_keyctl, (unsigned long)KEYCTL_JOIN_SESSION_KEYRING,
		     0UL, 0UL, 0UL, 0UL);
	if (jr < 0) {
		if (errno == ENOSYS || errno == EPERM ||
		    errno == EOPNOTSUPP || errno == EACCES) {
			*unsupported = true;
			__atomic_add_fetch(&shm->stats.recipe_unsupported, 1,
					   __ATOMIC_RELAXED);
		}
		return false;
	}

	memset(payload, 0xa5, sizeof(payload));

	cycles = 1 + rnd_modulo_u32(RECIPE_KEYS_REVOKE_MAX_CYCLES);

	for (i = 0; i < cycles; i++) {
		struct keys_revoke_racer_arg ra;
		pthread_t tid;
		long key;
		int rc;

		{
			size_t got = 0;

			/* Minority arm: replay a previously-recorded
			 * description (possibly mutated) so this add_key
			 * collides with an earlier one in the keyring search
			 * and key-link codepaths -- those only light up when
			 * two descriptions share dcache slots, which the
			 * always-fresh "<pid>-<iter>" form near-misses.  Fall
			 * through to the fresh path (and record it) when the
			 * pool is empty. */
			if (ONE_IN(8))
				got = name_pool_draw_mutated(NAME_KIND_KEY_DESC,
							     desc, sizeof(desc));

			if (got > 0) {
				if (got >= sizeof(desc))
					got = sizeof(desc) - 1;
				desc[got] = '\0';
			} else {
				snprintf(desc, sizeof(desc),
					 "trinity-keys-revoke-race-%u-%u",
					 (unsigned int)mypid(), i);
				name_pool_record(NAME_KIND_KEY_DESC,
						 desc, strlen(desc));
			}
		}

		key = trinity_raw_syscall(__NR_add_key, "user", desc,
			      payload, (size_t)sizeof(payload),
			      (unsigned long)KEY_SPEC_SESSION_KEYRING);
		if (key < 0) {
			if (i == 0 && (errno == ENOSYS || errno == EPERM ||
				       errno == EOPNOTSUPP ||
				       errno == EDQUOT)) {
				*unsupported = true;
				__atomic_add_fetch(&shm->stats.recipe_unsupported,
						   1, __ATOMIC_RELAXED);
				return false;
			}
			continue;
		}

		ra.key_id = (int32_t)key;
		if (clock_gettime(CLOCK_MONOTONIC, &ra.deadline) < 0) {
			(void)trinity_raw_syscall(__NR_keyctl, (unsigned long)KEYCTL_UNLINK,
				      (unsigned long)key,
				      (unsigned long)KEY_SPEC_SESSION_KEYRING,
				      0UL, 0UL);
			continue;
		}
		ra.deadline.tv_nsec += RECIPE_RACER_TIMEOUT_MS * 1000000L;
		while (ra.deadline.tv_nsec >= 1000000000L) {
			ra.deadline.tv_nsec -= 1000000000L;
			ra.deadline.tv_sec  += 1;
		}

		rc = pthread_create(&tid, NULL,
				    keys_revoke_racer_thread, &ra);
		if (rc != 0) {
			(void)trinity_raw_syscall(__NR_keyctl, (unsigned long)KEYCTL_UNLINK,
				      (unsigned long)key,
				      (unsigned long)KEY_SPEC_SESSION_KEYRING,
				      0UL, 0UL);
			if (++spawn_fail_streak >= RECIPE_THREAD_SPAWN_LATCH) {
				spawn_latched = true;
				break;
			}
			continue;
		}
		spawn_fail_streak = 0;

		/* Variable race window -- 0..100us picks a random sub-window
		 * of the racer's read loop to land the revoke in. */
		if ((rnd_u32() & 0xff) != 0)
			usleep((useconds_t)rnd_modulo_u32(101));

		(void)trinity_raw_syscall(__NR_keyctl, (unsigned long)KEYCTL_REVOKE,
			      (unsigned long)key, 0UL, 0UL, 0UL);

		(void)pthread_join(tid, NULL);

		/* Best-effort cleanup -- the key is revoked, but unlinking
		 * from the session keyring lets gc_works progress sooner.
		 * EKEYREVOKED on the unlink itself is fine. */
		(void)trinity_raw_syscall(__NR_keyctl, (unsigned long)KEYCTL_UNLINK,
			      (unsigned long)key,
			      (unsigned long)KEY_SPEC_SESSION_KEYRING,
			      0UL, 0UL);

		completed++;
	}

	/* If every cycle was lost to pthread_create EAGAIN under sibling
	 * thread pressure, that's transient nproc/thread exhaustion -- not
	 * a recipe failure.  Skip rather than score a partial, which would
	 * keep the picker re-selecting us against a kernel path we never
	 * actually exercised. */
	if (completed == 0 && spawn_latched)
		return true;

	return completed > 0;
}
