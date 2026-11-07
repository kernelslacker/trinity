/*
 * Self-check for the values the post oracles accept on a call that
 * worked.  Each case hands a post handler the return a successful call
 * produces and counts the corrupt-pointer bumps it makes: a value the
 * kernel returns must not bump, one it cannot return must.  A sampled
 * compare is counted by the anomalies it reports instead, or by the
 * line it logs where two share a counter, an untouched-buffer check by
 * the untouched buffers it reports, and the PR_FUTEX_HASH -EBUSY tally
 * by what it counts.  The handlers run as shipped; the post_state
 * table, post_snapshot_or_skip() and the bump itself are faked here,
 * bpf's pool publishes are counted through landlock_test.c's
 * publish_resource() hook, and capget's re-call goes to a model through
 * its syscall() hook.
 */

#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/fanotify.h>
#include <limits.h>
#include <sched.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/prctl.h>
#include <sys/sem.h>
#include <sys/shm.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include "arch.h"		/* ARCH_IS_BIARCH */
#include "bpf.h"		/* BPF_PROG_STREAM_READ_BY_FD */
#include "debug.h"		/* BUG */
#include "fake_parent.h"	/* fake_output_log */
#include "kernel/compat.h"	/* struct old_timeval32, ... */
#include "kernel/io_uring.h"	/* IORING_REGISTER_* */
#include "kernel/prctl.h"	/* PR_THP_DISABLE_EXCEPT_ADVISED */
#include "kernel/sched.h"	/* SCHED_EXT, SCHED_RESET_ON_FORK */
#include "kernel/timerfd.h"	/* TFD_CLOEXEC */
#include "maps.h"		/* get_map */
#include "net.h"		/* fd_from_socketinfo */
#include "publish_resource.h"	/* struct resource_meta */
#include "sanitise.h"		/* writable pool */
#include "shm.h"
#include "syscall.h"		/* struct syscallrecord */
#include "syscall-internal.h"	/* enforce_count_bound */
#include "syscalls/syscalls.h"	/* syscall_prctl */
#include "utils.h"
#include "utils-macros.h"	/* ARRAY_SIZE */

static unsigned int bumps;
static unsigned int failed;

/* A case that overwrites a live arg slot after dispatch sets
 * stomps_expected and counts the tripwire hits, here and in
 * landlock_test.c; any other hit means the oracle read a slot whose shadow
 * disagrees with it. */
unsigned int stomps;
bool stomps_expected;

void post_handler_corrupt_ptr_bump_site(struct syscallrecord *rec,
					void *caller_pc, const char *site)
{
	(void) rec;
	(void) caller_pc;
	(void) site;
	bumps++;
}

void post_handler_corrupt_ptr_bump_at(struct syscallrecord *rec,
				      void *caller_pc,
				      enum corrupt_ptr_site site)
{
	(void) rec;
	(void) caller_pc;
	(void) site;
	bumps++;
}

void arg_shadow_stomp_bump(struct syscallrecord *rec, unsigned int argnum,
			   unsigned long shadow, unsigned long current)
{
	(void) rec;
	(void) argnum;
	(void) shadow;
	(void) current;
	if (!stomps_expected)
		BUG("a post oracle read an arg whose shadow no longer matched");
	stomps++;
}

/* Copies unless a case says the buffer is not one the real helper would
 * prove readable. */
static bool snapshot_readable = true;

bool post_snapshot_or_skip(void *dst, const void *src, size_t len)
{
	if (!snapshot_readable || src == NULL)
		return false;
	memcpy(dst, src, len);
	return true;
}

/* A snapshot pointer a case says the ownership table does not hold; NULL
 * leaves every pointer owned. */
const void *post_state_disowned;

bool post_state_is_owned(const void *p)
{
	return post_state_disowned == NULL || p != post_state_disowned;
}

void post_state_register(void *p)
{
	(void) p;
}

void post_state_release(struct syscallrecord *rec, void *snap)
{
	if (rec->post_state == (unsigned long) snap)
		rec->post_state = 0;
	free(snap);
}

void post_state_install_sized(struct syscallrecord *rec, void *snap,
			      size_t size)
{
	(void) size;
	rec->post_state = (unsigned long) snap;
}

void *post_state_claim_owned(struct syscallrecord *rec,
			     unsigned long magic_expected,
			     const char *handler_name)
{
	void *snap = (void *) rec->post_state;

	(void) handler_name;
	if (snap == NULL || *(const unsigned long *) snap != magic_expected)
		return NULL;
	return snap;
}

/* The recv sanitisers reach these.  recvmsg's runs here with no socket
 * and every map lookup empty, so its iovec entries come out empty.
 * get_map() hands out fake_map_drawn, which a test that wants a mapping
 * picked sets and clears again, and a test that runs a sanitiser asking
 * for a socket fd sets fake_socket_fd_none to have it get -1, no socket,
 * or fake_socketinfo_fds to have it get the fd of the socketinfo it
 * handed the sanitiser. */
bool fake_socket_fd_none;
bool fake_socketinfo_fds;

int fd_from_socketinfo(struct socketinfo *si)
{
	if (fake_socketinfo_fds)
		return si->fd;
	if (!fake_socket_fd_none)
		BUG("a sanitiser asked for a socket fd");
	return -1;
}

struct map *fake_map_drawn;

struct map *__wrap_get_map(void);
struct map *__wrap_get_map(void)
{
	return fake_map_drawn;
}

struct map *__wrap_get_map_with_prot(int required_prot);
struct map *__wrap_get_map_with_prot(int required_prot)
{
	(void) required_prot;
	return NULL;
}

static void expect(const char *what, unsigned int got, unsigned int want)
{
	if (got == want)
		return;
	fprintf(stderr, "%s: %u bump(s), wanted %u\n", what, got, want);
	failed++;
}

/* The out-param the kernel writes through arg2. */
static unsigned int *out;

/* Run prctl's own sanitiser on @arg2 until it draws @option, so the
 * snapshot the post handler claims is the one the sanitiser built. */
static struct syscallrecord *prctl_rec(int option, unsigned long arg2)
{
	static struct syscallrecord rec;
	unsigned int tries;

	for (tries = 0; tries < 4096; tries++) {
		memset(&rec, 0, sizeof(rec));
		rec.a2 = arg2;
		syscall_prctl.sanitise(&rec);
		if (rec.a1 == (unsigned long) option)
			return &rec;
		free((void *) rec.post_state);
	}
	BUG("prctl sanitiser never drew the option");
	return NULL;
}

/* The option and arg2 the kernel was handed, as __do_syscall() shadows
 * them. */
static void prctl_ran(struct syscallrecord *rec, unsigned long option,
		      unsigned long arg2)
{
	rec->a1 = option;
	rec->a2 = arg2;
	rec->arg_snapshot_mask = syscall_prctl.arg_snapshot_mask;
	rec->arg_shadow[0] = option;
	rec->arg_shadow[1] = arg2;
}

static unsigned int prctl_get(int option, unsigned long retval,
			      unsigned int out_word)
{
	struct syscallrecord *rec = prctl_rec(option, (unsigned long) out);

	*out = out_word;
	rec->retval = retval;
	rec->errno_post = (retval == (unsigned long) -1L) ? EINVAL : 0;
	bumps = 0;
	syscall_prctl.post(rec);
	return bumps;
}

/* x86 and arm64 return 0 and store the mode through arg2; the other
 * architectures return -EINVAL. */
static void get_tsc(void)
{
	static const struct {
		const char *what;
		unsigned long retval;
		unsigned int out_word;
		bool readable;
		unsigned int bumps;
	} cases[] = {
		{ "PR_GET_TSC, mode ENABLE", 0, PR_TSC_ENABLE, true, 0 },
		{ "PR_GET_TSC, mode SIGSEGV", 0, PR_TSC_SIGSEGV, true, 0 },
		{ "PR_GET_TSC, -EINVAL", (unsigned long) -1L, 0, true, 0 },
		{ "PR_GET_TSC, buffer not provably readable",
		  0, 0, false, 0 },
		{ "PR_GET_TSC, mode 0 in the out-word", 0, 0, true, 1 },
		{ "PR_GET_TSC, mode 3 in the out-word", 0, 3, true, 1 },
		{ "PR_GET_TSC, the mode in the return slot",
		  PR_TSC_ENABLE, PR_TSC_ENABLE, true, 1 },
		{ "PR_GET_TSC, a -errno in the return slot",
		  (unsigned long) -22L, 0, true, 1 },
	};
	struct syscallrecord *rec;
	unsigned int i, mode;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		snapshot_readable = cases[i].readable;
		expect(cases[i].what,
		       prctl_get(PR_GET_TSC, cases[i].retval,
				 cases[i].out_word),
		       cases[i].bumps);
	}
	snapshot_readable = true;

	/* An arg2 rewritten after the sanitiser is where the kernel put the
	 * mode, and the buffer the sanitiser built is left as it was. */
	rec = prctl_rec(PR_GET_TSC, (unsigned long) out);
	*out = 0;
	mode = PR_TSC_ENABLE;
	prctl_ran(rec, PR_GET_TSC, (unsigned long) &mode);
	rec->retval = 0;
	bumps = 0;
	syscall_prctl.post(rec);
	expect("PR_GET_TSC, the mode stored through a rewritten arg2", bumps, 0);
}

/* 0 when THP is not disabled, 1 when it is disabled completely, and
 * 1 | PR_THP_DISABLE_EXCEPT_ADVISED when disabled except where advised. */
static void get_thp_disable(void)
{
	static const struct {
		const char *what;
		unsigned long retval;
		unsigned int bumps;
	} cases[] = {
		{ "PR_GET_THP_DISABLE, not disabled", 0, 0 },
		{ "PR_GET_THP_DISABLE, disabled", 1, 0 },
		{ "PR_GET_THP_DISABLE, disabled except advised",
		  1UL | PR_THP_DISABLE_EXCEPT_ADVISED, 0 },
		{ "PR_GET_THP_DISABLE, -EINVAL", (unsigned long) -1L, 0 },
		{ "PR_GET_THP_DISABLE, the flag without bit 0",
		  PR_THP_DISABLE_EXCEPT_ADVISED, 1 },
		{ "PR_GET_THP_DISABLE, an unknown flag", 1UL | (1UL << 2), 1 },
		{ "PR_GET_THP_DISABLE, a high bit set",
		  0x80000001UL, 1 },
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++)
		expect(cases[i].what,
		       prctl_get(PR_GET_THP_DISABLE, cases[i].retval, 0),
		       cases[i].bumps);
}

/* Calls per round-trip case: the readback is sampled one in twenty. */
#define ROUNDTRIP_CALLS	300

/* prctl calls the sanitiser built as @option on @arg2, which the kernel
 * ran as @ran_option on *@ran_arg2, or on the arg2 the sanitiser built
 * when @ran_arg2 is NULL, and answered 0; the cred anomalies their
 * sampled SET/GET round trips report. */
static unsigned long roundtrip_anomalies(int option, unsigned long arg2,
					 int ran_option,
					 const unsigned long *ran_arg2)
{
	unsigned long before = shm->stats.oracle.cred_oracle_anomalies;
	unsigned int i;

	for (i = 0; i < ROUNDTRIP_CALLS; i++) {
		struct syscallrecord *rec = prctl_rec(option, arg2);

		prctl_ran(rec, (unsigned long) ran_option,
			  ran_arg2 != NULL ? *ran_arg2 : rec->a2);
		rec->retval = 0;
		syscall_prctl.post(rec);
	}
	return shm->stats.oracle.cred_oracle_anomalies - before;
}

/* A SET that worked is read back with its GET and compared with the arg2
 * the kernel was handed, which chain substitution or a RedQueen pin can
 * rewrite after the sanitiser drew its own, as they can the option: a
 * call the kernel ran as another option is no SET to read back. */
static void prctl_roundtrip(void)
{
	unsigned long dumpable = (unsigned long) prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
	unsigned long keepcaps = (unsigned long) prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0);
	unsigned long other_dumpable = dumpable ^ 1, other_keepcaps = keepcaps ^ 1;
	unsigned long pdeathsig, other_sig, other_name;
	char name[16] = { 0 };
	int sig = 0;
	const struct {
		const char *what;
		int option;
		unsigned long arg2;
		int ran_option;
		const unsigned long *ran_arg2;
		bool reported;
	} cases[] = {
		{ "PR_SET_DUMPABLE, arg2 pinned to the value read back",
		  PR_SET_DUMPABLE, (unsigned long) out,
		  PR_SET_DUMPABLE, &dumpable, false },
		{ "PR_SET_DUMPABLE, a readback other than the arg2 run on",
		  PR_SET_DUMPABLE, dumpable,
		  PR_SET_DUMPABLE, &other_dumpable, true },
		{ "PR_SET_DUMPABLE, run as PR_GET_TIMING",
		  PR_SET_DUMPABLE, other_dumpable, PR_GET_TIMING, NULL, false },
		{ "PR_SET_KEEPCAPS, arg2 pinned to the value read back",
		  PR_SET_KEEPCAPS, (unsigned long) out,
		  PR_SET_KEEPCAPS, &keepcaps, false },
		{ "PR_SET_KEEPCAPS, a readback other than the arg2 run on",
		  PR_SET_KEEPCAPS, keepcaps,
		  PR_SET_KEEPCAPS, &other_keepcaps, true },
		{ "PR_SET_PDEATHSIG, arg2 pinned to the signal read back",
		  PR_SET_PDEATHSIG, 0, PR_SET_PDEATHSIG, &pdeathsig, false },
		{ "PR_SET_PDEATHSIG, a readback other than the arg2 run on",
		  PR_SET_PDEATHSIG, 0, PR_SET_PDEATHSIG, &other_sig, true },
		{ "PR_SET_NAME, run on another buffer",
		  PR_SET_NAME, 0, PR_SET_NAME, &other_name, false },
		{ "PR_SET_NAME, a readback other than the name built",
		  PR_SET_NAME, 0, PR_SET_NAME, NULL, true },
	};
	unsigned int i;

	if (prctl(PR_GET_PDEATHSIG, (unsigned long) &sig, 0, 0, 0) != 0 ||
	    prctl(PR_GET_NAME, (unsigned long) name, 0, 0, 0) != 0)
		BUG("prctl round trip: cannot read this task's state");
	pdeathsig = (unsigned long) sig;
	other_sig = pdeathsig ^ 1;
	/* Another buffer, holding the name the task already has. */
	other_name = (unsigned long) name;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		unsigned long n = roundtrip_anomalies(cases[i].option,
						      cases[i].arg2,
						      cases[i].ran_option,
						      cases[i].ran_arg2);

		if ((n != 0) != cases[i].reported) {
			fprintf(stderr, "prctl round trip, %s: %lu anomalies\n",
				cases[i].what, n);
			failed++;
		}
	}
}

/* SET_SLOTS refused with -EBUSY is counted by the sub-op the kernel was
 * handed, not the one the sanitiser drew. */
static void futex_hash_ebusy(void)
{
	static const struct {
		const char *what;
		unsigned long ran_op;
		unsigned long counted;
	} cases[] = {
		{ "SET_SLOTS refused busy", PR_FUTEX_HASH_SET_SLOTS, 1 },
		{ "SET_SLOTS rewritten to GET_SLOTS", PR_FUTEX_HASH_GET_SLOTS, 0 },
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		unsigned long before = shm->stats.prctl_futex_hash.set_slots_ebusy;
		unsigned long counted;
		struct syscallrecord *rec;

		/* The sanitiser draws either sub-op: build on SET_SLOTS. */
		for (;;) {
			rec = prctl_rec(PR_FUTEX_HASH, 0);
			if (rec->a2 == PR_FUTEX_HASH_SET_SLOTS)
				break;
			free((void *) rec->post_state);
		}
		prctl_ran(rec, PR_FUTEX_HASH, cases[i].ran_op);
		rec->retval = (unsigned long) -1L;
		rec->errno_post = EBUSY;
		syscall_prctl.post(rec);

		counted = shm->stats.prctl_futex_hash.set_slots_ebusy - before;
		if (counted != cases[i].counted) {
			fprintf(stderr, "PR_FUTEX_HASH, %s: counted %lu, wanted %lu\n",
				cases[i].what, counted, cases[i].counted);
			failed++;
		}
	}
}

/* The policy, with SCHED_RESET_ON_FORK OR'd in while the task has
 * sched_reset_on_fork set.  Only a query for the calling task (pid 0) is
 * judged. */
static void sched_getscheduler_policy(void)
{
	static const struct {
		const char *what;
		unsigned long pid;
		unsigned long retval;
		unsigned int bumps;
	} cases[] = {
		{ "sched_getscheduler, SCHED_OTHER", 0, SCHED_OTHER, 0 },
		{ "sched_getscheduler, SCHED_EXT", 0, SCHED_EXT, 0 },
		{ "sched_getscheduler, SCHED_OTHER with SCHED_RESET_ON_FORK",
		  0, SCHED_OTHER | SCHED_RESET_ON_FORK, 0 },
		{ "sched_getscheduler, SCHED_BATCH with SCHED_RESET_ON_FORK",
		  0, SCHED_BATCH | SCHED_RESET_ON_FORK, 0 },
		{ "sched_getscheduler, -1", 0, (unsigned long) -1L, 0 },
		{ "sched_getscheduler, a policy past SCHED_EXT",
		  0, SCHED_EXT + 1, 1 },
		{ "sched_getscheduler, a policy past SCHED_EXT with the flag",
		  0, (SCHED_EXT + 1) | SCHED_RESET_ON_FORK, 1 },
		{ "sched_getscheduler, a stray high bit",
		  0, 0x20000000UL | SCHED_OTHER, 1 },
		{ "sched_getscheduler, another task's pid is not judged",
		  1, 0x20000000UL, 0 },
	};
	static struct syscallrecord rec;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		memset(&rec, 0, sizeof(rec));
		rec.a1 = cases[i].pid;
		rec.arg_snapshot_mask = syscall_sched_getscheduler.arg_snapshot_mask;
		rec.arg_shadow[0] = cases[i].pid;
		rec.retval = cases[i].retval;
		rec.errno_post = ((long) cases[i].retval == -1L) ? EINVAL : 0;
		bumps = 0;
		syscall_sched_getscheduler.post(&rec);
		expect(cases[i].what, bumps, cases[i].bumps);
	}
}

/* handle_syscall_ret() runs enforce_count_bound() and then the handler,
 * so a bound that moves from the one to the other, or is annotated back,
 * shows here. */
static void dispatch_post(const struct syscallentry *entry,
			  struct syscallrecord *rec)
{
	enforce_count_bound(entry, rec);
	if (entry->post != NULL)
		entry->post(rec);
}

/* The bytes received, at most the buffer.  A datagram, raw, netlink,
 * packet or unix-dgram socket returns the real length of the datagram
 * under MSG_TRUNC instead, even past the buffer; all that bounds the
 * return then is the int sock_recvmsg() returns it in. */
static void recv_count(void)
{
	static const struct {
		const char *what;
		unsigned long size;
		unsigned long flags;
		unsigned long retval;
		bool flags_stomped;	/* MSG_TRUNC gone from the live slot */
		unsigned int bumps;
	} cases[] = {
		{ "the whole buffer", 4096, 0, 4096, false, 0 },
		{ "a short read", 4096, MSG_DONTWAIT, 17, false, 0 },
		{ "nothing", 4096, 0, 0, false, 0 },
		{ "-1", 4096, 0, (unsigned long) -1L, false, 0 },
		{ "a byte past the buffer", 4096, 0, 4097, false, 1 },
		{ "past the buffer, flags but not MSG_TRUNC",
		  4096, MSG_PEEK | MSG_WAITALL | MSG_DONTWAIT, 65536, false, 1 },
		{ "a datagram longer than the buffer, MSG_TRUNC",
		  100, MSG_TRUNC, 4096, false, 0 },
		{ "the length of a datagram, no buffer, MSG_PEEK | MSG_TRUNC",
		  0, MSG_PEEK | MSG_TRUNC, 512, false, 0 },
		{ "the largest int, MSG_TRUNC",
		  100, MSG_TRUNC, INT_MAX, false, 0 },
		{ "past the int, MSG_TRUNC",
		  100, MSG_TRUNC, (unsigned long) INT_MAX + 1, false, 1 },
		{ "a -errno in the return slot, MSG_TRUNC",
		  100, MSG_TRUNC, (unsigned long) -22L, false, 1 },
		{ "MSG_TRUNC stomped out of the live flags",
		  100, MSG_TRUNC, 4096, true, 0 },
	};
	const struct syscallentry *entries[] = {
		&syscall_recv, &syscall_recvfrom,
	};
	static struct syscallrecord rec;
	unsigned int e, i;

	for (e = 0; e < ARRAY_SIZE(entries); e++) {
		for (i = 0; i < ARRAY_SIZE(cases); i++) {
			char what[128];

			memset(&rec, 0, sizeof(rec));
			rec.a3 = cases[i].size;
			rec.a4 = cases[i].flags_stomped ? 0 : cases[i].flags;
			rec.arg_snapshot_mask = entries[e]->arg_snapshot_mask;
			rec.arg_shadow[2] = cases[i].size;
			rec.arg_shadow[3] = cases[i].flags;
			rec.retval = cases[i].retval;
			rec.errno_post = ((long) cases[i].retval == -1L) ? EINVAL : 0;

			bumps = 0;
			stomps = 0;
			stomps_expected = cases[i].flags_stomped;
			dispatch_post(entries[e], &rec);
			stomps_expected = false;

			snprintf(what, sizeof(what), "%s, %s", entries[e]->name,
				 cases[i].what);
			expect(what, bumps, cases[i].bumps);
			expect(what, stomps, cases[i].flags_stomped ? 1 : 0);
		}
	}
}

/* Sanitise until the msghdr carries no iovec, so the snapshot's iov_len_sum
 * is 0 and any byte received is past it.  The fake allocator does not
 * track, so the msghdr the carrier owns is freed by hand. */
static struct syscallrecord *recvmsg_rec(void)
{
	static struct syscallrecord rec;
	unsigned int tries;

	for (tries = 0; tries < 4096; tries++) {
		memset(&rec, 0, sizeof(rec));
		syscall_recvmsg.sanitise(&rec);
		if (((struct msghdr *) rec.a2)->msg_iov == NULL)
			return &rec;
		free((void *) rec.post_state);
		free((void *) rec.a2);
	}
	BUG("recvmsg sanitiser never drew a msghdr without an iovec");
	return NULL;
}

/* Bounded by the iovec it was given, or under MSG_TRUNC by the int. */
static void recvmsg_count(void)
{
	static const struct {
		const char *what;
		unsigned long flags;
		unsigned long retval;
		bool flags_stomped;	/* MSG_TRUNC gone from the live slot */
		unsigned int bumps;
	} cases[] = {
		{ "nothing", 0, 0, false, 0 },
		{ "-1", 0, (unsigned long) -1L, false, 0 },
		{ "a byte into no iovec", 0, 1, false, 1 },
		{ "a byte into no iovec, flags but not MSG_TRUNC",
		  MSG_PEEK | MSG_DONTWAIT, 1, false, 1 },
		{ "a datagram, MSG_TRUNC", MSG_TRUNC, 4096, false, 0 },
		{ "the largest int, MSG_TRUNC", MSG_TRUNC, INT_MAX, false, 0 },
		{ "past the int, MSG_TRUNC",
		  MSG_TRUNC, (unsigned long) INT_MAX + 1, false, 1 },
		{ "MSG_TRUNC stomped out of the live flags",
		  MSG_TRUNC, 4096, true, 0 },
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		struct syscallrecord *rec = recvmsg_rec();
		struct msghdr *msg = (struct msghdr *) rec->a2;
		char what[128];

		rec->a3 = cases[i].flags_stomped ? 0 : cases[i].flags;
		rec->arg_snapshot_mask = syscall_recvmsg.arg_snapshot_mask;
		rec->arg_shadow[2] = cases[i].flags;
		rec->retval = cases[i].retval;
		rec->errno_post = ((long) cases[i].retval == -1L) ? EINVAL : 0;

		bumps = 0;
		stomps = 0;
		stomps_expected = cases[i].flags_stomped;
		dispatch_post(&syscall_recvmsg, rec);
		stomps_expected = false;
		free(msg);

		snprintf(what, sizeof(what), "recvmsg, %s", cases[i].what);
		expect(what, bumps, cases[i].bumps);
		expect(what, stomps, cases[i].flags_stomped ? 1 : 0);
	}
}

/* An fd above stdio, which write's sanitiser keeps. */
#define WRITE_FD	100

/* The bytes written, at most the count the kernel was handed, which chain
 * substitution or a RedQueen pin can rewrite after the sanitiser drew its
 * own (1, or below a page). */
static void write_count(void)
{
	static const struct {
		const char *what;
		unsigned long count;
		unsigned long retval;
		unsigned int bumps;
	} cases[] = {
		{ "a rewritten count, all of it written", 65536, 65536, 0 },
		{ "a rewritten count, a short write", 65536, 4096, 0 },
		{ "nothing", 65536, 0, 0 },
		{ "-1", 65536, (unsigned long) -1L, 0 },
		{ "a byte past the rewritten count", 65536, 65537, 1 },
		{ "a byte past a rewritten count of 0", 0, 1, 1 },
	};
	static struct syscallrecord rec;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		memset(&rec, 0, sizeof(rec));
		rec.a1 = WRITE_FD;
		syscall_write.sanitise(&rec);
		rec.a3 = cases[i].count;
		rec.arg_snapshot_mask = syscall_write.arg_snapshot_mask;
		rec.arg_shadow[2] = cases[i].count;
		rec.retval = cases[i].retval;
		rec.errno_post = ((long) cases[i].retval == -1L) ? EBADF : 0;
		bumps = 0;
		dispatch_post(&syscall_write, &rec);
		expect(cases[i].what, bumps, cases[i].bumps);
		free((void *) rec.post_state);
		while (rec.owned_count > 0)
			free(rec.owned[--rec.owned_count]);
	}
}

/* The size the xattr getters are handed here, which their sanitisers keep
 * half the time. */
#define XATTR_DRAWN	64

/* The bytes of the value or name list, at most the size the kernel was
 * handed, which chain substitution or a RedQueen pin can rewrite after the
 * sanitiser drew its own; a size of 0 asks for their length, which nothing
 * bounds. */
static void xattr_size(void)
{
	static const struct {
		const struct syscallentry *entry;
		unsigned int slot;	/* the size's; the buffer's is the one before */
	} getters[] = {
		{ &syscall_getxattr, 4 },
		{ &syscall_lgetxattr, 4 },
		{ &syscall_fgetxattr, 4 },
		{ &syscall_listxattr, 3 },
		{ &syscall_llistxattr, 3 },
		{ &syscall_flistxattr, 3 },
		{ &syscall_listxattrat, 5 },
	};
	static const struct {
		const char *what;
		unsigned long size;
		unsigned long retval;
		unsigned int bumps;
	} cases[] = {
		{ "a rewritten size of 0, the length asked for",
		  0, XATTR_DRAWN + 1, 0 },
		{ "a rewritten size of 0, -1", 0, (unsigned long) -1L, 0 },
		{ "a larger rewritten size, filled past the drawn one",
		  4096, XATTR_DRAWN + 1, 0 },
		{ "a byte past a larger rewritten size", 4096, 4097, 1 },
		{ "a byte past a smaller rewritten size",
		  XATTR_DRAWN / 2, XATTR_DRAWN / 2 + 1, 1 },
	};
	static struct syscallrecord rec;
	unsigned long *slots[] = { &rec.a1, &rec.a2, &rec.a3, &rec.a4, &rec.a5, &rec.a6 };
	unsigned int g, i, k, tries;

	for (g = 0; g < ARRAY_SIZE(getters); g++) {
		const struct syscallentry *entry = getters[g].entry;
		unsigned int slot = getters[g].slot;

		for (i = 0; i < ARRAY_SIZE(cases); i++) {
			char what[128];

			for (tries = 0; tries < 4096; tries++) {
				memset(&rec, 0, sizeof(rec));
				*slots[slot - 2] = (unsigned long) get_writable_address(page_size);
				*slots[slot - 1] = XATTR_DRAWN;
				entry->sanitise(&rec);
				if (*slots[slot - 1] == XATTR_DRAWN)
					break;
				free((void *) rec.post_state);
			}
			if (tries == 4096)
				BUG("an xattr sanitiser never kept the size it was handed");

			*slots[slot - 1] = cases[i].size;
			/* The shadow __do_syscall() takes of what the kernel
			 * was handed. */
			for (k = 0; k < ARRAY_SIZE(slots); k++)
				rec.arg_shadow[k] = *slots[k];
			rec.arg_snapshot_mask = entry->arg_snapshot_mask;
			rec.retval = cases[i].retval;
			rec.errno_post = ((long) cases[i].retval == -1L) ? ENODATA : 0;
			bumps = 0;
			dispatch_post(entry, &rec);

			snprintf(what, sizeof(what), "%s, %s", entry->name,
				 cases[i].what);
			expect(what, bumps, cases[i].bumps);
		}
	}
}

/* sched_getaffinity's sanitiser run on @pid until it draws the canonical
 * sizeof(cpu_set_t), so a final len can lie on either side of it. */
static struct syscallrecord *affinity_rec(unsigned long pid)
{
	static struct syscallrecord rec;
	unsigned int tries;

	for (tries = 0; tries < 4096; tries++) {
		memset(&rec, 0, sizeof(rec));
		rec.a1 = pid;
		syscall_sched_getaffinity.sanitise(&rec);
		if (rec.a2 == sizeof(cpu_set_t))
			return &rec;
		free((void *) rec.post_state);
	}
	BUG("sched_getaffinity's sanitiser never drew sizeof(cpu_set_t)");
	return NULL;
}

/* The pid and len the kernel was handed, as __do_syscall() shadows them. */
static void affinity_ran(struct syscallrecord *rec, unsigned long pid,
			 unsigned long len)
{
	rec->a1 = pid;
	rec->a2 = len;
	rec->arg_snapshot_mask = syscall_sched_getaffinity.arg_snapshot_mask;
	rec->arg_shadow[0] = pid;
	rec->arg_shadow[1] = len;
}

/* min(len, cpumask_size()) bytes, at most the len the kernel was handed,
 * which chain substitution or a RedQueen pin can rewrite after the
 * sanitiser drew its own. */
static void sched_getaffinity_len(void)
{
	static const struct {
		const char *what;
		unsigned long len;
		unsigned long retval;
		unsigned int bumps;
	} cases[] = {
		{ "a larger rewritten len, a larger cpumask copied", 512, 512, 0 },
		{ "a byte past a larger rewritten len", 512, 513, 1 },
		{ "a smaller rewritten len, all of it copied", 8, 8, 0 },
		{ "a byte past a smaller rewritten len", 8, 9, 1 },
		{ "-1", 8, (unsigned long) -1L, 0 },
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		struct syscallrecord *rec = affinity_rec(0);
		char what[128];

		affinity_ran(rec, 0, cases[i].len);
		rec->retval = cases[i].retval;
		rec->errno_post = ((long) cases[i].retval == -1L) ? EINVAL : 0;
		bumps = 0;
		dispatch_post(&syscall_sched_getaffinity, rec);

		snprintf(what, sizeof(what), "sched_getaffinity, %s", cases[i].what);
		expect(what, bumps, cases[i].bumps);
	}
}

/* Calls per case: the compare is sampled one in a hundred. */
#define SAMPLED_CALLS	1500

/* Calls the sanitiser built on pid @built, which the kernel ran on pid
 * @ran, each answering an empty mask, which no task has; the anomalies
 * the /proc/self/status compare reports. */
static unsigned long affinity_anomalies(unsigned long built, unsigned long ran)
{
	unsigned long before = shm->stats.oracle.sched_getaffinity_oracle_anomalies;
	unsigned int i;

	for (i = 0; i < SAMPLED_CALLS; i++) {
		struct syscallrecord *rec = affinity_rec(built);

		memset((void *) rec->a3, 0, sizeof(cpu_set_t));
		affinity_ran(rec, ran, sizeof(cpu_set_t));
		rec->retval = sizeof(cpu_set_t);
		syscall_sched_getaffinity.post(rec);
	}
	return shm->stats.oracle.sched_getaffinity_oracle_anomalies - before;
}

/* Only a call on the calling task is compared with its own status, and
 * the task is the one the kernel was handed. */
static void sched_getaffinity_pid(void)
{
	unsigned long other = (unsigned long) gettid() + 1;

	if (affinity_anomalies(other, 0) == 0) {
		fprintf(stderr, "sched_getaffinity: a call on this task built for another was not compared\n");
		failed++;
	}
	if (affinity_anomalies(0, other) != 0) {
		fprintf(stderr, "sched_getaffinity: a call on another task was compared with this one\n");
		failed++;
	}
}

/* getcpu calls built by its sanitiser with nodep @offset bytes past cpup,
 * on which the kernel wrote @cpu and then @node; whether the sampled range
 * check reported the cpu it read back.  Told by the line it logs, as the
 * node check bumps the same counter. */
static bool getcpu_cpu_reported(unsigned int offset, unsigned int cpu,
				unsigned int node)
{
	static struct syscallrecord rec;
	unsigned int i;

	fake_output_log[0] = '\0';
	for (i = 0; i < SAMPLED_CALLS; i++) {
		char *buf = get_writable_address(2 * sizeof(unsigned int));

		memset(&rec, 0, sizeof(rec));
		rec.a1 = (unsigned long) buf;
		rec.a2 = (unsigned long) (buf + offset);
		syscall_getcpu.sanitise(&rec);
		memcpy((void *) rec.a1, &cpu, sizeof(cpu));
		memcpy((void *) rec.a2, &node, sizeof(node));
		rec.retval = 0;
		syscall_getcpu.post(&rec);
	}
	return strstr(fake_output_log, "getcpu oracle: cpu=") != NULL;
}

/* Only a cpu the node was not written over is range checked.  A node in
 * the top three bytes of cpu 0 reads back as 256 times the node, so one
 * a cpu count in 256s past the host's reads back as a cpu it lacks. */
static void getcpu_spliced(void)
{
	long conf = sysconf(_SC_NPROCESSORS_CONF);

	if (getcpu_cpu_reported(1, 0, (unsigned int) conf / 256 + 1)) {
		fprintf(stderr, "getcpu: a cpu the node was written over was range checked\n");
		failed++;
	}
	if (!getcpu_cpu_reported(sizeof(unsigned int), (unsigned int) conf, 0)) {
		fprintf(stderr, "getcpu: a cpu past the host's count went unreported\n");
		failed++;
	}
}

extern bool (*fake_syscall)(long number, const unsigned long a[6],
			    long *ret);	/* landlock_test.c */
extern bool fake_pid_draws;	/* dup_pool_test.c */

/* capget answering with a set the call before it did not see, as a task's
 * set reads once it has moved between the two. */
static bool model_moved_caps(long number, const unsigned long a[6], long *ret)
{
	struct __user_cap_data_struct *data = (void *) a[1];

	if (number != __NR_capget)
		return false;
	memset(data, 0, 2 * sizeof(*data));
	data[0].permitted = 1;
	*ret = 0;
	return true;
}

/* capget calls built by its sanitiser with the header naming @pid, on
 * which the kernel wrote an empty set and a re-call reads another; the
 * anomalies the sampled re-call reports. */
static unsigned long capget_anomalies(pid_t pid)
{
	unsigned long before = shm->stats.oracle.capget_oracle_anomalies;
	static struct syscallrecord rec;
	unsigned int i;

	fake_syscall = model_moved_caps;
	fake_pid_draws = true;
	for (i = 0; i < SAMPLED_CALLS; i++) {
		struct __user_cap_header_struct *hdr;

		memset(&rec, 0, sizeof(rec));
		rec.a2 = (unsigned long) get_writable_address(2 * sizeof(struct __user_cap_data_struct));
		syscall_capget.sanitise(&rec);
		hdr = (void *) rec.a1;
		hdr->version = _LINUX_CAPABILITY_VERSION_3;
		hdr->pid = pid;
		memset((void *) rec.a2, 0, 2 * sizeof(struct __user_cap_data_struct));
		rec.retval = 0;
		syscall_capget.post(&rec);
	}
	fake_pid_draws = false;
	fake_syscall = NULL;
	return shm->stats.oracle.capget_oracle_anomalies - before;
}

/* Only a call on the caller is re-called: another task's set moves with
 * its own capset() or unshare() between the call and the re-call. */
static void capget_target(void)
{
	pid_t self = gettid();

	if (capget_anomalies(self + 1) != 0) {
		fprintf(stderr, "capget: a call on another task was re-called\n");
		failed++;
	}
	if (capget_anomalies(0) == 0 || capget_anomalies(self) == 0) {
		fprintf(stderr, "capget: a call on the caller was not re-called\n");
		failed++;
	}
}

/* @entry's post handler on calls with @a1-@a3 that answered 0, which
 * @reported says its sampled getres[ug]id() compare should report. */
static void setid_case(const struct syscallentry *entry, unsigned long a1,
		       unsigned long a2, unsigned long a3, bool reported)
{
	unsigned long before = shm->stats.oracle.cred_oracle_anomalies;
	static struct syscallrecord rec;
	unsigned int i;

	for (i = 0; i < SAMPLED_CALLS; i++) {
		memset(&rec, 0, sizeof(rec));
		rec.a1 = a1;
		rec.a2 = a2;
		rec.a3 = a3;
		rec.retval = 0;
		entry->post(&rec);
	}
	if ((shm->stats.oracle.cred_oracle_anomalies != before) == reported)
		return;
	fprintf(stderr, "%s(%ld, %ld, %ld): %s\n", entry->name,
		(long) a1, (long) a2, (long) a3,
		reported ? "an id the call did not set went unreported"
			 : "an id left unchanged was checked");
	failed++;
}

/* A RedQueen pin can hand a set*id call (uid_t)-1, the "leave unchanged"
 * id the kernel compares each against: an id passed as -1 is not checked,
 * one the caller does not hold still is. */
static void setid_unchanged(void)
{
	const unsigned long keep = (uid_t) -1;
	uid_t r, e, s;
	gid_t rg, eg, sg;

	if (getresuid(&r, &e, &s) != 0 || getresgid(&rg, &eg, &sg) != 0)
		BUG("set*id: cannot read the test's ids");

	setid_case(&syscall_setreuid, keep, e, 0, false);
	setid_case(&syscall_setreuid, r + 1, e, 0, true);
	setid_case(&syscall_setresuid, keep, keep, keep, false);
	setid_case(&syscall_setresuid, r, e, s + 1, true);
	setid_case(&syscall_setregid, keep, eg, 0, false);
	setid_case(&syscall_setregid, rg + 1, eg, 0, true);
	setid_case(&syscall_setresgid, keep, keep, keep, false);
	setid_case(&syscall_setresgid, rg, eg, sg + 1, true);
}

/* setgroups calls the sanitiser built for @built gids, which the kernel
 * ran with @ran, the @ran at @gids, and answered 0; the anomalies the
 * sampled getgroups() and /proc/self/status compares report. */
static unsigned long setgroups_anomalies(unsigned long built,
					 unsigned long ran, const gid_t *gids)
{
	unsigned long before = shm->stats.oracle.cred_oracle_anomalies +
			       shm->stats.oracle.setgroups_oracle_anomalies;
	static struct syscallrecord rec;
	unsigned int i;

	for (i = 0; i < SAMPLED_CALLS; i++) {
		memset(&rec, 0, sizeof(rec));
		rec.a1 = built;
		rec.a2 = (unsigned long) get_writable_address(page_size);
		syscall_setgroups.sanitise(&rec);

		memcpy((void *) rec.a2, gids, ran * sizeof(*gids));
		rec.a1 = ran;
		rec.arg_snapshot_mask = syscall_setgroups.arg_snapshot_mask;
		rec.arg_shadow[0] = rec.a1;
		rec.arg_shadow[1] = rec.a2;
		rec.retval = 0;
		syscall_setgroups.post(&rec);
	}
	return shm->stats.oracle.cred_oracle_anomalies +
	       shm->stats.oracle.setgroups_oracle_anomalies - before;
}

/* A setgroups() that worked is read back by its count and gids, the ones
 * the kernel was handed, which chain substitution can rewrite after the
 * sanitiser drew its own. */
static void setgroups_count(void)
{
	static gid_t gids[65];
	int held = getgroups(0, NULL);

	if (held < 0 || held >= (int) ARRAY_SIZE(gids) ||
	    getgroups(held, gids) != held)
		BUG("setgroups: cannot read the groups this task holds");
	/* One more gid than the task holds. */
	gids[held] = 12345;

	if (setgroups_anomalies(held + 1, held, gids) != 0) {
		fprintf(stderr, "setgroups: a count rewritten to the groups the task holds was judged on the count built\n");
		failed++;
	}
	if (setgroups_anomalies(held, held + 1, gids) == 0) {
		fprintf(stderr, "setgroups: a count rewritten past the groups the task holds was not reported\n");
		failed++;
	}
}

/* The entries whose return enforce_count_bound() holds to a count the
 * kernel was handed, which chain substitution or a RedQueen pin can
 * rewrite after the sanitiser drew its own, and the count's slot. */
static void count_rewritten(void)
{
	static const struct {
		const struct syscallentry *entry;
		unsigned int slot;
	} entries[] = {
		{ &syscall_getcwd, 2 },
		{ &syscall_listns, 3 },
		{ &syscall_readlink, 3 },
		{ &syscall_listmount, 3 },
	};
	/* The kernel handed twice the count the sanitiser drew, or half,
	 * and filling all of it, or returning a byte past it. */
	static const struct {
		const char *what;
		bool larger;
		bool past;
		unsigned int bumps;
	} cases[] = {
		{ "a larger rewritten count, all of it filled", true, false, 0 },
		{ "a byte past a larger rewritten count", true, true, 1 },
		{ "a smaller rewritten count, all of it filled", false, false, 0 },
		{ "a byte past a smaller rewritten count", false, true, 1 },
	};
	static struct syscallrecord rec;
	unsigned long *slots[] = { &rec.a1, &rec.a2, &rec.a3, &rec.a4, &rec.a5, &rec.a6 };
	unsigned int e, i, k, tries;

	for (e = 0; e < ARRAY_SIZE(entries); e++) {
		const struct syscallentry *entry = entries[e].entry;
		unsigned long *count = slots[entries[e].slot - 1];

		for (i = 0; i < ARRAY_SIZE(cases); i++) {
			unsigned long drawn;
			char what[128];

			for (tries = 0; tries < 4096; tries++) {
				memset(&rec, 0, sizeof(rec));
				for (k = 0; k < ARRAY_SIZE(slots); k++)
					*slots[k] = (unsigned long) get_writable_address(page_size);
				*count = 64;
				entry->sanitise(&rec);
				if (*count >= 2)
					break;
				free((void *) rec.post_state);
				while (rec.owned_count > 0)
					free(rec.owned[--rec.owned_count]);
			}
			if (tries == 4096)
				BUG("a sanitiser never drew a count past 1");

			drawn = *count;
			*count = cases[i].larger ? drawn * 2 : drawn / 2;
			for (k = 0; k < ARRAY_SIZE(slots); k++)
				rec.arg_shadow[k] = *slots[k];
			rec.arg_snapshot_mask = entry->arg_snapshot_mask;
			rec.retval = *count + (cases[i].past ? 1 : 0);
			bumps = 0;
			dispatch_post(entry, &rec);
			while (rec.owned_count > 0)
				free(rec.owned[--rec.owned_count]);

			snprintf(what, sizeof(what), "%s, %s", entry->name, cases[i].what);
			expect(what, bumps, cases[i].bumps);
		}
	}
}

/* sendmmsg and recvmmsg return how many entries they sent or filled, at
 * most the vlen the kernel was handed: a vlen rewritten below the entries
 * the sanitiser built holds the return to it. */
static void mmsg_count(void)
{
	struct syscallentry *const entries[] = {
		&syscall_sendmmsg, &syscall_recvmmsg,
	};
	static const struct {
		const char *what;
		bool past;
		unsigned int bumps;
	} cases[] = {
		{ "all of a smaller rewritten vlen", false, 0 },
		{ "one past a smaller rewritten vlen", true, 1 },
	};
	static struct syscallrecord rec;
	unsigned int e, i, tries;

	fake_socket_fd_none = true;
	for (e = 0; e < ARRAY_SIZE(entries); e++) {
		struct syscallentry *entry = entries[e];

		for (i = 0; i < ARRAY_SIZE(cases); i++) {
			char what[128];

			for (tries = 0; tries < 4096; tries++) {
				memset(&rec, 0, sizeof(rec));
				entry->sanitise(&rec);
				if (rec.a3 >= 2)
					break;
				rec.retval = (unsigned long) -1L;
				entry->post(&rec);
				while (rec.owned_count > 0)
					free(rec.owned[--rec.owned_count]);
			}
			if (tries == 4096)
				BUG("an mmsg sanitiser never built two entries");

			rec.a3--;
			rec.arg_shadow[2] = rec.a3;
			rec.arg_snapshot_mask = entry->arg_snapshot_mask;
			rec.retval = rec.a3 + (cases[i].past ? 1 : 0);
			bumps = 0;
			entry->post(&rec);
			while (rec.owned_count > 0)
				free(rec.owned[--rec.owned_count]);
			snprintf(what, sizeof(what), "%s, %s", entry->name, cases[i].what);
			expect(what, bumps, cases[i].bumps);
		}
	}
	fake_socket_fd_none = false;
}

/* A grouplist still holding the poison getgroups' sanitiser stamped over
 * the 4 gids it drew, after a return of gids copied, is a buffer the
 * kernel never wrote; but a gidsetsize rewritten to 0 asks for the count
 * and copies nothing. */
static void getgroups_untouched(void)
{
	static const struct {
		const char *what;
		unsigned long gidsetsize;
		unsigned long retval;
		unsigned int untouched;
	} cases[] = {
		{ "getgroups, the count under a rewritten gidsetsize of 0", 0, 2, 0 },
		{ "getgroups, two gids claimed and none written", 4, 2, 1 },
		{ "getgroups, six gids claimed under a larger rewritten gidsetsize, none written",
		  8, 6, 1 },
	};
	static struct syscallrecord rec;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		unsigned long before;

		memset(&rec, 0, sizeof(rec));
		rec.a1 = 4;
		rec.a2 = (unsigned long) get_writable_address(page_size);
		syscall_getgroups.sanitise(&rec);

		rec.a1 = cases[i].gidsetsize;
		rec.arg_snapshot_mask = syscall_getgroups.arg_snapshot_mask;
		rec.arg_shadow[0] = rec.a1;
		rec.arg_shadow[1] = rec.a2;
		rec.retval = cases[i].retval;
		before = shm->stats.post_handler_untouched_out_buf;
		syscall_getgroups.post(&rec);
		expect(cases[i].what,
		       shm->stats.post_handler_untouched_out_buf - before,
		       cases[i].untouched);
	}
}

extern bool fake_overlaps_libc_heap;	/* fake_shm.c */

/* The SysV ctl commands that fill a buffer hand the kernel the buffer
 * their poison was stamped into, so a success whose copy reached it is no
 * untouched one.  The kernel's copy is stood in for by a byte flipped in
 * the buffer the call hands it.  A heap buffer is one asb_relocate()
 * moves the call off, and the fake allocator's are none, so every range
 * is said to overlap the heap while a sanitiser runs. */
static void sysv_ctl_untouched(void)
{
	static const struct {
		const char *what;
		struct syscallentry *entry;
		unsigned int cmd_slot;
		unsigned long cmd;
		unsigned int buf_slot;
	} cases[] = {
		{ "shmctl IPC_STAT", &syscall_shmctl, 2, IPC_STAT, 3 },
		{ "shmctl SHM_INFO", &syscall_shmctl, 2, SHM_INFO, 3 },
		{ "msgctl IPC_STAT", &syscall_msgctl, 2, IPC_STAT, 3 },
		{ "msgctl MSG_INFO", &syscall_msgctl, 2, MSG_INFO, 3 },
		{ "semctl IPC_STAT", &syscall_semctl, 3, IPC_STAT, 4 },
		{ "semctl SEM_INFO", &syscall_semctl, 3, SEM_INFO, 4 },
	};
	static struct syscallrecord rec;
	unsigned long *slots[] = { &rec.a1, &rec.a2, &rec.a3, &rec.a4, &rec.a5, &rec.a6 };
	unsigned int i, written;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		for (written = 0; written < 2; written++) {
			unsigned long before;
			char what[128];

			memset(&rec, 0, sizeof(rec));
			*slots[cases[i].cmd_slot - 1] = cases[i].cmd;
			fake_overlaps_libc_heap = true;
			cases[i].entry->sanitise(&rec);
			fake_overlaps_libc_heap = false;
			if (written)
				*(unsigned char *) *slots[cases[i].buf_slot - 1] ^= 0xff;
			rec.retval = 0;
			before = shm->stats.post_handler_untouched_out_buf;
			cases[i].entry->post(&rec);

			snprintf(what, sizeof(what), "%s, %s", cases[i].what,
				 written ? "the buffer written" : "nothing written");
			expect(what, shm->stats.post_handler_untouched_out_buf - before,
			       written ? 0 : 1);
		}
	}
}

extern bool fake_random_fd_empty;	/* fake_stubs.c */

/* Run io_uring_register's sanitiser until it draws @opcode, so the
 * snapshot the post handler claims is the one the sanitiser built.  The
 * payloads of the opcodes drawn on the way pick their fds from an empty
 * pool. */
static struct syscallrecord *io_uring_register_rec(unsigned int opcode)
{
	static struct syscallrecord rec;
	unsigned int tries;

	fake_random_fd_empty = true;
	for (tries = 0; tries < 4096; tries++) {
		memset(&rec, 0, sizeof(rec));
		syscall_io_uring_register.sanitise(&rec);
		if (rec.a2 == opcode)
			break;
		free((void *) rec.post_state);
	}
	fake_random_fd_empty = false;
	if (tries == 4096)
		BUG("io_uring_register sanitiser never drew the opcode");
	return &rec;
}

/* io_uring_register() answers by the opcode the kernel ran: PERSONALITY
 * with a new id, an update with the entries it updated, out of the nr
 * its struct names, and ENABLE_RINGS with 0.  Chain substitution can
 * rewrite the opcode, an ARG_OP slot, after the sanitiser built the
 * payload for its own, which names no nr for an update to be held to. */
static void io_uring_register_rewritten(void)
{
	static const struct {
		const char *what;
		unsigned int built;
		unsigned int ran;
		unsigned long retval;
		unsigned int bumps;
	} cases[] = {
		{ "io_uring_register, an id from a call rewritten onto PERSONALITY",
		  IORING_REGISTER_ENABLE_RINGS, IORING_REGISTER_PERSONALITY, 1, 0 },
		{ "io_uring_register, an id from a call rewritten onto ENABLE_RINGS",
		  IORING_REGISTER_PERSONALITY, IORING_REGISTER_ENABLE_RINGS, 1, 1 },
		{ "io_uring_register, a count from a call rewritten onto FILES_UPDATE2",
		  IORING_REGISTER_ENABLE_RINGS, IORING_REGISTER_FILES_UPDATE2, 1, 0 },
		{ "io_uring_register, a count past UINT_MAX from a call rewritten onto FILES_UPDATE2",
		  IORING_REGISTER_ENABLE_RINGS, IORING_REGISTER_FILES_UPDATE2,
		  1UL << 32, 1 },
	};
	unsigned int i, k;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		struct syscallrecord *rec = io_uring_register_rec(cases[i].built);
		unsigned long *slots[] = { &rec->a1, &rec->a2, &rec->a3,
					   &rec->a4, &rec->a5, &rec->a6 };

		/* The slots the kernel was handed, as __do_syscall()
		 * shadows them. */
		rec->a2 = cases[i].ran;
		for (k = 0; k < ARRAY_SIZE(slots); k++)
			rec->arg_shadow[k] = *slots[k];
		rec->arg_snapshot_mask = syscall_io_uring_register.arg_snapshot_mask;
		rec->retval = cases[i].retval;
		bumps = 0;
		syscall_io_uring_register.post(rec);
		expect(cases[i].what, bumps, cases[i].bumps);
	}
}

/* A post oracle over a time struct the kernel writes: its entry, its
 * anomaly counter, or NULL for one that bumps the corrupt-pointer
 * counter, and the slot of the buffer the kernel answers into. */
struct time_oracle {
	struct syscallentry *entry;
	unsigned long *anomalies;
	unsigned int slot;
};

/* @o's calls under compat number @nr, or native ones for 0, each
 * answering the @len bytes at @answer; the anomalies its sampled checks
 * report. */
static unsigned int time_oracle_anomalies(const struct time_oracle *o,
					  unsigned int nr,
					  const void *answer, size_t len)
{
	unsigned long before = o->anomalies != NULL ? *o->anomalies : bumps;
	unsigned int i;

	/* A whole-pool draw starts the bump cursor over, so no draw below
	 * sits within a page of the pool's end, where gettimeofday's
	 * past-the-end tv would stamp the guard page. */
	(void) get_writable_address(WRITABLE_POOL_BYTES);
	/* A clock the sanitiser picks may be a task's CPU clock. */
	fake_pid_draws = true;
	for (i = 0; i < SAMPLED_CALLS; i++) {
		static struct syscallrecord rec;
		unsigned long *slots[] = { &rec.a1, &rec.a2 };

		memset(&rec, 0, sizeof(rec));
		rec.a1 = (unsigned long) get_writable_address(sizeof(struct itimerspec));
		rec.a2 = (unsigned long) get_writable_address(sizeof(struct itimerspec));
		o->entry->sanitise(&rec);

		memcpy((void *) *slots[o->slot - 1], answer, len);
		if (nr != 0) {
			rec.do32bit = true;
			rec.nr = nr;
		}
		rec.retval = 0;
		o->entry->post(&rec);
	}
	fake_pid_draws = false;
	return (o->anomalies != NULL ? *o->anomalies : bumps) - before;
}

/* gettimeofday() writes tv as a struct old_timeval32 for a compat call,
 * 78 on i386, and as a struct timeval for a native one; either holds the
 * time now, which the sampled wall-clock compare must take as such. */
static void gettimeofday_compat(void)
{
	const struct time_oracle o = {
		&syscall_gettimeofday,
		&shm->stats.oracle.gettimeofday_oracle_anomalies, 1,
	};
	struct timeval now;
	struct old_timeval32 now32;

	if (gettimeofday(&now, NULL) != 0)
		BUG("gettimeofday: no time to answer with");
	now32.tv_sec = (int32_t) now.tv_sec;
	now32.tv_usec = (int32_t) now.tv_usec;

	expect("gettimeofday, a native call's time",
	       time_oracle_anomalies(&o, 0, &now, sizeof(now)), 0);
	expect("gettimeofday, a compat call's time",
	       time_oracle_anomalies(&o, 78, &now32, sizeof(now32)), 0);
}

/* clock_gettime() writes a struct old_timespec32 for a time32 call, 265
 * on i386, which the sampled range check must read as such. */
static void clock_gettime_compat(void)
{
	const struct time_oracle o = {
		&syscall_clock_gettime,
		&shm->stats.oracle.clock_gettime_oracle_anomalies, 2,
	};
	struct timespec now;
	struct old_timespec32 now32;

	if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
		BUG("clock_gettime: no time to answer with");
	now32.tv_sec = (int32_t) now.tv_sec;
	now32.tv_nsec = (int32_t) now.tv_nsec;

	expect("clock_gettime, a native call's time",
	       time_oracle_anomalies(&o, 0, &now, sizeof(now)), 0);
	expect("clock_gettime, a time32 call's time",
	       time_oracle_anomalies(&o, 265, &now32, sizeof(now32)), 0);
}

/* timer_gettime() writes a struct old_itimerspec32 for a time32 call,
 * 261 on i386, which the range check must read as such: here a timer
 * 1.5 s from expiry, with no interval. */
static void timer_gettime_compat(void)
{
	const struct time_oracle o = { &syscall_timer_gettime, NULL, 2 };
	const struct itimerspec left = { .it_value = { 1, 500000000 } };
	const struct old_itimerspec32 left32 = { .it_value = { 1, 500000000 } };

	expect("timer_gettime, a native call's setting",
	       time_oracle_anomalies(&o, 0, &left, sizeof(left)), 0);
	expect("timer_gettime, a time32 call's setting",
	       time_oracle_anomalies(&o, 261, &left32, sizeof(left32)), 0);
}

/* timerfd_gettime() writes a struct old_itimerspec32 for a time32 call,
 * 326 on i386, which the range check must read as such: here a timer
 * 1.5 s from expiry, with no interval. */
static void timerfd_gettime_compat(void)
{
	const struct time_oracle o = { &syscall_timerfd_gettime, NULL, 2 };
	const struct itimerspec left = { .it_value = { 1, 500000000 } };
	const struct old_itimerspec32 left32 = { .it_value = { 1, 500000000 } };

	expect("timerfd_gettime, a native call's setting",
	       time_oracle_anomalies(&o, 0, &left, sizeof(left)), 0);
	expect("timerfd_gettime, a time32 call's setting",
	       time_oracle_anomalies(&o, 326, &left32, sizeof(left32)), 0);
}

/* getitimer() writes a struct old_itimerval32 for a compat call, 105 on
 * i386, which the range check must read as such: here a timer 1.5 s
 * from expiry, with no interval. */
static void getitimer_compat(void)
{
	const struct time_oracle o = { &syscall_getitimer, NULL, 2 };
	const struct itimerval left = { .it_value = { 1, 500000 } };
	const struct old_itimerval32 left32 = { .it_value = { 1, 500000 } };

	expect("getitimer, a native call's value",
	       time_oracle_anomalies(&o, 0, &left, sizeof(left)), 0);
	expect("getitimer, a compat call's value",
	       time_oracle_anomalies(&o, 105, &left32, sizeof(left32)), 0);
}

/* get_mempolicy() writes maxnode - 1 bits of the node mask
 * (copy_nodes_to_user()), so a call handed a maxnode of 1, which a
 * single-node box takes, writes the policy and none of the mask.  The
 * kernel's copies are stood in for by the words the call writes. */
static void get_mempolicy_untouched(void)
{
	static const struct {
		const char *what;
		unsigned long maxnode;
		bool mask_written;
		unsigned int untouched;
	} cases[] = {
		{ "get_mempolicy, a maxnode of 1 and no mask to write", 1, false, 0 },
		{ "get_mempolicy, a maxnode of 64 and the mask left unwritten", 64, false, 1 },
		{ "get_mempolicy, a maxnode of 64 and the mask written", 64, true, 0 },
	};
	static struct syscallrecord rec;
	unsigned long *slots[] = { &rec.a1, &rec.a2, &rec.a3, &rec.a4, &rec.a5, &rec.a6 };
	unsigned int i, k;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		unsigned long before;

		memset(&rec, 0, sizeof(rec));
		rec.a1 = (unsigned long) get_writable_address(sizeof(int));
		rec.a2 = (unsigned long) get_writable_address(page_size);
		rec.a3 = cases[i].maxnode;
		syscall_get_mempolicy.sanitise(&rec);

		*(int *) rec.a1 = 0;
		if (cases[i].mask_written)
			*(unsigned long *) rec.a2 = 1;
		for (k = 0; k < ARRAY_SIZE(slots); k++)
			rec.arg_shadow[k] = *slots[k];
		rec.arg_snapshot_mask = syscall_get_mempolicy.arg_snapshot_mask;
		rec.retval = 0;
		before = shm->stats.post_handler_untouched_out_buf;
		syscall_get_mempolicy.post(&rec);
		expect(cases[i].what,
		       shm->stats.post_handler_untouched_out_buf - before,
		       cases[i].untouched);
	}
}

#ifdef ARCH_IS_BIARCH
/* No compat base is a kernel address: x86-64's access_ok() passes
 * 0xffffffff, and iter_to_pipe() returns the bytes the segments before
 * it moved, so a compat vmsplice that returns them is no finding. */
static void vmsplice_compat_iovec(void)
{
	struct compat_iovec *iov = alloc_compat_iovec(2, IOV_KERNEL_WRITE);
	struct syscallrecord rec;

	if (iov == NULL || (unsigned long) iov > UINT_MAX)
		BUG("vmsplice: no compat iovec array to judge");
	iov[0].iov_base = 0x1000; iov[0].iov_len = 16;
	iov[1].iov_base = UINT32_MAX; iov[1].iov_len = 8;
	memset(&rec, 0, sizeof(rec));
	rec.do32bit = true;
	rec.a2 = (unsigned long) iov;
	rec.a3 = 2;
	rec.retval = 16;
	bumps = 0;
	syscall_vmsplice.post(&rec);
	expect("vmsplice, a compat 0xffffffff base after a segment that moved bytes",
	       bumps, 0);
}
#endif

extern struct object *(*fake_publish_resource)(enum objecttype type,
					       unsigned long id,
					       const struct resource_meta *meta);	/* landlock_test.c */

static struct resource_meta published_meta;

static struct object *record_publish(enum objecttype type, unsigned long id,
				     const struct resource_meta *meta)
{
	(void) type;
	(void) id;
	published_meta = *meta;
	return NULL;
}

/* An fd a call publishes is tagged with the flags it was made with, which
 * a later sanitiser reads back: fanotify_mark's the group's class, and
 * timerfd_settime's the timer's clock.  Chain substitution can rewrite
 * either slot after the sanitiser drew its own. */
static void fd_tag_rewritten(void)
{
	static const struct {
		const char *what;
		struct syscallentry *entry;
		unsigned long ran[2];		/* the a1 and a2 the kernel ran */
		unsigned int flags, aux;	/* the tag they make */
	} cases[] = {
		{ "fanotify_init", &syscall_fanotify_init,
		  { FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_REPORT_MNT, O_RDWR },
		  FAN_CLOEXEC | FAN_CLASS_NOTIF | FAN_REPORT_MNT, O_RDWR },
		{ "timerfd_create", &syscall_timerfd_create,
		  { CLOCK_BOOTTIME, TFD_CLOEXEC }, TFD_CLOEXEC, CLOCK_BOOTTIME },
	};
	static struct syscallrecord rec;
	unsigned long *slots[] = { &rec.a1, &rec.a2, &rec.a3, &rec.a4, &rec.a5, &rec.a6 };
	unsigned int i, k, tries;

	fake_publish_resource = record_publish;
	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		for (tries = 0; tries < 4096; tries++) {
			memset(&rec, 0, sizeof(rec));
			cases[i].entry->sanitise(&rec);
			if (rec.a1 != cases[i].ran[0] && rec.a2 != cases[i].ran[1])
				break;
			free((void *) rec.post_state);
		}
		if (tries == 4096)
			BUG("a sanitiser never drew other slots than the kernel ran");

		/* The slots the kernel was handed, as __do_syscall()
		 * shadows them. */
		rec.a1 = cases[i].ran[0];
		rec.a2 = cases[i].ran[1];
		for (k = 0; k < ARRAY_SIZE(slots); k++)
			rec.arg_shadow[k] = *slots[k];
		rec.arg_snapshot_mask = cases[i].entry->arg_snapshot_mask;
		rec.retval = 7;
		memset(&published_meta, 0, sizeof(published_meta));
		cases[i].entry->post(&rec);
		if (published_meta.flags != cases[i].flags ||
		    published_meta.aux != cases[i].aux) {
			fprintf(stderr, "%s: a rewritten call's fd tagged %#x/%#x, not %#x/%#x\n",
				cases[i].what, published_meta.flags,
				published_meta.aux, cases[i].flags,
				cases[i].aux);
			failed++;
		}
	}
	fake_publish_resource = NULL;
}

/* The fd the last invalidate_obj_mmap_by_fd() named, which mm/maps-proc.c
 * implements outside this binary; -1 for none. */
static int invalidated_fd = -1;

unsigned int invalidate_obj_mmap_by_fd(int fd)
{
	invalidated_fd = fd;
	return 0;
}

/* The fd a call cuts the file of, and the one its sanitiser drew. */
#define CUT_FD		42
#define BUILT_FD	41

/* ftruncate and fallocate's content-destroying modes cut the file the
 * kernel was handed, whose pooled mappings a later write through would
 * SIGBUS on.  Chain substitution can rewrite the ARG_FD slot with a
 * previous call's fd, and fallocate's ARG_LIST mode, after the sanitiser
 * drew its own. */
static void cut_fd_rewritten(void)
{
	static const struct {
		const char *what;
		struct syscallentry *entry;
		unsigned long built_a2;		/* the a2 the sanitiser drew */
		unsigned long ran_a2;		/* and the one the kernel ran */
		int invalidated;
	} cases[] = {
		{ "fallocate, a hole punched in a rewritten fd", &syscall_fallocate,
		  0, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, CUT_FD },
		{ "fallocate, a punch rewritten to an allocation", &syscall_fallocate,
		  FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, -1 },
		{ "ftruncate, a rewritten fd", &syscall_ftruncate, 0, 0, CUT_FD },
		{ "ftruncate64, a rewritten fd", &syscall_ftruncate64, 0, 0, CUT_FD },
	};
	static struct syscallrecord rec;
	unsigned long *slots[] = { &rec.a1, &rec.a2, &rec.a3, &rec.a4, &rec.a5, &rec.a6 };
	unsigned int i, k, tries;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		for (tries = 0; tries < 4096; tries++) {
			memset(&rec, 0, sizeof(rec));
			rec.a1 = BUILT_FD;
			cases[i].entry->sanitise(&rec);
			if (rec.a2 == cases[i].built_a2)
				break;
			free((void *) rec.post_state);
		}
		if (tries == 4096)
			BUG("a sanitiser never drew the a2 a case builds on");

		/* The slots the kernel was handed, as __do_syscall()
		 * shadows them. */
		rec.a1 = CUT_FD;
		rec.a2 = cases[i].ran_a2;
		for (k = 0; k < ARRAY_SIZE(slots); k++)
			rec.arg_shadow[k] = *slots[k];
		rec.arg_snapshot_mask = cases[i].entry->arg_snapshot_mask;
		rec.retval = 0;
		invalidated_fd = -1;
		cases[i].entry->post(&rec);
		if (invalidated_fd != cases[i].invalidated) {
			fprintf(stderr, "%s: fd %d's mappings invalidated, wanted %d\n",
				cases[i].what, invalidated_fd,
				cases[i].invalidated);
			failed++;
		}
	}
}

/* Calls per rt_sigpending case: its procfs compare is sampled one in a
 * hundred. */
#define SIGPENDING_CALLS	1500

/* rt_sigpending calls the sanitiser built with a sigsetsize of 8, which
 * the kernel ran with @ran, writing that many bytes of this process's
 * pending mask, none pending, when @written; the untouched buffers and
 * the anomalies they report.  The buffer is a page, so a read past the
 * kernel's 8 bytes stays mapped. */
static void sigpending_reports(unsigned long ran, bool written,
			       unsigned long *untouched,
			       unsigned long *anomalies)
{
	static struct syscallrecord rec;
	static const uint64_t none_pending;
	unsigned long *slots[] = { &rec.a1, &rec.a2, &rec.a3, &rec.a4, &rec.a5, &rec.a6 };
	unsigned long untouched_before = shm->stats.post_handler_untouched_out_buf;
	unsigned long anomalies_before = shm->stats.oracle.rt_sigpending_oracle_anomalies;
	unsigned int i, k, tries;

	for (i = 0; i < SIGPENDING_CALLS; i++) {
		for (tries = 0; tries < 4096; tries++) {
			memset(&rec, 0, sizeof(rec));
			rec.a1 = (unsigned long) get_writable_address(page_size);
			syscall_rt_sigpending.sanitise(&rec);
			if (rec.a2 == sizeof(uint64_t))
				break;
			free((void *) rec.post_state);
		}
		if (tries == 4096)
			BUG("rt_sigpending sanitiser never drew the kernel's sigsetsize");

		if (written)
			memcpy((void *) rec.a1, &none_pending, ran);
		/* The slots the kernel was handed, as __do_syscall()
		 * shadows them. */
		rec.a2 = ran;
		for (k = 0; k < ARRAY_SIZE(slots); k++)
			rec.arg_shadow[k] = *slots[k];
		rec.arg_snapshot_mask = syscall_rt_sigpending.arg_snapshot_mask;
		rec.retval = 0;
		syscall_rt_sigpending.post(&rec);
	}
	*untouched = shm->stats.post_handler_untouched_out_buf - untouched_before;
	*anomalies = shm->stats.oracle.rt_sigpending_oracle_anomalies - anomalies_before;
}

/* rt_sigpending() writes the kernel's 8-byte set, not glibc's 128-byte
 * sigset_t: a call that wrote it is no untouched one and agrees with
 * /proc/self/status, and one that left the sanitiser's poison is reported
 * by both checks.  It takes any sigsetsize up to 8 and copies that many
 * bytes (kernel/signal.c), so a call chain substitution rewrote to a
 * smaller one leaves the tail of the poison in place, and one rewritten
 * to 0 all of it. */
static void sigpending_cases(void)
{
	static const struct {
		const char *what;
		unsigned long ran;
		bool written;
		bool untouched, anomalies;
	} cases[] = {
		{ "rt_sigpending, the whole mask", 8, true, false, false },
		{ "rt_sigpending, the mask left unwritten", 8, false, true, true },
		{ "rt_sigpending, a sigsetsize rewritten to 4", 4, true, false, false },
		{ "rt_sigpending, a sigsetsize rewritten to 0", 0, true, false, false },
	};
	unsigned long untouched, anomalies;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		sigpending_reports(cases[i].ran, cases[i].written, &untouched,
				   &anomalies);
		if ((untouched != 0) != cases[i].untouched ||
		    (anomalies != 0) != cases[i].anomalies) {
			fprintf(stderr, "%s: %lu untouched, %lu anomalies\n",
				cases[i].what, untouched, anomalies);
			failed++;
		}
	}
}

#ifdef USE_BPF
static unsigned int bpf_published;

static struct object *count_publish(enum objecttype type, unsigned long id,
				    const struct resource_meta *meta)
{
	(void) type;
	(void) id;
	(void) meta;
	bpf_published++;
	return NULL;
}

/* A bpf call the sanitiser built as @built, which the kernel ran as @ran
 * and which returned @retval; the bumps its post handler makes.  The
 * post handler hands the attr to deferred free, which refuses what the
 * fake allocator never tracked, so it is freed here. */
static unsigned int bpf_post(unsigned int built, unsigned int ran,
			     unsigned long retval)
{
	static struct syscallrecord rec;
	void *attr;

	memset(&rec, 0, sizeof(rec));
	rec.a1 = built;
	syscall_bpf.sanitise(&rec);
	attr = (void *) rec.a2;
	rec.a1 = ran;
	rec.arg_shadow[0] = ran;
	rec.arg_snapshot_mask = syscall_bpf.arg_snapshot_mask;
	rec.retval = retval;
	bumps = 0;
	syscall_bpf.post(&rec);
	free(attr);
	return bumps;
}

/* bpf's post handler judges, pools and closes what came back by the cmd
 * the kernel ran, which chain substitution or a RedQueen pin can rewrite
 * after the sanitiser built the attr for its own: an fd another cmd
 * returned is no object of the built cmd's pool, and a cmd that returns
 * no fd answers 0 or a count, which is no fd of the call's to close.
 * Every call here returns the number of an fd the case holds open. */
static void bpf_cmd_rewritten(void)
{
	static const struct {
		const char *what;
		unsigned int built;
		unsigned int ran;
		unsigned int bumps;
		unsigned int published;
		bool closed;
	} cases[] = {
		{ "a GET_NEXT_ID call run as MAP_CREATE",
		  BPF_PROG_GET_NEXT_ID, BPF_MAP_CREATE, 0, 0, true },
		{ "a BTF_GET_FD_BY_ID call run as MAP_GET_FD_BY_ID",
		  BPF_BTF_GET_FD_BY_ID, BPF_MAP_GET_FD_BY_ID, 0, 0, true },
		{ "an OBJ_GET call run as PROG_STREAM_READ_BY_FD",
		  BPF_OBJ_GET, BPF_PROG_STREAM_READ_BY_FD, 0, 0, false },
		{ "a BTF_GET_FD_BY_ID call", BPF_BTF_GET_FD_BY_ID,
		  BPF_BTF_GET_FD_BY_ID, 0, 1, false },
		{ "an OBJ_GET call", BPF_OBJ_GET, BPF_OBJ_GET, 0, 0, true },
	};
	unsigned int i;

	fake_publish_resource = count_publish;
	for (i = 0; i < ARRAY_SIZE(cases); i++) {
		int fd = open("/dev/null", O_RDONLY);
		bool closed;
		char what[128];

		if (fd < 0)
			BUG("bpf: cannot open an fd to hand back");
		bpf_published = 0;
		snprintf(what, sizeof(what), "bpf, %s", cases[i].what);
		expect(what, bpf_post(cases[i].built, cases[i].ran,
				      (unsigned long) fd),
		       cases[i].bumps);

		closed = fcntl(fd, F_GETFD) == -1 && errno == EBADF;
		if (bpf_published != cases[i].published ||
		    closed != cases[i].closed) {
			fprintf(stderr, "%s: %u published, fd %s\n", what,
				bpf_published, closed ? "closed" : "open");
			failed++;
		}
		if (!closed)
			close(fd);
	}
	fake_publish_resource = NULL;
}
#endif

void post_oracle_self_check(void);
void post_oracle_self_check(void)
{
	/* The pool is made once per process: take it as an earlier suite
	 * left it. */
	if (get_writable_address(sizeof(*out)) == NULL)
		writable_pool_init();
	out = get_writable_address(sizeof(*out));

	get_tsc();
	get_thp_disable();
	prctl_roundtrip();
	setgroups_count();
	futex_hash_ebusy();
	sched_getscheduler_policy();
	recv_count();
	recvmsg_count();
	write_count();
	xattr_size();
	sched_getaffinity_len();
	sched_getaffinity_pid();
	getcpu_spliced();
	capget_target();
	setid_unchanged();
	getgroups_untouched();
	sysv_ctl_untouched();
	get_mempolicy_untouched();
	gettimeofday_compat();
	clock_gettime_compat();
	timer_gettime_compat();
	timerfd_gettime_compat();
	getitimer_compat();
	io_uring_register_rewritten();
	fd_tag_rewritten();
	cut_fd_rewritten();
	sigpending_cases();
	count_rewritten();
	mmsg_count();
#ifdef ARCH_IS_BIARCH
	vmsplice_compat_iovec();
#endif
#ifdef USE_BPF
	bpf_cmd_rewritten();
#endif

	if (failed != 0)
		BUG("a post oracle judged a return value wrongly");
}
