/*
 * Self-check for what the bpf() sanitisers and the eBPF program generator
 * hand the kernel: each case holds one of them to a fact about the kernel's
 * handling of the call.  The pickers the sanitisers draw their fds from are
 * the fakes in fake_fds.c, and no call reaches the kernel.
 */

#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bpf.h"
#include "debug.h"		/* BUG */
#include "syscall.h"		/* struct syscallrecord */
#include "syscalls/syscalls.h"	/* syscall_bpf */

#ifdef USE_BPF_PROG_STREAM_OPEN
static unsigned int failed;

static void check(const char *what, const char *case_name, bool ok)
{
	if (ok)
		return;
	fprintf(stderr, "bpf gen: %s: %s\n", case_name, what);
	failed++;
}

/*
 * prog_stream_open() refuses a call whose attr has a byte set past flags
 * (CHECK_ATTR), bpf_stream_get() serves only the stdout and stderr ids, and
 * the kernel takes no flag but BPF_F_STREAM_NONBLOCK.  Most calls are meant
 * to pass all three, and some of each kind are not, to reach the ENOENT and
 * EINVAL returns; of the opens that pass, some leave the stream fd blocking.
 */
static void stream_open_draws_mostly_valid_calls(void)
{
	enum { ROUNDS = 4000 };
	static struct syscallrecord rec;
	unsigned int good_id = 0, bad_id = 0, good_flags = 0, bad_flags = 0;
	unsigned int stdout_ids = 0, stderr_ids = 0, blocking = 0, round;
	const union bpf_attr *attr;
	const unsigned char *raw;
	size_t i;

	for (round = 0; round < ROUNDS; round++) {
		memset(&rec, 0, sizeof(rec));
		rec.a1 = BPF_PROG_STREAM_OPEN;
		syscall_bpf.sanitise(&rec);
		attr = (const union bpf_attr *) rec.a2;
		raw = (const unsigned char *) attr;

		check("the size is not the three fields", "stream open",
		      rec.a3 == sizeof(attr->prog_stream_open));
		check("the call does not return an fd", "stream open",
		      rec.rettype == RET_FD);
		for (i = rec.a3; i < sizeof(union bpf_attr); i++) {
			if (raw[i] == 0)
				continue;
			check("a byte past flags is set", "stream open", false);
			break;
		}

		if (attr->prog_stream_open.stream_id == BPF_STREAM_STDOUT) {
			good_id++;
			stdout_ids++;
		} else if (attr->prog_stream_open.stream_id == BPF_STREAM_STDERR) {
			good_id++;
			stderr_ids++;
		} else {
			bad_id++;
		}

		if (attr->prog_stream_open.flags == 0) {
			good_flags++;
			blocking++;
		} else if (attr->prog_stream_open.flags == BPF_F_STREAM_NONBLOCK) {
			good_flags++;
		} else {
			bad_flags++;
		}

		/* Releases the snapshot, as the dispatcher does.  Deferred
		 * free refuses the attr, which the fake allocator never
		 * tracked, so it is freed here. */
		rec.retval = (unsigned long) -1L;
		rec.errno_post = ENOENT;
		syscall_bpf.post(&rec);
		free((void *) attr);
	}

	check("fewer than 85% of the ids are one the kernel serves",
	      "stream open", good_id * 100 >= ROUNDS * 85);
	check("no id reaches the ENOENT return", "stream open", bad_id > 0);
	check("an id of one stream is never drawn", "stream open",
	      stdout_ids > 0 && stderr_ids > 0);
	check("fewer than 85% of the flags are one the kernel takes",
	      "stream open", good_flags * 100 >= ROUNDS * 85);
	check("no flags value reaches the EINVAL return", "stream open",
	      bad_flags > 0);
	check("not a tenth to a half of the opens are blocking", "stream open",
	      blocking * 10 >= good_flags && blocking * 2 <= good_flags);
}
#endif /* USE_BPF_PROG_STREAM_OPEN */

void bpf_gen_self_check(void);
void bpf_gen_self_check(void)
{
#ifdef USE_BPF_PROG_STREAM_OPEN
	stream_open_draws_mostly_valid_calls();

	if (failed != 0)
		BUG("a bpf sanitiser or generator drew what the kernel does not take");
#endif
}
