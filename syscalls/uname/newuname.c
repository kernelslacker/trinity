/*
 *
 * SYSCALL_DEFINE1(newuname, struct new_utsname __user *, name)
 */
#include <stddef.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <linux/utsname.h>
#include <fcntl.h>
#include <string.h>
#include "output-poison.h"
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the one newuname input arg plus the poison seed read by
 * the post oracle, captured at sanitise time and consumed by the post
 * handler.  Lives in rec->post_state, a slot the syscall ABI does not
 * expose, so a sibling syscall scribbling rec->aN between the syscall
 * returning and the post handler running cannot redirect the procfs
 * cross-check at a foreign struct utsname user buffer or smear the
 * poison seed against a heap page that happens to still carry a
 * residual pattern from an earlier call.  A poison_seed of 0 means the
 * sanitise-time writability check refused to stamp poison for this
 * call -- the procfs cross-check still runs, the poison check does not.
 */
#define NEWUNAME_POST_STATE_MAGIC	0x4E554E4DUL	/* "NUNM" */
struct newuname_post_state {
	unsigned long magic;
	unsigned long name;
	uint64_t poison_seed;
};

static void sanitise_newuname(struct syscallrecord *rec)
{
	struct newuname_post_state *snap;
	void *buf;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	avoid_shared_buffer_out(&rec->a1, sizeof(struct utsname));

	/*
	 * Snapshot the one input arg for the post oracle.  Without this
	 * the post handler reads rec->a1 at post-time, when a sibling
	 * syscall may have scribbled the slot: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original name
	 * user-buffer pointer, so the source memcpy would touch a foreign
	 * allocation that the guard never inspected.  post_state is private
	 * to the post handler.  post_state_install pairs the rec->post_state
	 * assign with the ownership-table register so the observable window
	 * between the two is closed; post_newuname() will then gate the snap
	 * through post_state_claim_owned() and prove ownership before
	 * dereferencing any field.
	 */
	snap = zmalloc_tracked(sizeof(*snap));
	snap->magic = NEWUNAME_POST_STATE_MAGIC;
	snap->name = rec->a1;
	snap->poison_seed = 0;

	/*
	 * Stamp a per-call poison pattern into the output buffer the kernel
	 * is about to fill.  The post handler feeds the seed back into
	 * check_output_struct(); a byte-identical poison after a success
	 * return means the kernel skipped copy_to_user() entirely or short-
	 * copied and left an uninitialised tail readable in user memory (a
	 * kernel->user infoleak).  Done after avoid_shared_buffer_out() so
	 * the poison lands on the final buffer the kernel will see.  Gate
	 * on range_readable_user() so a writable-pool draw that landed on
	 * an address no longer provably mapped -- e.g. a sibling munmap
	 * between allocation and now -- does not SIGSEGV the sanitiser
	 * inside poison_output_struct's byte-walk.  On skip, poison_seed
	 * stays 0 and the post handler no-ops the poison check while the
	 * procfs cross-check oracle still runs against snap->name.
	 */
	buf = (void *)(unsigned long) rec->a1;
	if (range_readable_user(buf, sizeof(struct new_utsname)))
		snap->poison_seed = poison_output_struct(buf,
							 sizeof(struct new_utsname),
							 0);

	post_state_install(rec, snap);
}

static int read_kernel_string(const char *path, char *out, size_t outsz)
{
	ssize_t n;
	size_t len;
	int fd;
	char *nl;

	/* Raw open/read instead of fopen/fgets/fclose: this oracle runs from
	 * the post handler under fuzz; stdio's per-call malloc of the FILE
	 * struct + IO buffer is heap traffic we don't need on this hot path,
	 * and stdio's internal locking is undefined in async-signal contexts
	 * which the child fuzzer is heavily exposed to. */
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	n = read(fd, out, outsz - 1);
	close(fd);
	if (n <= 0)
		return -1;
	out[n] = '\0';

	/* fgets() truncated at the first newline; preserve that semantic so
	 * the downstream strcmp against a single utsname field still matches
	 * if /proc returns more than one line of data. */
	nl = strchr(out, '\n');
	if (nl != NULL)
		*nl = '\0';

	len = strlen(out);
	while (len > 0 && (out[len - 1] == '\r' ||
			   out[len - 1] == ' ' || out[len - 1] == '\t'))
		out[--len] = '\0';
	return 0;
}

/*
 * Oracle: newuname() copies a struct new_utsname out of the calling task's
 * uts_ns->name in a single copy_to_user, while /proc/sys/kernel/{ostype,
 * hostname,osrelease,version,domainname} surface the same five fields via
 * proc_dostring/sysctl_string handlers walking the same uts_ns->name slot.
 * Both views ought to be byte-identical for any given task, but they travel
 * through different code: the syscall is a sys_newuname -> down_read(uts_sem)
 * -> copy_to_user of the whole struct, the procfs path is per-field through
 * proc_do_uts_string()/proc_dostring() with strscpy semantics.  A divergence
 * between the two for the same task is its own corruption shape: a wrong
 * uts_ns lookup, a torn write into a field by a concurrent sethostname/
 * setdomainname, a sysctl_string proc_handler regression, or a
 * neighbour-namespace string leaking into the wrong view.
 *
 * TOCTOU defeat: the one input arg (name) is snapshotted at sanitise time
 * into a heap struct in rec->post_state, so a sibling that scribbles
 * rec->a1 between syscall return and post entry cannot redirect the
 * procfs cross-check at a foreign user buffer.
 */
static void post_newuname(struct syscallrecord *rec)
{
	static const struct {
		const char *path;
		const char *name;
		size_t off;
	} fields[] = {
		{ "/proc/sys/kernel/ostype",     "sysname",    offsetof(struct utsname, sysname)    },
		{ "/proc/sys/kernel/hostname",   "nodename",   offsetof(struct utsname, nodename)   },
		{ "/proc/sys/kernel/osrelease",  "release",    offsetof(struct utsname, release)    },
		{ "/proc/sys/kernel/version",    "version",    offsetof(struct utsname, version)    },
		{ "/proc/sys/kernel/domainname", "domainname", offsetof(struct utsname, domainname) },
	};
	struct newuname_post_state *snap;
	struct utsname uts;
	unsigned int i;

	/*
	 * Canonical SNAPSHOT_OWNED bracket: shape -> ownership -> magic,
	 * in that order.  The helper has already cleared rec->post_state,
	 * emitted any outputerr() diagnostic, and bumped the corruption
	 * counter on failure -- callers just early-return on NULL.
	 */
	snap = post_state_claim_owned(rec, NEWUNAME_POST_STATE_MAGIC,
				      __func__);
	if (snap == NULL)
		return;

	if ((long) rec->retval != 0)
		goto out_release;
	if (snap->name == 0)
		goto out_release;

	/* Local copy defends against a concurrent overwrite of the syscall
	 * output buffer while we're walking it. */
	if (!post_snapshot_or_skip(&uts,
				   (void *)(unsigned long) snap->name,
				   sizeof(uts)))
		goto out_release;

	/*
	 * Untouched-buffer poison check runs on every success sample the
	 * buffer snapshot succeeded on.  poison_seed of 0 means sanitise
	 * chose not to stamp poison (unwritable pointer) -- skip the check
	 * so "we couldn't poison" is not confused with "kernel didn't
	 * write".  Counts against the shared post_handler_untouched_out_buf
	 * slot.  The heavier procfs cross-check below stays gated on
	 * ONE_IN(100) because it opens five procfs paths; this check is a
	 * cheap memcmp with no I/O.
	 *
	 * If the poison survives we also skip the procfs arm: strcmp() on
	 * a field that is entirely poison bytes (no embedded NUL) would
	 * walk past the 65-byte field and, since the whole uts is poison,
	 * past the end of the 390-byte stack copy.  The untouched signal
	 * is already captured in the shared counter; the procfs arm has
	 * nothing meaningful to say about a buffer the kernel did not
	 * write.
	 */
	if (snap->poison_seed != 0 &&
	    check_output_struct(&uts, sizeof(uts), snap->poison_seed)) {
		__atomic_add_fetch(&shm->stats.post_handler_untouched_out_buf,
				   1, __ATOMIC_RELAXED);
		goto out_release;
	}

	if (!ONE_IN(100))
		goto out_release;

	for (i = 0; i < sizeof(fields) / sizeof(fields[0]); i++) {
		char proc_buf[__NEW_UTS_LEN + 1];
		const char *syscall_field = (const char *)&uts + fields[i].off;

		if (read_kernel_string(fields[i].path, proc_buf,
				       sizeof(proc_buf)) != 0)
			continue;

		if (strcmp(proc_buf, syscall_field) != 0) {
			output(0, "newuname oracle: field %s syscall=\"%s\" but %s=\"%s\"\n",
			       fields[i].name, syscall_field,
			       fields[i].path, proc_buf);
			__atomic_add_fetch(&shm->stats.oracle.newuname_oracle_anomalies,
					   1, __ATOMIC_RELAXED);
		}
	}

out_release:
	post_state_release(rec, snap);
}

struct syscallentry syscall_newuname = {
	.name = "newuname",
	.num_args = 1,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "name" },
	.sanitise = sanitise_newuname,
	.post = post_newuname,
	.group = GROUP_PROCESS,
	.rettype = RET_ZERO_SUCCESS,
	.flags = REEXEC_SANITISE_OK,
};
