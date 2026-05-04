/*
 *
 * SYSCALL_DEFINE1(newuname, struct new_utsname __user *, name)
 */
#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <linux/utsname.h>
#include "deferred-free.h"
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"
#include "utils.h"

/*
 * Snapshot of the one newuname input arg read by the post oracle,
 * captured at sanitise time and consumed by the post handler.  Lives in
 * rec->post_state, a slot the syscall ABI does not expose, so a sibling
 * syscall scribbling rec->aN between the syscall returning and the post
 * handler running cannot redirect the procfs cross-check at a foreign
 * struct utsname user buffer.
 */
struct newuname_post_state {
	unsigned long name;
};

static void sanitise_newuname(struct syscallrecord *rec)
{
	struct newuname_post_state *snap;

	/*
	 * Clear post_state up front so an early return below leaves the
	 * post handler with a NULL snapshot to bail on rather than a stale
	 * pointer carried over from an earlier syscall on this record.
	 */
	rec->post_state = 0;

	avoid_shared_buffer(&rec->a1, sizeof(struct utsname));

	/*
	 * Snapshot the one input arg for the post oracle.  Without this
	 * the post handler reads rec->a1 at post-time, when a sibling
	 * syscall may have scribbled the slot: looks_like_corrupted_ptr()
	 * cannot tell a real-but-wrong heap address from the original name
	 * user-buffer pointer, so the source memcpy would touch a foreign
	 * allocation that the guard never inspected.  post_state is private
	 * to the post handler.
	 */
	snap = zmalloc(sizeof(*snap));
	snap->name = rec->a1;
	rec->post_state = (unsigned long) snap;
}

static int read_kernel_string(const char *path, char *out, size_t outsz)
{
	FILE *fp;
	size_t len;

	fp = fopen(path, "r");
	if (!fp)
		return -1;
	if (!fgets(out, outsz, fp)) {
		fclose(fp);
		return -1;
	}
	fclose(fp);

	len = strlen(out);
	while (len > 0 && (out[len - 1] == '\n' || out[len - 1] == '\r' ||
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
	struct newuname_post_state *snap =
		(struct newuname_post_state *) rec->post_state;
	struct utsname uts;
	unsigned int i;

	if (snap == NULL)
		return;

	/*
	 * post_state is private to the post handler, but the whole
	 * syscallrecord can still be wholesale-stomped, so guard the
	 * snapshot pointer before dereferencing it.
	 */
	if (looks_like_corrupted_ptr(snap)) {
		outputerr("post_newuname: rejected suspicious post_state=%p (pid-scribbled?)\n",
			  snap);
		__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
		rec->post_state = 0;
		return;
	}

	if (!ONE_IN(100))
		goto out_free;
	if (rec->retval != 0)
		goto out_free;
	if (snap->name == 0)
		goto out_free;

	{
		void *name = (void *)(unsigned long) snap->name;

		/*
		 * Defense in depth: even with the post_state snapshot, a
		 * wholesale stomp could rewrite the snapshot's inner name
		 * field.  Reject pid-scribbled name before deref.
		 */
		if (looks_like_corrupted_ptr(name)) {
			outputerr("post_newuname: rejected suspicious name=%p (post_state-scribbled?)\n",
				  name);
			__atomic_add_fetch(&shm->stats.post_handler_corrupt_ptr, 1, __ATOMIC_RELAXED);
			goto out_free;
		}
	}

	/* Local copy defends against a concurrent overwrite of the syscall
	 * output buffer while we're walking it. */
	memcpy(&uts, (void *)(unsigned long) snap->name, sizeof(uts));

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
			__atomic_add_fetch(&shm->stats.newuname_oracle_anomalies,
					   1, __ATOMIC_RELAXED);
		}
	}

out_free:
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_newuname = {
	.name = "newuname",
	.num_args = 1,
	.argtype = { [0] = ARG_NON_NULL_ADDRESS },
	.argname = { [0] = "name" },
	.sanitise = sanitise_newuname,
	.post = post_newuname,
	.group = GROUP_PROCESS,
};
