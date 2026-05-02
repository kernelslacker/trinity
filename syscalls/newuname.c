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
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"

static void sanitise_newuname(struct syscallrecord *rec)
{
	avoid_shared_buffer(&rec->a1, sizeof(struct utsname));
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
	struct utsname uts;
	unsigned int i;

	if (!ONE_IN(100))
		return;
	if (rec->retval != 0)
		return;
	if (rec->a1 == 0)
		return;

	/* Local copy defends against a concurrent overwrite of the syscall
	 * output buffer while we're walking it. */
	memcpy(&uts, (void *) rec->a1, sizeof(uts));

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
