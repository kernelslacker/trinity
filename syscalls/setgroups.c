/*
 * SYSCALL_DEFINE2(setgroups, int, gidsetsize, gid_t __user *, grouplist)
 */
#include <grp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include "random.h"
#include "shm.h"
#include "sanitise.h"
#include "trinity.h"

static void sanitise_setgroups(struct syscallrecord *rec)
{
	int count = (int) rec->a1;
	gid_t *list;
	int i;

	if (count <= 0 || count > 65536)
		return;

	list = (gid_t *) get_writable_address(count * sizeof(gid_t));
	for (i = 0; i < count; i++)
		list[i] = (gid_t) rand();

	rec->a2 = (unsigned long) list;
}

static int gid_cmp(const void *a, const void *b)
{
	gid_t ga = *(const gid_t *) a;
	gid_t gb = *(const gid_t *) b;

	return (ga > gb) - (ga < gb);
}

/*
 * Parse the "Groups:" line from /proc/self/status into a freshly
 * malloc'd gid_t array.  Returns 0 on success and stores the array
 * pointer in *out and the entry count in *n_out (caller frees).
 * Returns -1 on any error (file missing, no Groups line, OOM).
 */
static int read_proc_groups(gid_t **out, int *n_out)
{
	FILE *f;
	char *line = NULL;
	size_t cap = 0;
	gid_t *vec = NULL;
	int count = 0, alloc = 0;
	int found = 0;

	f = fopen("/proc/self/status", "r");
	if (!f)
		return -1;

	while (getline(&line, &cap, f) != -1) {
		char *p, *end;

		if (strncmp(line, "Groups:", 7) != 0)
			continue;
		found = 1;
		p = line + 7;
		while (*p == ' ' || *p == '\t')
			p++;

		while (*p && *p != '\n') {
			unsigned long v = strtoul(p, &end, 10);

			if (end == p)
				break;
			if (count == alloc) {
				int newcap = alloc ? alloc * 2 : 16;
				gid_t *nv = realloc(vec, (size_t) newcap *
						    sizeof(gid_t));
				if (!nv) {
					free(vec);
					free(line);
					fclose(f);
					return -1;
				}
				vec = nv;
				alloc = newcap;
			}
			vec[count++] = (gid_t) v;
			p = end;
			while (*p == ' ' || *p == '\t')
				p++;
		}
		break;
	}
	free(line);
	fclose(f);

	if (!found) {
		free(vec);
		return -1;
	}
	*out = vec;
	*n_out = count;
	return 0;
}

/*
 * Oracle: after a successful setgroups(n, list), getgroups must report
 * the same set.  The kernel calls groups_sort() on the supplied list
 * (ascending by gid value) but does not deduplicate, so a sorted copy
 * of the input must memcmp equal to the readback.  Any divergence —
 * wrong count or a missing/extra/permuted gid — means the kernel's
 * stored supplementary group set diverged from what the syscall said
 * it accepted.
 *
 * A second oracle re-reads the supplementary group list via
 * /proc/self/status's "Groups:" line.  getgroups() and the procfs
 * formatter both derive from the same task cred but travel different
 * paths — getgroups() is a thin syscall returning a snapshot of
 * cred->group_info, while procfs walks task_struct via
 * proc_pid_status() and emits each gid through from_kgid_munged() in
 * the reader's user namespace.  A divergence between the two views of
 * the same task's group set is its own corruption shape (e.g. a stale
 * group_info pointer, partial copy_creds(), or a userns munging bug
 * that drops/adds entries) and is structurally distinct from the
 * cred-snapshot mismatch the getgroups oracle catches.
 *
 * Compare both sides as a sorted multiset (the kernel sorts but does
 * not deduplicate) so a benign reordering — or, more importantly, a
 * swap of two entries in storage — does not trip; only an actual
 * drop, addition, or value mismatch counts.
 */
static void post_setgroups(struct syscallrecord *rec)
{
	int n_set, n_get, n_proc = 0;
	gid_t *list_set, *list_get, *sorted, *proc_list = NULL;

	if ((long) rec->retval != 0)
		return;

	n_set = (int) rec->a1;
	if (n_set < 0 || n_set > 65536)
		return;

	list_set = (gid_t *) rec->a2;

	if (ONE_IN(20)) {
		n_get = getgroups(0, NULL);
		if (n_get < 0)
			goto procfs;
		if (n_get != n_set) {
			output(0, "cred oracle: setgroups(%d, ...) succeeded but "
			       "getgroups()=%d\n", n_set, n_get);
			__atomic_add_fetch(&shm->stats.cred_oracle_anomalies, 1,
					   __ATOMIC_RELAXED);
			goto procfs;
		}
		if (n_get == 0)
			goto procfs;
		if (list_set == NULL)
			goto procfs;

		list_get = malloc((size_t) n_get * sizeof(gid_t));
		sorted = malloc((size_t) n_set * sizeof(gid_t));
		if (!list_get || !sorted) {
			free(list_get);
			free(sorted);
			goto procfs;
		}

		if (getgroups(n_get, list_get) == n_get) {
			memcpy(sorted, list_set,
			       (size_t) n_set * sizeof(gid_t));
			qsort(sorted, (size_t) n_set, sizeof(gid_t), gid_cmp);

			if (memcmp(sorted, list_get,
				   (size_t) n_set * sizeof(gid_t)) != 0) {
				output(0, "cred oracle: setgroups(%d, ...) succeeded but "
				       "getgroups() readback differs from sorted input\n",
				       n_set);
				__atomic_add_fetch(&shm->stats.cred_oracle_anomalies,
						   1, __ATOMIC_RELAXED);
			}
		}
		free(list_get);
		free(sorted);
	}

procfs:
	if (!ONE_IN(100))
		return;
	if (n_set > 0 && list_set == NULL)
		return;

	if (read_proc_groups(&proc_list, &n_proc) < 0)
		return;

	if (n_proc != n_set) {
		output(0, "setgroups oracle: setgroups(%d, ...) succeeded but "
		       "/proc/self/status Groups has %d entries\n",
		       n_set, n_proc);
		__atomic_add_fetch(&shm->stats.setgroups_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
		free(proc_list);
		return;
	}

	if (n_set == 0) {
		free(proc_list);
		return;
	}

	sorted = malloc((size_t) n_set * sizeof(gid_t));
	if (!sorted) {
		free(proc_list);
		return;
	}
	memcpy(sorted, list_set, (size_t) n_set * sizeof(gid_t));
	qsort(sorted, (size_t) n_set, sizeof(gid_t), gid_cmp);
	qsort(proc_list, (size_t) n_proc, sizeof(gid_t), gid_cmp);

	if (memcmp(sorted, proc_list, (size_t) n_set * sizeof(gid_t)) != 0) {
		output(0, "setgroups oracle: setgroups(%d, ...) succeeded but "
		       "/proc/self/status Groups list differs from sorted input\n",
		       n_set);
		__atomic_add_fetch(&shm->stats.setgroups_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

	free(sorted);
	free(proc_list);
}

struct syscallentry syscall_setgroups = {
	.name = "setgroups",
	.num_args = 2,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_ADDRESS },
	.argname = { [0] = "gidsetsize", [1] = "grouplist" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65536,
	.sanitise = sanitise_setgroups,
	.post = post_setgroups,
	.group = GROUP_PROCESS,
};


/*
 * SYSCALL_DEFINE2(getgroups16, int, gidsetsize, old_gid_t __user *, grouplist)
 */

struct syscallentry syscall_setgroups16 = {
	.name = "setgroups16",
	.num_args = 2,
	.argtype = { [0] = ARG_RANGE, [1] = ARG_ADDRESS },
	.argname = { [0] = "gidsetsize", [1] = "grouplist" },
	.arg_params[0].range.low = 0,
	.arg_params[0].range.hi = 65536,
	.group = GROUP_PROCESS,
};
