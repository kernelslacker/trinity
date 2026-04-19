/*
 * SYSCALL_DEFINE2(setgroups, int, gidsetsize, gid_t __user *, grouplist)
 */
#include <grp.h>
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
 * Oracle: after a successful setgroups(n, list), getgroups must report
 * the same set.  The kernel calls groups_sort() on the supplied list
 * (ascending by gid value) but does not deduplicate, so a sorted copy
 * of the input must memcmp equal to the readback.  Any divergence —
 * wrong count or a missing/extra/permuted gid — means the kernel's
 * stored supplementary group set diverged from what the syscall said
 * it accepted.
 */
static void post_setgroups(struct syscallrecord *rec)
{
	int n_set, n_get;
	gid_t *list_set, *list_get, *sorted;

	if ((long) rec->retval != 0)
		return;
	if (!ONE_IN(20))
		return;

	n_set = (int) rec->a1;
	if (n_set < 0 || n_set > 65536)
		return;

	n_get = getgroups(0, NULL);
	if (n_get < 0)
		return;
	if (n_get != n_set) {
		output(0, "cred oracle: setgroups(%d, ...) succeeded but "
		       "getgroups()=%d\n", n_set, n_get);
		__atomic_add_fetch(&shm->stats.cred_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
		return;
	}
	if (n_get == 0)
		return;

	list_set = (gid_t *) rec->a2;
	if (list_set == NULL)
		return;

	list_get = malloc((size_t) n_get * sizeof(gid_t));
	sorted = malloc((size_t) n_set * sizeof(gid_t));
	if (!list_get || !sorted)
		goto out;

	if (getgroups(n_get, list_get) != n_get)
		goto out;

	memcpy(sorted, list_set, (size_t) n_set * sizeof(gid_t));
	qsort(sorted, (size_t) n_set, sizeof(gid_t), gid_cmp);

	if (memcmp(sorted, list_get, (size_t) n_set * sizeof(gid_t)) != 0) {
		output(0, "cred oracle: setgroups(%d, ...) succeeded but "
		       "getgroups() readback differs from sorted input\n",
		       n_set);
		__atomic_add_fetch(&shm->stats.cred_oracle_anomalies, 1,
				   __ATOMIC_RELAXED);
	}

out:
	free(list_get);
	free(sorted);
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
