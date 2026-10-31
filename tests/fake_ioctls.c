/*
 * Fake ioctl registry for the tests that link a group from ioctls/.  The
 * groups register themselves at load time; ioctls/ioctls.c stays out of the
 * link, so the registry and the group index are stood in for here, and the
 * opt-out of each group is handed to the efault cache as the real registry
 * hands it.
 */

#include <string.h>

#include "efault_cache.h"	/* ioctl_efault_register_group */
#include "fake_ioctls.h"
#include "ioctls.h"		/* struct ioctl_group */
#include "syscall.h"		/* struct syscallrecord */

#define FAKE_IOCTL_GROUPS_MAX	64

static const struct ioctl_group *groups[FAKE_IOCTL_GROUPS_MAX];
static unsigned int ngroups;

unsigned long fake_ioctl_request;

void register_ioctl_group(const struct ioctl_group *grp)
{
	if (ngroups < FAKE_IOCTL_GROUPS_MAX) {
		ioctl_efault_register_group(grp, ngroups);
		groups[ngroups++] = grp;
	}
}

int ioctl_group_index(const struct ioctl_group *grp)
{
	unsigned int i;

	for (i = 0; i < ngroups; i++)
		if (groups[i] == grp)
			return i;
	return -1;
}

const struct ioctl_group *fake_ioctl_group(const char *name)
{
	unsigned int i;

	for (i = 0; i < ngroups; i++)
		if (groups[i]->name != NULL && strcmp(groups[i]->name, name) == 0)
			return groups[i];
	return NULL;
}

const struct ioctl_group *const *fake_ioctl_groups(unsigned int *n)
{
	*n = ngroups;
	return groups;
}

void pick_random_ioctl(const struct ioctl_group *grp, struct syscallrecord *rec)
{
	(void)grp;
	rec->a2 = fake_ioctl_request;
	rec->a3 = FAKE_IOCTL_JUNK_ARG;
}
