/*
 * SYSCALL_DEFINE1(sysctl, struct __sysctl_args __user *, args
 *
 * Deprecated since Linux 2.6, but still exercises kernel code paths.
 */
#include <stddef.h>
#include <string.h>
#include "random.h"
#include "sanitise.h"

/* Define locally to avoid linux/sysctl.h glibc conflicts. */
struct __sysctl_args_local {
	int *name;
	int nlen;
	void *oldval;
	size_t *oldlenp;
	void *newval;
	size_t newlen;
	unsigned long __unused[4];
};

#define CTL_KERN 1
#define CTL_VM   2
#define CTL_NET  3
#define CTL_FS   5

#define KERN_OSTYPE    1
#define KERN_OSRELEASE 2
#define KERN_VERSION   4

static void sanitise_sysctl(struct syscallrecord *rec)
{
	struct __sysctl_args_local *sa;
	int *name;
	size_t *oldlenp;
	char *oldval;

	sa = (struct __sysctl_args_local *) get_writable_address(sizeof(*sa));
	memset(sa, 0, sizeof(*sa));

	/* sysctl name is an int array path, e.g. {CTL_KERN, KERN_OSTYPE} */
	name = (int *) get_writable_address(4 * sizeof(int));
	switch (rand() % 4) {
	case 0:	/* kern.ostype */
		name[0] = CTL_KERN;
		name[1] = KERN_OSTYPE;
		sa->nlen = 2;
		break;
	case 1:	/* kern.osrelease */
		name[0] = CTL_KERN;
		name[1] = KERN_OSRELEASE;
		sa->nlen = 2;
		break;
	case 2:	/* kern.version */
		name[0] = CTL_KERN;
		name[1] = KERN_VERSION;
		sa->nlen = 2;
		break;
	default: /* random path */
		name[0] = 1 + (rand() % 7);
		name[1] = 1 + (rand() % 32);
		sa->nlen = 2;
		break;
	}
	sa->name = name;

	/* Provide a read buffer. */
	oldval = (char *) get_writable_address(256);
	oldlenp = (size_t *) get_writable_address(sizeof(*oldlenp));
	*oldlenp = 256;

	sa->oldval = oldval;
	sa->oldlenp = oldlenp;

	rec->a1 = (unsigned long) sa;
}

struct syscallentry syscall_sysctl = {
	.name = "sysctl",
	.num_args = 1,
	.argname = { [0] = "args" },
	.group = GROUP_VFS,
	.sanitise = sanitise_sysctl,
};
