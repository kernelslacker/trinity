#pragma once

#include <sys/ioctl.h>		/* _IOC_SIZE for IOCTL_SIZE_ASSERT() */
#include <sys/stat.h>
#include "syscall.h"

struct ioctl {
	const char *name;
	unsigned int request;
};

#define DEV_CHAR  1
#define DEV_BLOCK 2
#define DEV_MISC  3

#define IOCTL_GROUPS_MAX 64

struct ioctl_group {
	/* optional user visible string that describes this group of ioctl
	 * operations. */
	const char *name;

	/* Non-NULL sanitise routine for this ioctl group. Initialize to
	 * "pick_random_ioctl" to pick one random ioctl. */
	void (*sanitise)(const struct ioctl_group *, struct syscallrecord *rec);

	/* Plug the available ioctls here. */
	const struct ioctl *ioctls;
	size_t ioctls_cnt;

	/* One of the DEV_* constants. */
	int devtype;

	/* List the device names from /proc/devices or /proc/misc that these
	 * ioctl operations are valid for. */
	const char *const *devs;
	size_t devs_cnt;

	/* Optional routine that should return 0 if the file descriptor is
	 * valid for this group. */
	int (*fd_test)(int fd, const struct stat *);

	/* Typed-fd class of the fds fd_test claims, or ARG_UNDEFINED.  A
	 * group that names one, and has an fd_test, can be drawn before the
	 * fd, and the fd then comes from get_typed_fd() (see
	 * sanitise_ioctl()).  That lookup serves the parent's fds only, but
	 * the fd pick also hands ioctl() the child's own recent returns,
	 * which sit in its local pool, so the fd_test claims those too. */
	enum argtype fd_class;

	/* The group's sanitiser builds valid args only for the cmds it means
	 * to see work, and some cmds must never get them: a box-safety list,
	 * a cmd its table leaves out on purpose, a write it fixes up for a
	 * scratch device.  The final cmd is then held to the one it drew
	 * (vet_final_ioctl() in syscalls/ioctl.c), since a cmd pinned or
	 * substituted after it would take args built for another. */
	bool cmd_held;

	/* The group's cmds act on a request before they look at its arg, so
	 * the bogus one the EFAULT probe sends (ioctls/efault_cache.c) does
	 * not stop them, and what they make, a new fd, is one nothing closes.
	 * A group matched by devname is opted out through efault_optout_devs[]
	 * there; one matched by fd_test alone has no devname to list, and sets
	 * this. */
	bool no_efault_probe;
};

void register_ioctl_group(const struct ioctl_group *);

const struct ioctl_group *find_ioctl_group(int fd);

const struct ioctl_group *get_random_ioctl_group(void);

/* Like get_random_ioctl_group(), among the groups that set fd_class and
 * have an fd_test. */
const struct ioctl_group *get_random_fd_class_ioctl_group(void);

void pick_random_ioctl(const struct ioctl_group *, struct syscallrecord *rec);

/* Whether @cmd, as the kernel reads it, is one of the pidfs namespace
 * getters: the cmds whose return value is the nsfd they made. */
bool pidfd_ns_getter(unsigned long cmd);

/* Whether @cmd, as the kernel reads it, is one of the nsfs requests whose
 * return value is the nsfd they made. */
bool nsfs_getter(unsigned long cmd);

/* Whether @fd is a file on nsfs, which is what a namespace getter makes.
 * statfs()'s answer: a namespace file is a regular file with no size, like
 * many others, and nothing else tells them apart. */
bool fd_is_nsfs(int fd);

void dump_ioctls(void);

#define IOCTL(_request) \
	{ .request = _request, .name = #_request, }

#define IOCTL_SIZE_ASSERT(cmd, type) \
	_Static_assert(sizeof(type) == _IOC_SIZE(cmd), \
		       #type " size vs " #cmd " _IOC_SIZE mismatch")

#define REG_IOCTL_GROUP(_struct) \
	static void __attribute__((constructor)) register_##_struct(void) { \
		register_ioctl_group(&_struct); \
	}

