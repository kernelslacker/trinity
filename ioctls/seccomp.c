#ifdef USE_SECCOMP

#include <linux/ioctl.h>
#include <linux/seccomp.h>
#include <string.h>

#include "fd.h"
#include "ioctls.h"
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "utils.h"

#include "kernel/seccomp.h"

/*
 * Compile-time: the two SECCOMP_IOCTL_NOTIF_* commands this file
 * fills with a fixed-shape struct -- NOTIF_SEND (struct
 * seccomp_notif_resp) and NOTIF_ADDFD (struct seccomp_notif_addfd)
 * -- must have sizeof(struct) matching the _IOC_SIZE the request
 * encodes.  Pin the pairing at build time so a <linux/seccomp.h>
 * change that grows or shrinks either struct hard-fails the
 * compile rather than silently having the kernel copy_from_user()
 * a different number of bytes than the sanitiser prepared.
 *
 * SECCOMP_IOCTL_NOTIF_ID_VALID and SECCOMP_IOCTL_NOTIF_SET_FLAGS
 * take a bare __u64; SECCOMP_IOCTL_NOTIF_RECV takes struct
 * seccomp_notif but the sanitiser here does not build one -- the
 * kernel writes the struct out to userspace on RECV.  Asserting
 * sizeof(struct) against a scalar, or against a struct this file
 * never fills, would be the wrong shape of check.
 */
IOCTL_SIZE_ASSERT(SECCOMP_IOCTL_NOTIF_SEND, struct seccomp_notif_resp);
IOCTL_SIZE_ASSERT(SECCOMP_IOCTL_NOTIF_ADDFD, struct seccomp_notif_addfd);

/*
 * Seccomp notification listener ioctls.  These operate on the anonymous fd
 * returned by seccomp(SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, ...).
 *
 * The fd_test matches against fds registered by the seccomp_notif fd provider,
 * so ioctl fuzzing is directed at the right file descriptors.
 */
static int seccomp_notif_fd_test(int fd, const struct stat *st __attribute__((unused)))
{
	struct objhead *head;
	struct object *obj;
	unsigned int idx;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_SECCOMP_NOTIF);

	for_each_obj(head, obj, idx) {
		if (obj->seccomp_notifobj.fd == fd)
			return 0;
	}

	return -1;
}

static const struct ioctl seccomp_notif_ioctls[] = {
	IOCTL(SECCOMP_IOCTL_NOTIF_RECV),
	IOCTL(SECCOMP_IOCTL_NOTIF_SEND),
	IOCTL(SECCOMP_IOCTL_NOTIF_ID_VALID),
	IOCTL(SECCOMP_IOCTL_NOTIF_ADDFD),
	IOCTL(SECCOMP_IOCTL_NOTIF_SET_FLAGS),
};

/*
 * Seed the cookie-gated NOTIF commands with a fresh random 64-bit id.
 *
 * SECCOMP_IOCTL_NOTIF_SEND, NOTIF_ADDFD, and NOTIF_ID_VALID all gate on
 * an id (cookie) drawn from struct seccomp_notif handed back by
 * NOTIF_RECV.  Trinity does not service the listener fd, so it never
 * holds a real cookie.  Letting pick_random_ioctl install the default
 * random arg leaves the kernel rejecting at the copy_from_user / size
 * check on a malformed struct, and any id read out lives in unrelated
 * scratch memory -- the id-lookup path under the filter's notify mutex
 * (seccomp_notify_find / id matching) is never reached.
 *
 * Allocate the correctly-sized struct for the cmd, zero it, and stamp a
 * fresh random id (plus randomised tail fields, so flag-validation and
 * fd-installation edges in the SEND / ADDFD handlers also get exercised).
 * The expected outcome is mostly -ENOENT; the point is that the dispatch
 * + lookup path actually runs.
 */
static void seccomp_notif_sanitise(const struct ioctl_group *grp,
				   struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case SECCOMP_IOCTL_NOTIF_SEND: {
		struct seccomp_notif_resp *resp;

		resp = (struct seccomp_notif_resp *) get_writable_struct(sizeof(*resp));
		if (!resp)
			break;
		memset(resp, 0, sizeof(*resp));
		resp->id = rnd_u64();
		resp->val = (__s64) rnd_u64();
		resp->error = (__s32) rnd_u32();
		resp->flags = rnd_u32();
		rec->a3 = (unsigned long) resp;
		break;
	}
	case SECCOMP_IOCTL_NOTIF_ADDFD: {
		struct seccomp_notif_addfd *afd;

		afd = (struct seccomp_notif_addfd *) get_writable_struct(sizeof(*afd));
		if (!afd)
			break;
		memset(afd, 0, sizeof(*afd));
		afd->id = rnd_u64();
		afd->flags = rnd_u32();
		afd->srcfd = (__u32) get_random_fd();
		afd->newfd = rnd_u32();
		afd->newfd_flags = rnd_u32();
		rec->a3 = (unsigned long) afd;
		break;
	}
	case SECCOMP_IOCTL_NOTIF_ID_VALID: {
		__u64 *id;

		id = (__u64 *) get_writable_struct(sizeof(*id));
		if (!id)
			break;
		*id = rnd_u64();
		rec->a3 = (unsigned long) id;
		break;
	}
	default:
		break;
	}
}

static const struct ioctl_group seccomp_notif_grp = {
	.name = "seccomp-notif",
	.fd_test = seccomp_notif_fd_test,
	.sanitise = seccomp_notif_sanitise,
	.ioctls = seccomp_notif_ioctls,
	.ioctls_cnt = ARRAY_SIZE(seccomp_notif_ioctls),
};

REG_IOCTL_GROUP(seccomp_notif_grp)

#endif /* USE_SECCOMP */
