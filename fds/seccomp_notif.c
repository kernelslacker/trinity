/* seccomp notification FDs */

#ifdef USE_SECCOMP

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <linux/filter.h>
#include <linux/seccomp.h>

#include "fd.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "compat.h"
#include "trinity.h"
#include "utils.h"

#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER 1
#endif
#ifndef SECCOMP_FILTER_FLAG_NEW_LISTENER
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#endif
#ifndef SECCOMP_RET_USER_NOTIF
#define SECCOMP_RET_USER_NOTIF 0x7fc00000U
#endif
#ifndef SECCOMP_RET_ALLOW
#define SECCOMP_RET_ALLOW 0x7fff0000U
#endif

static void seccomp_notif_destructor(struct object *obj)
{
	close(obj->seccomp_notifobj.fd);
}

/*
 * Cross-process safe: only reads obj->seccomp_notifobj.fd (now in shm
 * via alloc_shared_obj) and the scope scalar.  No process-local
 * pointers are dereferenced, so it is correct to call this from a
 * different process than the one that allocated the obj — which
 * matters because head->dump runs from dump_childdata() in the
 * parent's crash diagnostics path even when a child triggered the
 * crash.
 */
static void seccomp_notif_dump(struct object *obj, enum obj_scope scope)
{
	output(2, "seccomp_notif fd:%d scope:%d\n",
		obj->seccomp_notifobj.fd, scope);
}

/*
 * Build a minimal BPF program that returns SECCOMP_RET_USER_NOTIF for
 * getpid() and SECCOMP_RET_ALLOW for everything else.  This gives us
 * a notification fd without interfering with normal operation.
 */
static int create_seccomp_notif_fd(void)
{
	struct sock_filter filter[] = {
		/* A = syscall number */
		BPF_STMT(BPF_LD | BPF_W | BPF_ABS,
			 offsetof(struct seccomp_data, nr)),
		/* if (A == __NR_getpid) goto notify */
		BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_getpid, 0, 1),
		/* notify: return USER_NOTIF */
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_USER_NOTIF),
		/* allow: return ALLOW */
		BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
	};
	struct sock_fprog prog = {
		.len = (unsigned short)(sizeof(filter) / sizeof(filter[0])),
		.filter = filter,
	};

	return syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER,
		       SECCOMP_FILTER_FLAG_NEW_LISTENER, &prog);
}

static int open_seccomp_notif(void)
{
	struct object *obj;
	int fd;

	fd = create_seccomp_notif_fd();
	if (fd < 0) {
		outputerr("open_seccomp_notif: seccomp(SET_MODE_FILTER, NEW_LISTENER) failed: %s\n",
			strerror(errno));
		return false;
	}

	obj = alloc_shared_obj(sizeof(struct object));
	if (obj == NULL) {
		outputerr("open_seccomp_notif: alloc_shared_obj failed\n");
		close(fd);
		return false;
	}
	obj->seccomp_notifobj.fd = fd;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_SECCOMP_NOTIF);
	return true;
}

static int init_seccomp_notif_fds(void)
{
	struct objhead *head;
	int ret = false;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_SECCOMP_NOTIF);
	head->destroy = &seccomp_notif_destructor;
	head->dump = &seccomp_notif_dump;
	/*
	 * Opt this provider into the shared obj heap.  __destroy_object()
	 * checks this flag to route the obj struct release through
	 * free_shared_obj() instead of free().  seccomp_notifobj is {int fd;}
	 * with no pointer members, so this is a mechanical conversion that
	 * matches the pidfd template exactly.
	 */
	head->shared_alloc = true;

	/* Create a small pool.  Each call installs a new seccomp filter,
	 * so don't go overboard. */
	if (open_seccomp_notif())
		ret = true;
	if (open_seccomp_notif())
		ret = true;

	return ret;
}

static int get_rand_seccomp_notif_fd(void)
{
	struct object *obj;

	if (objects_empty(OBJ_FD_SECCOMP_NOTIF) == true)
		return -1;

	obj = get_random_object(OBJ_FD_SECCOMP_NOTIF, OBJ_GLOBAL);
	if (obj == NULL)
		return -1;
	return obj->seccomp_notifobj.fd;
}

static const struct fd_provider seccomp_notif_fd_provider = {
	.name = "seccomp-notif",
	.objtype = OBJ_FD_SECCOMP_NOTIF,
	.enabled = true,
	.init = &init_seccomp_notif_fds,
	.get = &get_rand_seccomp_notif_fd,
	.open = &open_seccomp_notif,
};

REG_FD_PROV(seccomp_notif_fd_provider);

#endif /* USE_SECCOMP */
