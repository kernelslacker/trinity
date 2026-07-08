#include <stdint.h>
#include <unistd.h>
#include "child.h"
#include "compiler.h"
#include "objects.h"
#include "objects-internal.h"
#include "syscall.h"
#include "utils.h"

/*
 * Invalidate the fd stored in an object by setting it to -1.
 * Used before calling the destructor when the fd was already closed
 * (e.g. after a successful close() syscall) to prevent double-close.
 * The destructor's close(-1) call will harmlessly return EBADF.
 */
void invalidate_object_fd(struct object *obj, enum objecttype type)
{
	switch (type) {
	case OBJ_FD_PIPE:	obj->pipeobj.fd = -1; break;
	case OBJ_FD_DEVFILE:	obj->fileobj.fd = -1; break;
	case OBJ_FD_DEV_TEMPLATE: obj->fileobj.fd = -1; break;
	case OBJ_FD_PROCFILE:	obj->fileobj.fd = -1; break;
	case OBJ_FD_SYSFILE:	obj->fileobj.fd = -1; break;
	case OBJ_FD_PERF:	obj->perfobj.fd = -1; break;
	case OBJ_FD_EPOLL:	obj->epollobj.fd = -1; break;
	case OBJ_FD_EVENTFD:	obj->eventfdobj.fd = -1; break;
	case OBJ_FD_TIMERFD:	obj->timerfdobj.fd = -1; break;
	case OBJ_FD_TESTFILE:	obj->testfileobj.fd = -1; break;
	case OBJ_FD_MEMFD:	obj->memfdobj.fd = -1; break;
	case OBJ_FD_MEMFD_SECRET: obj->memfd_secretobj.fd = -1; break;
	case OBJ_FD_DRM:	obj->drmfd = -1; break;
	case OBJ_FD_INOTIFY:	obj->inotifyobj.fd = -1; break;
	case OBJ_FD_SOCKET:	obj->sockinfo.fd = -1; break;
	case OBJ_FD_USERFAULTFD: obj->userfaultobj.fd = -1; break;
	case OBJ_FD_FANOTIFY:	obj->fanotifyobj.fd = -1; break;
	case OBJ_FD_BPF_MAP:	obj->bpfobj.map_fd = -1; break;
	case OBJ_FD_BPF_PROG:	obj->bpfprogobj.fd = -1; break;
	case OBJ_FD_BPF_LINK:	obj->bpflinkobj.fd = -1; break;
	case OBJ_FD_BPF_BTF:	obj->bpfbtfobj.fd = -1; break;
	case OBJ_FD_BPF_TOKEN:	obj->bpftokenobj.fd = -1; break;
	case OBJ_FD_IO_URING:	obj->io_uringobj.fd = -1; break;
	case OBJ_FD_LANDLOCK:	obj->landlockobj.fd = -1; break;
	case OBJ_FD_PIDFD:	obj->pidfdobj.fd = -1; break;
	case OBJ_FD_MQ:		obj->mqobj.fd = -1; break;
	case OBJ_FD_SPARSE_FILE: obj->sparsefileobj.fd = -1; break;
	case OBJ_FD_SECCOMP_NOTIF: obj->seccomp_notifobj.fd = -1; break;
	case OBJ_FD_IOMMUFD:	obj->iommufdobj.fd = -1; break;
	case OBJ_FD_FS_CTX:	obj->fsctxobj.fd = -1; break;
	case OBJ_FD_KVM_SYSTEM:	obj->kvmsysobj.fd = -1; break;
	case OBJ_FD_KVM_VM:	obj->kvmvmobj.fd = -1; break;
	case OBJ_FD_KVM_VCPU:	obj->kvmvcpuobj.fd = -1; break;
	case OBJ_FD_PAGECACHE:	obj->fileobj.fd = -1; break;
	case OBJ_FD_WRITEABLE_PAGECACHE: obj->fileobj.fd = -1; break;
	case OBJ_FD_CANARY:	obj->fileobj.fd = -1; break;
	case OBJ_FD_SIGNALFD:	obj->signalfdobj.fd = -1; break;
	case OBJ_FD_MOUNT:	obj->mountfdobj.fd = -1; break;
	case OBJ_FD_CGROUP:	obj->cgroupfdobj.fd = -1; break;
	case OBJ_FD_WATCH_QUEUE: obj->watch_queueobj.fd = -1; break;
	case OBJ_FD_SCRATCH_BLOCK: obj->fileobj.fd = -1; break;
	default:		break;
	}
}

/*
 * Store an fd into the appropriate union field for this object type.
 * The inverse of fd_from_object(); used by the generic post-hook that
 * registers fds returned by RET_FD syscalls without a custom handler.
 */
void set_object_fd(struct object *obj, enum objecttype type, int fd)
{
	switch (type) {
	case OBJ_FD_PIPE:	obj->pipeobj.fd = fd; break;
	case OBJ_FD_DEVFILE:
	case OBJ_FD_DEV_TEMPLATE:
	case OBJ_FD_PROCFILE:
	case OBJ_FD_SYSFILE:
	case OBJ_FD_PAGECACHE:
	case OBJ_FD_WRITEABLE_PAGECACHE:
	case OBJ_FD_SCRATCH_BLOCK:
	case OBJ_FD_CANARY:	obj->fileobj.fd = fd; break;
	case OBJ_FD_PERF:	obj->perfobj.fd = fd; break;
	case OBJ_FD_EPOLL:	obj->epollobj.fd = fd; break;
	case OBJ_FD_EVENTFD:	obj->eventfdobj.fd = fd; break;
	case OBJ_FD_TIMERFD:	obj->timerfdobj.fd = fd; break;
	case OBJ_FD_TESTFILE:	obj->testfileobj.fd = fd; break;
	case OBJ_FD_MEMFD:	obj->memfdobj.fd = fd; break;
	case OBJ_FD_MEMFD_SECRET: obj->memfd_secretobj.fd = fd; break;
	case OBJ_FD_DRM:	obj->drmfd = fd; break;
	case OBJ_FD_INOTIFY:	obj->inotifyobj.fd = fd; break;
	case OBJ_FD_SOCKET:	obj->sockinfo.fd = fd; break;
	case OBJ_FD_USERFAULTFD: obj->userfaultobj.fd = fd; break;
	case OBJ_FD_FANOTIFY:	obj->fanotifyobj.fd = fd; break;
	case OBJ_FD_BPF_MAP:	obj->bpfobj.map_fd = fd; break;
	case OBJ_FD_BPF_PROG:	obj->bpfprogobj.fd = fd; break;
	case OBJ_FD_BPF_LINK:	obj->bpflinkobj.fd = fd; break;
	case OBJ_FD_BPF_BTF:	obj->bpfbtfobj.fd = fd; break;
	case OBJ_FD_BPF_TOKEN:	obj->bpftokenobj.fd = fd; break;
	case OBJ_FD_IO_URING:	obj->io_uringobj.fd = fd; break;
	case OBJ_FD_LANDLOCK:	obj->landlockobj.fd = fd; break;
	case OBJ_FD_PIDFD:	obj->pidfdobj.fd = fd; break;
	case OBJ_FD_MQ:		obj->mqobj.fd = fd; break;
	case OBJ_FD_SPARSE_FILE: obj->sparsefileobj.fd = fd; break;
	case OBJ_FD_SECCOMP_NOTIF: obj->seccomp_notifobj.fd = fd; break;
	case OBJ_FD_IOMMUFD:	obj->iommufdobj.fd = fd; break;
	case OBJ_FD_FS_CTX:	obj->fsctxobj.fd = fd; break;
	case OBJ_FD_KVM_SYSTEM:	obj->kvmsysobj.fd = fd; break;
	case OBJ_FD_KVM_VM:	obj->kvmvmobj.fd = fd; break;
	case OBJ_FD_KVM_VCPU:	obj->kvmvcpuobj.fd = fd; break;
	case OBJ_FD_SIGNALFD:	obj->signalfdobj.fd = fd; break;
	case OBJ_FD_MOUNT:	obj->mountfdobj.fd = fd; break;
	case OBJ_FD_CGROUP:	obj->cgroupfdobj.fd = fd; break;
	case OBJ_FD_WATCH_QUEUE: obj->watch_queueobj.fd = fd; break;
	default:		break;
	}
}

/*
 * Extract the fd from an object, given its type.
 * Returns -1 for non-fd object types.
 */
int fd_from_object(struct object *obj, enum objecttype type)
{
	/*
	 * Attribution overlay for the SELF-corruption cluster.  A sibling
	 * scribble that lands on an OBJ_LOCAL slot pointer in head->array[]
	 * leaves obj pointing at either a wild low-VA value (NULL-ish /
	 * pid-shaped) or a kernel-VA leak; the switch below then derefs
	 * obj-> and SIGSEGVs the child with the SREC of the innocent fd
	 * consumer (fds/fds.c, objects/registry.c walkers) rather than the
	 * syscall whose arg-gen produced the wild pointer.  Log the current
	 * SREC BEFORE the switch runs so the child bug-log carries a
	 * SELF-CORRUPT line naming the culprit before the SEGV clobbers rec.
	 *
	 * Same [0x10000, 2^47) userspace-VA bracket as the other always-on
	 * gates; matches the value shape zmalloc / zmalloc_tracked hand out
	 * for every real obj alloc, so a false positive is impossible for a
	 * legitimate object.  Log-only: the switch below runs unchanged,
	 * preserving the "NO change to deref behavior" contract of the
	 * attribution overlay.
	 */
	{
		uintptr_t v = (uintptr_t)obj;

		if (unlikely(!(v >= 0x10000UL && v < 0x800000000000UL))) {
			struct childdata *cc = this_child();

			log_self_corrupt_culprit(
				"objects:fd_from_object", v,
				cc != NULL ? &cc->syscall : NULL);
		}
	}

	switch (type) {
	case OBJ_FD_PIPE:	return obj->pipeobj.fd;
	case OBJ_FD_DEVFILE:
	case OBJ_FD_DEV_TEMPLATE:
	case OBJ_FD_PROCFILE:
	case OBJ_FD_SYSFILE:
	case OBJ_FD_PAGECACHE:
	case OBJ_FD_WRITEABLE_PAGECACHE:
	case OBJ_FD_SCRATCH_BLOCK:
	case OBJ_FD_CANARY:	return obj->fileobj.fd;
	case OBJ_FD_PERF:	return obj->perfobj.fd;
	case OBJ_FD_EPOLL:	return obj->epollobj.fd;
	case OBJ_FD_EVENTFD:	return obj->eventfdobj.fd;
	case OBJ_FD_TIMERFD:	return obj->timerfdobj.fd;
	case OBJ_FD_TESTFILE:	return obj->testfileobj.fd;
	case OBJ_FD_MEMFD:	return obj->memfdobj.fd;
	case OBJ_FD_MEMFD_SECRET: return obj->memfd_secretobj.fd;
	case OBJ_FD_DRM:	return obj->drmfd;
	case OBJ_FD_INOTIFY:	return obj->inotifyobj.fd;
	case OBJ_FD_SOCKET:	return obj->sockinfo.fd;
	case OBJ_FD_USERFAULTFD: return obj->userfaultobj.fd;
	case OBJ_FD_FANOTIFY:	return obj->fanotifyobj.fd;
	case OBJ_FD_BPF_MAP:	return obj->bpfobj.map_fd;
	case OBJ_FD_BPF_PROG:	return obj->bpfprogobj.fd;
	case OBJ_FD_BPF_LINK:	return obj->bpflinkobj.fd;
	case OBJ_FD_BPF_BTF:	return obj->bpfbtfobj.fd;
	case OBJ_FD_BPF_TOKEN:	return obj->bpftokenobj.fd;
	case OBJ_FD_IO_URING:	return obj->io_uringobj.fd;
	case OBJ_FD_LANDLOCK:	return obj->landlockobj.fd;
	case OBJ_FD_PIDFD:	return obj->pidfdobj.fd;
	case OBJ_FD_MQ:		return obj->mqobj.fd;
	case OBJ_FD_SPARSE_FILE: return obj->sparsefileobj.fd;
	case OBJ_FD_SECCOMP_NOTIF: return obj->seccomp_notifobj.fd;
	case OBJ_FD_IOMMUFD:	return obj->iommufdobj.fd;
	case OBJ_FD_FS_CTX:	return obj->fsctxobj.fd;
	case OBJ_FD_KVM_SYSTEM:	return obj->kvmsysobj.fd;
	case OBJ_FD_KVM_VM:	return obj->kvmvmobj.fd;
	case OBJ_FD_KVM_VCPU:	return obj->kvmvcpuobj.fd;
	case OBJ_FD_SIGNALFD:	return obj->signalfdobj.fd;
	case OBJ_FD_MOUNT:	return obj->mountfdobj.fd;
	case OBJ_FD_CGROUP:	return obj->cgroupfdobj.fd;
	case OBJ_FD_WATCH_QUEUE: return obj->watch_queueobj.fd;
	default:		return -1;
	}
}
