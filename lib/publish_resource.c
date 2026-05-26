/*
 * publish_resource() — typed object-publish wrapper.
 *
 * See include/publish_resource.h for the rationale and the
 * per-pool field-routing table.
 */

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include "object-types.h"
#include "objects.h"
#include "publish_resource.h"

struct object *publish_resource(enum objecttype type, unsigned long id,
				const struct resource_meta *meta)
{
	static const struct resource_meta zero_meta;
	const struct resource_meta *m = meta ? meta : &zero_meta;
	struct object *obj;

	obj = alloc_object();
	if (obj == NULL)
		return NULL;

	/*
	 * Stamp the type-specific primary handle.  FD pools route
	 * through set_object_fd() so the per-pool union-member
	 * mapping stays in exactly one place (objects.c).  Non-fd
	 * pools each have a one-line typed assignment below — these
	 * are the only id-only OBJ types in the enum and the cost of
	 * stamping them inline is one switch arm each.
	 */
	switch (type) {
	case OBJ_FD_PIPE:
	case OBJ_FD_DEVFILE:
	case OBJ_FD_PROCFILE:
	case OBJ_FD_SYSFILE:
	case OBJ_FD_PERF:
	case OBJ_FD_EPOLL:
	case OBJ_FD_EVENTFD:
	case OBJ_FD_TIMERFD:
	case OBJ_FD_TESTFILE:
	case OBJ_FD_MEMFD:
	case OBJ_FD_MEMFD_SECRET:
	case OBJ_FD_DRM:
	case OBJ_FD_INOTIFY:
	case OBJ_FD_SOCKET:
	case OBJ_FD_USERFAULTFD:
	case OBJ_FD_FANOTIFY:
	case OBJ_FD_BPF_MAP:
	case OBJ_FD_BPF_PROG:
	case OBJ_FD_BPF_LINK:
	case OBJ_FD_BPF_BTF:
	case OBJ_FD_BPF_TOKEN:
	case OBJ_FD_IO_URING:
	case OBJ_FD_LANDLOCK:
	case OBJ_FD_PIDFD:
	case OBJ_FD_MQ:
	case OBJ_FD_SECCOMP_NOTIF:
	case OBJ_FD_IOMMUFD:
	case OBJ_FD_FS_CTX:
	case OBJ_FD_KVM_SYSTEM:
	case OBJ_FD_KVM_VM:
	case OBJ_FD_KVM_VCPU:
	case OBJ_FD_MOUNT:
	case OBJ_FD_SIGNALFD:
	case OBJ_FD_CGROUP:
		set_object_fd(obj, type, (int)id);
		break;
	case OBJ_AIO_CTX:	obj->aioobj.ctx = id; break;
	case OBJ_KEY_SERIAL:	obj->keyserialobj.serial = (int32_t)id; break;
	case OBJ_PKEY:		obj->pkey_obj.id = (int)id; break;
	case OBJ_TIMERID:	obj->timeridobj.tid = (int32_t)id; break;
	case OBJ_PID:		obj->pidobj.pid = (pid_t)id; break;
	case OBJ_SYSV_SEM:	obj->sysvsemobj.semid = (int)id; break;
	case OBJ_SYSV_MSG:	obj->sysvmsgobj.msqid = (int)id; break;
	default:
		/*
		 * mmap/sockinfo/watch_queue/pipe/epoll/kvm_vm/kvm_vcpu
		 * and the futex/sysv_shm/aio_iocb families need
		 * pool-specific state the unified shape can't carry.
		 * Return NULL so the caller falls back to the legacy
		 * alloc_object()/add_object() pair.
		 */
		return NULL;
	}

	/*
	 * Stamp secondary metadata fields.  Pools not listed here
	 * either take id only or fall under the default-return-NULL
	 * arm above.  Pools listed here but called with meta == NULL
	 * get the zero-meta defaults from the static const sentinel,
	 * matching the existing producers that leave these fields at
	 * implicit zero after alloc_object().
	 */
	switch (type) {
	case OBJ_FD_EVENTFD:
		obj->eventfdobj.flags = m->flags;
		obj->eventfdobj.count = m->extra_int;
		break;
	case OBJ_FD_TIMERFD:
		obj->timerfdobj.flags = m->flags;
		obj->timerfdobj.clockid = (int)m->aux;
		break;
	case OBJ_FD_INOTIFY:
		obj->inotifyobj.flags = m->flags;
		break;
	case OBJ_FD_USERFAULTFD:
		obj->userfaultobj.flags = m->flags;
		break;
	case OBJ_FD_FANOTIFY:
		obj->fanotifyobj.flags = m->flags;
		obj->fanotifyobj.eventflags = m->aux;
		break;
	case OBJ_FD_MEMFD:
		obj->memfdobj.flags = m->flags;
		obj->memfdobj.name = m->name;
		break;
	case OBJ_FD_MEMFD_SECRET:
		obj->memfd_secretobj.flags = m->flags;
		break;
	case OBJ_FD_PERF:
		obj->perfobj.flags = m->flags;
		break;
	case OBJ_FD_BPF_MAP:
		obj->bpfobj.map_type = m->subtype;
		break;
	case OBJ_FD_BPF_PROG:
		obj->bpfprogobj.prog_type = m->subtype;
		break;
	case OBJ_FD_BPF_LINK:
		obj->bpflinkobj.attach_type = m->subtype;
		break;
	case OBJ_FD_PIDFD:
		obj->pidfdobj.pid = (pid_t)m->extra_int;
		break;
	case OBJ_FD_KVM_SYSTEM:
		obj->kvmsysobj.api_version = (int)m->aux;
		break;
	default:
		break;
	}

	add_object(obj, OBJ_LOCAL, type);
	return obj;
}
