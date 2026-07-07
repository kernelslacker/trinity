/*
 * SYSV Shared mapping creation.
 */

#include <sys/shm.h>
#include <limits.h>

#include "arch.h"
#include "deferred-free.h"
#include "random.h"
#include "rnd.h"
#include "sysv-shm.h"
#include "objects.h"
#include "utils.h"

#include "kernel/shm.h"
static void dump_sysv_shm(struct object *obj, enum obj_scope scope)
{
	output(0, "sysv_shm: id:%u size:%zu flags:%x ptr:%p scope:%d\n",
		obj->sysv_shm.id, obj->sysv_shm.size,
		obj->sysv_shm.flags, obj->sysv_shm.ptr, scope);
}

static void sysv_shm_destructor(struct object *obj)
{
	/* Detach the mapping, mark the segment for removal once the last
	 * attach is gone, and drop the shared-region bookkeeping that
	 * track_shared_region() created at create time. */
	if (obj->sysv_shm.ptr != NULL && obj->sysv_shm.ptr != (void *)-1) {
		untrack_shared_region((unsigned long)obj->sysv_shm.ptr,
				      obj->sysv_shm.size);
		(void)shmdt(obj->sysv_shm.ptr);
	}
	(void)shmctl(obj->sysv_shm.id, IPC_RMID, NULL);
}

void create_sysv_shms(void)
{
	struct objhead *head;
	unsigned int i;
	int shmget_flags[] = {
		0,	// Just CREAT|EXCL
		SHM_HUGETLB|SHM_HUGE_2MB,
		SHM_HUGETLB|SHM_HUGE_1GB,
		SHM_NORESERVE,
		SHM_HUGETLB|SHM_HUGE_2MB|SHM_NORESERVE,
		SHM_HUGETLB|SHM_HUGE_1GB|SHM_NORESERVE,
	};

	head = get_objhead(OBJ_GLOBAL, OBJ_SYSV_SHM);
	head->dump = dump_sysv_shm;
	head->destroy = &sysv_shm_destructor;

	for (i = 0; i < ARRAY_SIZE(shmget_flags); i++) {
		void *p;
		struct object *obj;
		size_t size = 0;
		int flags;
		int id;

		obj = alloc_object();
		if (obj == NULL)
			continue;

		flags = 0660 | IPC_CREAT | IPC_EXCL | shmget_flags[i];

		size = page_size * (1 + rnd_modulo_u32(10));

		id = shmget(IPC_PRIVATE, size, flags);
		if (id == -1) {
			tracked_free_now(obj);
			continue;
		}
		obj->sysv_shm.id = id;
		obj->sysv_shm.flags = flags;

		p = shmat(id, NULL, 0);
		if (p == (void *) -1)
			p = shmat(id, NULL, SHM_RDONLY);
		if (p == (void *) -1)
			p = shmat(id, NULL, SHM_EXEC);
		if (p == (void *) -1) {
			shmctl(id, IPC_RMID, NULL);
			tracked_free_now(obj);
			continue;
		}
		obj->sysv_shm.ptr = p;

		/*
		 * The kernel rounds hugetlb segments up to a multiple of
		 * the VMA's hugepage size; the size we requested may be
		 * smaller than the actual VMA extent.  Query the post-
		 * allocation size via IPC_STAT so the recorded size and
		 * the tracked shared region match the kernel's view.
		 * Anything walking shared_regions[] with tight-extent
		 * assumptions (range_overlaps_shared, range_in_tracked_shared)
		 * needs the real extent or it will miss addresses inside
		 * the VMA but past the requested size.
		 */
		{
			struct shmid_ds buf;
			size_t real_size = size;

			if (shmctl(id, IPC_STAT, &buf) == 0 && buf.shm_segsz > 0)
				real_size = (size_t) buf.shm_segsz;
			obj->sysv_shm.size = real_size;
			track_shared_region((unsigned long)p, real_size);
		}

		add_object(obj, OBJ_GLOBAL, OBJ_SYSV_SHM);
	}
}

REG_GLOBAL_OBJ(sysv_shms, create_sysv_shms);
