/*
 * SYSV Shared mapping creation.
 */

#include <sys/shm.h>
#include <limits.h>

#include "arch.h"
#include "compat.h"
#include "list.h"
#include "random.h"
#include "sysv-shm.h"
#include "objects.h"
#include "utils.h"

static void dump_sysv_shm(struct object *obj, enum obj_scope scope)
{
	output(0, "sysv_shm: id:%u size:%ld flags:%x ptr:%p scope:%d\n",
		obj->sysv_shm.id, obj->sysv_shm.size,
		obj->sysv_shm.flags, obj->sysv_shm.ptr, scope);
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
	head->shared_alloc = true;

	for (i = 0; i < ARRAY_SIZE(shmget_flags); i++) {
		void *p;
		struct object *obj;
		size_t size = 0;
		int flags;
		int id;

		obj = alloc_shared_obj(sizeof(struct object));
		if (obj == NULL)
			continue;
		INIT_LIST_HEAD(&obj->list);

		flags = 0660 | IPC_CREAT | IPC_EXCL | shmget_flags[i];

		size = page_size * (1 + rand() % 10);

		id = shmget(IPC_PRIVATE, size, flags);
		if (id == -1) {
			free_shared_obj(obj, sizeof(struct object));
			continue;
		}
		obj->sysv_shm.id = id;
		obj->sysv_shm.flags = flags;
		obj->sysv_shm.size = size;

		p = shmat(id, NULL, 0);
		if (p == (void *) -1)
			p = shmat(id, NULL, SHM_RDONLY);
		if (p == (void *) -1)
			p = shmat(id, NULL, SHM_EXEC);
		if (p == (void *) -1) {
			shmctl(id, IPC_RMID, NULL);
			free_shared_obj(obj, sizeof(struct object));
			continue;
		}
		obj->sysv_shm.ptr = p;

		add_object(obj, OBJ_GLOBAL, OBJ_SYSV_SHM);
	}
}

REG_GLOBAL_OBJ(sysv_shms, create_sysv_shms);
