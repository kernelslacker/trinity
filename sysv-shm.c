/*
 * SYSV Shared mapping creation.
 */

#include <sys/shm.h>
#include <limits.h>

#include "arch.h"
#include "compat.h"
#include "random.h"
#include "sysv-shm.h"
#include "objects.h"
#include "utils.h"

void create_sysv_shms(void)
{
	unsigned int i;
	int shmget_flags[] = {
		0,	// Just CREAT|EXCL
		SHM_HUGETLB|SHM_HUGE_2MB,
		SHM_HUGETLB|SHM_HUGE_1GB,
		SHM_NORESERVE,
		SHM_HUGETLB|SHM_HUGE_2MB|SHM_NORESERVE,
		SHM_HUGETLB|SHM_HUGE_1GB|SHM_NORESERVE,
	};

	for (i = 0; i < ARRAY_SIZE(shmget_flags); i++) {
		void *p;
		struct object *obj;
		size_t size = 0;
		int flags;
		int id;

		obj = alloc_object();

		flags = 0660 | IPC_CREAT | IPC_EXCL | shmget_flags[i];

		size = page_size * (1 + rnd() % 10);

		id = shmget(IPC_PRIVATE, page_size, flags);
		if (id == -1) {
			free(obj);
			continue;
		}
		obj->sysv_shm.id = id;
		obj->sysv_shm.flags = flags;
		obj->sysv_shm.size = size;

		add_object(obj, OBJ_GLOBAL, OBJ_SYSV_SHM);

		p = shmat(id, NULL, 0);	// TODO: Try alternative flags.
		if (p != (void *) -1)
			obj->sysv_shm.ptr = p;
	}
	//dump_objects(OBJ_GLOBAL, OBJ_SYSV_SHM);
}
