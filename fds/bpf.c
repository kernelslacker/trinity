/* bpf FDs */

#include "config.h"
#ifdef USE_BPF

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/bpf.h>

#include "fd.h"
#include "log.h"
#include "objects.h"
#include "random.h"
#include "sanitise.h"
#include "shm.h"
#include "compat.h"
#include "trinity.h"

static int bpf(__unused__ int cmd, __unused__ union bpf_attr *attr, __unused__ unsigned int size)
{
#ifdef SYS_bpf
	return syscall(SYS_bpf, cmd, attr, size);
#else
	return -ENOSYS;
#endif
}

static int bpf_create_map(enum bpf_map_type map_type, unsigned int key_size,
			unsigned int value_size, unsigned int max_entries)
{
	union bpf_attr attr = {
		.map_type    = map_type,
		.key_size    = key_size,
		.value_size  = value_size,
		.max_entries = max_entries
	};

	return bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}


static void bpf_destructor(struct object *obj)
{
	close(obj->bpf_map_fd);
}

static int open_bpf_fds(void)
{
	struct objhead *head;
	int fd, key;
	long long value = 0;
	struct object *obj;

	head = get_objhead(OBJ_GLOBAL, OBJ_FD_BPF_MAP);
	head->destroy = &bpf_destructor;

	fd = bpf_create_map(BPF_MAP_TYPE_ARRAY,sizeof(key), sizeof(value), 256);
	if (fd < 0)
		goto out;

	obj = alloc_object();
	obj->bpf_map_fd = fd;
	add_object(obj, OBJ_GLOBAL, OBJ_FD_BPF_MAP);
	output(2, "fd[%d] = bpf\n", fd);


out:
	//FIXME: right now, returning FALSE means "abort everything", not
	// "skip this provider", so on -ENOSYS, we have to still register.

	return TRUE;
}

static int get_rand_bpf_fd(void)
{
	struct object *obj;

	/* check if bpf unavailable/disabled. */
	if (objects_empty(OBJ_FD_BPF_MAP) == TRUE)
		return -1;

	obj = get_random_object(OBJ_FD_BPF_MAP, OBJ_GLOBAL);
	return obj->bpf_map_fd;
}

static const struct fd_provider bpf_fd_provider = {
	.name = "bpf",
	.enabled = TRUE,
	.open = &open_bpf_fds,
	.get = &get_rand_bpf_fd,
};

REG_FD_PROV(bpf_fd_provider);
#endif
