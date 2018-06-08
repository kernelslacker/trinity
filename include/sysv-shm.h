#pragma once

void create_sysv_shms(void);

struct sysv_shm {
	void *ptr;
	int id;
	size_t size;
	int flags;
};
