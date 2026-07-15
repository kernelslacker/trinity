#pragma once

#include <linux/kcmp.h>

#ifndef _LINUX_KCMP_H
#include <stdint.h>

#ifndef KCMP_TYPES
enum kcmp_type {
	KCMP_FILE,
	KCMP_VM,
	KCMP_FILES,
	KCMP_FS,
	KCMP_SIGHAND,
	KCMP_IO,
	KCMP_SYSVSEM,
	KCMP_EPOLL_TFD,

	KCMP_TYPES,
};
#endif

/*
 * struct kcmp_epoll_slot was added to the uapi alongside KCMP_EPOLL_TFD.
 * Provide a layout-compatible fallback for builds against older uapi
 * headers that predate it.
 */
struct kcmp_epoll_slot {
	uint32_t efd;
	uint32_t tfd;
	uint32_t toff;
};
#endif
