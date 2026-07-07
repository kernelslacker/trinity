#pragma once

#include <linux/kcmp.h>

#ifndef _LINUX_KCMP_H
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
#endif
