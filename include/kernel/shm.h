#pragma once

#include <sys/shm.h>

#ifndef SHM_HUGE_SHIFT
#define SHM_HUGE_SHIFT 26
#endif
#ifndef SHM_HUGE_2MB
#define SHM_HUGE_2MB (21 << SHM_HUGE_SHIFT)
#define SHM_HUGE_1GB (30 << SHM_HUGE_SHIFT)
#endif
#ifndef SHM_NORESERVE
#define SHM_NORESERVE 0x2000
#endif
