#pragma once

#include <sys/ioctl.h>
#define KCOV_INIT_TRACE	_IOR('c', 1, unsigned long)
#define KCOV_ENABLE	_IO('c', 100)
#define KCOV_DISABLE	_IO('c', 101)
#define COVER_SIZE	(64<<10)

void init_kcov(void);
void enable_kcov(void);
void dump_kcov_buffer(void);
void disable_kcov(void);
void shutdown_kcov(void);
