#pragma once

#include <sys/eventfd.h>

#ifndef EFD_SEMAPHORE
#define EFD_SEMAPHORE 1
#endif
#ifndef EFD_CLOEXEC
#define EFD_CLOEXEC 02000000
#endif
#ifndef EFD_NONBLOCK
#define EFD_NONBLOCK 04000
#endif
