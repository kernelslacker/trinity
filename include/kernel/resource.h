#pragma once

#include <sys/resource.h>

#ifndef RLIM_INFINITY
#define RLIM_INFINITY		(~0UL)
#endif
#ifndef RLIMIT_RTTIME
#define RLIMIT_RTTIME           15
#endif
