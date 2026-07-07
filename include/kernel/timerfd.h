#pragma once

#include <sys/timerfd.h>

#ifndef TFD_CLOEXEC
#define TFD_CLOEXEC             02000000
#endif
#ifndef TFD_NONBLOCK
#define TFD_NONBLOCK            04000
#endif
#ifndef TFD_TIMER_ABSTIME
#define TFD_TIMER_ABSTIME       1
#define TFD_TIMER_CANCEL_ON_SET (1 << 1)
#endif
