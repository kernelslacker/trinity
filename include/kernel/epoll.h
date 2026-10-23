#pragma once

#include <sys/epoll.h>

#ifndef EPOLLEXCLUSIVE
#define EPOLLEXCLUSIVE (1 << 28)
#endif
#ifndef EPOLLWAKEUP
#define EPOLLWAKEUP (1u << 29)
#endif
