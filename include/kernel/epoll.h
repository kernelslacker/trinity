#pragma once

#include <sys/epoll.h>

#ifndef EPOLLEXCLUSIVE
#define EPOLLEXCLUSIVE (1 << 28)
#endif
#ifndef EPOLLWAKEUP
#define EPOLLWAKEUP (1u << 29)
#endif

#ifndef EPIOCSPARAMS
#include <linux/ioctl.h>
#include <linux/types.h>

struct epoll_params {
	__u32 busy_poll_usecs;
	__u16 busy_poll_budget;
	__u8 prefer_busy_poll;
	__u8 __pad;
};
#define EPOLL_IOC_TYPE 0x8A
#define EPIOCSPARAMS _IOW(EPOLL_IOC_TYPE, 0x01, struct epoll_params)
#define EPIOCGPARAMS _IOR(EPOLL_IOC_TYPE, 0x02, struct epoll_params)
#endif
