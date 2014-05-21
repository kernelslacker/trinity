#pragma once

int open_epoll_fds(void);
int get_rand_epoll_fd(void);

#define MAX_EPOLL_FDS 10
