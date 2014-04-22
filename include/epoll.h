#pragma once

void open_epoll_fds(void);
int rand_epoll_fd(void);

#define MAX_EPOLL_FDS 10
