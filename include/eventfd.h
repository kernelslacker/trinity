#pragma once

int open_eventfd_fds(void);
int get_rand_eventfd_fd(void);

#define MAX_EVENTFD_FDS 8
