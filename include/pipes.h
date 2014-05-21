#pragma once

int open_pipes(void);
int get_rand_pipe_fd(void);

#define MAX_PIPE_FDS 4
