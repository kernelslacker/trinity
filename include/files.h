#pragma once

#include <sys/stat.h>
#include "fd.h"

unsigned long get_o_flags(void);

const struct fd_provider file_fd_provider;

void parse_devices(void);
const char *map_dev(dev_t, mode_t);

extern unsigned int nr_file_fds;
extern char *victim_path;
extern const char **fileindex;
extern unsigned int files_in_index;

int open_with_fopen(const char *filename, int flags);

#define NR_FILE_FDS 250U
