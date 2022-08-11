#pragma once

#include <fcntl.h>
#include "fd.h"

unsigned long get_o_flags(void);

void parse_devices(void);
const char *map_dev(dev_t, mode_t);

int open_with_fopen(const char *filename, int flags);
