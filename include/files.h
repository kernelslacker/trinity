#pragma once

#include <fcntl.h>
#include <stdbool.h>
#include "fd.h"
#include "object-types.h"

unsigned long get_o_flags(void);

bool parse_devices(void);
const char *map_dev(dev_t, mode_t);

int open_with_fopen(const char *filename, int flags);

int open_pool_files(unsigned int pool_id, enum objecttype objtype);
int get_rand_pool_fd(enum objecttype objtype);
int open_pool_fd(unsigned int pool_id, enum objecttype objtype);

int get_rand_pagecache_fd(void);
