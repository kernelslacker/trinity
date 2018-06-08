#pragma once

#include "types.h"

#define TAINT_NAME_LEN 32

extern int kernel_taint_initial;

int get_taint(void);

bool is_tainted(void);

void process_taint_arg(char *taintarg);

void init_taint_checking(void);
