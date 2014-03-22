#pragma once

#define TAINT_NAME_LEN 32

extern int kernel_taint_initial;

int check_tainted(void);

void process_taint_arg(char *taintarg);
