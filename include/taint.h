#pragma once

#define TAINT_NAME_LEN 32

int check_tainted(void);

void process_taint_arg(char *taintarg);
