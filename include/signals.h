#pragma once

#include <setjmp.h>

extern sigjmp_buf ret_jump;

void mask_signals_child(void);
void setup_main_signals(void);
