#pragma once

#include <setjmp.h>
#include <signal.h>

extern sigjmp_buf ret_jump;
extern volatile sig_atomic_t xcpu_pending;

void mask_signals_child(void);
void setup_main_signals(void);
