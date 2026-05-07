#pragma once

#include <signal.h>

extern volatile sig_atomic_t sigalrm_pending;
extern volatile sig_atomic_t xcpu_pending;
extern volatile sig_atomic_t ctrlc_pending;
extern volatile sig_atomic_t in_do_syscall;

void mask_signals_child(void);
void setup_main_signals(void);
