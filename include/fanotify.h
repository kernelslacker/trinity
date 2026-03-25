#pragma once

#include <sys/syscall.h>

unsigned long get_fanotify_init_flags(void);

unsigned long get_fanotify_init_event_flags(void);
