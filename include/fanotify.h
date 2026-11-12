#pragma once

#include <stdbool.h>
#include <sys/syscall.h>

unsigned long get_fanotify_init_flags(bool privileged);

unsigned long get_fanotify_init_event_flags(void);
