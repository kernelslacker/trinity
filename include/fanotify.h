#pragma once

unsigned long get_fanotify_init_flags(void);

unsigned long get_fanotify_init_event_flags(void);

// FIXME: Keep all this here until glibc supports it.
#ifndef SYS_fanotify_init
#ifdef __x86_64__
#define SYS_fanotify_init 300
#endif
#ifdef __i386__
#define SYS_fanotify_init 338
#endif
#endif
