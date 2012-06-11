#ifndef _SANITISE_H
#define _SANITISE_H 1

#include "syscall.h"

void sanitise_mmap(unsigned long *a1, unsigned long *a2, unsigned long *a3, unsigned long *a4, unsigned long *a5, unsigned long *a6);
void sanitise_sendto(unsigned long *a1, unsigned long *a2, unsigned long *a3, unsigned long *a4, unsigned long *a5, unsigned long *a6);
void sanitise_rt_sigaction(unsigned long *a1, unsigned long *a2, unsigned long *a3, unsigned long *a4, unsigned long *a5, unsigned long *a6);
void sanitise_socket(unsigned long *a1, unsigned long *a2, unsigned long *a3, unsigned long *a4, unsigned long *a5, unsigned long *a6);
void sanitise_ioctl_sg_io(unsigned long *a1, unsigned long *a2, unsigned long *a3, unsigned long *a4, unsigned long *a5, unsigned long *a6);

void generic_sanitise(int call,
	unsigned long *a1, unsigned long *a2, unsigned long *a3,
	unsigned long *a4, unsigned long *a5, unsigned long *a6);

extern char * filebuffer;
extern unsigned long filebuffersize;

unsigned long get_interesting_value();
unsigned long get_interesting_32bit_value();
unsigned long rand64();
void *get_address();
void *get_non_null_address();
unsigned long get_len();

#endif	/* _SANITISE_H */
