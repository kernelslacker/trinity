#ifndef _SANITISE_H
#define _SANITISE_H 1

#include "syscall.h"

void sanitise_mmap(int childno);
void sanitise_sendto(int childno);
void sanitise_rt_sigaction(int childno);
void sanitise_socket(int childno);

void sanitise_ioctl_sg_io(int childno);

void generic_sanitise(int childno);

extern char * filebuffer;
extern unsigned long filebuffersize;

unsigned long get_interesting_value();
unsigned long get_interesting_32bit_value();
unsigned long rand64();
void *get_address();
void *get_non_null_address();
unsigned long get_len();
unsigned int get_pid(void);
int get_random_fd(void);

#endif	/* _SANITISE_H */
