#ifndef _SANITISE_H
#define _SANITISE_H 1

void sanitise_mmap(unsigned long *a1, unsigned long *a2, unsigned long *a3, unsigned long *a4, unsigned long *a5, unsigned long *a6);
void sanitise_sendto(unsigned long *a1, unsigned long *a2, unsigned long *a3, unsigned long *a4, unsigned long *a5, unsigned long *a6);
void sanitise_rt_sigaction(unsigned long *a1, unsigned long *a2, unsigned long *a3, unsigned long *a4, unsigned long *a5, unsigned long *a6);
void sanitise_socket(unsigned long *a1, unsigned long *a2, unsigned long *a3, unsigned long *a4, unsigned long *a5, unsigned long *a6);
void sanitise_ioctl_sg_io(unsigned long *a1, unsigned long *a2, unsigned long *a3, unsigned long *a4, unsigned long *a5, unsigned long *a6);

#define ARG_FD	1
#define ARG_LEN	2
#define ARG_ADDRESS 3
#define ARG_PID 4
#define ARG_RANGE 5
#define ARG_LIST 6
#define ARG_RANDPAGE	7	/* ->sanitise will scribble over this. */
#define ARG_CPU 8

#define CAPABILITY_CHECK (1<<0)
#define AVOID_SYSCALL (1<<1)
#define NI_SYSCALL (1<<2)

void generic_sanitise(int call,
	unsigned long *a1, unsigned long *a2, unsigned long *a3,
	unsigned long *a4, unsigned long *a5, unsigned long *a6);

extern char * filebuffer;
extern unsigned long filebuffersize;

unsigned long get_interesting_value();
unsigned long get_interesting_32bit_value();
unsigned long rand64();
void *get_address();
unsigned long get_len();

#endif	/* _SANITISE_H */
