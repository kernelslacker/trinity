#ifndef _SANITISE_H
#define _SANITISE_H 1

#include "syscall.h"

void sanitise_mmap(int childno);
void sanitise_rt_sigaction(int childno);
void sanitise_socket(int childno);

void sanitise_ioctl_sg_io(int childno);

void generic_sanitise(int childno);

extern char * filebuffer;
extern unsigned long filebuffersize;

unsigned long get_interesting_value(void);
unsigned long get_interesting_32bit_value(void);
unsigned long get_reg(void);
void *get_address(void);
void *get_non_null_address(void);
unsigned long get_len(void);
unsigned int get_pid(void);
char * get_filename(void);
int get_random_fd(void);

void fabricate_onepage_struct(char *page);

void generate_sockaddr(unsigned long *addr, unsigned long *addrlen, int pf);
#define PF_NOHINT (-1)

#endif	/* _SANITISE_H */
