#pragma once

#include "syscall.h"

//FIXME: Fold this into the sigaction file and make static
void sanitise_rt_sigaction(int childno, struct syscallrecord *rec);

unsigned long set_rand_bitmask(unsigned int num, const unsigned long *values);
void generic_sanitise(int childno);
void generic_free_arg(int childno);

unsigned long get_interesting_value(void);
unsigned int get_interesting_32bit_value(void);

void *get_address(void);
void *get_non_null_address(void);
void *get_writable_address(unsigned long size);
unsigned long find_previous_arg_address(int childno, unsigned int argnum);
struct iovec * alloc_iovec(unsigned int num);
unsigned long get_len(void);
unsigned int get_pid(void);
const char * get_filename(void);
int get_random_fd(void);
const char * generate_pathname(void);

void gen_unicode_page(char *page);

bool this_syscallname(const char *thisname, int childno);
