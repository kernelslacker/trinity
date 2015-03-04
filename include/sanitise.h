#pragma once

#include "syscall.h"

void generic_sanitise(struct syscallrecord *rec);
void generic_free_arg(struct syscallrecord *rec);

unsigned long get_interesting_value(void);

void *get_address(void);
void *get_non_null_address(void);
void *get_writable_address(unsigned long size);
unsigned long find_previous_arg_address(struct syscallrecord *rec, unsigned int argnum);
struct iovec * alloc_iovec(unsigned int num);
unsigned long get_len(void);
unsigned int get_pid(void);
const char * get_filename(void);
int get_random_fd(void);
const char * generate_pathname(void);

void gen_unicode_page(char *page);

void generate_syscall_args(struct syscallrecord *rec);
