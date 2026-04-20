#pragma once

#include "syscall.h"

void generic_sanitise(struct syscallrecord *rec);
void generic_free_arg(struct syscallrecord *rec);

unsigned long get_interesting_value(void);
unsigned int get_interesting_32bit_value(void);
unsigned long get_boundary_value(void);
unsigned long get_sizeof_boundary_value(void);
unsigned long mutate_value(unsigned long val);
unsigned long shift_flag_bit(unsigned long flag);

unsigned long get_argval(struct syscallrecord *rec, unsigned int argnum);

void *get_address(void);
void *get_non_null_address(void);
void *get_writable_address(unsigned long size);
void *get_writable_struct(size_t size);
void avoid_shared_buffer(unsigned long *addr, unsigned long len);
unsigned long find_previous_arg_address(struct syscallrecord *rec, unsigned int argnum);
struct iovec * alloc_iovec(unsigned int num);
unsigned long get_len(void);
unsigned int get_pid(void);

void gen_unicode_page(char *page);

enum argtype get_argtype(struct syscallentry *entry, unsigned int argnum);
void generate_syscall_args(struct syscallrecord *rec);
