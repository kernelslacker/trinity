#pragma once

#include <stdint.h>
#include <sys/uio.h>
#include <sys/socket.h>

#include "syscall.h"

void generic_sanitise(struct syscallentry *entry, struct syscallrecord *rec);
void generic_free_arg(struct syscallentry *entry, struct syscallrecord *rec);

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
void scrub_iovec_for_kernel_write(struct iovec *iov, unsigned long count);
void scrub_msghdr_for_kernel_write(struct msghdr *msg);
unsigned long find_previous_arg_address(struct syscallentry *entry, struct syscallrecord *rec, unsigned int argnum);
struct iovec * alloc_iovec(unsigned int num);
unsigned long get_len(void);
unsigned int get_pid(void);
int32_t get_random_key_serial(void);
void register_key_serial(int32_t serial);
int32_t get_random_timerid(void);
void register_timerid(int32_t tid);

void gen_unicode_page(char *page);

enum argtype get_argtype(struct syscallentry *entry, unsigned int argnum);
void generate_syscall_args(struct syscallrecord *rec);
