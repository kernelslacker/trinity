/*
 * bpf-internal.h
 *
 * Shared declarations for the syscalls/bpf.c source-split.  Each
 * per-command family (map / prog / link / btf) lives in its own
 * sibling translation unit; the aggregator syscalls/bpf.c keeps the
 * switch dispatch, cross-family helpers, post-state plumbing,
 * sanitise_bpf_default, and the syscall_bpf registration.
 *
 * This header is private to the syscalls/bpf*.c TUs -- do not include
 * it from anywhere else.
 *
 * The two file-static helpers bpf_fill_obj_name and bpf_random_token_fd
 * were deliberately widened from static to external linkage so the
 * split map / prog / btf / get_fd_by_id sites can reach them without
 * duplicating the pool-draw / mutated-name logic across TUs.
 */

#ifndef SYSCALLS_BPF_INTERNAL_H
#define SYSCALLS_BPF_INTERNAL_H

#ifdef USE_BPF

#include <stdbool.h>
#include <linux/bpf.h>

#include "syscall.h"

/* Shared helpers (defined in syscalls/bpf.c). */
void bpf_fill_obj_name(char *name);
int bpf_random_token_fd(void);

/* Map family (defined in syscalls/bpf-map.c). */
void sanitise_bpf_map_create(union bpf_attr *attr, struct syscallrecord *rec);
void sanitise_bpf_map_lookup(union bpf_attr *attr, struct syscallrecord *rec);
void sanitise_bpf_map_update(union bpf_attr *attr, struct syscallrecord *rec);
void sanitise_bpf_map_delete(union bpf_attr *attr, struct syscallrecord *rec);
void sanitise_bpf_map_get_next_key(union bpf_attr *attr, struct syscallrecord *rec);
void sanitise_bpf_map_freeze(union bpf_attr *attr, struct syscallrecord *rec);
void sanitise_bpf_obj_get(union bpf_attr *attr, struct syscallrecord *rec);
void post_bpf_map_create(int fd, bool attr_readable, union bpf_attr *attr);
void post_bpf_map_get_fd_by_id(int fd);

/* Prog family (defined in syscalls/bpf-prog.c). */
bool sanitise_bpf_prog_load(union bpf_attr *attr, struct syscallrecord *rec);
void sanitise_bpf_prog_attach(union bpf_attr *attr, struct syscallrecord *rec);
void sanitise_bpf_prog_test_run(union bpf_attr *attr, struct syscallrecord *rec);
void sanitise_bpf_raw_tracepoint(union bpf_attr *attr, struct syscallrecord *rec);
void post_bpf_prog_load(int fd, bool attr_readable, union bpf_attr *attr,
			bool classic_bpf_insns);
void post_bpf_prog_get_fd_by_id(int fd);
void post_bpf_prog_attach(unsigned long ret, bool attr_readable,
			  union bpf_attr *attr);

/* Link family (defined in syscalls/bpf-link.c). */
void sanitise_bpf_link_create(union bpf_attr *attr, struct syscallrecord *rec);
void sanitise_bpf_link_update(union bpf_attr *attr, struct syscallrecord *rec);
void sanitise_bpf_link_detach(union bpf_attr *attr, struct syscallrecord *rec);
void sanitise_bpf_iter_create(union bpf_attr *attr, struct syscallrecord *rec);
void post_bpf_link_create(int fd, bool attr_readable, union bpf_attr *attr);
void post_bpf_link_get_fd_by_id(int fd);

/* BTF family (defined in syscalls/bpf-btf.c). */
void sanitise_bpf_btf_load(union bpf_attr *attr, struct syscallrecord *rec);
void sanitise_bpf_obj_get_info_by_fd(union bpf_attr *attr, struct syscallrecord *rec);
void post_bpf_btf_fd(int fd);

/* Schema-aware bpf_attr fallback (defined in syscalls/bpf-fallback.c). */
void sanitise_bpf_default(union bpf_attr *attr, struct syscallrecord *rec);

#endif	/* USE_BPF */

#endif	/* SYSCALLS_BPF_INTERNAL_H */
