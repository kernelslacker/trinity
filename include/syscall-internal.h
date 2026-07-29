#pragma once

/*
 * Private helpers shared across the dispatch/syscall-*.c files.  Not part
 * of the public syscall.h API; consumers live only in dispatch/.
 */

#include <stdbool.h>

#include "syscall.h"
#include "syscall_record.h"
#include "tables.h"

/* effective_rettype() moved to syscall.h so non-dispatch consumers
 * (random_syscall/fd-group.c, persist/minicorpus-xprop.c) can share
 * the same source-of-truth helper for op-multiplexed rettype (bpf,
 * seccomp, fcntl, futex publish rec->rettype from their sanitise). */

void arena_liveness_probe(struct syscallentry *entry,
			  struct syscallrecord *rec);

bool reject_corrupt_retfd(const struct syscallentry *entry,
			  struct syscallrecord *rec);
void register_returned_fd(const struct syscallentry *entry,
			  struct syscallrecord *rec);

void enforce_count_bound(const struct syscallentry *entry,
			 struct syscallrecord *rec);
void validate_ret_bound(const struct syscallentry *entry,
			struct syscallrecord *rec);
void deactivate_enosys(struct syscallrecord *rec,
		       struct syscallentry *entry, unsigned int call);

struct kcov_child;
struct childdata;

void __do_syscall(struct syscallrecord *rec, struct syscallentry *entry,
		  enum syscallstate state,
		  struct kcov_child *kc, struct childdata *child);
void do_extrafork(struct syscallrecord *rec, struct syscallentry *entry,
		  struct childdata *child);
