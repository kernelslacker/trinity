#pragma once

/*
 * Private helpers shared across the dispatch/syscall-*.c files.  Not part
 * of the public syscall.h API; consumers live only in dispatch/.
 */

#include "syscall.h"

void arena_liveness_probe(struct syscallentry *entry,
			  struct syscallrecord *rec);
