#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/*
 * Fill `buf[0..sz)` with the 8-byte pattern in `seed`, repeated.  If
 * `seed` is 0, generate one via rnd_u64().  Returns the seed actually
 * used so the caller can stash it for a matching check_output_struct
 * call after the syscall returns.
 */
uint64_t poison_output_struct(void *buf, size_t sz, uint64_t seed);

/*
 * Return true iff every byte of `buf[0..sz)` still equals the byte the
 * matching poison_output_struct(seed) would have written there.
 */
bool check_output_struct(const void *buf, size_t sz, uint64_t seed);
