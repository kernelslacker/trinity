#pragma once

/*
 * --arg-len-semantics: A/B knob for the object-size-relative ARG_LEN
 * generator in generate-args.c.  OFF (default) keeps gen_arg_len calling
 * get_len() byte-identical to the historical distribution -- no new RNG
 * draw, no companion-arg lookup, no entry into get_len_relative().  ON
 * lets gen_arg_len find an immediately-preceding ARG_ADDRESS companion,
 * resolve its writable-region size from the shared-region tracker, and
 * draw from a boundary set capped by that size (so the kernel-WRITES-
 * buffer syscalls in this set cannot scribble past the writable extent).
 *
 * Loaded with __ATOMIC_RELAXED on the hot arg-gen path: the value is
 * published once by parse_args() before any worker spawns, so a relaxed
 * read sees a stable value and pays no fence cost per call.
 */
enum arg_len_semantics_mode {
	ARG_LEN_SEMANTICS_OFF = 0,
	ARG_LEN_SEMANTICS_ON = 1,
};

extern enum arg_len_semantics_mode arg_len_semantics_mode;
