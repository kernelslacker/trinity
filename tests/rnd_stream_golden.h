#pragma once

/*
 * Fixed-seed golden-hash suite for the raw RNG helpers.
 * See rnd_stream_golden.c for the load-bearing invariant and
 * bless procedure.
 */
void rnd_stream_golden_check(void);
