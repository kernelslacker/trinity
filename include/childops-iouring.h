#pragma once
/*
 * Shared submission/completion ring word accessors for the io_uring
 * childops.
 *
 * The SQ/CQ ring head/tail/mask words are shared with the kernel via
 * mmap and updated lock-free; access through a volatile pointer
 * prevents the compiler from coalescing or hoisting loads/stores out
 * of the submit/reap loops.  Several childops carried byte-identical
 * copies of these two helpers; this header is the single home.
 */

static inline unsigned int ring_u32(void *ring, unsigned int off)
{
	return *(volatile unsigned int *)((char *)ring + off);
}

static inline void ring_store_u32(void *ring, unsigned int off, unsigned int v)
{
	*(volatile unsigned int *)((char *)ring + off) = v;
}
