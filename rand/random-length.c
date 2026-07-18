
#include "arch.h"	// page_size
#include "arg-len-semantics.h"
#include "sanitise.h"
#include "random.h"
#include "rnd.h"
#include "shm.h"

/*
 * Default OFF.  Until --arg-len-semantics flips this ON, gen_arg_len
 * stays on its historical get_len() path and never enters
 * get_len_relative(), so the per-call arg stream is byte-identical to
 * a build without this knob.
 */
enum arg_len_semantics_mode arg_len_semantics_mode = ARG_LEN_SEMANTICS_OFF;

unsigned long get_len(void)
{
	unsigned int i = 0;

	/* ~1 in 8: return a boundary value (0, 1, page_size, MAX, etc.) */
	if (ONE_IN(8))
		return get_boundary_value();

	/* ~1 in 16: return a sizeof-boundary value (UINT_MAX/sizeof, etc.) */
	if (ONE_IN(16))
		return get_sizeof_boundary_value();

	if (RAND_BOOL()) {
		switch (rnd_modulo_u32(6)) {
		case 0:	return sizeof(char);
		case 1:	return sizeof(short);
		case 2:	return sizeof(int);
		case 3:	return sizeof(long);
		case 4: return sizeof(void *);
		case 5: return page_size;
		}
	}

	i = rand32();

	/* short circuit if 0 */
	if (i == 0)
		return 0;

	switch (rnd_modulo_u32(5)) {
	case 0:	i &= 0xff;
		break;
	case 1: i &= page_size - 1;
		break;
	case 2:	i &= 0xffff;
		break;
	case 3:	i &= 0xffffff;
		break;
	case 4:
		// Pass through
		break;
	}

	/* again, short circuit if 0 */
	if (i == 0)
		return 0;

	/* we might get lucky if something is counting ints/longs etc. */
	if (ONE_IN(4)) {
		int divisor = 1 << RAND_RANGE(1, 4);	/* 2,4,8 or 16 */
		i /= divisor;
	}

	return i;
}

/*
 * Object-size-relative length draw, capped at @objsize so a kernel-
 * WRITES-buffer caller (read / pread / recv / ...) cannot pick a length
 * that would make the kernel scribble past the writable region into
 * the abutting page.
 *
 * Half the time the helper defers to get_len() so the broader random
 * and sizeof coverage (UINT_MAX masks, sizeof(int/long), page_size
 * boundary, get_boundary_value's full table) is preserved alongside
 * the new object-edge boundary class.  When the relative arm fires it
 * picks from {0, 1, objsize, objsize-1, objsize/2, min(page_size +/- 1,
 * objsize)}: every value <= objsize, so the write-direction safety
 * invariant in the caller's gen_arg_len comment holds by construction.
 *
 * The kernel checks length against the buffer the syscall describes
 * (read's writable count, write's readable extent), so a relative draw
 * here gives the kernel a boundary value it actually branches on,
 * which the size-blind get_len() distribution rarely hits.
 */
unsigned long get_len_relative(unsigned long objsize)
{
	if (objsize == 0)
		return get_len();

	/* Half the time blend in the wider get_len() distribution (UINT_MAX
	 * masks, sizeof(int/long), get_boundary_value's full table) so the
	 * broader coverage is not lost.  Clamp to objsize so the safety
	 * invariant holds: even on the fallback arm a kernel-WRITES-buffer
	 * caller cannot pick a length that lets the kernel scribble past
	 * the writable region. */
	if (RAND_BOOL()) {
		unsigned long v = get_len();

		__atomic_add_fetch(&shm->stats.arg.len_objrel_blend_getlen, 1,
				   __ATOMIC_RELAXED);
		return v > objsize ? objsize : v;
	}

	__atomic_add_fetch(&shm->stats.arg.len_objrelative_used, 1,
			   __ATOMIC_RELAXED);

	switch (rnd_modulo_u32(8)) {
	case 0:
		__atomic_add_fetch(&shm->stats.arg.len_objrel_zero, 1,
				   __ATOMIC_RELAXED);
		return 0;
	case 1:
		__atomic_add_fetch(&shm->stats.arg.len_objrel_one, 1,
				   __ATOMIC_RELAXED);
		return 1;
	case 2:
		__atomic_add_fetch(&shm->stats.arg.len_objrel_objsize, 1,
				   __ATOMIC_RELAXED);
		return objsize;
	case 3:
		__atomic_add_fetch(&shm->stats.arg.len_objrel_objsize_minus_1, 1,
				   __ATOMIC_RELAXED);
		return objsize - 1;
	case 4:
		__atomic_add_fetch(&shm->stats.arg.len_objrel_objsize_half, 1,
				   __ATOMIC_RELAXED);
		return objsize / 2;
	case 5:
		__atomic_add_fetch(&shm->stats.arg.len_objrel_pagesize, 1,
				   __ATOMIC_RELAXED);
		if (page_size > 0 && objsize >= page_size)
			return page_size;
		return objsize;
	case 6:
		__atomic_add_fetch(&shm->stats.arg.len_objrel_pagesize_plus_1, 1,
				   __ATOMIC_RELAXED);
		if (page_size > 0 && objsize >= page_size + 1)
			return page_size + 1;
		return objsize;
	case 7:
		__atomic_add_fetch(&shm->stats.arg.len_objrel_pagesize_minus_1, 1,
				   __ATOMIC_RELAXED);
		if (page_size > 1 && objsize >= page_size - 1)
			return page_size - 1;
		return objsize;
	}
	return objsize;
}
