#include <stdio.h>
#include <stdlib.h>
#include "log.h"	// for BUG

unsigned long get_interesting_32bit_value(void)
{
	unsigned int i, bit;

	i = rand() % 10;

	switch (i) {

	/* rare case, single bit. */
	case 0:
		bit = rand() % 63;
		return (1L << bit);

	/* common case, return small values*/
	case 1 ... 7:
		i = rand() % 8;

		switch (i) {
		case 0:	return 0x00000000;
		case 1:	return 0x00000001;
		case 2:	return rand() % 256;
		case 3:	return 0x00000fff;	// 4095
		case 4:	return 0x00001000;	// 4096
		case 5:	return 0x00001001;	// 4097
		case 6:	return 0x00008000;
		case 7:	return 0x0000ffff;
		default:
			BUG("unreachable!\n");
			return 0;
		}
		break;

	/* less common case, go crazy */
	case 8 ... 10:
		i = rand() % 13;

		switch (i) {
		case 0:	return 0x00010000;
		case 1:	return 0x40000000;
		case 2:	return 0x7fffffff;
		case 3:	return 0x80000000;
		case 4:	return 0x80000001;
		case 5:	return 0x8fffffff;
		case 6: return 0xc0000000;
		case 7:	return 0xf0000000;
		case 8:	return 0xff000000;
		case 9:	return 0xffff0000;
		case 10: return 0xffffe000;
		case 11: return 0xffffff00 | (rand() % 256);
		case 12: return 0xffffffff;
		default:
			BUG("unreachable!\n");
			return 0;
		}
		break;

	default:
		BUG("unreachable!\n");
		break;
	}

	BUG("unreachable!\n");
	return 0;
}

unsigned long get_interesting_value(void)
{
#if __WORDSIZE == 32
	return get_interesting_32bit_value();
#else
	int i;
	unsigned long low;

	low = get_interesting_32bit_value();

	i = rand() % 18;

	switch (i) {
	case 0: return 0;
	case 1: return 0x0000000100000000;
	case 2: return 0x7fffffff00000000;
	case 3: return 0x8000000000000000;
	case 4: return 0xffffffff00000000;
	case 5: return low;
	case 6: return 0x0000000100000000 | low;
	case 7: return 0x00007fffffffffff;			// x86-64 canonical addr end.
	case 8: return 0x0000800000000000;			// First x86-64 non-canonical addr
	case 9: return 0x7fffffff00000000 | low;
	case 10: return 0x8000000000000000 | low;
	// FIXME: Use per-arch #defines for these
	case 11: return 0xffff800000000000 | (low << 4);	// x86-64 canonical addr range 2 begin
	case 12: return 0xffff880000000000 | (low << 4);	// x86-64 PAGE_OFFSET
	case 13: return 0xffffffff00000000 | low;
	case 14: return 0xffffffff80000000 | (low & 0xffffff);	// x86-64 kernel text address
	case 15: return 0xffffffffa0000000 | (low & 0xffffff);	// x86-64 module space
	case 16: return 0xffffffffff600000 | (low & 0x0fffff);	// x86-64 vdso
	case 17: return 0xffffffffffffff00 | (rand() % 256);
	default:
		BUG("unreachable!\n");
		return 0;
	}
	BUG("unreachable!\n");
	return 0;
#endif
}
