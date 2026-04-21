#include <stdlib.h>

#include "arch.h"	// page_size
#include "sanitise.h"
#include "random.h"

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
		switch (rand() % 6) {
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

	switch (rand() % 5) {
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
