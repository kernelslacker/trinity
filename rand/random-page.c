/*
 * Routines to dirty a range of memory.
 */

#include <unistd.h>
#include "arch.h"
#include "random.h"
#include "sanitise.h"
#include "utils.h"

//FIXME: Double check on 32bit
static void fabricate_struct(char *p, unsigned int len)
{
	unsigned int i = 0;

	while (i < len) {
		void **ptr = (void*) &p[i];
		unsigned long val = 0;

		switch (rnd() % 3) {
		case 0:
			if (!IS_ALIGNED(i, 8))
				break;

			i += sizeof(unsigned long);
			if (i > len)
				return;

			switch (rnd() % 4) {
			case 0:	val = rand64();
				break;
			case 1:	val = (unsigned long) get_address();
				break;
			case 2:	val = (unsigned long) ptr;
				break;
			case 3:	val = get_len();
				break;
			}

			*(unsigned long *)ptr = val;
			break;

		case 1:
			if (!IS_ALIGNED(i, 4))
				break;

			i += sizeof(unsigned int);
			if (i > len)
				return;

			*(unsigned int *)ptr = rand32();
			break;

		case 2:
			if (!IS_ALIGNED(i, 2))
				break;

			if (RAND_BOOL()) {
				/* one u16 */
				i += sizeof(unsigned short);
				if (i > len)
					return;

				*(unsigned short *)ptr = rand16();
			} else {
				/* two u8's */
				for (int j = 0; j < 2; j++) {
					i += sizeof(unsigned char);
					if (i > len)
						return;
				}
				*(unsigned char *)ptr = RAND_BYTE();
			}
			break;
		}
	}
}

//TODO: Some of this code used to assume page_size. It needs auditting
// to be sure we don't write past len.
void generate_rand_bytes(unsigned char *ptr, unsigned int len)
{
	char *p;
	unsigned int i;
	unsigned char separators[] = { ':', ',', '.', ' ', '-', '\0', };
	unsigned char separator;
	unsigned int randrange = 9;

	/* If we only have a small buffer, don't do
	 * the longer generators. */
	if (len < 24)
		randrange = 6;
	else {
		/* Make sure we're always dealing with an even number */
		if (len & 1)
			len--;
	}

	switch (rnd() % randrange) {
	case 0:
		/* Complete garbage. */
		for (i = 0; i < len; i++)
			ptr[i] = RAND_BYTE();
		break;
	case 1:
		memset(ptr, 0, len);
		return;
	case 2:
		memset(ptr, 0xff, len);
		return;
	case 3:
		memset(ptr, RAND_BYTE(), len);
		return;
	case 4:
		for (i = 0; i < len; i++)
			ptr[i] = (unsigned char)RAND_BOOL();
		return;
	case 5:
		/* printable text strings. */
		for (i = 0; i < len; i++)
			ptr[i] = 32 + rnd() % (0x7f - 32);
		break;

	case 6:
		/* ascii representation of random numbers */
		separator = separators[rnd() % sizeof(separators)];

		p = (char *) ptr;

		while (p < (char *)(ptr + (len-23))) {		// 23 is the longest case below + separator.
			if (RAND_BOOL()) {
				/* hex */
				switch (rnd() % 3) {
				case 0:	p += sprintf(p, "0x%lx", (unsigned long) rand64());
					break;
				case 1:	p += sprintf(p, "0x%lx", (unsigned long) rand64());
					break;
				case 2:	p += sprintf(p, "0x%x", (int) rand32());
					break;
				}
			} else {
				/* decimal */

				/* perhaps negative ?*/
				if (RAND_BOOL())
					p += sprintf(p, "-");

				switch (rnd() % 3) {
				case 0:	p += sprintf(p, "%lu", (unsigned long) rand64());
					break;
				case 1:	p += sprintf(p, "%u", (unsigned int) rand32());
					break;
				case 2:	p += sprintf(p, "%u", (unsigned char) rnd());
					break;
				}
			}

			/* insert commas and/or spaces */
			*p = separator;
			p++;
		}
		ptr[len-1] = 0;
		break;

	/* return something that looks kinda like a struct */
	case 7:
		fabricate_struct((char *)ptr, len);
		return;

	/* format strings. */
	case 8:
		for (i = 0; i < len; i += 2) {
			ptr[i] = '%';
			switch (RAND_BOOL()) {
			case 0:	ptr[i + 1] = 'd';
				break;
			case 1:	ptr[i + 1] = 's';
				break;
			}
		}
		ptr[rnd() % len] = 0;
		return;
	}
}

void generate_random_page(char *page)
{
	generate_rand_bytes((void *)page, page_size);
}
