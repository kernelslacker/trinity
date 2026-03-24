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

		switch (rand() % 3) {
		case 0:
			if (!IS_ALIGNED(i, 8))
				break;

			i += sizeof(unsigned long);
			if (i > len)
				return;

			switch (rand() % 4) {
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
				i += 2;
				if (i > len)
					return;
				*(unsigned char *)ptr = RAND_BYTE();
				*((unsigned char *)ptr + 1) = RAND_BYTE();
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

	switch (rand() % randrange) {
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
			ptr[i] = 32 + rand() % (0x7f - 32);
		break;

	case 6:
		/* ascii representation of random numbers */
		separator = separators[rand() % sizeof(separators)];

		p = (char *) ptr;

		while (p < (char *)(ptr + (len-23))) {		// 23 is the longest case below + separator.
			if (RAND_BOOL()) {
				/* hex */
				switch (rand() % 3) {
				case 0:	p += sprintf(p, "0x%lx", (unsigned long) rand64());
					break;
				case 1:	p += sprintf(p, "0x%08x", (unsigned int) rand32());
					break;
				case 2:	p += sprintf(p, "0x%x", (int) rand32());
					break;
				}
			} else {
				/* decimal */

				/* perhaps negative ?*/
				if (RAND_BOOL())
					p += sprintf(p, "-");

				switch (rand() % 3) {
				case 0:	p += sprintf(p, "%lu", (unsigned long) rand64());
					break;
				case 1:	p += sprintf(p, "%u", (unsigned int) rand32());
					break;
				case 2:	p += sprintf(p, "%u", (unsigned char) rand());
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

	/* format strings targeting kernel printk specifiers. */
	case 8:
		for (i = 0; i + 1 < len; i += 2) {
			ptr[i] = '%';
			switch (rand() % 8) {
			case 0:	ptr[i + 1] = 'd'; break;	/* signed decimal integer */
			case 1:	ptr[i + 1] = 's'; break;	/* string */
			case 2:	ptr[i + 1] = 'x'; break;	/* unsigned hex (lowercase) */
			case 3:	ptr[i + 1] = 'u'; break;	/* unsigned decimal integer */
			case 4:	ptr[i + 1] = 'i'; break;	/* signed decimal integer (alias for %d) */
			case 5:	ptr[i + 1] = 'o'; break;	/* unsigned octal */
			case 6:	ptr[i + 1] = 'c'; break;	/* character */
			case 7:				/* pointer (extensions follow) */
				ptr[i + 1] = 'p';
				/*
				 * Half the time, follow %p with a kernel
				 * pointer extension specifier.  These need
				 * a third byte, so bounds-check first.
				 */
				if (RAND_BOOL() && i + 2 < len) {
					static const char exts[] = {
						'S',	/* symbol+offset */
						's',	/* symbol */
						'B',	/* backtrace symbol */
						'I',	/* IP address */
						'M',	/* MAC address */
						'd',	/* dentry name */
						'D',	/* file path */
						'U',	/* UUID/GUID */
						'K',	/* kernel pointer (restricted) */
						'x',	/* unhashed pointer */
						'e',	/* error pointer */
						'V',	/* va_format */
						'g',	/* block_device name */
						'r',	/* struct resource (numeric) */
						'R',	/* struct resource (decoded) */
						't',	/* time/date */
						'C',	/* struct clk */
						'G',	/* flags bitfield */
						'N',	/* netdev features */
						'O',	/* device tree node */
						'A',	/* Rust fmt::Arguments */
					};
					ptr[i + 2] = exts[rand() % sizeof(exts)];
					i++;
				}
				break;
			}
		}
		ptr[rand() % len] = 0;
		return;
	}
}

void generate_random_page(char *page)
{
	generate_rand_bytes((void *)page, page_size);
}
