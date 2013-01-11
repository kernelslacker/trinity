#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include <linux/uio.h>

#include "files.h"
#include "arch.h"
#include "trinity.h"
#include "sanitise.h"
#include "syscall.h"
#include "shm.h"

char * filebuffer = NULL;
unsigned long filebuffersize = 0;

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

	i = rand() % 17;

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
	default:
		BUG("unreachable!\n");
		return 0;
	}
	BUG("unreachable!\n");
	return 0;
#endif
}

static void * _get_address(unsigned char null_allowed)
{
	int i;
	void *addr = NULL;

	if (null_allowed == TRUE)
		i = rand() % 9;
	else
		i = (rand() % 8) + 1;


	switch (i) {
	case 0: addr = NULL;
		break;
	case 1:	addr = (void *) KERNEL_ADDR;
		break;
	case 2:	addr = page_zeros;
		break;
	case 3:	addr = page_0xff;
		break;
	case 4:	addr = page_rand;
		break;
	case 5: addr = page_allocs;
		break;
	case 6:	addr = (void *) get_interesting_value();
		break;
	case 7: addr = get_map();
		break;
	case 8: addr = malloc(page_size * 2);
		break;
	default:
		BUG("unreachable!\n");
		break;
	}

	/*
	 * Most of the time, we just return the address we got above unmunged.
	 * But sometimes, we return an address just before the end of the page.
	 * The idea here is that we might see some bugs that are caused by page boundary failures.
	 */
	i = rand() % 100;
	switch (i) {
	case 0:	addr += (page_size - sizeof(char));
		break;
	case 1:	addr += (page_size - sizeof(int));
		break;
	case 2:	addr += (page_size - sizeof(long));
		break;
	case 3:	addr += (page_size / 2);
		break;
	case 4 ... 99:
	default: break;
	}

	return addr;
}

void * get_address(void)
{
	return _get_address(TRUE);
}

void * get_non_null_address(void)
{
	return _get_address(FALSE);
}

unsigned long get_reg(void)
{
	if ((rand() % 2) == 0)
		return random();

	return get_interesting_value();
}

void fabricate_onepage_struct(char *page)
{
	void *addr;
	unsigned int i, j;

	for (i = 0; i < page_size; i++) {
		j = rand() % 4;
		switch (j) {
		case 0: page[i] = get_interesting_32bit_value();
			i += sizeof(unsigned long);
			break;
		case 1: page[i] = get_interesting_value();
			i += sizeof(unsigned long long);
			break;
		case 2: addr = get_address();
			page[i] = (unsigned long) addr;
			i += sizeof(unsigned long);
			break;
		case 3: page[i] = (unsigned int) rand() % page_size;
			i += sizeof(unsigned int);
			break;
		default:
			BUG("unreachable!\n");
			return;
		}
	}
}

void regenerate_random_page(void)
{
	unsigned int i;
	unsigned int type = rand() % 3;

	/* sometimes return a page that looks kinda like a struct */
	if ((rand() % 100) < 50) {
		fabricate_onepage_struct(page_rand);
		return;
	}

	/* The rest of the time, return a page of complete trash */
	switch (type) {
	case 0:	/* bytes */
		for (i = 0; i < page_size; i++)
			page_rand[i++] = (unsigned char)rand();
		return;

	case 1:	/* ints */
		for (i = 0; i < (page_size / 2); i++) {
			page_rand[i++] = 0;
			page_rand[i++] = (unsigned char)rand();
		}
		return;

	case 2:	/* longs */
		for (i = 0; i < (page_size / 4); i++) {
			page_rand[i++] = 0;
			page_rand[i++] = 0;
			page_rand[i++] = 0;
			page_rand[i++] = (unsigned char)rand();
		}
		return;
	default:
		BUG("unreachable!\n");
		return;
	}
}

static unsigned int get_cpu(void)
{
	int i;
	i = rand() % 3;

	switch (i) {
	case 0: return -1;
	case 1: return rand() & 4095;
	case 2: return rand() & 15;
	default:
		BUG("unreachable!\n");
		break;
	}
	return 0;
}

unsigned long get_len(void)
{
	int i = 0;

	i = get_interesting_value();

	switch(rand() % 6) {

	case 0:	i &= 0xff;
		break;
	case 1: i &= page_size;
		break;
	case 2:	i &= 0xffff;
		break;
	case 3:	i &= 0xffffff;
		break;
	case 4:	i &= 0xffffffff;
		break;
	default:
		// Pass through
		break;
	}

	/* we might get lucky if something is counting ints/longs etc. */
	if (rand() % 100 < 25) {
		switch (rand() % 3) {
		case 0:	i /= sizeof(int);
			break;
		case 1:	i /= sizeof(long);
			break;
		case 2:	i /= sizeof(long long);
			break;
		default:
			break;
		}
	}

	return i;
}

static struct iovec * alloc_iovec(unsigned int num)
{
	struct iovec *iov;
	unsigned int i;

	iov = malloc(num * sizeof(struct iovec));
	if (iov != NULL) {
		for (i = 0; i < num; i++) {
			iov[i].iov_base = malloc(page_size);
			iov[i].iov_len = page_size;
		}
	}
	return iov;
}

static unsigned long find_previous_arg_address(unsigned int argnum, unsigned int call, int childno)
{
	unsigned long addr = 0;

	if (argnum > 1)
		if ((syscalls[call].entry->arg1type == ARG_ADDRESS) ||
		    (syscalls[call].entry->arg1type == ARG_NON_NULL_ADDRESS))
			addr = shm->a1[childno];

	if (argnum > 2)
		if ((syscalls[call].entry->arg2type == ARG_ADDRESS) ||
		    (syscalls[call].entry->arg2type == ARG_NON_NULL_ADDRESS))
			addr = shm->a2[childno];

	if (argnum > 3)
		if ((syscalls[call].entry->arg3type == ARG_ADDRESS) ||
		    (syscalls[call].entry->arg3type == ARG_NON_NULL_ADDRESS))
			addr = shm->a3[childno];

	if (argnum > 4)
		if ((syscalls[call].entry->arg4type == ARG_ADDRESS) ||
		    (syscalls[call].entry->arg4type == ARG_NON_NULL_ADDRESS))
			addr = shm->a4[childno];

	if (argnum > 5)
		if ((syscalls[call].entry->arg5type == ARG_ADDRESS) ||
		    (syscalls[call].entry->arg5type == ARG_NON_NULL_ADDRESS))
			addr = shm->a5[childno];

	return addr;
}

char * get_filename(void)
{
	return fileindex[rand() % files_in_index];
}

static unsigned long fill_arg(int childno, int call, int argnum)
{
	unsigned long i;
	unsigned long mask = 0;
	unsigned long low = 0, high = 0;
	unsigned long addr = 0;
	unsigned int bits;
	unsigned int num = 0;
	const unsigned int *values = NULL;
	enum argtype argtype = 0;
	unsigned long sockaddr = 0, sockaddrlen = 0;

	switch (argnum) {
	case 1:	argtype = syscalls[call].entry->arg1type;
		break;
	case 2:	argtype = syscalls[call].entry->arg2type;
		break;
	case 3:	argtype = syscalls[call].entry->arg3type;
		break;
	case 4:	argtype = syscalls[call].entry->arg4type;
		break;
	case 5:	argtype = syscalls[call].entry->arg5type;
		break;
	case 6:	argtype = syscalls[call].entry->arg6type;
		break;
	default:
		BUG("unreachable!\n");
		return 0;
	}

	switch (argtype) {
	case ARG_UNDEFINED:
	case ARG_RANDOM_INT:
		return (unsigned long)rand();

	case ARG_FD:
		return get_random_fd();
	case ARG_LEN:
		return (unsigned long)get_len();

	case ARG_ADDRESS:
		if ((rand() % 2) == 0)
			return (unsigned long)get_address();

		/* Half the time, we look to see if earlier args were also ARG_ADDRESS,
		 * and munge that instead of returning a new one from get_address() */

		addr = find_previous_arg_address(argnum, call, childno);

		switch (rand() % 4) {
		case 0:	break;	/* return unmodified */
		case 1:	addr++;
			break;
		case 2:	addr+= sizeof(int);
			break;
		case 3:	addr+= sizeof(long);
			break;
		default: BUG("unreachable!\n");
			break;
		}

		return addr;

	case ARG_NON_NULL_ADDRESS:
		return (unsigned long)get_non_null_address();
	case ARG_PID:
		return (unsigned long)get_pid();
	case ARG_RANGE:
		switch (argnum) {
		case 1:	low = syscalls[call].entry->low1range;
			high = syscalls[call].entry->hi1range;
			break;
		case 2:	low = syscalls[call].entry->low2range;
			high = syscalls[call].entry->hi2range;
			break;
		case 3:	low = syscalls[call].entry->low3range;
			high = syscalls[call].entry->hi3range;
			break;
		case 4:	low = syscalls[call].entry->low4range;
			high = syscalls[call].entry->hi4range;
			break;
		case 5:	low = syscalls[call].entry->low5range;
			high = syscalls[call].entry->hi5range;
			break;
		case 6:	low = syscalls[call].entry->low6range;
			high = syscalls[call].entry->hi6range;
			break;
		default:
			BUG("Should never happen.\n");
			break;
		}

		if (high == 0)
			printf("%s forgets to set hirange!\n", syscalls[call].entry->name);

		i = random() % high;
		if (i < low) {
			i += low;
			i &= high;
		}
		return i;

	case ARG_OP:	/* Like ARG_LIST, but just a single value. */
		switch (argnum) {
		case 1:	num = syscalls[call].entry->arg1list.num;
			values = syscalls[call].entry->arg1list.values;
			break;
		case 2:	num = syscalls[call].entry->arg2list.num;
			values = syscalls[call].entry->arg2list.values;
			break;
		case 3:	num = syscalls[call].entry->arg3list.num;
			values = syscalls[call].entry->arg3list.values;
			break;
		case 4:	num = syscalls[call].entry->arg4list.num;
			values = syscalls[call].entry->arg4list.values;
			break;
		case 5:	num = syscalls[call].entry->arg5list.num;
			values = syscalls[call].entry->arg5list.values;
			break;
		case 6:	num = syscalls[call].entry->arg6list.num;
			values = syscalls[call].entry->arg6list.values;
			break;
		default: break;
		}
		mask |= values[rand() % num];
		return mask;

	case ARG_LIST:
		switch (argnum) {
		case 1:	num = syscalls[call].entry->arg1list.num;
			values = syscalls[call].entry->arg1list.values;
			break;
		case 2:	num = syscalls[call].entry->arg2list.num;
			values = syscalls[call].entry->arg2list.values;
			break;
		case 3:	num = syscalls[call].entry->arg3list.num;
			values = syscalls[call].entry->arg3list.values;
			break;
		case 4:	num = syscalls[call].entry->arg4list.num;
			values = syscalls[call].entry->arg4list.values;
			break;
		case 5:	num = syscalls[call].entry->arg5list.num;
			values = syscalls[call].entry->arg5list.values;
			break;
		case 6:	num = syscalls[call].entry->arg6list.num;
			values = syscalls[call].entry->arg6list.values;
			break;
		default: break;
		}
		bits = rand() % num;	/* num of bits to OR */
		for (i=0; i<bits; i++)
			mask |= values[rand() % num];
		return mask;

	case ARG_RANDPAGE:
		if ((rand() % 2) == 0)
			return (unsigned long) page_allocs;
		else
			return (unsigned long) page_rand;

	case ARG_CPU:
		return (unsigned long) get_cpu();

	case ARG_PATHNAME:
		return (unsigned long) get_filename();

	case ARG_IOVEC:
		i = (rand() % 4) + 1;

		switch (argnum) {
		case 1:	if (syscalls[call].entry->arg2type == ARG_IOVECLEN)
				shm->a2[childno] = i;
			break;
		case 2:	if (syscalls[call].entry->arg3type == ARG_IOVECLEN)
				shm->a3[childno] = i;
			break;
		case 3:	if (syscalls[call].entry->arg4type == ARG_IOVECLEN)
				shm->a4[childno] = i;
			break;
		case 4:	if (syscalls[call].entry->arg5type == ARG_IOVECLEN)
				shm->a5[childno] = i;
			break;
		case 5:	if (syscalls[call].entry->arg6type == ARG_IOVECLEN)
				shm->a6[childno] = i;
			break;
		case 6:
		default: BUG("impossible\n");
		}
		return (unsigned long) alloc_iovec(i);

	case ARG_IOVECLEN:
	case ARG_SOCKADDRLEN:
		switch (argnum) {
		case 1:	return(shm->a1[childno]);
		case 2:	return(shm->a2[childno]);
		case 3:	return(shm->a3[childno]);
		case 4:	return(shm->a4[childno]);
		case 5:	return(shm->a5[childno]);
		case 6:	return(shm->a6[childno]);
		default: break;
		}
		;; // fallthrough

	case ARG_SOCKADDR:
		generate_sockaddr(&sockaddr, &sockaddrlen, PF_NOHINT);

		switch (argnum) {
		case 1:	if (syscalls[call].entry->arg2type == ARG_SOCKADDRLEN)
				shm->a2[childno] = sockaddrlen;
			break;
		case 2:	if (syscalls[call].entry->arg3type == ARG_SOCKADDRLEN)
				shm->a3[childno] = sockaddrlen;
			break;
		case 3:	if (syscalls[call].entry->arg4type == ARG_SOCKADDRLEN)
				shm->a4[childno] = sockaddrlen;
			break;
		case 4:	if (syscalls[call].entry->arg5type == ARG_SOCKADDRLEN)
				shm->a5[childno] = sockaddrlen;
			break;
		case 5:	if (syscalls[call].entry->arg6type == ARG_SOCKADDRLEN)
				shm->a6[childno] = sockaddrlen;
			break;
		case 6:
		default: BUG("impossible\n");
		}
		return (unsigned long) sockaddr;


	default:
		BUG("unreachable!\n");
		return 0;
	}

	BUG("unreachable!\n");
	return 0x5a5a5a5a;	/* Should never happen */
}

void generic_sanitise(int childno)
{
	unsigned int call = shm->syscallno[childno];

	if (syscalls[call].entry->arg1type != 0)
		shm->a1[childno] = fill_arg(childno, call, 1);
	if (syscalls[call].entry->arg2type != 0)
		shm->a2[childno] = fill_arg(childno, call, 2);
	if (syscalls[call].entry->arg3type != 0)
		shm->a3[childno] = fill_arg(childno, call, 3);
	if (syscalls[call].entry->arg4type != 0)
		shm->a4[childno] = fill_arg(childno, call, 4);
	if (syscalls[call].entry->arg5type != 0)
		shm->a5[childno] = fill_arg(childno, call, 5);
	if (syscalls[call].entry->arg6type != 0)
		shm->a6[childno] = fill_arg(childno, call, 6);
}
