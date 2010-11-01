#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include "files.h"
#include "scrashme.h"

#ifdef __x86_64__
#define TASK_SIZE       (0x800000000000UL - 4096)
#endif
#ifdef __i386__
#define PAGE_OFFSET 0xC0000000
#define TASK_SIZE (PAGE_OFFSET)
/*
 * Alternative possibilities for PAGE_OFFSET:
 * default 0xB0000000 if VMSPLIT_3G_OPT
 * default 0x78000000 if VMSPLIT_2G
 * default 0x40000000 if VMSPLIT_1G
 */
#endif
#ifdef __powerpc__
#define PAGE_OFFSET 0xC0000000
#define TASK_SIZE (PAGE_OFFSET)
#endif
#ifdef __ia64__
#define PAGE_OFFSET 0xe000000000000000
#define TASK_SIZE 0xa000000000000000
#endif
#ifdef __sparc__
#ifdef __arch64__
#define TASK_SIZE ~0UL
#else
#define TASK_SIZE 0xF0000000UL
#endif
#endif

static char * filebuffer = NULL;
static unsigned long filebuffersize = 0;

#ifndef S_SPLINT_S
#define __unused __attribute((unused))
#else
#define __unused /*@unused@*/
#endif

static unsigned long get_interesting_value()
{
	int i;

	i = rand() & 10;

	switch (i) {
	/* 32 bit */
	case 0:		return 0x00000001;
	case 1:		return 0x80000000;
	case 2:		return 0x80000001;
	case 3:		return 0x8fffffff;
	case 4:		return 0xf0000000;
	case 5:		return 0xff000000;
	case 6:		return 0xffffffff;

	/* 64 bit */
	case 7:		return 0x0000000100000000;
	case 8:		return 0x0000000100000001;
	case 9:		return 0x00000001ffffffff;

	case 10:	return 0x0000000800000000;
	case 11:	return 0x0000000800000001;
	case 12:	return 0x00000008ffffffff;

	case 13:	return 0x8000000000000000;
	case 14:	return 0x8000000000000001;
	case 15:	return 0x80000000ffffffff;

	case 16:	return 0xffffffff00000000;
	case 17:	return 0xffffffff00000001;
	case 18:	return 0xffffffff7fffffff;
	case 19:	return 0xfffffff7ffffffff;
	case 20:	return 0xffffffffffffffff;
	}
	/* Should never be reached. */
	return 0;
}



static unsigned long fill_arg(int argtype)
{
	int fd;

	switch (argtype) {
	case ARG_FD:
		fd = get_random_fd();
		//printf (YELLOW "DBG: %x" WHITE "\n", fd);
		return fd;
	case ARG_LEN:
		return get_interesting_value();
	}

	return 0x5a5a5a5a;	/* Should never happen */
}


void generic_sanitise(int call,
	unsigned long *a1,
	unsigned long *a2,
	unsigned long *a3,
	unsigned long *a4,
	unsigned long *a5,
	unsigned long *a6)
{
	if (syscalls[call].arg1type != 0)
		*a1 = fill_arg(syscalls[call].arg1type);
	if (syscalls[call].arg2type != 0)
		*a2 = fill_arg(syscalls[call].arg2type);
	if (syscalls[call].arg3type != 0)
		*a3 = fill_arg(syscalls[call].arg3type);
	if (syscalls[call].arg4type != 0)
		*a4 = fill_arg(syscalls[call].arg4type);
	if (syscalls[call].arg5type != 0)
		*a5 = fill_arg(syscalls[call].arg5type);
	if (syscalls[call].arg6type != 0)
		*a6 = fill_arg(syscalls[call].arg6type);

}



/*
 * asmlinkage ssize_t sys_read(unsigned int fd, char __user * buf, size_t count)
 */
void sanitise_read(
		__unused unsigned long *a1,
		unsigned long *a2,
		unsigned long *a3,
		__unused unsigned long *a4,
		__unused unsigned long *a5,
		__unused unsigned long *a6)
{
	unsigned long newsize = (unsigned int) *a3 >> 16;

	if (filebuffer != NULL) {
		if (filebuffersize < newsize) {
			free(filebuffer);
			filebuffersize = 0;
			filebuffer = NULL;
		}
	}

	if (filebuffer == NULL) {
retry:
		printf("Trying to allocate %lu bytes\n", newsize);
		filebuffer = malloc(newsize);
		if (filebuffer == NULL) {
			newsize >>= 1;
			goto retry;
		}
		filebuffersize = newsize;
	}
	*a2 = (unsigned long) filebuffer;
	*a3 = newsize;
	memset(filebuffer, 0, newsize);
}

/*
 * asmlinkage ssize_t sys_write(unsigned int fd, char __user * buf, size_t count)
 */
void sanitise_write(
		__unused unsigned long *a1,
		unsigned long *a2,
		unsigned long *a3,
		__unused unsigned long *a4,
		__unused unsigned long *a5,
		__unused unsigned long *a6)
{
	unsigned long newsize = *a3 & 0xffff;
	void *newbuffer;

retry:
	newbuffer = malloc(newsize);
	if (newbuffer == NULL) {
		newsize >>= 1;
		goto retry;
	}

	free(filebuffer);
	filebuffer = newbuffer;
	filebuffersize = newsize;

	*a2 = (unsigned long) filebuffer;
	*a3 = newsize;
}


/*
 * sys_mprotect(unsigned long start, size_t len, unsigned long prot)
 */
#include <sys/mman.h>
#define PROT_SEM    0x8

void sanitise_mprotect(
		unsigned long *a1,
		unsigned long *a2,
		unsigned long *a3,
		__unused unsigned long *a4,
		__unused unsigned long *a5,
		__unused unsigned long *a6)
{
	unsigned long end;
	unsigned long mask = ~(page_size-1);
	int grows;

retry_prot:
	grows = *a3 & (PROT_GROWSDOWN|PROT_GROWSUP);
	if (grows == (PROT_GROWSDOWN|PROT_GROWSUP)) {
		*a3 = rand();
		goto retry_prot;
	}
	if (*a3 & ~(PROT_READ | PROT_WRITE | PROT_EXEC | PROT_SEM)) {
		*a3 = rand();
		goto retry_prot;
	}

retry_start:
	if (*a1 & ~mask) {
		*a1 &= mask;
		goto retry_start;
	}

	/* End must be after start */
retry_end:
	end = *a1 + *a2;
	if (end <= *a1) {
		*a2 *= 2;
		goto retry_end;
	}
}


/*
 * asmlinkage long sys_rt_sigaction(int sig,
          const struct sigaction __user *act,
          struct sigaction __user *oact,
          size_t sigsetsize)
 */
#include <signal.h>

void sanitise_rt_sigaction(
		__unused unsigned long *a1,
		__unused unsigned long *a2,
		__unused unsigned long *a3,
		unsigned long *a4,
		__unused unsigned long *a5,
		__unused unsigned long *a6)
{
	*a4 = sizeof(sigset_t);
}

/*
 * asmlinkage long
 sys_rt_sigprocmask(int how, sigset_t __user *set, sigset_t __user *oset, size_t sigsetsize)
 */
void sanitise_rt_sigprocmask(
		__unused unsigned long *a1,
		__unused unsigned long *a2,
		__unused unsigned long *a3,
		unsigned long *a4,
		__unused unsigned long *a5,
		__unused unsigned long *a6)
{
	*a4 = sizeof(sigset_t);
}


/*
 * asmlinkage ssize_t sys_pread64(unsigned int fd, char __user *buf,
				                 size_t count, loff_t pos)
 */
void sanitise_pread64(
		__unused unsigned long *a1,
		__unused unsigned long *a2,
		__unused unsigned long *a3,
		unsigned long *a4,
		__unused unsigned long *a5,
		__unused unsigned long *a6)
{

retry_pos:
	if ((int)*a4 < 0) {
		*a4 = rand();
		goto retry_pos;
	}
}

/*
 * asmlinkage ssize_t sys_pwrite64(unsigned int fd, char __user *buf,
				                 size_t count, loff_t pos)
 */
void sanitise_pwrite64(
		__unused unsigned long *a1,
		__unused unsigned long *a2,
		__unused unsigned long *a3,
		unsigned long *a4,
		__unused unsigned long *a5,
		__unused unsigned long *a6)
{

retry_pos:
	if ((int)*a4 < 0) {
		*a4 = rand();
		goto retry_pos;
	}
}



/*
 * asmlinkage unsigned long sys_mremap(unsigned long addr,
 *   unsigned long old_len, unsigned long new_len,
 *   unsigned long flags, unsigned long new_addr)
 *
 * This syscall is a bit of a nightmare to fuzz as we -EINVAL all over the place.
 * It might be more useful once we start passing around valid maps instead of just
 * trying random addresses.
 */
#include <linux/mman.h>

void sanitise_mremap(
		unsigned long *addr,
		__unused unsigned long *old_len,
		unsigned long *new_len,
		unsigned long *flags,
		unsigned long *new_addr,
		__unused unsigned long *a6)
{
	unsigned long mask = ~(page_size-1);
	int i;

	*flags = rand()	& ~(MREMAP_FIXED | MREMAP_MAYMOVE);

	*addr &= mask;

	i=0;
	if (*flags & MREMAP_FIXED) {
		*flags &= ~MREMAP_MAYMOVE;
		*new_len &= TASK_SIZE-*new_len;
retry_addr:
		*new_addr &= mask;
		if ((*new_addr <= *addr) && (*new_addr+*new_len) > *addr) {
			*new_addr -= *addr - rand() % 1000;
			goto retry_addr;
		}

		if ((*addr <= *new_addr) && (*addr+*old_len) > *new_addr) {
			*new_addr += *addr - rand() % 1000;
			goto retry_addr;
		}

		/* new_addr > TASK_SIZE - new_len*/
retry_tasksize_end:
		if (*new_addr > TASK_SIZE - *new_len) {
			*new_addr >>= 1;
			i++;
			goto retry_tasksize_end;
		}
		printf("retried_tasksize_end: %d\n", i);
	}

	//TODO: Lots more checks here.
	// We already check for overlap in do_mremap()
}

/*
 * asmlinkage long sys_splice(int fd_in, loff_t __user *off_in, int fd_out, loff_t __user *off_out, size_t len, unsigned int flags)
 *
 * : len must be > 0
 * : fdin & fdout must be file handles
 *
 */
void sanitise_splice(
		unsigned long *a1,
		__unused unsigned long *a2,
		unsigned long *a3,
		__unused unsigned long *a4,
		__unused unsigned long *a5,
		__unused unsigned long *a6)
{
	/* first param is fdin */
	*a1 = get_pipe_fd();

	/* third param is fdout */
	*a3 = get_pipe_fd();
}


/*
 * asmlinkage long sys_sync_file_range(int fd, loff_t offset, loff_t nbytes, unsigned int flags)
 * flags must be part of VALID_FLAGS (SYNC_FILE_RANGE_WAIT_BEFORE|SYNC_FILE_RANGE_WRITE| SYNC_FILE_RANGE_WAIT_AFTER)
 */

#define SYNC_FILE_RANGE_WAIT_BEFORE 1
#define SYNC_FILE_RANGE_WRITE       2
#define SYNC_FILE_RANGE_WAIT_AFTER  4

#define VALID_SFR_FLAGS (SYNC_FILE_RANGE_WAIT_BEFORE|SYNC_FILE_RANGE_WRITE|SYNC_FILE_RANGE_WAIT_AFTER)

void sanitise_sync_file_range(
		__unused unsigned long *fd,
		long *offset,
		long *nbytes,
		unsigned long *flags,
		__unused unsigned long *a5,
		__unused unsigned long *a6)
{

retry_flags:
	if (*flags & ~VALID_SFR_FLAGS) {
		*flags = rand() & VALID_SFR_FLAGS;
		goto retry_flags;
	}

retry_offset:
	if (*offset < 0) {
		*offset = rand();
		goto retry_offset;
	}

	if (*offset+*nbytes < 0)
		goto retry_offset;

	if (*offset+*nbytes < *offset)
		goto retry_offset;
}

/*
 * asmlinkage long sys_set_robust_list(struct robust_list_head __user *head,
 *           size_t len)
*/
struct robust_list {
	struct robust_list *next;
};
struct robust_list_head {
	struct robust_list list;
	long futex_offset;
	struct robust_list *list_op_pending;
};

void sanitise_set_robust_list(
	__unused unsigned long *a1,
	unsigned long *len,
	__unused unsigned long *a3,
	__unused unsigned long *a4,
	__unused unsigned long *a5,
	__unused unsigned long *a6)
{
	*len = sizeof(struct robust_list_head);
}


/*
 * asmlinkage long sys_vmsplice(int fd, const struct iovec __user *iov,
 *                unsigned long nr_segs, unsigned int flags)
 */

void sanitise_vmsplice(
	unsigned long *fd,
	__unused unsigned long *a2,
	__unused unsigned long *a3,
	__unused unsigned long *a4,
	__unused unsigned long *a5,
	__unused unsigned long *a6)
{
new_a3:	*a3 = random();
	if (*a3 > 1024)	/* UIO_MAXIOV */
		goto new_a3;

	*fd = get_pipe_fd();
}

#include <sys/types.h>
#include <sys/socket.h>
void sanitise_sendto(unsigned long *fd,
	__unused unsigned long *buff,
	__unused unsigned long *len,
	__unused unsigned long *flags,
	unsigned long *addr,
	unsigned long *addr_len)
{
	int domain, type, protocol;
retry:
	domain = random() % 34;
	type = random() % 10;
	protocol = random();

	*fd = socket(domain, type, protocol);
	if (*fd == -1UL)
		goto retry;

	*addr = (unsigned long)useraddr;

	*addr_len %= 128;	// MAX_SOCK_ADDR
}
