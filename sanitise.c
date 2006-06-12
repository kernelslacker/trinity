#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include "files.h"

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

static char * filebuffer = NULL;
static unsigned long filebuffersize = 0;

#ifndef S_SPLINT_S
#define __unused __attribute((unused))
#else
#define __unused /*@unused@*/
#endif

/*
 * asmlinkage ssize_t sys_read(unsigned int fd, char __user * buf, size_t count)
 */
void sanitise_read(
		unsigned long *a1,
		unsigned long *a2,
		unsigned long *a3,
		__unused unsigned long *a4,
		__unused unsigned long *a5,
		__unused unsigned long *a6)
{
	unsigned long newsize = ((unsigned int) *a3) >>8;

	*a1 = get_random_fd();

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
		unsigned long *a1,
		unsigned long *a2,
		unsigned long *a3,
		__unused unsigned long *a4,
		__unused unsigned long *a5,
		__unused unsigned long *a6)
{
	unsigned long newsize = *a3 & 0xffff;
	void *newbuffer;

	*a1 = get_random_fd();

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
 * asmlinkage long sys_open(const char __user *filename, int flags, int mode)
 * TODO: Create a helper to pass in some filenames of real files.
 */

/*
 * asmlinkage long sys_close(unsigned int fd)
 */
void sanitise_close(
		unsigned long *a1,
		__unused unsigned long *a2,
		__unused unsigned long *a3,
		__unused unsigned long *a4,
		__unused unsigned long *a5,
		__unused unsigned long *a6)
{
	*a1 = get_random_fd();
}


/*
 * asmlinkage long sys_newstat(char __user *filename, struct stat __user *statbuf)
 */

/*
 * asmlinkage long sys_newfstat(unsigned int fd, struct stat __user *statbuf)
 */
void sanitise_newfstat(
		unsigned long *a1,
		__unused unsigned long *a2,
		__unused unsigned long *a3,
		__unused unsigned long *a4,
		__unused unsigned long *a5,
		__unused unsigned long *a6)
{
	*a1 = get_random_fd();
}


/*
 * asmlinkage long sys_newlstat(char __user *filename, struct stat __user *statbuf)
 */

/*
 * asmlinkage long sys_poll(struct pollfd __user *ufds, unsigned int nfds,
             long timeout_msecs)
 */

/*
 * asmlinkage off_t sys_lseek(unsigned int fd, off_t offset, unsigned int origin)
 */
void sanitise_lseek(
		unsigned long *a1,
		__unused unsigned long *a2,
		__unused unsigned long *a3,
		__unused unsigned long *a4,
		__unused unsigned long *a5,
		__unused unsigned long *a6)
{
	*a1 = get_random_fd();
}

/*
 * asmlinkage long sys_mmap(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags,
   unsigned long fd, unsigned long off)
 */
void sanitise_mmap(
		__unused unsigned long *a1,
		__unused unsigned long *a2,
		__unused unsigned long *a3,
		__unused unsigned long *a4,
		unsigned long *a5,
		__unused unsigned long *a6)
{
	*a5 = get_random_fd();
}

/*
 * sys_mprotect(unsigned long start, size_t len, unsigned long prot)
 */
#include <sys/mman.h>
#include <asm/page.h>
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
	if (*a1 & ~PAGE_MASK) {
		*a1 &= PAGE_MASK;
		goto retry_start;
	}

	/* len must be >0 */
retry_len:
	if (*a2 == 0) {
		*a2 = rand();
		goto retry_len;
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
 * asmlinkage long sys_munmap(unsigned long addr, size_t len)
 */

/*
 * asmlinkage unsigned long sys_brk(unsigned long brk)
 */

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
 * asmlinkage int sys_rt_sigreturn(unsigned long __unused)
 */

/*
 * asmlinkage long sys_ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
 */
void sanitise_ioctl(
		unsigned long *a1,
		__unused unsigned long *a2,
		__unused unsigned long *a3,
		__unused unsigned long *a4,
		__unused unsigned long *a5,
		__unused unsigned long *a6)
{
	*a1 = get_random_fd();
}

/*
 * asmlinkage ssize_t sys_pread64(unsigned int fd, char __user *buf,
				                 size_t count, loff_t pos)
 */
void sanitise_pread64(
		unsigned long *a1,
		__unused unsigned long *a2,
		__unused unsigned long *a3,
		unsigned long *a4,
		__unused unsigned long *a5,
		__unused unsigned long *a6)
{
	*a1 = get_random_fd();

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
		unsigned long *a1,
		__unused unsigned long *a2,
		__unused unsigned long *a3,
		unsigned long *a4,
		__unused unsigned long *a5,
		__unused unsigned long *a6)
{
	*a1 = get_random_fd();

retry_pos:
	if ((int)*a4 < 0) {
		*a4 = rand();
		goto retry_pos;
	}
}

/*
 * asmlinkage ssize_t
 * sys_readv(unsigned long fd, const struct iovec __user *vec, unsigned long vlen)
 */
void sanitise_readv(
		unsigned long *a1,
		__unused unsigned long *a2,
		__unused unsigned long *a3,
		__unused unsigned long *a4,
		__unused unsigned long *a5,
		__unused unsigned long *a6)
{
	*a1 = get_random_fd();
}

/*
 * asmlinkage ssize_t
 * sys_writev(unsigned long fd, const struct iovec __user *vec, unsigned long vlen)
 */
void sanitise_writev(
		unsigned long *a1,
		__unused unsigned long *a2,
		__unused unsigned long *a3,
		__unused unsigned long *a4,
		__unused unsigned long *a5,
		__unused unsigned long *a6)
{
	*a1 = get_random_fd();
}

/*
 * asmlinkage long sys_access(const char __user *filename, int mode)
 */

/*
 * asmlinkage long sys_pipe(int __user *fildes)
 */

/*
 * asmlinkage long sys_select(int n, fd_set __user *inp, fd_set __user *outp,
             fd_set __user *exp, struct timeval __user *tvp)
 */

/*
 * asmlinkage long sys_sched_yield(void)
 */

/*
 * asmlinkage unsigned long sys_mremap(unsigned long addr,
 *   unsigned long old_len, unsigned long new_len,
 *   unsigned long flags, unsigned long new_addr)
 */
#include <linux/mman.h>

void sanitise_mremap(
		unsigned long *a1,
		__unused unsigned long *a2,
		unsigned long *a3,
		unsigned long *a4,
		unsigned long *a5,
		__unused unsigned long *a6)
{
retry_flags:
	if (*a4 & ~(MREMAP_FIXED | MREMAP_MAYMOVE)) {
		*a4 = rand();
		goto retry_flags;
	}

retry_addr:
	if (*a1 & ~PAGE_MASK) {
		*a1 &= PAGE_MASK;
		goto retry_addr;
	}

retry_newlen:
	if (!*a3) {
		*a3 = rand();
		goto retry_newlen;
	}

	if (*a4 & MREMAP_FIXED) {
		*a5 &= PAGE_MASK;

		if (!(*a4 & MREMAP_MAYMOVE))
			*a4 &= ~MREMAP_MAYMOVE;

		if (*a3 > TASK_SIZE)	/* new_len > TASK_SIZE */
			*a3 &= TASK_SIZE;

		/* new_addr > TASK_SIZE - new_len*/
retry_tasksize_end:
		if (*a5 > TASK_SIZE - *a3) {
			*a5 -= rand();
			goto retry_tasksize_end;
		}
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
	*a1 = get_random_fd();

	/* third param is fdout */
	*a3 = get_random_fd();

	/* Returns 0 if !len */
retry:
	if (*a5 == 0) {
		*a5 = rand();
		goto retry;
	}
}

/*
 * asmlinkage long sys_tee(int fdin, int fdout, size_t len, unsigned int flags)
 *
 * : len must be > 0
 * : fdin & fdout must be file handles
 *
 */
void sanitise_tee(
		unsigned long *a1,
		unsigned long *a2,
		__unused unsigned long *a3,
		__unused unsigned long *a4,
		__unused unsigned long *a5,
		__unused unsigned long *a6)
{
	/* first param is fdin */
	*a1 = get_random_fd();

	/* second param is fdout */
	*a2 = get_random_fd();
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
		unsigned long *fd,
		long *offset,
		long *nbytes,
		unsigned long *flags,
		__unused unsigned long *a5,
		__unused unsigned long *a6)
{
	*fd = get_random_fd();

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
	*fd = get_random_fd();
}
