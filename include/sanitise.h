#pragma once

#include <stdint.h>
#include <sys/uio.h>
#include <sys/socket.h>

#include "compiler.h"
#include "syscall.h"

void generic_sanitise(struct syscallentry *entry, struct syscallrecord *rec);
void generic_free_arg(struct syscallentry *entry, struct syscallrecord *rec);
void blanket_address_scrub(struct syscallentry *entry, struct syscallrecord *rec);

unsigned long get_interesting_value(void);
unsigned int get_interesting_32bit_value(void);
unsigned long get_boundary_value(void);
unsigned long get_sizeof_boundary_value(void);
unsigned long mutate_value(unsigned long val);
unsigned long shift_flag_bit(unsigned long flag);

unsigned long get_argval(struct syscallrecord *rec, unsigned int argnum);

void *get_address(void);
void *get_non_null_address(void);
void *get_writable_address(unsigned long size);
/*
 * As get_writable_address(), but returns a page-aligned start with a
 * full `size` bytes of reservation above it.  For kernel APIs that
 * round the caller pointer down to PAGE_SIZE (VFIO_IOMMU_MAP_DMA vaddr,
 * anything using iommu_map()-style pinning), so the align-down cannot
 * rewind into the sanitiser's own struct that lives immediately below
 * in the pool.
 */
void *get_writable_page_aligned(unsigned long size);
void *get_writable_struct(size_t size);
/*
 * Output-only redirect: relocate *addr away from shared/heap if it
 * overlaps, without copying the original bytes. Use for buffers the
 * kernel writes (read, recv, getdents, getsockname, …).
 */
void avoid_shared_buffer_out(unsigned long *addr, unsigned long len);
/*
 * Input or value-result redirect: relocate AND memcpy the original
 * bytes into the replacement before rewriting the pointer. Use for
 * buffers the kernel reads from (or both reads and writes).
 */
void avoid_shared_buffer_inout(unsigned long *addr, unsigned long len);
void scrub_iovec_for_kernel_write(struct iovec *iov, unsigned long count);
void scrub_msghdr_for_kernel_write(struct msghdr *msg);
unsigned long find_previous_arg_address(struct syscallentry *entry, struct syscallrecord *rec, unsigned int argnum);

/*
 * Direction the iovec is presented to the kernel:
 *   IOV_KERNEL_READ  - kernel reads bytes from iov_base (writev, sendmsg,
 *                      vmsplice, process_vm_writev). The picker drops
 *                      shapes that would EFAULT a read (SHAPE_NULL,
 *                      SHAPE_INVALID) and the trailing relocation
 *                      preserves the original bytes.
 *   IOV_KERNEL_WRITE - kernel writes bytes into iov_base (readv, recvmsg,
 *                      process_vm_readv, process_madvise). The full shape
 *                      table is in play and the trailing relocation
 *                      discards original bytes.
 */
enum iov_direction {
	IOV_KERNEL_READ,
	IOV_KERNEL_WRITE,
};
struct iovec * alloc_iovec(unsigned int num, enum iov_direction dir) __must_check;
/*
 * One-shot parent-side allocator for alloc_iovec()'s iov[] backing
 * buffer.  Allocates a dedicated UIO_MAXIOV-sized MAP_PRIVATE|MAP_ANON
 * mapping and registers it with the shared-region tracker so the mm-
 * syscall sanitisers refuse fuzzed addresses landing inside it.  Called
 * once from init_shm before any child forks; every forked child
 * inherits the mapping via COW and re-uses the same iov[] buffer for
 * the lifetime of the run.  Exits on mmap failure -- without this
 * buffer trinity cannot generate iovec args at all, matching the
 * fail-loud posture of the other parent-side shared regions.
 */
void alloc_iovec_init(void);
/*
 * One-shot parent-side allocator for get_writable_address()'s backing
 * pool.  Allocates a dedicated MAP_PRIVATE|MAP_ANON region and registers
 * it with the shared-region tracker so the mm-syscall sanitisers refuse
 * fuzzed addresses landing inside it.  Called once from init_shm before
 * any child forks; every forked child inherits the mapping via COW and
 * bump-allocates from it for the lifetime of the run.  Exits on mmap
 * failure -- without this buffer get_writable_address() cannot vend at
 * all.
 */
void writable_pool_init(void);
unsigned long get_len(void);
/*
 * Object-size-relative length draw.  Returns a value from a boundary
 * set capped by objsize so a kernel-WRITES-buffer caller cannot ask
 * the kernel to scribble past the writable region.  objsize == 0 is
 * "no resolvable companion size", and the helper falls back to plain
 * get_len() so the caller still produces a length value.
 */
unsigned long get_len_relative(unsigned long objsize);
unsigned int get_pid(void);
pid_t get_random_pid_from_pool(void);
void register_returned_pid(pid_t pid);
int32_t get_random_key_serial(void);
void register_key_serial(int32_t serial);
int get_random_pkey_id(void);
void register_pkey_obj(int id);
int32_t get_random_timerid(void);
void register_timerid(int32_t tid);
unsigned long get_random_aio_ctx(void);
void register_aio_ctx(unsigned long ctx);
unsigned long seed_aio_ctx_if_empty(void);
int32_t seed_timerid_if_empty(void);
int get_random_sysv_sem(void);
void register_sysv_sem(int semid);
int get_random_sysv_msg(void);
void register_sysv_msg(int msqid);
int get_random_sysv_shm(void);
void register_sysv_shm(int shmid);

enum argtype get_argtype(struct syscallentry *entry, unsigned int argnum);
void generate_syscall_args(struct syscallrecord *rec);
