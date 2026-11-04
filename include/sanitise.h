#pragma once

#include <stdint.h>
#include <sys/uio.h>
#include <sys/socket.h>

#include "compiler.h"
#include "kernel/compat.h"
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
/* Size of the pool get_writable_address() and its siblings vend from. */
#define WRITABLE_POOL_BYTES   (1UL << 20)   /* 1 MiB */
/*
 * @size bytes of scratch from the pool the current call reaches: the low
 * pool while this_child()'s record is compat, since its kernel reads each
 * pointer slot as its low 32 bits, and the writable pool otherwise.
 */
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
 * True iff len is non-zero and [addr, addr + len) lies wholly inside the
 * writable pool, so a pointer that passes is mapped, writable scratch.
 * Always false before writable_pool_init().  range_in_tracked_shared()
 * is no substitute: it also admits trinity's own shared state and the
 * sibling childdata mappings frozen read-only.
 */
bool range_in_writable_pool(unsigned long addr, unsigned long len);
/*
 * True iff [addr, addr + len) is scratch a call's buffers come from: wholly
 * inside the writable pool, or starting in the low pool, which ends at a
 * guard page.  The iovec scrubs leave such an entry for a kernel write.
 */
bool range_in_call_pools(unsigned long addr, unsigned long len);
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
void scrub_compat_iovec_for_kernel_write(struct compat_iovec *iov,
					 unsigned long count);
void scrub_msghdr_for_kernel_write(struct msghdr *msg);
void scrub_compat_msghdr_for_kernel_write(struct compat_msghdr *msg);

/*
 * Layout-aware iovec access for arrays whose entry width follows the
 * call's ABI: a compat call's kernel reads 8-byte struct compat_iovec
 * entries from the MAP_32BIT pool twin, a native call's 16-byte struct
 * iovec entries.  Walkers, scrubs and collapses over an ARG_IOVEC
 * array must go through these with the record's do32bit, never by
 * casting to struct iovec: a native stride over a compat array reads
 * entry 512 of a full array on the last pool slice off the slice, on
 * the guard page, and writes the next entry's base with each entry's
 * length.  scrub_iovec_for_kernel_write_layout() dispatches to the
 * matching scrub twin.  The accessors read and write one entry at
 * its ABI width and stride; an index past UIO_MAXIOV reads zero and
 * writes nothing, since no array a walker may touch is longer.
 * A setter under the compat layout fails closed on a value the
 * 32-bit field cannot carry: a base past UINT_MAX zeroes the entry,
 * a length past UINT_MAX clamps to UINT_MAX.
 */
void scrub_iovec_for_kernel_write_layout(void *iov, unsigned long count,
					 bool do32bit);
unsigned long iovec_entry_base(const void *iov, unsigned long idx,
			       bool do32bit);
unsigned long iovec_entry_len(const void *iov, unsigned long idx,
			      bool do32bit);
void iovec_set_entry(void *iov, unsigned long idx, unsigned long base,
		     unsigned long len, bool do32bit);
void iovec_set_entry_len(void *iov, unsigned long idx, unsigned long len,
			 bool do32bit);
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
 * Compat twin of alloc_iovec(): carves struct compat_iovec arrays
 * from a MAP_32BIT pool twin so a compat call's kernel reads the
 * 8-byte entries at an address its 32-bit pointer reaches.  Every
 * entry base is checked to fit in 32 bits at fill time; a base that
 * does not fit drops that entry to NULL / 0 rather than truncating
 * it to a different mapping.  NULL when the compat pool was never
 * initialised (non-biarch builds have no compat calls).
 */
struct compat_iovec * alloc_compat_iovec(unsigned int num,
					 enum iov_direction dir) __must_check;
void alloc_compat_iovec_init(void);
/*
 * One-shot parent-side allocator for alloc_iovec()'s iov[] backing
 * buffer.  Allocates a dedicated UIO_MAXIOV-sized MAP_PRIVATE|MAP_ANON
 * mapping, with a PROT_NONE guard page behind it, and registers the
 * mapping with the shared-region tracker so the mm-syscall sanitisers
 * refuse fuzzed addresses landing inside it.  Called
 * once from init_shm before any child forks; every forked child
 * inherits the mapping via COW and re-uses the same iov[] buffer for
 * the lifetime of the run.  Exits on mmap failure -- without this
 * buffer trinity cannot generate iovec args at all, matching the
 * fail-loud posture of the other parent-side shared regions.
 */
void alloc_iovec_init(void);
/*
 * True iff len is non-zero and [addr, addr + len) lies wholly inside the
 * pool alloc_iovec() carves its arrays from.  Always false before
 * alloc_iovec_init().
 */
bool range_in_iovec_pool(unsigned long addr, unsigned long len);
/*
 * One-shot parent-side allocator for get_writable_address()'s backing
 * pool.  Allocates a dedicated MAP_PRIVATE|MAP_ANON region, with a
 * PROT_NONE guard page behind it, and registers the region with the
 * shared-region tracker so the mm-syscall sanitisers refuse
 * fuzzed addresses landing inside it.  Called once from init_shm before
 * any child forks; every forked child inherits the mapping via COW and
 * bump-allocates from it for the lifetime of the run.  Exits on mmap
 * failure -- without this buffer get_writable_address() cannot vend at
 * all.
 */
void writable_pool_init(void);
/*
 * One-shot parent-side allocator for the low pool: the writable pool's
 * twin, with its size, guard page and tracking, but made MAP_32BIT, below
 * 2 GiB, on the one arch with compat calls.  Called from init_shm before
 * any child forks.  Exits on mmap failure, as writable_pool_init() does:
 * every buffer a compat call is built with comes from it.
 */
void low_pool_init(void);
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
