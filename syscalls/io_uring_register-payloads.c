/*
 * Per-opcode payload builders for io_uring_register(2).  Split out of
 * syscalls/io_uring_register.c via io_uring_register-internal.h so the
 * builder family compiles in parallel with the dispatch/sanitise/post
 * core.  The builders touch no file-statics in io_uring_register.c.
 */
#include <limits.h>
#include <sched.h>
#include <string.h>
#include "arch.h"
#include "kernel/io_uring.h"
#include "objects.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"
#include "io_uring_register-internal.h"

/*
 * Hard ceiling for the trinity-side flex-array allocation count in
 * IORING_REGISTER_RESTRICTIONS.  Independent of the rnd bound used to
 * pick nr_res so the sizeof() multiply cannot overflow size_t if that
 * bound is ever widened past a sane fuzz value.
 */
#define TRINITY_IO_URING_NR_RES_MAX	16

/*
 * IORING_REGISTER_BUFFERS: arg = struct iovec[], nr_args = count.
 * Kernel iterates the array copying each iovec from userspace.
 * IORING_UNREGISTER_BUFFERS takes no arg.
 */
struct ioring_register_payload ioring_reg_buffers_payload(unsigned int opcode)
{
	struct ioring_register_payload p = { 0, 0, 0 };
	unsigned int nr;

	if (opcode == IORING_UNREGISTER_BUFFERS)
		return p;

	nr = 1 + (rnd_modulo_u32(8));
	p.arg = (unsigned long) alloc_iovec(nr, IOV_KERNEL_WRITE);
	p.nr = nr;
	p.len = nr * sizeof(struct iovec);
	return p;
}

/*
 * IORING_REGISTER_FILES: arg = int[] of fds, nr_args = count.
 * Use -1 as placeholder; kernel accepts sparse sets with -1 holes.
 * IORING_UNREGISTER_FILES takes no arg.
 */
struct ioring_register_payload ioring_reg_files_payload(unsigned int opcode)
{
	struct ioring_register_payload p = { 0, 0, 0 };
	unsigned int nr;
	void *buf;

	if (opcode == IORING_UNREGISTER_FILES)
		return p;

	nr = 1 + (rnd_modulo_u32(16));
	buf = get_writable_struct(nr * sizeof(int));
	if (buf)
		memset(buf, 0xff, nr * sizeof(int));  /* fill with -1 */
	p.arg = (unsigned long) buf;
	p.nr = nr;
	p.len = nr * sizeof(int);
	return p;
}

/*
 * IORING_REGISTER_EVENTFD / IORING_REGISTER_EVENTFD_ASYNC:
 * arg = int *eventfd_fd, nr_args = 1.  Seed *u with a real eventfd
 * from the OBJ_FD_EVENTFD pool ~75% of the time so io_eventfd_register
 * reaches eventfd_ctx_fdget() rather than -EBADF'ing on a garbage fd;
 * the rest of the time inject a random int32 to walk the validator's
 * "wrong fd type / closed fd" reject paths.  IORING_UNREGISTER_EVENTFD
 * takes no arg.
 */
struct ioring_register_payload ioring_reg_eventfd_payload(unsigned int opcode)
{
	struct ioring_register_payload p = { 0, 0, 0 };
	int *u;

	if (opcode == IORING_UNREGISTER_EVENTFD)
		return p;

	u = (int *) get_writable_struct(sizeof(int));
	if (u) {
		if ((rnd_modulo_u32(4)) != 0) {
			int efd = get_typed_fd(ARG_FD_EVENTFD);
			*u = (efd >= 0) ? efd : (int) rnd_u32();
		} else {
			*u = (int) rnd_u32();
		}
	}
	p.arg = (unsigned long) u;
	p.nr = 1;
	p.len = sizeof(int);
	return p;
}

/*
 * IORING_REGISTER_PROBE: arg = struct io_uring_probe with trailing
 * ops[], nr_args = number of op slots.
 */
struct ioring_register_payload ioring_reg_probe_payload(void)
{
	struct ioring_register_payload p;
	struct io_uring_probe *probe;
	unsigned int nr = IORING_OP_LAST;

	probe = (struct io_uring_probe *)
		get_writable_struct(sizeof(*probe) +
				    nr * sizeof(probe->ops[0]));
	if (probe)
		memset(probe, 0, sizeof(*probe) + nr * sizeof(probe->ops[0]));
	p.arg = (unsigned long) probe;
	p.nr = nr;
	p.len = sizeof(*probe) + nr * sizeof(probe->ops[0]);
	return p;
}

/*
 * IORING_REGISTER_PERSONALITY / IORING_UNREGISTER_PERSONALITY: no arg.
 */
struct ioring_register_payload ioring_reg_personality_payload(void)
{
	struct ioring_register_payload p = { 0, 0, 0 };
	return p;
}

/*
 * IORING_REGISTER_RESTRICTIONS (task-scoped via the blind fd == -1
 * path): arg = struct io_uring_task_restriction with a flex-array of
 * struct io_uring_restriction[nr_res], nr_args = 1.  flags must be 0
 * and the resv slot must be all-zero or io_register_restrictions_task
 * bails at -EINVAL.  Allocate room for a small nr_res so
 * io_parse_restrictions actually iterates the array; zeroed entries
 * still walk the parser.  The real-fd RESTRICTIONS path takes a flat
 * array shape and reaches this case too -- a zeroed io_uring_task_-
 * restriction overlays cleanly onto a single zero io_uring_restriction
 * (both paths read sane payloads from the same buffer).
 */
struct ioring_register_payload ioring_reg_restrictions_payload(void)
{
	struct ioring_register_payload p;
	struct trinity_io_uring_task_restriction *tr;
	unsigned int nr_res = min(rnd_modulo_u32(4),
			(unsigned int) TRINITY_IO_URING_NR_RES_MAX);
	size_t sz = sizeof(*tr) +
		nr_res * sizeof(struct trinity_io_uring_restriction);

	tr = (struct trinity_io_uring_task_restriction *)
		get_writable_struct(sz);
	if (tr) {
		memset(tr, 0, sz);
		tr->nr_res = nr_res;
	}
	p.arg = (unsigned long) tr;
	p.nr = 1;
	p.len = sz;
	return p;
}

/*
 * IORING_REGISTER_IOWQ_AFF: arg = cpu_set_t *, nr_args = sizeof(cpu_set_t).
 * Build a small valid affinity mask (a couple of bits set on online CPUs)
 * so io_register_iowq_aff's cpumask_parse / cpumask_subset checks pass
 * and the call reaches io_wq_cpu_affinity().  Skip memset -- the
 * cpu_set_t bit layout matters for the cpumask validator.
 *
 * IORING_REGISTER_IOWQ_MAX_WORKERS: arg = uint[2] (bounded/unbounded),
 * nr_args = 2.
 *
 * IORING_UNREGISTER_IOWQ_AFF: no arg.
 */
struct ioring_register_payload ioring_reg_iowq_payload(unsigned int opcode)
{
	struct ioring_register_payload p = { 0, 0, 0 };
	void *buf;

	switch (opcode) {
	case IORING_UNREGISTER_IOWQ_AFF:
		return p;

	case IORING_REGISTER_IOWQ_MAX_WORKERS:
		buf = get_writable_struct(2 * sizeof(unsigned int));
		if (buf)
			memset(buf, 0, 2 * sizeof(unsigned int));
		p.arg = (unsigned long) buf;
		p.nr = 2;
		p.len = 2 * sizeof(unsigned int);
		return p;

	case IORING_REGISTER_IOWQ_AFF: {
		cpu_set_t *cs = (cpu_set_t *) get_writable_address(sizeof(cpu_set_t));
		if (cs) {
			unsigned int n = num_online_cpus ? num_online_cpus : 1;
			unsigned int i, k = 1 + (rnd_modulo_u32(3));
			CPU_ZERO(cs);
			for (i = 0; i < k; i++)
				CPU_SET(rnd_modulo_u32(n), cs);
		}
		p.arg = (unsigned long) cs;
		p.nr = sizeof(cpu_set_t);
		p.len = sizeof(cpu_set_t);
		return p;
	}
	}
	return p;
}

/*
 * IORING_REGISTER_NAPI / IORING_UNREGISTER_NAPI:
 * arg = struct io_uring_napi, nr_args = 0.  Default opcode field
 * to IO_URING_NAPI_REGISTER_OP (0) so io_register_napi reaches
 * io_napi_register_napi() rather than rejecting at the opcode
 * switch.  Occasionally fuzz the opcode/tracking-strategy fields.
 */
struct ioring_register_payload ioring_reg_napi_payload(void)
{
	struct ioring_register_payload p;
	struct trinity_io_uring_napi *n;

	n = (struct trinity_io_uring_napi *)
		get_writable_struct(sizeof(*n));
	if (n) {
		memset(n, 0, sizeof(*n));
		n->busy_poll_to = rnd_modulo_u32(1000);
		n->prefer_busy_poll = rnd_u32() & 1;
		n->opcode = (rnd_modulo_u32(8) == 0) ? rnd_u32() & 0xff : 0;
		n->op_param = rnd_u32();
	}
	p.arg = (unsigned long) n;
	p.nr = 0;
	p.len = sizeof(*n);
	return p;
}

/*
 * IORING_REGISTER_FILE_ALLOC_RANGE: arg = struct io_uring_file_index_range,
 * nr_args = 0.  Kernel rejects nr_args != 0 before dispatch, so the
 * default catch-all (which sets nr_args = 1) never reaches the handler
 * body.  Bias off/len against a small registered file table; 1-in-32
 * inject INT_MAX to probe arithmetic overflow checks in the range
 * allocator.
 */
struct ioring_register_payload ioring_reg_file_alloc_range_payload(void)
{
	struct ioring_register_payload p;
	struct trinity_io_uring_file_index_range *r;

	r = (struct trinity_io_uring_file_index_range *)
		get_writable_struct(sizeof(*r));
	if (r) {
		memset(r, 0, sizeof(*r));
		if ((rnd_modulo_u32(32)) == 0) {
			r->off = INT_MAX;
			r->len = INT_MAX;
		} else {
			r->off = rnd_modulo_u32(16);
			r->len = 1 + (rnd_modulo_u32(16));
		}
	}
	p.arg = (unsigned long) r;
	p.nr = 0;
	p.len = sizeof(*r);
	return p;
}

/*
 * IORING_REGISTER_CLOCK: arg = struct io_uring_clock_register,
 * nr_args = 0.  Same nr_args == 0 gate as FILE_ALLOC_RANGE.  75% of
 * the time pick a clockid the kernel's io_register_clock will accept
 * (CLOCK_MONOTONIC / CLOCK_BOOTTIME -- CLOCK_REALTIME is rejected by
 * the validator but exercises that reject path); 25% garbage to
 * exercise the validator.  1-in-16 leave a non-zero __resv slot to
 * exercise the memchr_inv reject path.  Hard-code the clockid values
 * (0/1/7 from uapi/linux/time.h) to keep trinity hermetic against
 * <time.h> enum drift.
 */
struct ioring_register_payload ioring_reg_clock_payload(void)
{
	static const __s32 valid_clockids[] = {
		0,	/* CLOCK_REALTIME */
		1,	/* CLOCK_MONOTONIC */
		7,	/* CLOCK_BOOTTIME */
	};
	struct ioring_register_payload p;
	struct trinity_io_uring_clock_register *cr;

	cr = (struct trinity_io_uring_clock_register *)
		get_writable_struct(sizeof(*cr));
	if (cr) {
		memset(cr, 0, sizeof(*cr));
		if ((rnd_modulo_u32(4)) == 0)
			cr->clockid = rnd_u32();
		else
			cr->clockid = valid_clockids[rnd_modulo_u32(ARRAY_SIZE(valid_clockids))];
		if ((rnd_modulo_u32(16)) == 0)
			cr->__resv[rnd_modulo_u32(3)] = rnd_u32();
	}
	p.arg = (unsigned long) cr;
	p.nr = 0;
	p.len = sizeof(*cr);
	return p;
}

/*
 * IORING_REGISTER_RING_FDS / IORING_UNREGISTER_RING_FDS:
 * arg = struct io_uring_rsrc_update[], nr_args = entry count
 * (kernel cap IO_RINGFD_REG_MAX = 16).  Both opcodes share the same
 * payload shape -- io_ringfd_register iterates the array consuming
 * data as the io_uring fd to install and offset as the slot id;
 * io_ringfd_unregister consumes offset only.  Seed data with a real
 * io_uring fd from the existing object pool ~75% of the time so the
 * register path actually installs slots rather than -EBADF'ing on
 * the first entry; the rest of the time inject -1 / garbage to walk
 * the validator's reject paths.  resv must be 0 or io_ringfd_register
 * bails at -EINVAL; occasionally fuzz it to exercise that gate.
 * NULL-guard the writable buffer -- get_writable_struct() can return
 * NULL on pool exhaustion and the populate loop must not deref it;
 * a NULL rec->a3 still EFAULTs cleanly past the kernel's first
 * copy_from_user, and the trailing avoid_shared_buffer scrub runs
 * unconditionally for both paths.
 */
struct ioring_register_payload ioring_reg_ring_fds_payload(void)
{
	struct ioring_register_payload p;
	struct io_uring_rsrc_update *u;
	unsigned int nr = 1 + (rnd_modulo_u32(16));
	unsigned int i;

	u = (struct io_uring_rsrc_update *)
		get_writable_struct(nr * sizeof(*u));
	if (u) {
		memset(u, 0, nr * sizeof(*u));
		for (i = 0; i < nr; i++) {
			unsigned int roll = rnd_modulo_u32(100);
			u[i].offset = rnd_u32() & 0xf;
			if ((rnd_modulo_u32(32)) == 0)
				u[i].resv = rnd_u32();
			if (roll < 75) {
				struct io_uringobj *r2 = get_io_uring_ring();
				u[i].data = (r2 != NULL) ?
					(__u64) r2->fd : (__u64) -1;
			} else if (roll < 87) {
				u[i].data = (__u64) -1;
			} else {
				u[i].data = ((__u64) rnd_u32() << 32) |
					(__u32) rnd_u32();
			}
		}
	}
	p.arg = (unsigned long) u;
	p.nr = nr;
	p.len = nr * sizeof(*u);
	return p;
}

/*
 * IORING_REGISTER_PBUF_RING / IORING_UNREGISTER_PBUF_RING:
 * arg = struct io_uring_buf_reg, nr_args = 1.  Seed ring_entries
 * with a small power-of-2 so io_register_pbuf_ring's
 * is_power_of_2(reg.ring_entries) sanity check passes and the
 * handler reaches the buf_ring allocation path.  Leave ring_addr
 * NULL -- the handler will EFAULT past the size check, which still
 * exercises far more code than the default zero-page path.
 */
struct ioring_register_payload ioring_reg_pbuf_ring_payload(void)
{
	struct ioring_register_payload p;
	struct trinity_io_uring_buf_reg *r;

	r = (struct trinity_io_uring_buf_reg *)
		get_writable_struct(sizeof(*r));
	if (r) {
		memset(r, 0, sizeof(*r));
		r->ring_entries = 1U << (4 + (rnd_modulo_u32(4)));  /* 16..128 */
		r->bgid = rnd_modulo_u32(16);
	}
	p.arg = (unsigned long) r;
	p.nr = 1;
	p.len = sizeof(*r);
	return p;
}

/*
 * IORING_REGISTER_PBUF_STATUS: arg = struct io_uring_buf_status,
 * nr_args = 1.  Seed buf_group small so io_register_pbuf_status's
 * xa_load() lookup actually hits a registered buf-ring slot some of
 * the time; head is an output field, leave 0.  The kernel walks resv[]
 * with memchr_inv() and rejects non-zero -- mostly leave it zero, but
 * 1-in-32 fuzz a slot to exercise that gate.
 */
struct ioring_register_payload ioring_reg_pbuf_status_payload(void)
{
	struct ioring_register_payload p;
	struct trinity_io_uring_buf_status *s;

	s = (struct trinity_io_uring_buf_status *)
		get_writable_struct(sizeof(*s));
	if (s) {
		unsigned int i;
		memset(s, 0, sizeof(*s));
		s->buf_group = rnd_u32() & 0xf;
		for (i = 0; i < 8; i++)
			if ((rnd_modulo_u32(32)) == 0)
				s->resv[i] = rnd_u32();
	}
	p.arg = (unsigned long) s;
	p.nr = 1;
	p.len = sizeof(*s);
	return p;
}

/*
 * IORING_REGISTER_ZCRX_IFQ: arg = struct io_uring_zcrx_ifq_reg,
 * nr_args = 1.  Seed rq_entries with a small power-of-2 so the
 * is_power_of_2 check in io_register_zcrx_ifq passes; if_idx /
 * if_rxq pick small values that may or may not resolve to a real
 * netdev.  area_ptr / region_ptr are left NULL on purpose -- the
 * handler EFAULTs past validation, exercising the early checks.
 */
struct ioring_register_payload ioring_reg_zcrx_ifq_payload(void)
{
	struct ioring_register_payload p;
	struct trinity_io_uring_zcrx_ifq_reg *z;

	z = (struct trinity_io_uring_zcrx_ifq_reg *)
		get_writable_struct(sizeof(*z));
	if (z) {
		memset(z, 0, sizeof(*z));
		z->rq_entries = 1U << (4 + (rnd_modulo_u32(4)));
		z->if_idx = 1 + (rnd_modulo_u32(4));
		z->if_rxq = rnd_modulo_u32(4);
	}
	p.arg = (unsigned long) z;
	p.nr = 1;
	p.len = sizeof(*z);
	return p;
}

/*
 * IORING_REGISTER_RESIZE_RINGS: arg = struct io_uring_params,
 * nr_args = 0.  Kernel-side this is gated on the source ring
 * having been created with IORING_SETUP_DEFER_TASKRUN; trinity
 * does not control how its ARG_FD_IO_URING fd was set up, so most
 * invocations will be rejected at io_register_resize_rings's
 * IORING_SETUP_DEFER_TASKRUN check.  Still seed sq_entries /
 * cq_entries non-zero so the rare ring that does qualify reaches
 * io_allocate_scq_urings rather than bailing on entry-count == 0.
 */
struct ioring_register_payload ioring_reg_resize_rings_payload(void)
{
	struct ioring_register_payload p;
	struct io_uring_params *up;

	up = (struct io_uring_params *)
		get_writable_struct(sizeof(*up));
	if (up) {
		memset(up, 0, sizeof(*up));
		up->sq_entries = 1U << (3 + (rnd_modulo_u32(5)));   /* 8..128 */
		up->cq_entries = up->sq_entries * 2;
	}
	p.arg = (unsigned long) up;
	p.nr = 0;
	p.len = sizeof(*up);
	return p;
}

/*
 * IORING_REGISTER_MEM_REGION: arg = struct io_uring_mem_region_reg,
 * nr_args = 1.  region_uptr points to a struct io_uring_region_desc
 * the kernel copy_from_users separately; wire it to a fresh
 * get_writable_address() page so io_create_region reaches its own
 * field validation rather than EFAULTing at the second copy.
 */
struct ioring_register_payload ioring_reg_mem_region_payload(void)
{
	struct ioring_register_payload p;
	struct trinity_io_uring_mem_region_reg *m;
	void *region_desc;

	m = (struct trinity_io_uring_mem_region_reg *)
		get_writable_struct(sizeof(*m));
	region_desc = get_writable_address(page_size);
	if (region_desc)
		memset(region_desc, 0, page_size);
	if (m) {
		memset(m, 0, sizeof(*m));
		m->region_uptr = (unsigned long) region_desc;
	}
	p.arg = (unsigned long) m;
	p.nr = 1;
	p.len = sizeof(*m);
	return p;
}

/*
 * IORING_REGISTER_FILES2 / IORING_REGISTER_BUFFERS2: arg = struct
 * io_uring_rsrc_register, nr_args = sizeof(struct).  data points to
 * the underlying fd[] (FILES2) or iovec[] (BUFFERS2); tags points to
 * a per-resource u64 tag table.  flags occasionally carries
 * IORING_RSRC_REGISTER_SPARSE to exercise the sparse-table path that
 * skips the data copy entirely.  resv2 must be zero or
 * io_register_rsrc bails at -EINVAL before any allocation.
 */
struct ioring_register_payload ioring_reg_rsrc_register_payload(unsigned int opcode)
{
	struct ioring_register_payload p;
	struct io_uring_rsrc_register *r;
	void *data_buf = NULL;
	void *tags_buf;
	size_t data_sz;
	unsigned int nr = 1 + (rnd_modulo_u32(8));

	r = (struct io_uring_rsrc_register *)
		get_writable_struct(sizeof(*r));
	if (opcode == IORING_REGISTER_FILES2) {
		data_sz = nr * sizeof(int);
		data_buf = get_writable_struct(data_sz);
		if (data_buf)
			memset(data_buf, 0xff, data_sz);  /* -1 fill */
	} else {
		data_buf = alloc_iovec(nr, IOV_KERNEL_WRITE);
	}
	tags_buf = get_writable_struct(nr * sizeof(__u64));
	if (tags_buf)
		memset(tags_buf, 0, nr * sizeof(__u64));
	if (r) {
		memset(r, 0, sizeof(*r));
		r->nr = nr;
		if ((rnd_modulo_u32(4)) == 0) {
			r->flags = IORING_RSRC_REGISTER_SPARSE;
			r->data = 0;
		} else {
			r->data = (__u64)(uintptr_t) data_buf;
		}
		r->tags = (__u64)(uintptr_t) tags_buf;
	}
	p.arg = (unsigned long) r;
	p.nr = sizeof(*r);
	p.len = sizeof(*r);
	return p;
}

/*
 * IORING_REGISTER_FILES_UPDATE2 / IORING_REGISTER_BUFFERS_UPDATE:
 * arg = struct io_uring_rsrc_update2, nr_args = sizeof(struct).  Same
 * data/tags split as the *2 register pair; offset selects the slot to
 * start updating at, nr is the count.  resv / resv2 must be zero.
 */
struct ioring_register_payload ioring_reg_rsrc_update_payload(unsigned int opcode)
{
	struct ioring_register_payload p;
	struct io_uring_rsrc_update2 *u;
	void *data_buf;
	void *tags_buf;
	size_t data_sz;
	unsigned int nr = 1 + (rnd_modulo_u32(8));

	u = (struct io_uring_rsrc_update2 *)
		get_writable_struct(sizeof(*u));
	if (opcode == IORING_REGISTER_FILES_UPDATE2) {
		data_sz = nr * sizeof(int);
		data_buf = get_writable_struct(data_sz);
		if (data_buf)
			memset(data_buf, 0xff, data_sz);
	} else {
		data_buf = alloc_iovec(nr, IOV_KERNEL_WRITE);
	}
	tags_buf = get_writable_struct(nr * sizeof(__u64));
	if (tags_buf)
		memset(tags_buf, 0, nr * sizeof(__u64));
	if (u) {
		memset(u, 0, sizeof(*u));
		u->offset = rnd_u32() & 0xf;
		u->nr = nr;
		u->data = (__u64)(uintptr_t) data_buf;
		u->tags = (__u64)(uintptr_t) tags_buf;
	}
	p.arg = (unsigned long) u;
	p.nr = sizeof(*u);
	p.len = sizeof(*u);
	return p;
}

/*
 * IORING_REGISTER_QUERY: arg = chain of struct io_uring_query_hdr,
 * nr_args = chain length.  io_query walks a user-pointer linked list:
 * each hdr has next_entry (next user ptr or 0), query_data (per-op
 * union payload ptr), query_op (selector 0..2), size (payload bytes),
 * result (kernel write-back).  Allocate 1-3 hdrs contiguously and
 * chain via next_entry pointers to neighboring slots; per-hdr
 * query_data points to a separate small writable buffer sized
 * generously to satisfy any IO_URING_QUERY_* variant's copy.  Bias
 * query_op 75% to a valid value to reach the per-op handler; 25%
 * garbage to walk the selector validator.  __resv must be zero or
 * the mem_is_zero(__resv) reject path trips -- mostly leave it zero,
 * 1-in-16 fuzz a slot to exercise that gate.
 */
struct ioring_register_payload ioring_reg_query_payload(void)
{
	struct ioring_register_payload p;
	struct trinity_io_uring_query_hdr *chain;
	unsigned int nr = 1 + (rnd_modulo_u32(3));  /* 1..3 hdrs */
	unsigned int i;

	chain = (struct trinity_io_uring_query_hdr *)
		get_writable_struct(nr * sizeof(*chain));
	if (chain) {
		memset(chain, 0, nr * sizeof(*chain));
		for (i = 0; i < nr; i++) {
			void *qd = get_writable_struct(64);
			if (qd)
				memset(qd, 0, 64);
			chain[i].query_data = (__u64)(uintptr_t) qd;
			chain[i].size = 48;
			if ((rnd_modulo_u32(4)) == 0)
				chain[i].query_op = rnd_u32();
			else
				chain[i].query_op =
					rnd_modulo_u32(TRINITY_IO_URING_QUERY_LAST);
			chain[i].next_entry = (i + 1 < nr) ?
				(__u64)(uintptr_t) &chain[i + 1] : 0;
			if ((rnd_modulo_u32(16)) == 0)
				chain[i].__resv[rnd_modulo_u32(3)] = rnd_u32();
		}
	}
	p.arg = (unsigned long) chain;
	p.nr = nr;
	p.len = nr * sizeof(*chain);
	return p;
}

/*
 * IORING_REGISTER_ZCRX_CTRL: arg = struct zcrx_ctrl, nr_args = 1.
 * op selects the union arm (FLUSH_RQ = 0 / EXPORT = 1); 75% pick a
 * valid op to reach the per-op handler, 25% garbage.  For
 * ZCRX_CTRL_EXPORT occasionally seed zc_export.zcrx_fd from the fd
 * pool so io_zcrx_ctrl_export reaches its real-fd validators rather
 * than -EBADF'ing on a garbage fd.  __resv must be zero or the
 * reservedness check fires.  zcrx_id picks a small value; the kernel
 * looks it up against the io_ring_ctx's zcrx xarray.
 */
struct ioring_register_payload ioring_reg_zcrx_ctrl_payload(void)
{
	struct ioring_register_payload p;
	struct trinity_io_uring_zcrx_ctrl *z;

	z = (struct trinity_io_uring_zcrx_ctrl *)
		get_writable_struct(sizeof(*z));
	if (z) {
		memset(z, 0, sizeof(*z));
		z->zcrx_id = rnd_u32() & 0xf;
		if ((rnd_modulo_u32(4)) == 0)
			z->op = rnd_u32();
		else
			z->op = rnd_modulo_u32(TRINITY_ZCRX_CTRL_LAST);
		if (z->op == TRINITY_ZCRX_CTRL_EXPORT &&
		    (rnd_modulo_u32(2)) == 0) {
			int xfd = get_random_fd();
			z->body.zc_export.zcrx_fd =
				(xfd >= 0) ? (__u32) xfd : (__u32) rnd_u32();
		}
	}
	p.arg = (unsigned long) z;
	p.nr = 1;
	p.len = sizeof(*z);
	return p;
}

/*
 * IORING_REGISTER_CLONE_BUFFERS: arg = struct io_uring_clone_buffers,
 * nr_args = 1.  src_fd defaults to the same ring fd, exercising the
 * src == dst rejection path; nr non-zero so we reach the buffer-table
 * walk rather than bailing at the count==0 check.
 */
struct ioring_register_payload ioring_reg_clone_buffers_payload(struct io_uringobj *ring)
{
	struct ioring_register_payload p;
	struct trinity_io_uring_clone_buffers *c;

	c = (struct trinity_io_uring_clone_buffers *)
		get_writable_struct(sizeof(*c));
	if (c) {
		memset(c, 0, sizeof(*c));
		c->src_fd = (ring != NULL) ? (__u32) ring->fd : (__u32) -1;
		c->nr = 1 + (rnd_modulo_u32(16));
	}
	p.arg = (unsigned long) c;
	p.nr = 1;
	p.len = sizeof(*c);
	return p;
}

/*
 * IORING_REGISTER_SYNC_CANCEL: arg = struct io_uring_sync_cancel_reg,
 * nr_args = 1.  All-zero is a legal payload (matches "cancel any") and
 * reaches io_sync_cancel's request-search loop, the bug-rich part.
 * Occasionally seed a non-zero opcode/flags to walk the validator.
 */
struct ioring_register_payload ioring_reg_sync_cancel_payload(void)
{
	struct ioring_register_payload p;
	struct trinity_io_uring_sync_cancel_reg *s;

	s = (struct trinity_io_uring_sync_cancel_reg *)
		get_writable_struct(sizeof(*s));
	if (s) {
		memset(s, 0, sizeof(*s));
		s->fd = -1;
		if ((rnd_modulo_u32(8)) == 0) {
			s->opcode = rnd_u32() & 0xff;
			s->flags = rnd_u32();
		}
	}
	p.arg = (unsigned long) s;
	p.nr = 1;
	p.len = sizeof(*s);
	return p;
}

/*
 * IORING_REGISTER_SEND_MSG_RING (blind, fd == -1 only): arg = struct
 * io_uring_sqe with opcode = IORING_OP_MSG_RING, nr_args = 1.  The
 * handler (io_uring_register_send_msg_ring) reads the SQE and
 * dispatches as if it were an MSG_RING op via io_uring_sync_msg_ring
 * -- otherwise it returns -EINVAL early on opcode mismatch.  flags
 * must be 0 or the same -EINVAL gate fires.
 */
struct ioring_register_payload ioring_reg_send_msg_ring_payload(void)
{
	struct ioring_register_payload p;
	struct io_uring_sqe *sqe;

	sqe = (struct io_uring_sqe *) get_writable_struct(sizeof(*sqe));
	if (sqe) {
		memset(sqe, 0, sizeof(*sqe));
		sqe->opcode = IORING_OP_MSG_RING;
	}
	p.arg = (unsigned long) sqe;
	p.nr = 1;
	p.len = sizeof(*sqe);
	return p;
}

/*
 * IORING_REGISTER_BPF_FILTER (task-scoped via the blind fd == -1
 * path): arg = struct io_uring_bpf with cmd_type =
 * IO_URING_BPF_CMD_FILTER and an embedded io_uring_bpf_filter,
 * nr_args = 1.  CAP_SYS_ADMIN gates the path unless task_no_new_-
 * privs is set; trinity may not satisfy either, but the EACCES
 * reject still exercises the gate.  filter_ptr left NULL --
 * bpf_prog_create_from_user EFAULTs past it, exercising the early
 * io_bpf_filter_import validators (cmd_type/flags/opcode/filter_len
 * checks) before the copy.
 */
struct ioring_register_payload ioring_reg_bpf_filter_payload(void)
{
	struct ioring_register_payload p;
	struct trinity_io_uring_bpf *bp;

	bp = (struct trinity_io_uring_bpf *)
		get_writable_struct(sizeof(*bp));
	if (bp) {
		memset(bp, 0, sizeof(*bp));
		bp->cmd_type = TRINITY_IO_URING_BPF_CMD_FILTER;
		bp->filter.opcode = rnd_modulo_u32(IORING_OP_LAST);
		bp->filter.filter_len = rnd_modulo_u32(8);
	}
	p.arg = (unsigned long) bp;
	p.nr = 1;
	p.len = sizeof(*bp);
	return p;
}

/*
 * For opcodes with struct args we don't model in detail, provide a
 * zeroed page so the kernel reaches argument parsing rather than
 * faulting immediately on a garbage pointer.  arg_len falls back to
 * page_size for these -- mirrors the pre-bucket behaviour for the
 * exact set of opcodes we have not catalogued, leaving the modeled
 * opcodes (every case above) on their precise sizes.
 */
struct ioring_register_payload ioring_reg_default_payload(void)
{
	struct ioring_register_payload p;
	void *buf;

	buf = get_writable_address(page_size);
	if (buf)
		memset(buf, 0, page_size);
	p.arg = (unsigned long) buf;
	p.nr = 1;
	p.len = page_size;
	return p;
}
