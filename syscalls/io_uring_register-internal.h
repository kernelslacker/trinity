/*
 * io_uring_register-internal.h
 *
 * Shared declarations split out of syscalls/io_uring_register.c so the
 * per-opcode ioring_reg_*_payload builder family can live in its own
 * translation unit and compile in parallel with the picker tables,
 * dispatch switch, sanitise/post hooks and syscallentry that stay in
 * io_uring_register.c.  This header is private to the two TUs that
 * make up io_uring_register -- do not include it from anywhere else.
 *
 * The builders touch no file-statics in io_uring_register.c; they read
 * only trinity's rnd_, get_writable_, get_typed_fd and alloc_iovec
 * helpers and the ARG_FD_ arg-type enum, and return a sized payload by
 * value.
 * Each is deliberately widened from file-static to external linkage so
 * the dispatch switch in io_uring_register.c can reach them across the
 * TU boundary.
 */

#ifndef SYSCALLS_IO_URING_REGISTER_INTERNAL_H
#define SYSCALLS_IO_URING_REGISTER_INTERNAL_H

struct io_uringobj;

/*
 * Per-opcode payload returned by the family helpers below.  The dispatch
 * switch in sanitise_io_uring_register copies these straight into
 * rec->a3 / rec->a4 and the local arg_len.
 */
struct ioring_register_payload {
	unsigned long arg;
	unsigned int nr;
	unsigned long len;
};

struct ioring_register_payload ioring_reg_buffers_payload(unsigned int opcode);
struct ioring_register_payload ioring_reg_files_payload(unsigned int opcode);
struct ioring_register_payload ioring_reg_eventfd_payload(unsigned int opcode);
struct ioring_register_payload ioring_reg_probe_payload(void);
struct ioring_register_payload ioring_reg_personality_payload(void);
struct ioring_register_payload ioring_reg_restrictions_payload(void);
struct ioring_register_payload ioring_reg_iowq_payload(unsigned int opcode);
struct ioring_register_payload ioring_reg_napi_payload(void);
struct ioring_register_payload ioring_reg_file_alloc_range_payload(void);
struct ioring_register_payload ioring_reg_clock_payload(void);
struct ioring_register_payload ioring_reg_ring_fds_payload(void);
struct ioring_register_payload ioring_reg_pbuf_ring_payload(void);
struct ioring_register_payload ioring_reg_pbuf_status_payload(void);
struct ioring_register_payload ioring_reg_zcrx_ifq_payload(void);
struct ioring_register_payload ioring_reg_resize_rings_payload(void);
struct ioring_register_payload ioring_reg_mem_region_payload(void);
struct ioring_register_payload ioring_reg_rsrc_register_payload(unsigned int opcode);
struct ioring_register_payload ioring_reg_rsrc_update_payload(unsigned int opcode);
struct ioring_register_payload ioring_reg_query_payload(void);
struct ioring_register_payload ioring_reg_zcrx_ctrl_payload(void);
struct ioring_register_payload ioring_reg_clone_buffers_payload(struct io_uringobj *ring);
struct ioring_register_payload ioring_reg_sync_cancel_payload(void);
struct ioring_register_payload ioring_reg_send_msg_ring_payload(void);
struct ioring_register_payload ioring_reg_bpf_filter_payload(void);
struct ioring_register_payload ioring_reg_default_payload(void);

#endif /* SYSCALLS_IO_URING_REGISTER_INTERNAL_H */
