#pragma once

struct syscallrecord;

/*
 * Cross-arg consistency validator.  Runs between argument generation
 * and syscall dispatch to catch (buf_ptr, count) and similar coupled
 * argument pairs that are dead-on-arrival from the kernel's point of
 * view -- the kernel would reject them at the earliest validation
 * step, so the dispatch wastes a syscall, a kcov enable/disable
 * round-trip, and a stats update on a call that cannot exercise any
 * meaningful kernel path.
 *
 * Returns 0 when the rec passes (or no per-syscall rule applies);
 * returns -1 when an inconsistency is detected.  On -1 the caller
 * should skip the dispatch and synthesize a rejection retval so the
 * post path stays consistent with a normal kernel EINVAL failure;
 * the rejection is logged via outputerr() with a per-syscall tag.
 */
int validate_arg_coupling(struct syscallrecord *rec);
