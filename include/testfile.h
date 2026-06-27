#pragma once

int get_rand_testfile_fd(void);

/*
 * Soft-invalidate every OBJ_MMAP_TESTFILE entry backed by an fd that
 * fds/testfiles.c opened against trinity-testfile<index>.  Called from
 * post handlers whose syscall may have shrunk the file below the
 * page_size mapping the testfile bootstrap established -- the next
 * past-EOF access through the mapping would SIGBUS, taking trinity
 * itself down since OBJ_MMAP_TESTFILE is the shared writable arg pool
 * for the consumer pools.
 *
 * @index is 1-based, must be in [1, MAX_TESTFILES]; out-of-range values
 * are silently ignored so callers can pass an unconditional snap field
 * without bracketing the call.  Multiple fds may map the same basename
 * (the bootstrap rotates 20 fds across 4 inodes), so the helper walks
 * the OBJ_FD_TESTFILE pool and dispatches a per-fd
 * invalidate_obj_mmap_by_fd() for every match.
 */
void invalidate_testfile_mmaps_for_index(unsigned int index);
