#pragma once

#include <sys/syscall.h>

/*
 * Create a userfaultfd for the calling process, preferring
 * UFFD_USER_MODE_ONLY (see fds/userfaultfd.c).  @flags carries only
 * the O_CLOEXEC / O_NONBLOCK bits.  Returns the fd, or -1 with
 * errno set.
 */
int create_userfaultfd(unsigned int flags);
