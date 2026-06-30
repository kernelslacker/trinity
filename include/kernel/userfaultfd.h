#pragma once

/*
 * Wrapper around <linux/userfaultfd.h> that ships an #ifndef-guarded
 * fallback for UFFD_USER_MODE_ONLY, which may be missing on older
 * installed uapi headers.  The syscall itself is available on every
 * kernel trinity targets.
 */
#include <linux/userfaultfd.h>

#ifndef UFFD_USER_MODE_ONLY
#define UFFD_USER_MODE_ONLY 1
#endif
