#pragma once

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC             0x0001U
#define MFD_ALLOW_SEALING       0x0002U
#endif

#include "fd.h"

struct fd_provider memfd_fd_provider;

#define MAX_MEMFD_FDS 4
