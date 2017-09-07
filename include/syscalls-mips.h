#pragma once

#include "sanitise.h"
#include "syscall.h"
#include "syscalls/syscalls.h"

#if _MIPS_SIM == _ABIO32
#include "syscalls-mips-o32.h"
#elif _MIPS_SIM == _ABIN32
#include "syscalls-mips-n32.h"
#elif _MIPS_SIM == _ABI64
#include "syscalls-mips-64.h"
#else
#error Unknown MIPS ABI
#endif
