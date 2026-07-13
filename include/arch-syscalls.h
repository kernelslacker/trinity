#pragma once

#ifdef __x86_64__
#include "syscalls-x86_64.h"
#include "syscalls-i386.h"
#endif
#ifdef __i386__
#include "syscalls-i386.h"
#endif
#ifdef __arm__
#include "syscalls-arm.h"
#endif
#ifdef __aarch64__
#include "syscalls-aarch64.h"
#endif
