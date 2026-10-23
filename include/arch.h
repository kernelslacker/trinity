#pragma once

#include "types.h"

#ifdef __x86_64__
#include "arch-x86-64.h"
#endif

#ifdef __i386__
#include "arch-i386.h"
#endif

#ifdef __arm__
#include "arch-arm.h"
#endif

#ifdef __aarch64__
#include "arch-aarch64.h"
#endif

#if defined(__riscv) && __riscv_xlen == 64
#include "arch-riscv64.h"
#endif

#ifdef __loongarch64
#include "arch-loongarch.h"
#endif

#ifndef SYSCALL_OFFSET
#define SYSCALL_OFFSET 0
#endif

#define PAGE_MASK (~((unsigned long)(page_size) - 1))
extern unsigned int page_size;

extern bool biarch;
