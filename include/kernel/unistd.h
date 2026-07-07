#pragma once

#ifndef __NR_io_uring_enter
#if defined(__x86_64__)
#define __NR_io_uring_enter 426
#elif defined(__i386__)
#define __NR_io_uring_enter 426
#elif defined(__aarch64__)
#define __NR_io_uring_enter 426
#else
#define __NR_io_uring_enter 426
#endif
#endif
