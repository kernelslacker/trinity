#pragma once

#include <linux/audit.h>

/* Fallback for headers without AUDIT_ARCH_RISCV64; EM_RISCV is absent there too. */
#ifndef AUDIT_ARCH_RISCV64
#define AUDIT_ARCH_RISCV64	(243 | 0x80000000 | 0x40000000)
#endif
