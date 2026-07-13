#pragma once

#include <linux/prctl.h>

#ifndef PR_MCE_KILL_GET
#define PR_MCE_KILL_GET 34
#endif

#ifndef PR_SET_MM
#define PR_SET_MM               35
#endif

#ifndef PR_SET_CHILD_SUBREAPER
#define PR_SET_CHILD_SUBREAPER  36
#define PR_GET_CHILD_SUBREAPER  37
#endif

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS     38
#define PR_GET_NO_NEW_PRIVS     39
#endif

#ifndef PR_GET_TID_ADDRESS
#define PR_GET_TID_ADDRESS      40
#endif

#ifndef PR_SET_THP_DISABLE
#define PR_SET_THP_DISABLE      41
#define PR_GET_THP_DISABLE      42
#endif

#ifndef PR_CAP_AMBIENT
#define PR_CAP_AMBIENT		47
#endif

#ifndef PR_SVE_SET_VL
#define PR_SVE_SET_VL		50 
#define PR_SVE_GET_VL           51
#endif

#ifndef PR_GET_SPECULATION_CTRL
#define PR_GET_SPECULATION_CTRL         52
#define PR_SET_SPECULATION_CTRL         53
#endif

#ifndef PR_PAC_RESET_KEYS
#define PR_PAC_RESET_KEYS               54
#endif
#ifndef PR_SET_TAGGED_ADDR_CTRL
#define PR_SET_TAGGED_ADDR_CTRL		55
#define PR_GET_TAGGED_ADDR_CTRL		56
#endif
#ifndef PR_SET_IO_FLUSHER
#define PR_SET_IO_FLUSHER		57
#define PR_GET_IO_FLUSHER		58
#endif
#ifndef PR_SET_SYSCALL_USER_DISPATCH
#define PR_SET_SYSCALL_USER_DISPATCH	59
#endif
#ifndef PR_SCHED_CORE
#define PR_SCHED_CORE			62
#endif
#ifndef PR_SET_MDWE
#define PR_SET_MDWE			65
#define PR_GET_MDWE			66
#endif
#ifndef PR_SET_MEMORY_MERGE
#define PR_SET_MEMORY_MERGE		67
#define PR_GET_MEMORY_MERGE		68
#endif
#ifndef PR_GET_SHADOW_STACK_STATUS
#define PR_GET_SHADOW_STACK_STATUS	74
#define PR_SET_SHADOW_STACK_STATUS	75
#define PR_LOCK_SHADOW_STACK_STATUS	76
#endif
#ifndef PR_TIMER_CREATE_RESTORE_IDS
#define PR_TIMER_CREATE_RESTORE_IDS	77
#endif
#ifndef PR_FUTEX_HASH
#define PR_FUTEX_HASH			78
#endif
#ifndef PR_RSEQ_SLICE_EXTENSION
#define PR_RSEQ_SLICE_EXTENSION		79
#endif
#ifndef PR_GET_CFI
#define PR_GET_CFI			80
#define PR_SET_CFI			81
#define PR_CFI_BRANCH_LANDING_PADS	0
#define PR_CFI_ENABLE			(1U << 0)
#define PR_CFI_DISABLE			(1U << 1)
#define PR_CFI_LOCK			(1U << 2)
#endif
#ifndef PR_SET_PTRACER
#define PR_SET_PTRACER			0x59616d61
#endif
#ifndef PR_SET_VMA
#define PR_SET_VMA			0x53564d41
#endif
#ifndef PR_GET_AUXV
#define PR_GET_AUXV			0x41555856
#endif
