#pragma once

#include <linux/memfd.h>

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC		0x0001U
#endif
#ifndef MFD_ALLOW_SEALING
#define MFD_ALLOW_SEALING	0x0002U
#endif
#ifndef MFD_HUGETLB
#define MFD_HUGETLB		0x0004U
#endif
#ifndef MFD_NOEXEC_SEAL
#define MFD_NOEXEC_SEAL		0x0008U
#endif
#ifndef MFD_EXEC
#define MFD_EXEC		0x0010U
#endif
