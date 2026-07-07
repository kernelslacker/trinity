#pragma once

#include <linux/mroute.h>

#ifndef MRT_TABLE
#define MRT_TABLE		(MRT_BASE+9)
#endif
#ifndef MRT_ADD_MFC_PROXY
#define MRT_ADD_MFC_PROXY	(MRT_BASE+10)
#endif
#ifndef MRT_DEL_MFC_PROXY
#define MRT_DEL_MFC_PROXY	(MRT_BASE+11)
#endif
