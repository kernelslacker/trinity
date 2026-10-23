#pragma once

#include <signal.h>

#ifndef SI_USER
#define SI_USER		0
#endif
#ifndef SI_QUEUE
#define SI_QUEUE	-1
#endif
#ifndef SI_TIMER
#define SI_TIMER	-2
#endif
#ifndef SI_ASYNCIO
#define SI_ASYNCIO	-4
#endif
#ifndef SI_TKILL
#define SI_TKILL	-6
#endif

#ifndef SS_AUTODISARM
#define SS_AUTODISARM	(1U << 31)
#endif
