#pragma once

#include <sys/signalfd.h>

#ifndef SFD_CLOEXEC
#define SFD_CLOEXEC	02000000
#endif
#ifndef SFD_NONBLOCK
#define SFD_NONBLOCK	04000
#endif
