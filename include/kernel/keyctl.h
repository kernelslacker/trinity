#pragma once

/*
 * Wrapper around <linux/keyctl.h> that ships #ifndef-guarded fallbacks
 * for KEYCTL_* values added after our installed uapi header.
 */
#include <linux/keyctl.h>

#ifndef KEYCTL_GET_PERSISTENT
#define KEYCTL_GET_PERSISTENT		22
#endif
#ifndef KEYCTL_DH_COMPUTE
#define KEYCTL_DH_COMPUTE		23
#endif
#ifndef KEYCTL_PKEY_QUERY
#define KEYCTL_PKEY_QUERY		24
#endif
#ifndef KEYCTL_PKEY_ENCRYPT
#define KEYCTL_PKEY_ENCRYPT		25
#endif
#ifndef KEYCTL_PKEY_DECRYPT
#define KEYCTL_PKEY_DECRYPT		26
#endif
#ifndef KEYCTL_PKEY_SIGN
#define KEYCTL_PKEY_SIGN		27
#endif
#ifndef KEYCTL_PKEY_VERIFY
#define KEYCTL_PKEY_VERIFY		28
#endif
#ifndef KEYCTL_RESTRICT_KEYRING
#define KEYCTL_RESTRICT_KEYRING		29
#endif
#ifndef KEYCTL_MOVE
#define KEYCTL_MOVE			30
#endif
#ifndef KEYCTL_CAPABILITIES
#define KEYCTL_CAPABILITIES		31
#endif
#ifndef KEYCTL_WATCH_KEY
#define KEYCTL_WATCH_KEY		32
#endif
