#pragma once

/*
 * Wrapper around <linux/ublk_cmd.h> that ships #ifndef-guarded fallbacks
 * for the UBLK_CMD_* / UBLK_U_CMD_* / UBLK_U_IO_* values touched by
 * childops/fs/ublk-lifecycle.c.  Per-symbol #ifndef so a sysroot that
 * ships only a subset of the ublk_cmd.h symbols (older LTS, stripped
 * headers) still compiles.  The _IOWR expansions reference the
 * consumer's locally-named struct mirrors (ublk_lc_ctrl_cmd /
 * ublk_lc_io_cmd); those structs live with the handler in the .c and
 * must be in scope wherever these macros are expanded.
 */
#include <linux/ublk_cmd.h>

#ifndef UBLK_CMD_ADD_DEV
#define UBLK_CMD_ADD_DEV	0x04
#endif
#ifndef UBLK_CMD_DEL_DEV
#define UBLK_CMD_DEL_DEV	0x05
#endif
#ifndef UBLK_U_CMD_ADD_DEV
#define UBLK_U_CMD_ADD_DEV	_IOWR('u', UBLK_CMD_ADD_DEV, struct ublk_lc_ctrl_cmd)
#endif
#ifndef UBLK_U_CMD_DEL_DEV
#define UBLK_U_CMD_DEL_DEV	_IOWR('u', UBLK_CMD_DEL_DEV, struct ublk_lc_ctrl_cmd)
#endif
#ifndef UBLK_U_IO_FETCH_REQ
#define UBLK_U_IO_FETCH_REQ	_IOWR('u', 0x20, struct ublk_lc_io_cmd)
#endif
