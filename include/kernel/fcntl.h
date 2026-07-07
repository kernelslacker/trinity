#pragma once

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH           0x1000
#endif
#ifndef AT_SYMLINK_NOFOLLOW
#define AT_SYMLINK_NOFOLLOW	0x100
#endif
#ifndef AT_RECURSIVE
#define AT_RECURSIVE		0x8000
#endif

#ifndef O_PATH
#define O_PATH        010000000
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC       02000000
#endif

#ifndef O_LARGEFILE
#define O_LARGEFILE	00100000
#endif

#ifndef O_TMPFILE
#define O_TMPFILE	(020000000 | 00200000)
#endif

#ifndef AT_NO_AUTOMOUNT
#define AT_NO_AUTOMOUNT 0x800
#endif

#ifndef F_LINUX_SPECIFIC_BASE
#define F_LINUX_SPECIFIC_BASE 1024
#endif

#ifndef F_SETPIPE_SZ
#define F_SETPIPE_SZ    (F_LINUX_SPECIFIC_BASE + 7)
#endif

#ifndef F_GETPIPE_SZ
#define F_GETPIPE_SZ    (F_LINUX_SPECIFIC_BASE + 8)
#endif

#ifndef F_DUPFD_CLOEXEC
#define F_DUPFD_CLOEXEC (F_LINUX_SPECIFIC_BASE + 6)
#endif

#ifndef F_SETOWN_EX
#define F_SETOWN_EX 15
#endif

#ifndef F_GETOWN_EX
#define F_GETOWN_EX 16
#endif

#ifndef F_GETOWNER_UIDS
#define F_GETOWNER_UIDS	17
#endif

#ifndef F_OFD_GETLK
#define F_OFD_GETLK       36
#define F_OFD_SETLK       37
#define F_OFD_SETLKW      38
#endif
#ifndef F_DUPFD_QUERY
#define F_DUPFD_QUERY		(F_LINUX_SPECIFIC_BASE + 3)
#endif
#ifndef F_CREATED_QUERY
#define F_CREATED_QUERY		(F_LINUX_SPECIFIC_BASE + 4)
#endif
#ifndef F_CANCELLK
#define F_CANCELLK		(F_LINUX_SPECIFIC_BASE + 5)
#endif
#ifndef F_ADD_SEALS
#define F_ADD_SEALS		(F_LINUX_SPECIFIC_BASE + 9)
#define F_GET_SEALS		(F_LINUX_SPECIFIC_BASE + 10)
#endif
#ifndef F_SEAL_SEAL
#define F_SEAL_SEAL		0x0001
#define F_SEAL_SHRINK		0x0002
#define F_SEAL_GROW		0x0004
#define F_SEAL_WRITE		0x0008
#endif
#ifndef F_SEAL_FUTURE_WRITE
#define F_SEAL_FUTURE_WRITE	0x0010
#endif
#ifndef F_SEAL_EXEC
#define F_SEAL_EXEC		0x0020
#endif
#ifndef F_GET_RW_HINT
#define F_GET_RW_HINT		(F_LINUX_SPECIFIC_BASE + 11)
#define F_SET_RW_HINT		(F_LINUX_SPECIFIC_BASE + 12)
#define F_GET_FILE_RW_HINT	(F_LINUX_SPECIFIC_BASE + 13)
#define F_SET_FILE_RW_HINT	(F_LINUX_SPECIFIC_BASE + 14)
#endif
#ifndef F_GETDELEG
#define F_GETDELEG		(F_LINUX_SPECIFIC_BASE + 15)
#define F_SETDELEG		(F_LINUX_SPECIFIC_BASE + 16)
#endif
