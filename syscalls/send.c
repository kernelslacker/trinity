/*
 *  SYSCALL_DEFINE4(send, int, fd, void __user *, buff, size_t, len,
                unsigned, flags)
 */
#include <sys/socket.h>
#include "compat.h"
#include "sanitise.h"

struct syscallentry syscall_send = {
	.name = "send",
	.num_args = 4,
	.arg1name = "fd",
	.arg1type = ARG_FD,
	.arg2name = "buff",
	.arg2type = ARG_ADDRESS,
	.arg3name = "len",
	.arg3type = ARG_LEN,
	.arg4name = "flags",
        .arg4type = ARG_LIST,
	.arg4list = {
		.num = 20,
		.values = { MSG_OOB, MSG_PEEK, MSG_DONTROUTE, MSG_CTRUNC,
			MSG_PROBE, MSG_TRUNC, MSG_DONTWAIT, MSG_EOR,
			MSG_WAITALL, MSG_FIN, MSG_SYN, MSG_CONFIRM,
			MSG_RST, MSG_ERRQUEUE, MSG_NOSIGNAL, MSG_MORE,
			MSG_WAITFORONE, MSG_FASTOPEN, MSG_CMSG_CLOEXEC, MSG_CMSG_COMPAT,
		},
	},
};
