#pragma once

#include <linux/kcm.h>

/* UAPI fallbacks for stripped sysroots without <linux/kcm.h>.  The values
 * are stable since the kernel UAPI shipped in 4.7. */
#ifndef KCMPROTO_CONNECTED
#define KCMPROTO_CONNECTED	0
#endif
#ifndef KCM_RECV_DISABLE
#define KCM_RECV_DISABLE	1
#endif
#ifndef SOL_KCM
#define SOL_KCM			281
#endif
#ifndef SIOCKCMATTACH
#define SIOCKCMATTACH		(SIOCPROTOPRIVATE + 0)
#define SIOCKCMUNATTACH		(SIOCPROTOPRIVATE + 1)
#define SIOCKCMCLONE		(SIOCPROTOPRIVATE + 2)
struct kcm_attach {
	int fd;
	int bpf_fd;
};
struct kcm_clone {
	int fd;
};
#endif
