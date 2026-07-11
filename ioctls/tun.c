/* TUN/TAP ioctl group for /dev/net/tun. */

#include <linux/filter.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/sockios.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#include "ioctls.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"
#include "utils-macros.h"

/*
 * /dev/net/tun is a misc character device (major 10, minor 200 in the
 * kernel's include/uapi/linux/miscdevice.h).  It lives one directory
 * below /dev, so map_dev()'s /proc/misc lookup and the devs[]
 * basename comparison in find_ioctl_group() cannot see it -- match on
 * st_rdev instead.  TUN_MINOR is not exposed via linux/if_tun.h.
 */
#ifndef TUN_MINOR
#define TUN_MINOR 200
#endif

static int tun_fd_test(int fd __attribute__((unused)),
		       const struct stat *st)
{
	if (!S_ISCHR(st->st_mode))
		return -1;
	if (major(st->st_rdev) != 10)
		return -1;
	if (minor(st->st_rdev) != TUN_MINOR)
		return -1;
	return 0;
}

/*
 * Common ifreq filler.  TUNSETIFF is encoded as _IOW('T', 202, int),
 * so the generic Tier 1 picker in ioctl_arg_for_request() sizes the
 * buffer from _IOC_SIZE(request) == sizeof(int) and hands the kernel
 * a four-byte pointer.  The kernel then copy_from_user()s a whole
 * struct ifreq off that pointer and faults past the first field --
 * the exact under-size bug class kvm-vm.c documents for its own
 * hand-fillers.  Allocate a real ifreq, zero it (pool residue leaks
 * back on any output-carrying command), stamp ifr_name and ifr_flags
 * with plausible values, and rewrite a3 to point at it.
 */
static const unsigned short tun_iff_flags[] = {
	IFF_TUN,
	IFF_TAP,
	IFF_TUN | IFF_NO_PI,
	IFF_TAP | IFF_NO_PI,
	IFF_TUN | IFF_VNET_HDR,
	IFF_TAP | IFF_VNET_HDR,
	IFF_TAP | IFF_MULTI_QUEUE,
	IFF_TAP | IFF_MULTI_QUEUE | IFF_NO_PI,
};

static void sanitise_tun_ifreq(struct syscallrecord *rec)
{
	struct ifreq *ifr;

	ifr = (struct ifreq *) get_writable_struct(sizeof(*ifr));
	if (!ifr)
		return;
	memset(ifr, 0, sizeof(*ifr));
	if (RAND_BOOL())
		snprintf(ifr->ifr_name, IFNAMSIZ, "tun%u",
			 rnd_modulo_u32(16));
	else
		snprintf(ifr->ifr_name, IFNAMSIZ, "tap%u",
			 rnd_modulo_u32(16));
	ifr->ifr_flags = (short) RAND_ARRAY(tun_iff_flags);
	rec->a3 = (unsigned long) ifr;
}

/* TUNATTACHFILTER / TUNDETACHFILTER take a struct sock_fprog. */
static void sanitise_tun_sock_fprog(struct syscallrecord *rec)
{
	struct sock_fprog *prog;
	struct sock_filter *insns;
	unsigned short len;
	unsigned int i;

	prog = (struct sock_fprog *) get_writable_struct(sizeof(*prog));
	if (!prog)
		return;
	memset(prog, 0, sizeof(*prog));
	len = (unsigned short) (1u + rnd_modulo_u32(8));
	insns = (struct sock_filter *) get_writable_struct(len * sizeof(*insns));
	if (!insns) {
		prog->len = 0;
		prog->filter = NULL;
	} else {
		memset(insns, 0, len * sizeof(*insns));
		for (i = 0; i < len - 1u; i++) {
			insns[i].code = (unsigned short) rnd_u32();
			insns[i].jt = (unsigned char) rnd_u32();
			insns[i].jf = (unsigned char) rnd_u32();
			insns[i].k = rnd_u32();
		}
		/* Terminate with BPF_RET|BPF_K so the classic verifier
		 * doesn't reject the whole program on a fall-through
		 * before we ever exercise the attach path. */
		insns[len - 1].code = 0x06;	/* BPF_RET | BPF_K */
		insns[len - 1].k = rnd_u32();
		prog->len = len;
		prog->filter = insns;
	}
	rec->a3 = (unsigned long) prog;
}

/* Commands that take *int (kernel dereferences the arg). */
static void sanitise_tun_int_ptr(struct syscallrecord *rec, int val)
{
	int *p;

	p = (int *) get_writable_struct(sizeof(*p));
	if (!p)
		return;
	memset(p, 0, sizeof(*p));
	*p = val;
	rec->a3 = (unsigned long) p;
}

/* Writeback-only int; kernel copies out via put_user(). */
static void sanitise_tun_int_out(struct syscallrecord *rec)
{
	int *p;

	p = (int *) get_writable_struct(sizeof(*p));
	if (!p)
		return;
	memset(p, 0, sizeof(*p));
	rec->a3 = (unsigned long) p;
}

/* Writeback-only unsigned int (TUNGETFEATURES). */
static void sanitise_tun_uint_out(struct syscallrecord *rec)
{
	unsigned int *p;

	p = (unsigned int *) get_writable_struct(sizeof(*p));
	if (!p)
		return;
	memset(p, 0, sizeof(*p));
	rec->a3 = (unsigned long) p;
}

/* TUN_F_* offload feature bits accepted by TUNSETOFFLOAD. */
#ifndef TUN_F_CSUM
#define TUN_F_CSUM	0x01
#endif
#ifndef TUN_F_TSO4
#define TUN_F_TSO4	0x02
#endif
#ifndef TUN_F_TSO6
#define TUN_F_TSO6	0x04
#endif
#ifndef TUN_F_TSO_ECN
#define TUN_F_TSO_ECN	0x08
#endif
#ifndef TUN_F_UFO
#define TUN_F_UFO	0x10
#endif
#ifndef TUN_F_USO4
#define TUN_F_USO4	0x20
#endif
#ifndef TUN_F_USO6
#define TUN_F_USO6	0x40
#endif

#define TUN_F_ALL (TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6 | TUN_F_TSO_ECN | \
		   TUN_F_UFO | TUN_F_USO4 | TUN_F_USO6)

static void tun_sanitise(const struct ioctl_group *grp,
			 struct syscallrecord *rec)
{
	pick_random_ioctl(grp, rec);

	switch (rec->a2) {
	case TUNSETIFF:
	case TUNGETIFF:
	case TUNSETQUEUE:
		sanitise_tun_ifreq(rec);
		break;

	case TUNATTACHFILTER:
	case TUNDETACHFILTER:
		sanitise_tun_sock_fprog(rec);
		break;

	case TUNSETPERSIST:
		/* Arg is used directly as a bool -- keep it scalar. */
		rec->a3 = rnd_modulo_u32(2);
		break;

	case TUNSETOWNER:
	case TUNSETGROUP:
		/* uid_t / gid_t: -1 means "unset", otherwise a plausible
		 * small id.  Passed directly as arg (not via a pointer). */
		rec->a3 = RAND_BOOL() ? (unsigned long) -1
				      : rnd_modulo_u32(65536);
		break;

	case TUNSETOFFLOAD:
		/* Feature bitmask.  Arg is used directly. */
		rec->a3 = RAND_BOOL() ? TUN_F_ALL
				      : (rnd_u32() & TUN_F_ALL);
		break;

	case TUNSETSNDBUF:
		sanitise_tun_int_ptr(rec, (int) rnd_u32());
		break;

	case TUNSETVNETHDRSZ:
		/* Sizes 0, sizeof(virtio_net_hdr), and a large value cover
		 * the accepted/rejected/pathological arms.  Kernel enforces
		 * a minimum of sizeof(struct virtio_net_hdr) (10 bytes). */
		switch (rnd_modulo_u32(4)) {
		case 0:  sanitise_tun_int_ptr(rec, 0); break;
		case 1:  sanitise_tun_int_ptr(rec, 10); break;
		case 2:  sanitise_tun_int_ptr(rec, 12); break;
		default: sanitise_tun_int_ptr(rec, (int) rnd_u32()); break;
		}
		break;

	case TUNSETVNETLE:
	case TUNSETVNETBE:
		sanitise_tun_int_ptr(rec, (int) rnd_modulo_u32(2));
		break;

	case TUNSETCARRIER:
		sanitise_tun_int_ptr(rec, (int) rnd_modulo_u32(2));
		break;

	case TUNSETSTEERINGEBPF:
	case TUNSETFILTEREBPF:
		/* Kernel reads an int (bpf prog fd) from userspace.  -1
		 * detaches; any other value is looked up and typically
		 * rejected as ENOENT unless it happens to hit a real
		 * BPF_PROG_TYPE_SOCKET_FILTER fd in the child. */
		sanitise_tun_int_ptr(rec,
			RAND_BOOL() ? -1 : (int) rnd_modulo_u32(1024));
		break;

	case TUNGETFEATURES:
		sanitise_tun_uint_out(rec);
		break;

	case TUNGETSNDBUF:
	case TUNGETVNETHDRSZ:
		sanitise_tun_int_out(rec);
		break;

	default:
		break;
	}
}

/*
 * Compile-time: TUNATTACHFILTER / TUNDETACHFILTER encode
 * sizeof(struct sock_fprog) in their request bits, so a header
 * refactor that grew or shrank sock_fprog would silently desync
 * the _IOC_SIZE the kernel reads against the buffer the sanitiser
 * hands it.  struct sock_fprog embeds a struct sock_filter *
 * pointer, so its size is arch/compat-dependent, but for the
 * native compile-time build the sizeof and _IOC_SIZE always agree
 * -- an in-tree mismatch would still trip these asserts.  The rest
 * of the table encodes bare int / unsigned int / ifreq handled
 * inline and is intentionally not asserted.
 */
_Static_assert(sizeof(struct sock_fprog) ==
	       _IOC_SIZE(TUNATTACHFILTER),
	       "sock_fprog size vs TUNATTACHFILTER mismatch");
_Static_assert(sizeof(struct sock_fprog) ==
	       _IOC_SIZE(TUNDETACHFILTER),
	       "sock_fprog size vs TUNDETACHFILTER mismatch");

static const struct ioctl tun_ioctls[] = {
	IOCTL(TUNSETIFF),
	IOCTL(TUNGETIFF),
	IOCTL(TUNSETPERSIST),
	IOCTL(TUNSETOWNER),
	IOCTL(TUNSETGROUP),
	IOCTL(TUNGETFEATURES),
	IOCTL(TUNSETOFFLOAD),
	IOCTL(TUNGETSNDBUF),
	IOCTL(TUNSETSNDBUF),
	IOCTL(TUNGETVNETHDRSZ),
	IOCTL(TUNSETVNETHDRSZ),
	IOCTL(TUNSETQUEUE),
	IOCTL(TUNSETVNETLE),
	IOCTL(TUNSETVNETBE),
	IOCTL(TUNSETCARRIER),
	IOCTL(TUNSETSTEERINGEBPF),
	IOCTL(TUNSETFILTEREBPF),
	IOCTL(TUNATTACHFILTER),
	IOCTL(TUNDETACHFILTER),
};

static const struct ioctl_group tun_grp = {
	.name = "tun",
	.fd_test = tun_fd_test,
	.sanitise = tun_sanitise,
	.ioctls = tun_ioctls,
	.ioctls_cnt = ARRAY_SIZE(tun_ioctls),
};

REG_IOCTL_GROUP(tun_grp)
