/* Generate valid extended attribute name strings for xattr syscalls. */
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <linux/xattr.h>
#include <stdio.h>
#include <string.h>
#include "arch.h"
#include "name-pool.h"
#include "random.h"
#include "sanitise.h"
#include "syscall.h"
#include "utils.h"
#include "xattr.h"

static const char *xattr_prefixes[] = {
	"user.",
	"security.",
	"system.",
	"trusted.",
};

static const char *xattr_suffixes[] = {
	"test",
	"data",
	"attr",
	"mime_type",
	"selinux",
	"posix_acl_access",
	"posix_acl_default",
	"capability",
	"sehash",
	"evm",
	"ima",
	"apparmor",
};

/* Generate a valid xattr name like "user.test" or "security.selinux". */
void gen_xattr_name(char *buf, size_t len)
{
	if (len > XATTR_NAME_BUFSZ)
		len = XATTR_NAME_BUFSZ;
	snprintf(buf, len, "%s%s",
		 RAND_ARRAY(xattr_prefixes),
		 RAND_ARRAY(xattr_suffixes));
}

/*
 * Curated names covering the xattrs most likely to actually be present
 * on real objects: SELinux contexts, file capabilities, SMACK, POSIX
 * ACLs, plus the user.* and trusted.* names fuzzers themselves tend to
 * plant.  Hitting one of these drags a substantial fraction of draws
 * past the namespace gate vfs_*xattr does first; with the unweighted
 * <random_prefix> + <random_suffix> generator above ~99% of names
 * return EOPNOTSUPP/ENODATA at the gate before any real codepath
 * runs.
 */
static const char *xattr_pooled_names[] = {
	"user.test", "user.foo", "user.bar", "user.long_attr_name",
	"trusted.test", "trusted.acl",
	"security.selinux", "security.capability", "security.SMACK64",
	"system.posix_acl_access", "system.posix_acl_default",
};

/*
 * Namespace-aware name generator with a 70 / 20 / 10 distribution:
 *   - 70% curated pool (above).
 *   - 20% "user.<random>" -- exercises the suffix-validation path on a
 *     guaranteed-valid prefix without colliding with stored names.
 *   - 10% fall through to gen_xattr_name's any-prefix-any-suffix mix
 *     so the namespace-invalid and long-tail paths stay exercised.
 */
void gen_xattr_name_pooled(char *buf, size_t len)
{
	unsigned int r;
	int wrote;
	size_t wlen;

	if (len > XATTR_NAME_BUFSZ)
		len = XATTR_NAME_BUFSZ;
	if (len == 0)
		return;

	/* Minority arm: replay a previously-recorded xattr name (possibly
	 * mutated) so a later getxattr/removexattr/listxattr in the same
	 * child can hit a name an earlier setxattr planted on an object.
	 * The dentry-level xattr-list scan and the per-handler "is this
	 * name already present?" branches only light up on a name match;
	 * independent fresh draws ("user.foo" vs "user.r3187241") almost
	 * never produce one.  Pool exhaustion returns 0 and we fall
	 * through to the curated / fresh generator below so the
	 * namespace-prefix coverage and any-prefix/any-suffix tail stay
	 * exercised. */
	if (ONE_IN(4)) {
		size_t got = name_pool_draw_mutated(NAME_KIND_XATTR_NAME,
						    buf, len);

		if (got > 0) {
			if (got >= len)
				got = len - 1;
			buf[got] = '\0';
			return;
		}
	}

	r = rnd_modulo_u32(10);

	if (r < 7) {
		wrote = snprintf(buf, len, "%s", RAND_ARRAY(xattr_pooled_names));
	} else if (r < 9) {
		wrote = snprintf(buf, len, "user.r%u", rnd_u32());
	} else {
		gen_xattr_name(buf, len);
		wrote = (int) strnlen(buf, len);
	}

	if (wrote <= 0)
		return;
	wlen = (size_t) wrote;
	if (wlen >= len)
		wlen = len - 1;
	name_pool_record(NAME_KIND_XATTR_NAME, buf, wlen);
}

bool sanitise_xattr_name_arg_pooled(struct syscallrecord *rec, unsigned int argno)
{
	char *name;
	unsigned long *slot;

	switch (argno) {
	case 1: slot = &rec->a1; break;
	case 2: slot = &rec->a2; break;
	case 3: slot = &rec->a3; break;
	case 4: slot = &rec->a4; break;
	case 5: slot = &rec->a5; break;
	case 6: slot = &rec->a6; break;
	default: return false;
	}

	name = (char *) get_writable_struct(XATTR_NAME_BUFSZ);
	if (!name) {
		/* Pool exhausted.  Force the slot to NULL so a stale ARG_ADDRESS
		 * pointer left over from a prior draw can't be handed to the
		 * kernel (or to xattr_fill_value via xattr_set_value) as if it
		 * were a valid xattr name.  Mirrors the getpeername / recvfrom
		 * pool-exhaustion guard. */
		*slot = 0;
		return false;
	}
	gen_xattr_name_pooled(name, XATTR_NAME_BUFSZ);
	*slot = (unsigned long) name;
	return true;
}

/*
 * Buffer-size legality buckets for the get/set xattr value buffer.
 * Same idea as xattr_pick_listbuf_bucket but with the small "exact
 * length" bucket (64 bytes) that real xattrs frequently land on -- the
 * SELinux context, the file-cap struct, and most user.* values are
 * in that range -- so 64 acts as the "kernel hits the equality path"
 * bucket as well as a boundary check.  Must be called BEFORE
 * avoid_shared_buffer_out() for the same reason as the listbuf
 * variant.
 */
void xattr_pick_valuebuf_bucket(unsigned long *bufp, unsigned long *sizep)
{
	void *p;

	if (!ONE_IN(2))
		return;

	switch (rnd_modulo_u32(8)) {
	case 0:	/* NULL buffer, size=0 -- pure probe */
		*bufp = 0;
		*sizep = 0;
		break;
	case 1:	*sizep = 0;	break;	/* size=0 probe */
	case 2:	*sizep = 1;	break;	/* 1-byte truncation */
	case 3:	*sizep = 64;	break;	/* common-real-xattr length */
	case 4:	*sizep = 4095;	break;	/* off-by-one below page */
	case 5:	*sizep = 4096;	break;	/* page boundary */
	case 6:	*sizep = 4097;	break;	/* off-by-one above page */
	case 7:	/* huge bucket: back it with a real allocation */
		p = get_writable_address(1UL << 16);
		if (p) {
			*bufp = (unsigned long) p;
			*sizep = 1UL << 16;
		} else {
			*sizep = 4096;
		}
		break;
	}
}

bool sanitise_xattr_name_arg(struct syscallrecord *rec, unsigned int argno)
{
	char *name;
	unsigned long *slot;

	switch (argno) {
	case 1: slot = &rec->a1; break;
	case 2: slot = &rec->a2; break;
	case 3: slot = &rec->a3; break;
	case 4: slot = &rec->a4; break;
	case 5: slot = &rec->a5; break;
	case 6: slot = &rec->a6; break;
	default: return false;
	}

	name = (char *) get_writable_struct(XATTR_NAME_BUFSZ);
	if (!name)
		return false;
	gen_xattr_name(name, XATTR_NAME_BUFSZ);
	*slot = (unsigned long) name;
	return true;
}

unsigned long xattr_set_flags[2] = { XATTR_CREATE, XATTR_REPLACE };
unsigned long xattrat_flags[2]   = { AT_SYMLINK_NOFOLLOW, AT_EMPTY_PATH };

/*
 * Buffer-size legality buckets for the listxattr family.  Random sizes
 * from ARG_LEN rarely land on the boundaries the kernel cares about
 * (NULL/0 probe, 1-byte truncation, page-boundary exact / off-by-one,
 * huge), so on roughly half of all draws replace (*bufp, *sizep) with
 * a curated bucket.  Must be called BEFORE avoid_shared_buffer_out()
 * so the post-clamp pre/post comparison correctly classifies the
 * resulting buffer as "freshly assigned" when we substitute one.
 *
 * The huge bucket allocates a real backing buffer via
 * get_writable_address() so the existing clamp -- which caps a stray
 * size against the proven allocation -- does not silently cap the
 * advertised size back to page_size.
 */
void xattr_pick_listbuf_bucket(unsigned long *bufp, unsigned long *sizep)
{
	void *p;

	if (!ONE_IN(2))
		return;

	switch (rnd_modulo_u32(7)) {
	case 0:	/* NULL buffer paired with size=0 -- pure probe */
		*bufp = 0;
		*sizep = 0;
		break;
	case 1:	/* size=0 with non-NULL buffer -- probe, kernel returns required size */
		*sizep = 0;
		break;
	case 2:	*sizep = 1;	break;	/* 1-byte truncation */
	case 3:	*sizep = 4095;	break;	/* off-by-one below page */
	case 4:	*sizep = 4096;	break;	/* page boundary */
	case 5:	*sizep = 4097;	break;	/* off-by-one above page */
	case 6:	/* huge bucket: back it with a real allocation so the
		 * downstream clamp does not silently cap it. */
		p = get_writable_address(1UL << 16);
		if (p) {
			*bufp = (unsigned long) p;
			*sizep = 1UL << 16;
		} else {
			*sizep = 4096;
		}
		break;
	}
}

/*
 * Per-namespace value generator for the setxattr family.  Random byte
 * buffers for security.selinux / security.capability / system.posix_acl_*
 * are rejected by the namespace's validator long before vfs_setxattr
 * touches the inode -- the kernel checks SELinux context syntax,
 * vfs_cap_data magic_etc, and POSIX-ACL header version up front.  Hand
 * each well-known namespace a value of roughly the right shape so the
 * draw makes it past validation and into the real per-fs xattr handler.
 *
 * The shapes are "sane enough", not kernel-valid in every detail: the
 * cap permitted/inheritable bits are random, the POSIX ACL has only
 * the version header, the SELinux contexts are picked from a tiny
 * pool of plausible strings.  user.* / trusted.* and anything else
 * gets a small random byte buffer (1..255 bytes) since those
 * namespaces accept arbitrary opaque data.
 *
 * Returns the number of bytes written into buf, clamped to bufsz.
 */
size_t xattr_fill_value(const char *name, void *buf, size_t bufsz)
{
	static const char * const selinux_ctx[] = {
		"system_u:object_r:user_home_t:s0",
		"system_u:object_r:tmp_t:s0",
		"unconfined_u:object_r:user_home_t:s0",
	};
	size_t n;

	/* All branches below dispatch on strncmp(name, ...) and memcpy into
	 * buf -- a NULL or zero-size buffer, or a NULL name pointer, would
	 * fault before producing a value.  Return zero bytes ("no value");
	 * the caller leaves *sizep at 0, which is a valid setxattr draw. */
	if (name == NULL || buf == NULL || bufsz == 0)
		return 0;

	if (strncmp(name, "security.selinux", 16) == 0) {
		const char *ctx = RAND_ARRAY(selinux_ctx);

		n = strlen(ctx) + 1;
		if (n > bufsz)
			n = bufsz;
		memcpy(buf, ctx, n);
		return n;
	}

	if (strncmp(name, "security.capability", 19) == 0) {
		/*
		 * struct vfs_cap_data shape:
		 *   __le32 magic_etc                = revision | flags
		 *   struct { __le32 permitted; __le32 inheritable; } data[2];
		 *
		 * VFS_CAP_REVISION_2 = 0x02000000, VFS_CAP_FLAGS_EFFECTIVE = 0x01.
		 * Use literal 0x01 for the flags bit -- the kernel headers may
		 * or may not be available in this tree.
		 */
		struct cap_shape {
			uint32_t magic_etc;
			struct {
				uint32_t permitted;
				uint32_t inheritable;
			} data[2];
		} cap;

		cap.magic_etc = 0x02000000UL | 0x01UL;
		cap.data[0].permitted   = rnd_u32();
		cap.data[0].inheritable = rnd_u32();
		cap.data[1].permitted   = rnd_u32();
		cap.data[1].inheritable = rnd_u32();
		n = sizeof(cap);
		if (n > bufsz)
			n = bufsz;
		memcpy(buf, &cap, n);
		return n;
	}

	if (strncmp(name, "system.posix_acl_", 17) == 0) {
		/* POSIX_ACL_XATTR_VERSION = 0x0002 (4-byte LE header). */
		uint32_t hdr = 0x00000002UL;

		n = sizeof(hdr);
		if (n > bufsz)
			n = bufsz;
		memcpy(buf, &hdr, n);
		return n;
	}

	/* user.*, trusted.*, fallback: small random opaque buffer. */
	n = 1 + rnd_modulo_u32(255);
	if (n > bufsz)
		n = bufsz;
	generate_rand_bytes((unsigned char *) buf, n);
	return n;
}

/*
 * Plant a per-namespace value buffer + size for the setxattr family.
 * Allocates a fresh page-sized buffer, fills it via xattr_fill_value,
 * and rewrites *bufp / *sizep.  Leaves the slot untouched on
 * allocation failure -- the existing ARG_ADDRESS / ARG_LEN draw stays
 * in place as a fallback.
 *
 * Call AFTER sanitise_xattr_name_arg_pooled so the name at *namep is
 * already valid and we can dispatch on its namespace.
 */
void xattr_set_value(const char *name, unsigned long *bufp, unsigned long *sizep)
{
	void *p;
	size_t n;

	/* If the name slot was forced to NULL (pool exhaustion in
	 * sanitise_xattr_name_arg_pooled), don't dispatch on it -- leave
	 * the original ARG_ADDRESS / ARG_LEN draw in place as a fallback. */
	if (name == NULL)
		return;

	p = get_writable_address(page_size);
	if (!p)
		return;
	n = xattr_fill_value(name, p, page_size);
	*bufp = (unsigned long) p;
	*sizep = (unsigned long) n;
}

/*
 * Flag bucket for the setxattr family.  Distribution:
 *   30% 0 (default -- create-or-replace)
 *   30% XATTR_CREATE (must-create)
 *   30% XATTR_REPLACE (must-replace)
 *   10% random-bit invalid-flag draw
 *
 * The pre-existing arg_params[*].list draw picked CREATE / REPLACE
 * 50/50 with no zero slot and no invalid-bits coverage, so the
 * flag-validation path saw only the two valid bits and the
 * create/replace decision path was never exercised with a real "any
 * existing state is OK" draw.
 */
void xattr_pick_set_flags(unsigned long *flagsp)
{
	unsigned int r = rnd_modulo_u32(10);

	if (r < 3)
		*flagsp = 0;
	else if (r < 6)
		*flagsp = XATTR_CREATE;
	else if (r < 9)
		*flagsp = XATTR_REPLACE;
	else
		*flagsp = rnd_u32();	/* invalid bits */
}
