/* Generate valid extended attribute name strings for xattr syscalls. */
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/xattr.h>
#include "random.h"
#include "sanitise.h"
#include "syscall.h"
#include "utils.h"
#include "xattr.h"

#define XATTR_NAME_BUFSZ 256

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
	unsigned int r = rnd_modulo_u32(10);

	if (r < 7) {
		snprintf(buf, len, "%s", RAND_ARRAY(xattr_pooled_names));
	} else if (r < 9) {
		snprintf(buf, len, "user.r%u", rnd_u32());
	} else {
		gen_xattr_name(buf, len);
	}
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
	if (!name)
		return false;
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
