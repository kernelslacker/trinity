/* Generate valid extended attribute name strings for xattr syscalls. */
#include <fcntl.h>
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
