/* Generate valid extended attribute name strings for xattr syscalls. */
#include <stdio.h>
#include <stdlib.h>
#include "random.h"
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
	snprintf(buf, len, "%s%s",
		 RAND_ARRAY(xattr_prefixes),
		 RAND_ARRAY(xattr_suffixes));
}
