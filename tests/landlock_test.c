/*
 * Self-check for the Landlock sanitisers and the Landlock fd provider
 * (syscalls/landlock/, fds/landlock.c): the rules and rulesets they build are
 * held to what security/landlock/syscalls.c answers a call with, the kernel
 * half of each rule cited where it is checked.  A model of the two syscalls
 * stands in for the kernel while a provider runs; syscall() is wrapped for it.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "debug.h"		/* BUG */
#include "fake_objects.h"	/* fake_alloc_object, fake_add_object */
#include "fd.h"
#include "fds/fds-internal.h"	/* fd_providers */
#include "kernel/landlock.h"
#include "kernel/sched.h"
#include "landlock.h"
#include "list.h"
#include "objects.h"
#include "syscall.h"
#include "syscalls/syscalls.h"	/* syscall_landlock_add_rule */
#include "utils-macros.h"	/* ARRAY_SIZE */

void landlock_self_check(void);

extern bool fake_random_fd_empty;	/* fake_stubs.c */
extern struct objhead *(*fake_get_objhead)(enum obj_scope scope,
					   enum objecttype type);	/* fake_objects.c */

/* Calls per case: enough that a draw one time in sixteen is seen hundreds of
 * times. */
#define NR_CALLS	20000

/* The members the kernel keeps: CLONE_NS_ALL, and CAP_VALID_MASK, whose last
 * capability is CAP_CHECKPOINT_RESTORE (40). */
#define NS_ALL		(CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWUTS | \
			 CLONE_NEWIPC | CLONE_NEWUSER | CLONE_NEWPID | \
			 CLONE_NEWNET | CLONE_NEWTIME)
#define CAPS_ALL	((1ULL << 41) - 1)

#define BOTH_PERMISSIONS (LANDLOCK_PERMISSION_NAMESPACE_USE | \
			  LANDLOCK_PERMISSION_CAPABILITY_USE)

static unsigned int failed;

/* A rule broken by every call would print NR_CALLS lines; the first few say it. */
static void expect(bool ok, const char *what, unsigned long got)
{
	if (ok)
		return;
	if (failed++ < 10)
		fprintf(stderr, "landlock: %s (got %lu)\n", what, got);
}

/*
 * add_rule_namespace() and add_rule_capability() for a ruleset that handles
 * @handled: any flag is -EINVAL (LANDLOCK_ADD_RULE_QUIET too, "Namespace rules
 * support no add-rule flags"), no permission is -ENOMSG, a selector other than
 * the one the type is for, or one the ruleset does not handle, is -EINVAL,
 * and a rule that neither allows nor quiets a member is -ENOMSG.
 */
static int permission_rule_answer(unsigned long rule_type, unsigned long flags,
				  const struct landlock_permission_attr *pa,
				  unsigned long long handled)
{
	unsigned long long want = rule_type == LANDLOCK_RULE_CAPABILITY_COMPAT ?
		LANDLOCK_PERMISSION_CAPABILITY_USE :
		LANDLOCK_PERMISSION_NAMESPACE_USE;

	if (flags)
		return -EINVAL;
	if (!pa->permissions)
		return -ENOMSG;
	if (pa->permissions != want)
		return -EINVAL;
	if (!(handled & want))
		return -EINVAL;
	if (!pa->allowed && !pa->quiet)
		return -ENOMSG;
	return 0;
}

static void check_permission_rules(void)
{
	static const unsigned long types[] = {
		LANDLOCK_RULE_NAMESPACE_COMPAT, LANDLOCK_RULE_CAPABILITY_COMPAT,
	};
	unsigned int t;

	for (t = 0; t < ARRAY_SIZE(types); t++) {
		unsigned long accepted = 0, enomsg = 0, einval = 0, every = 0, i;

		for (i = 0; i < NR_CALLS; i++) {
			const struct landlock_permission_attr *pa;
			struct syscallrecord rec;
			int ret;

			memset(&rec, 0, sizeof(rec));
			rec.a2 = types[t];
			syscall_landlock_add_rule.sanitise(&rec);

			expect(rec.a3 != 0, "the rule is built", types[t]);
			if (rec.a3 == 0)
				continue;
			pa = (const struct landlock_permission_attr *) rec.a3;
			expect(rec.a4 == 0, "a permission rule carries no flag",
			       rec.a4);

			ret = permission_rule_answer(types[t], rec.a4, pa,
						     BOTH_PERMISSIONS);
			accepted += ret == 0;
			enomsg += ret == -ENOMSG;
			einval += ret == -EINVAL;
			every += pa->allowed == ~0ULL;
		}

		expect(accepted * 4 >= NR_CALLS * 3,
		       "three in four permission rules are ones the kernel takes",
		       accepted);
		expect(enomsg > 0 && einval > 0,
		       "the refusals are drawn as well", enomsg);
		expect(every * 2 > NR_CALLS,
		       "most allowed masks name every member", every);
	}
}

/* The two older rule types keep the quiet flag the kernel takes for them. */
static void check_older_rule_flags(void)
{
	static const unsigned long types[] = {
		LANDLOCK_RULE_PATH_BENEATH_COMPAT, LANDLOCK_RULE_NET_PORT_COMPAT,
	};
	unsigned int t;

	/* The path rule names an fd from the pool, which is empty here. */
	fake_random_fd_empty = true;

	for (t = 0; t < ARRAY_SIZE(types); t++) {
		unsigned long quiet = 0, i;

		for (i = 0; i < NR_CALLS; i++) {
			struct syscallrecord rec;

			memset(&rec, 0, sizeof(rec));
			rec.a2 = types[t];
			syscall_landlock_add_rule.sanitise(&rec);

			expect(rec.a4 == 0 || rec.a4 == LANDLOCK_ADD_RULE_QUIET,
			       "a path or port rule takes the quiet flag or none",
			       rec.a4);
			quiet += rec.a4 == LANDLOCK_ADD_RULE_QUIET;
		}
		expect(quiet > NR_CALLS / 4 && quiet < NR_CALLS * 3 / 4,
		       "the quiet flag is drawn about half the time", quiet);
	}

	fake_random_fd_empty = false;
}

/* A rule type the sanitiser builds is dead code unless the draw of the type
 * argument can name it. */
static void check_rule_types_drawn(void)
{
	static const unsigned long types[] = {
		LANDLOCK_RULE_PATH_BENEATH_COMPAT, LANDLOCK_RULE_NET_PORT_COMPAT,
		LANDLOCK_RULE_NAMESPACE_COMPAT, LANDLOCK_RULE_CAPABILITY_COMPAT,
	};
	const struct arglist *list = &syscall_landlock_add_rule.arg_params[1].list;
	unsigned int t, i;

	for (t = 0; t < ARRAY_SIZE(types); t++) {
		bool found = false;

		for (i = 0; i < list->num; i++)
			found |= list->values[i] == types[t];
		expect(found, "the rule type argument can name the type", types[t]);
	}
}

#ifdef __NR_landlock_create_ruleset

/*
 * A Landlock kernel of the ABI fake_abi names, which stands in for the real
 * one while it is set: the ruleset a create call makes is an fd on /dev/null,
 * with the handled permissions and the members each rule allowed recorded
 * against it, and every add_rule call and its answer is kept.
 */
static int fake_abi;
static unsigned long last_create_size;
static int last_create_fd = -1;

/* A rule type the model turns away with fake_refuse_errno, whatever it says,
 * as a seccomp filter or a kernel with one more check would: nothing is added. */
static unsigned int fake_refuse_type;
static int fake_refuse_errno;

struct fake_ruleset {
	bool used;
	int fd;
	unsigned long long handled_permissions;
	unsigned long long allowed_ns, allowed_caps;
};
static struct fake_ruleset rulesets[16];

struct rule_call {
	int fd;
	unsigned int type, flags;
	struct landlock_permission_attr attr;
	long ret;
};
static struct rule_call rule_calls[64];
static unsigned int nr_rule_calls;

static struct fake_ruleset *find_ruleset(int fd)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(rulesets); i++) {
		if (rulesets[i].used && rulesets[i].fd == fd)
			return &rulesets[i];
	}
	return NULL;
}

/* What struct landlock_ruleset_attr is in bytes at each ABI. */
static unsigned long fake_ksize(void)
{
	if (fake_abi >= 12)
		return 56;
	if (fake_abi >= 10)
		return 48;
	return fake_abi >= 6 ? 24 : 16;
}

/*
 * sys_landlock_create_ruleset(): the size has to hold the first field and fit
 * a page, copy_struct_from_user() refuses a tail past what the kernel has
 * unless it is zero, then each mask is checked against the ABI's and a quiet
 * mask against the handled one, and a ruleset that handles nothing is -ENOMSG.
 */
static long fake_create_ruleset(const unsigned char *attr, size_t size,
				unsigned int flags)
{
	unsigned long long f[7] = { 0 };
	unsigned long ksize = fake_ksize(), i;
	struct fake_ruleset *rs;
	int fd;

	if (flags) {
		if (attr || size)
			return -EINVAL;
		return flags == LANDLOCK_CREATE_RULESET_VERSION ? fake_abi : -EINVAL;
	}

	if (!attr)
		return -EFAULT;
	if (size < sizeof(f[0]))
		return -EINVAL;
	if (size > 4096)
		return -E2BIG;
	memcpy(f, attr, size < ksize ? size : ksize);
	for (i = ksize; i < size; i++) {
		if (attr[i])
			return -E2BIG;
	}
	last_create_size = size;

	if (f[0] & ~(fake_abi >= 9 ? 0x1ffffULL : 0xffffULL))
		return -EINVAL;
	if (f[1] & ~(fake_abi >= 10 ? 0xfULL : 0x3ULL))
		return -EINVAL;
	if (f[2] & ~0x3ULL)
		return -EINVAL;
	if ((f[3] | f[0]) != f[0] || (f[4] | f[1]) != f[1] ||
	    (f[5] | f[2]) != f[2])
		return -EINVAL;
	if (f[6] & ~BOTH_PERMISSIONS)
		return -EINVAL;
	if (!f[0] && !f[1] && !f[2] && !f[6])
		return -ENOMSG;

	fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	rs = find_ruleset(fd);
	if (rs == NULL) {
		for (i = 0; i < ARRAY_SIZE(rulesets) && rulesets[i].used; i++)
			;
		if (i == ARRAY_SIZE(rulesets))
			BUG("landlock: the fake kernel is out of rulesets");
		rs = &rulesets[i];
	}
	memset(rs, 0, sizeof(*rs));
	rs->used = true;
	rs->fd = fd;
	rs->handled_permissions = f[6];
	last_create_fd = fd;
	return fd;
}

/*
 * sys_landlock_add_rule() for the two permission types, which the older two
 * stand beside unmodelled: the flags, then the ruleset fd, then the rule type,
 * of which a kernel from before ABI 12 knows two.  A rule that gets through
 * adds its members the way the kernel masks them, CLONE_NS_ALL and
 * CAP_VALID_MASK, to the ruleset.
 */
static long fake_add_rule(int fd, unsigned int type, const void *attr,
			  unsigned int flags)
{
	struct landlock_permission_attr pa = { 0 };
	struct fake_ruleset *rs = find_ruleset(fd);
	long ret;

	if (flags && flags != LANDLOCK_ADD_RULE_QUIET)
		ret = -EINVAL;
	else if (rs == NULL)
		ret = -EBADF;
	else if (fake_refuse_errno != 0 && type == fake_refuse_type)
		ret = -fake_refuse_errno;
	else if ((type == LANDLOCK_RULE_NAMESPACE_COMPAT ||
		  type == LANDLOCK_RULE_CAPABILITY_COMPAT) && fake_abi < 12)
		ret = -EINVAL;
	else if (type == LANDLOCK_RULE_NAMESPACE_COMPAT ||
		 type == LANDLOCK_RULE_CAPABILITY_COMPAT) {
		memcpy(&pa, attr, sizeof(pa));
		ret = permission_rule_answer(type, flags, &pa,
					     rs->handled_permissions);
		if (ret == 0 && type == LANDLOCK_RULE_NAMESPACE_COMPAT)
			rs->allowed_ns |= pa.allowed & NS_ALL;
		else if (ret == 0)
			rs->allowed_caps |= pa.allowed & CAPS_ALL;
	} else if (type == LANDLOCK_RULE_PATH_BENEATH_COMPAT ||
		   type == LANDLOCK_RULE_NET_PORT_COMPAT) {
		ret = 0;
	} else {
		ret = -EINVAL;
	}

	if (nr_rule_calls < ARRAY_SIZE(rule_calls)) {
		struct rule_call *rc = &rule_calls[nr_rule_calls++];

		rc->fd = fd;
		rc->type = type;
		rc->flags = flags;
		rc->attr = pa;
		rc->ret = ret;
	}
	return ret;
}

long __real_syscall(long number, ...);
long __wrap_syscall(long number, ...);

long __wrap_syscall(long number, ...)
{
	unsigned long a[6];
	va_list ap;
	long ret;
	int i;

	va_start(ap, number);
	for (i = 0; i < 6; i++)
		a[i] = va_arg(ap, unsigned long);
	va_end(ap);

	if (fake_abi != 0 && number == __NR_landlock_create_ruleset)
		ret = fake_create_ruleset((const unsigned char *) a[0], a[1],
					  (unsigned int) a[2]);
	else if (fake_abi != 0 && number == __NR_landlock_add_rule)
		ret = fake_add_rule((int) a[0], (unsigned int) a[1],
				    (const void *) a[2], (unsigned int) a[3]);
	else
		return __real_syscall(number, a[0], a[1], a[2], a[3], a[4], a[5]);

	if (ret < 0) {
		errno = (int) -ret;
		return -1;
	}
	return ret;
}

/* The provider's pool head names these two, which objects/registry-diag.c owns. */
void close_fd_destructor(struct object *obj)
{
	(void) obj;
}

void generic_fd_dump(struct object *obj, enum obj_scope scope)
{
	(void) obj;
	(void) scope;
}

static struct objhead fake_head;
static struct object objs[4];
static unsigned int nr_objs;

/* What the ruleset held when the provider handed it to the pool: whatever it
 * does to it after that, nothing restricts itself with the ruleset before. */
static unsigned int published;
static struct fake_ruleset at_publish;

static struct objhead *head_hook(enum obj_scope scope, enum objecttype type)
{
	(void) scope;
	(void) type;
	return &fake_head;
}

static struct object *alloc_hook(void)
{
	if (nr_objs == ARRAY_SIZE(objs))
		BUG("landlock: the provider allocated more objects than expected");
	memset(&objs[nr_objs], 0, sizeof(objs[nr_objs]));
	return &objs[nr_objs++];
}

static void add_hook(struct object *obj, enum obj_scope scope,
		     enum objecttype type)
{
	struct fake_ruleset *rs = find_ruleset(obj->landlockobj.fd);

	(void) scope;
	(void) type;
	published++;
	if (rs != NULL)
		at_publish = *rs;
}

/* Run the landlock provider's init hook as open_fds() does, against fake hooks. */
static bool run_provider_init(void)
{
	int (*init)(void) = NULL;
	struct list_head *node;
	bool ok;

	list_for_each(node, &fd_providers->list) {
		struct fd_provider *prov = (struct fd_provider *) node;

		if (strcmp(prov->name, "landlock") == 0)
			init = prov->init;
	}
	if (init == NULL)
		BUG("landlock: the landlock provider is not registered");

	fake_get_objhead = head_hook;
	fake_alloc_object = alloc_hook;
	fake_add_object = add_hook;
	ok = init();
	fake_get_objhead = NULL;
	fake_alloc_object = NULL;
	fake_add_object = NULL;
	return ok;
}

/* Close what the fake kernel and the pool hold, and start the model over. */
static void reset_kernel(void)
{
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(rulesets); i++) {
		if (rulesets[i].used)
			close(rulesets[i].fd);
	}
	memset(rulesets, 0, sizeof(rulesets));
	memset(rule_calls, 0, sizeof(rule_calls));
	memset(&at_publish, 0, sizeof(at_publish));
	nr_rule_calls = 0;
	nr_objs = 0;
	published = 0;
	last_create_size = 0;
	last_create_fd = -1;
	fake_refuse_type = 0;
	fake_refuse_errno = 0;
}

/* The rule calls that were for @type, and how many of them the kernel took. */
static unsigned int count_rule_calls(unsigned int type, unsigned int *taken)
{
	unsigned int i, n = 0;

	*taken = 0;
	for (i = 0; i < nr_rule_calls; i++) {
		if (rule_calls[i].type != type)
			continue;
		n++;
		*taken += rule_calls[i].ret == 0 && rule_calls[i].flags == 0;
	}
	return n;
}

/*
 * A ruleset that handles a permission and holds no rule for it denies every
 * member of it, and a child that restricts itself with one loses every
 * capability or namespace type for good.  On an ABI 12 kernel the provider's
 * ruleset handles both permissions, and has to allow every member of both by
 * the time it is in the pool; on an older kernel it asks for nothing of the
 * kind, in a struct the kernel has the size of.
 */
static void check_provider(void)
{
	static const int older[] = { 6, 10, 11 };
	unsigned int ns_taken, caps_taken, ns_calls, caps_calls, i;

	fake_abi = 12;
	reset_kernel();
	expect(run_provider_init(), "the provider makes its ruleset on ABI 12", 0);
	expect(published == 1, "the ruleset is published once", published);
	expect(last_create_size == 56, "the ABI 12 struct is sent whole",
	       last_create_size);
	expect(at_publish.handled_permissions == BOTH_PERMISSIONS,
	       "the ruleset handles both permissions",
	       at_publish.handled_permissions);
	ns_calls = count_rule_calls(LANDLOCK_RULE_NAMESPACE_COMPAT, &ns_taken);
	caps_calls = count_rule_calls(LANDLOCK_RULE_CAPABILITY_COMPAT, &caps_taken);
	expect(ns_calls == 1 && ns_taken == 1,
	       "one namespace rule, and the kernel takes it", ns_taken);
	expect(caps_calls == 1 && caps_taken == 1,
	       "one capability rule, and the kernel takes it", caps_taken);
	expect(at_publish.allowed_ns == NS_ALL,
	       "every namespace type is allowed when the ruleset is published",
	       at_publish.allowed_ns);
	expect(at_publish.allowed_caps == CAPS_ALL,
	       "every capability is allowed when the ruleset is published",
	       at_publish.allowed_caps);

	/* ABI 10 and 11 know 48 bytes of the struct and answer -E2BIG to a
	 * non-zero byte past them, so only ABI 12 is sent handled_permissions. */
	for (i = 0; i < ARRAY_SIZE(older); i++) {
		fake_abi = older[i];
		reset_kernel();
		expect(run_provider_init(),
		       "the provider makes its ruleset on an older ABI", older[i]);
		expect(published == 1, "the older ruleset is published once", published);
		expect(last_create_size == 24, "an older kernel is sent 24 bytes",
		       last_create_size);
		expect(at_publish.handled_permissions == 0,
		       "an older ruleset handles no permission",
		       at_publish.handled_permissions);
		ns_calls = count_rule_calls(LANDLOCK_RULE_NAMESPACE_COMPAT, &ns_taken);
		caps_calls = count_rule_calls(LANDLOCK_RULE_CAPABILITY_COMPAT, &caps_taken);
		expect(ns_calls == 0 && caps_calls == 0,
		       "an older ruleset is given no permission rule",
		       ns_calls + caps_calls);
	}

	fake_abi = 0;
	reset_kernel();
}

/*
 * A permission rule the kernel turns away, whatever its errno, leaves a ruleset
 * that handles the permission and allows none of it.  The provider must not
 * publish that, and must close it: an fd left open and out of the pool can
 * still be named by a guessed number and restrict a child with it.
 */
static void check_provider_refused(void)
{
	static const unsigned int types[] = {
		LANDLOCK_RULE_NAMESPACE_COMPAT, LANDLOCK_RULE_CAPABILITY_COMPAT,
	};
	static const int errnos[] = { EINVAL, EPERM, ENOMEM };
	unsigned int t, e;

	fake_abi = 12;
	for (t = 0; t < ARRAY_SIZE(types); t++) {
		for (e = 0; e < ARRAY_SIZE(errnos); e++) {
			struct fake_ruleset *rs;
			int fd;

			reset_kernel();
			fake_refuse_type = types[t];
			fake_refuse_errno = errnos[e];

			expect(!run_provider_init(),
			       "a refused permission rule fails the provider", types[t]);
			expect(published == 0,
			       "a ruleset whose permission rule was refused is not published",
			       published);

			fd = last_create_fd;
			expect(fd >= 0 && fcntl(fd, F_GETFD) == -1 && errno == EBADF,
			       "the ruleset whose permission rule was refused is closed",
			       fd);
			/* Closed already, so reset_kernel() must not close it again. */
			rs = find_ruleset(fd);
			if (rs != NULL)
				rs->used = false;
		}
	}

	fake_abi = 0;
	reset_kernel();
}

/* A ruleset on the model kernel that handles @handled, in the struct the
 * newest ABI has, which an older kernel takes with its newer fields zero. */
static long make_ruleset(unsigned long long handled)
{
	struct landlock_ruleset_attr_abi12 attr = {
		.handled_access_fs = 1,
		.handled_permissions = handled,
	};

	return syscall(__NR_landlock_create_ruleset, &attr, sizeof(attr), 0);
}

/*
 * landlock_allow_permissions() is told what the ruleset handles and asks for
 * that and nothing else: what it handles ends up allowed whole, and a
 * permission the ruleset does not handle, which the kernel answers -EINVAL, is
 * refused like any rule the kernel turns away.
 */
static void check_allow_permissions(void)
{
	static const unsigned long long handles[] = {
		0, LANDLOCK_PERMISSION_NAMESPACE_USE,
		LANDLOCK_PERMISSION_CAPABILITY_USE, BOTH_PERMISSIONS,
	};
	unsigned int i;
	long fd;

	fake_abi = 12;
	for (i = 0; i < ARRAY_SIZE(handles); i++) {
		struct fake_ruleset *rs;

		reset_kernel();
		fd = make_ruleset(handles[i]);
		expect(fd >= 0, "the model makes a ruleset", i);
		if (fd < 0)
			continue;

		expect(landlock_allow_permissions(fd, handles[i]),
		       "a ruleset armed for what it handles is fit to publish", i);
		expect(nr_rule_calls ==
		       (unsigned int) __builtin_popcountll(handles[i]),
		       "one rule for each permission handled and no other",
		       nr_rule_calls);

		rs = find_ruleset(fd);
		expect(rs != NULL && rs->allowed_ns ==
		       ((handles[i] & LANDLOCK_PERMISSION_NAMESPACE_USE) ? NS_ALL : 0),
		       "namespace types are allowed exactly when handled", i);
		expect(rs != NULL && rs->allowed_caps ==
		       ((handles[i] & LANDLOCK_PERMISSION_CAPABILITY_USE) ? CAPS_ALL : 0),
		       "capabilities are allowed exactly when handled", i);
	}

	reset_kernel();
	fd = make_ruleset(LANDLOCK_PERMISSION_NAMESPACE_USE);
	expect(fd >= 0, "the model makes a namespace-only ruleset", 0);
	if (fd >= 0)
		expect(!landlock_allow_permissions(fd, BOTH_PERMISSIONS),
		       "a rule for a permission the ruleset does not handle fails",
		       0);

	/* A permission past the two there are has no rule here to arm it with. */
	reset_kernel();
	fd = make_ruleset(BOTH_PERMISSIONS);
	expect(fd >= 0, "the model makes a ruleset that handles both", 0);
	if (fd >= 0)
		expect(!landlock_allow_permissions(fd,
					BOTH_PERMISSIONS | (1ULL << 2)),
		       "a permission this has no rule for fails the arming", 0);

	/* A kernel from before ABI 12 has no ruleset that handles a permission:
	 * nothing is asked of it and nothing can fail.  Asked for one anyway, it
	 * refuses the rule type. */
	fake_abi = 6;
	reset_kernel();
	fd = make_ruleset(0);
	expect(fd >= 0, "the model makes an ABI 6 ruleset", 0);
	if (fd >= 0) {
		expect(landlock_allow_permissions(fd, 0) && nr_rule_calls == 0,
		       "an ABI 6 ruleset is armed with nothing asked", nr_rule_calls);
		expect(!landlock_allow_permissions(fd, BOTH_PERMISSIONS) &&
		       nr_rule_calls > 0 && rule_calls[0].ret == -EINVAL,
		       "an older kernel refuses the permission rule types",
		       nr_rule_calls);
	}

	fake_abi = 0;
	reset_kernel();
}

/*
 * A rule the kernel turns away fails the arming, whatever the errno.  -EINVAL
 * is what a permission the ruleset does not handle draws, but a filter or a
 * stricter kernel can draw it for one it does, and the ruleset then allows
 * none of it.
 */
static void check_allow_refused(void)
{
	static const unsigned int types[] = {
		LANDLOCK_RULE_NAMESPACE_COMPAT, LANDLOCK_RULE_CAPABILITY_COMPAT,
	};
	static const int errnos[] = { EINVAL, EPERM, ENOMEM };
	unsigned int t, e;

	fake_abi = 12;
	for (t = 0; t < ARRAY_SIZE(types); t++) {
		for (e = 0; e < ARRAY_SIZE(errnos); e++) {
			long fd;

			reset_kernel();
			fd = make_ruleset(BOTH_PERMISSIONS);
			expect(fd >= 0, "the model makes a ruleset to refuse a rule of", t);
			if (fd < 0)
				continue;

			fake_refuse_type = types[t];
			fake_refuse_errno = errnos[e];
			expect(!landlock_allow_permissions(fd, BOTH_PERMISSIONS),
			       "a refused permission rule fails the arming", errnos[e]);
		}
	}

	fake_abi = 0;
	reset_kernel();
}

#endif /* __NR_landlock_create_ruleset */

void landlock_self_check(void)
{
	check_permission_rules();
	check_older_rule_flags();
	check_rule_types_drawn();
#ifdef __NR_landlock_create_ruleset
	check_provider();
	check_provider_refused();
	check_allow_permissions();
	check_allow_refused();
#endif

	if (failed != 0)
		BUG("landlock: a check failed");
}
