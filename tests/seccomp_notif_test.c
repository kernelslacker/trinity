/*
 * The seccomp-notif provider's filter (fds/seccomp_notif.c) parks a
 * listener on one syscall number trinity never issues and lets every
 * other call through, that number under a foreign arch's table included:
 * a biarch kernel's compat table puts a different call there.  The filter
 * is caught on its way to seccomp() and run over seccomp_data here.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>

#include "arch.h"		/* NATIVE_AUDIT_ARCH */
#include "debug.h"		/* BUG */
#include "fake_objects.h"	/* fake_alloc_object, fake_add_object */
#include "fd.h"			/* struct fd_provider */
#include "fds/fds-internal.h"	/* fd_providers */
#include "list.h"
#include "objects.h"
#include "utils.h"		/* ARRAY_SIZE */

#ifdef USE_SECCOMP
#include <linux/filter.h>
#include "kernel/audit.h"
#include "kernel/seccomp.h"

extern struct objhead *(*fake_get_objhead)(enum obj_scope scope,
					   enum objecttype type);	/* fake_objects.c */
extern bool (*fake_syscall)(long number, const unsigned long a[6],
			    long *ret);	/* landlock_test.c */

#define MAX_FILTER_INSNS	64

static struct sock_filter caught[MAX_FILTER_INSNS];
static unsigned int caught_len;
static struct objhead fake_head;
static struct object fake_obj;

static bool catch_filter(long number, const unsigned long a[6], long *ret)
{
	const struct sock_fprog *prog = (const struct sock_fprog *) a[2];

	if (number != __NR_seccomp || a[0] != SECCOMP_SET_MODE_FILTER)
		return false;
	if (prog->len > MAX_FILTER_INSNS)
		BUG("seccomp notif: the filter outgrew the test's copy");
	memcpy(caught, prog->filter, prog->len * sizeof(caught[0]));
	caught_len = prog->len;
	*ret = 90001;	/* a listener number no fd table holds */
	return true;
}

static struct objhead *head_for_init(enum obj_scope scope, enum objecttype type)
{
	(void) scope;
	(void) type;
	return &fake_head;
}

static struct object *object_for_init(void)
{
	return &fake_obj;
}

static void drop_published(struct object *obj, enum obj_scope scope,
			   enum objecttype type)
{
	(void) obj;
	(void) scope;
	(void) type;
}

/* Run the caught filter over @d, with the loads, jumps and returns it is
 * built from; anything else fails the test rather than guessing. */
static uint32_t run_filter(const struct seccomp_data *d)
{
	unsigned int pc = 0;
	uint32_t a = 0;

	while (pc < caught_len) {
		const struct sock_filter *insn = &caught[pc++];

		switch (insn->code) {
		case BPF_LD | BPF_W | BPF_ABS:
			if (insn->k > sizeof(*d) - sizeof(a))
				BUG("seccomp notif: the filter loads past seccomp_data");
			memcpy(&a, (const char *) d + insn->k, sizeof(a));
			break;
		case BPF_JMP | BPF_JEQ | BPF_K:
			pc += a == insn->k ? insn->jt : insn->jf;
			break;
		case BPF_RET | BPF_K:
			return insn->k;
		default:
			BUG("seccomp notif: the filter holds an instruction the test cannot run");
		}
	}
	BUG("seccomp notif: the filter runs off its end");
}
#endif

void seccomp_notif_self_check(void);
void seccomp_notif_self_check(void)
{
#ifdef USE_SECCOMP
	static const uint32_t arches[] = {
		AUDIT_ARCH_I386, AUDIT_ARCH_X86_64, AUDIT_ARCH_ARM,
		AUDIT_ARCH_AARCH64, AUDIT_ARCH_RISCV64, AUDIT_ARCH_LOONGARCH64,
	};
	int (*init)(void) = NULL;
	unsigned int i, parked = 0;
	struct seccomp_data d;
	struct list_head *node;
	int nr, target = 0;

	list_for_each(node, &fd_providers->list) {
		struct fd_provider *prov = (struct fd_provider *) node;

		if (strcmp(prov->name, "seccomp-notif") == 0)
			init = prov->init;
	}
	if (init == NULL)
		BUG("seccomp notif: the provider is not registered");

	fake_get_objhead = head_for_init;
	fake_alloc_object = object_for_init;
	fake_add_object = drop_published;
	fake_syscall = catch_filter;
	init();
	fake_syscall = NULL;
	fake_add_object = NULL;
	fake_alloc_object = NULL;
	fake_get_objhead = NULL;
	if (caught_len == 0)
		BUG("seccomp notif: no filter reached seccomp()");

	/* The number the listener is parked on, in the native table: the
	 * syscall numbers in use, and the top of the int range a table that
	 * never had query_module parks on. */
	memset(&d, 0, sizeof(d));
	d.arch = NATIVE_AUDIT_ARCH;
	for (nr = 0; nr <= 4096; nr++) {
		d.nr = nr < 4096 ? nr : 0x7fffffff;
		switch (run_filter(&d)) {
		case SECCOMP_RET_ALLOW:
			break;
		case SECCOMP_RET_USER_NOTIF:
			parked++;
			target = d.nr;
			break;
		default:
			BUG("seccomp notif: the filter returns neither ALLOW nor USER_NOTIF");
		}
	}
	if (parked != 1)
		BUG("seccomp notif: the filter does not park on exactly one native number");

	/* Under another arch's table that number is some other call. */
	d.nr = target;
	for (i = 0; i < ARRAY_SIZE(arches); i++) {
		if (arches[i] == NATIVE_AUDIT_ARCH)
			continue;
		d.arch = arches[i];
		if (run_filter(&d) != SECCOMP_RET_ALLOW)
			BUG("seccomp notif: a foreign arch's call under the parked number is caught");
	}
#endif
}
