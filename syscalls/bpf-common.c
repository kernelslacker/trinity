/*
 * syscalls/bpf-common.c -- the fourth and fifth arguments of bpf(): the
 * struct bpf_common_attr a command carries when BPF_COMMON_ATTRS is set in
 * its number.
 */

#ifdef USE_BPF

#include <linux/bpf.h>
#include <stddef.h>
#include <string.h>

#include "arch.h"
#include "bpf.h"
#include "bpf-internal.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "utils.h"

/* bpf_check_uarg_tail_zero() wants zeroes past the last field it knows, not
 * past the struct, whose padding is part of the tail. */
#define COMMON_ATTR_FIELDS_END	(offsetof(struct bpf_common_attr, log_true_size) + sizeof(__u32))

/* BPF_LOG_MASK: the log_level bits bpf_verifier_log_attr_valid() takes. */
#define COMMON_LOG_MASK		0xfU

/* The shapes of a draw the kernel refuses, one rule broken each. */
enum common_rule {
	RULE_NONE,
	RULE_TOO_LONG,
	RULE_TAIL_SET,
	RULE_UNREADABLE,
	RULE_BAD_LOG,
	RULE_LOGS_DIFFER,
	RULES
};

/*
 * __sys_bpf() copies the struct whenever cmd carries the flag, whatever the
 * command, but only BPF_MAP_CREATE, BPF_PROG_LOAD and BPF_BTF_LOAD do
 * anything with it: they take their verifier log from it.  A load that
 * names a log in its own attr too must name the same one
 * (bpf_log_attr_init()), so a load keeps one of the two logs, or names the
 * one twice, unless the draw is the one meant to differ.
 *
 * Most calls leave both slots 0 and the flag clear.  Of those that carry
 * the struct most are ones the kernel takes, and one in eight breaks one
 * rule so each rejection stays reachable.  The commands that read it carry
 * it oftener than the rest, which only run the checks around the copy.
 */
void sanitise_bpf_common_attr(union bpf_attr *attr, struct syscallrecord *rec)
{
	/* The struct's size, for most; one that ends on log_true_size; one
	 * that stops before it, so no true size comes back; one that sends
	 * nothing. */
	static const unsigned int sizes[] = {
		sizeof(struct bpf_common_attr), sizeof(struct bpf_common_attr),
		sizeof(struct bpf_common_attr), sizeof(struct bpf_common_attr),
		COMMON_ATTR_FIELDS_END, COMMON_ATTR_FIELDS_END,
		offsetof(struct bpf_common_attr, log_true_size), 0,
	};
	unsigned int cmd = rec->a1 & ~BPF_COMMON_ATTRS;
	bool loads = cmd == BPF_PROG_LOAD || cmd == BPF_BTF_LOAD;
	struct bpf_common_attr *common;
	__u64 *own_buf = NULL;
	__u32 *own_size = NULL, *own_level = NULL;
	enum common_rule rule = RULE_NONE;
	unsigned int size;
	void *logbuf;

	rec->a4 = 0;
	rec->a5 = 0;

	if (!ONE_IN((loads || cmd == BPF_MAP_CREATE) ? 4 : 32))
		return;

	if (ONE_IN(8))
		rule = 1 + rnd_modulo_u32(RULES - 1);

	size = sizes[rnd_modulo_u32(ARRAY_SIZE(sizes))];
	if (ONE_IN(8))
		size = sizeof(*common) + 1 + rnd_modulo_u32(page_size - sizeof(*common));
	switch (rule) {
	case RULE_TOO_LONG:
		size = page_size + 1 + rnd_modulo_u32(page_size);
		break;
	case RULE_UNREADABLE:
		if (size == 0)
			size = sizeof(*common);
		break;
	case RULE_TAIL_SET:
	case RULE_BAD_LOG:
	case RULE_LOGS_DIFFER:
		if (size < sizeof(*common))
			size = sizeof(*common);
		break;
	default:
		break;
	}

	/* Always a zeroed page: the tail check reads every byte a size runs
	 * past the fields, and the blanket address scrub judges a page from
	 * the pointer, so a shorter buffer at the pool's end would be moved. */
	common = get_writable_address(page_size);
	if (common == NULL)
		return;
	memset(common, 0, page_size);

	/* A log needs the fields up to log_level in what the kernel copies. */
	if (size >= offsetof(struct bpf_common_attr, log_true_size)) {
		unsigned int shape = rnd_modulo_u32(8);

		if (rule == RULE_BAD_LOG || rule == RULE_LOGS_DIFFER)
			shape = 7;

		if (shape == 1 || shape == 2) {
			/* A level and no buffer: the kernel measures the log
			 * and reports its size. */
			common->log_level = rnd_modulo_u32(COMMON_LOG_MASK + 1);
		} else if (shape > 2) {
			common->log_size = 1 + rnd_modulo_u32(page_size - 1);
			logbuf = get_writable_address(common->log_size);
			if (logbuf != NULL) {
				common->log_buf = (unsigned long) logbuf;
				common->log_level = 1 + rnd_modulo_u32(COMMON_LOG_MASK);
			} else {
				common->log_size = 0;
			}
		}
	}

	if (rule == RULE_BAD_LOG) {
		/* Each of these breaks one of the four rules of
		 * bpf_verifier_log_attr_valid() the full log above keeps. */
		switch (rnd_modulo_u32(4)) {
		case 0:
			common->log_size = 0;
			break;
		case 1:
			common->log_buf = 0;
			break;
		case 2:
			common->log_level = 0;
			break;
		default:
			common->log_level = COMMON_LOG_MASK + 1 + rnd_modulo_u32(240);
			break;
		}
	}

	if (rule == RULE_TAIL_SET)
		((unsigned char *) common)[COMMON_ATTR_FIELDS_END +
			rnd_modulo_u32(size - COMMON_ATTR_FIELDS_END)] =
			1 + rnd_modulo_u32(255);

	if (cmd == BPF_PROG_LOAD) {
		own_buf = &attr->log_buf;
		own_size = &attr->log_size;
		own_level = &attr->log_level;
	} else if (cmd == BPF_BTF_LOAD) {
		own_buf = &attr->btf_log_buf;
		own_size = &attr->btf_log_size;
		own_level = &attr->btf_log_level;
	}
	if (own_buf != NULL && *own_buf != 0 && common->log_buf != 0 &&
	    rule == RULE_NONE) {
		if (ONE_IN(4)) {
			common->log_buf = *own_buf;
			common->log_size = *own_size;
			common->log_level = *own_level;
		} else {
			*own_buf = 0;
			*own_size = 0;
			*own_level = 0;
		}
	}

	rec->a4 = (unsigned long) common;
	if (rule == RULE_UNREADABLE)
		rec->a4 = rnd_modulo_u32(page_size);	/* the NULL page */
	rec->a5 = size;
	rec->a1 |= BPF_COMMON_ATTRS;
}

#endif	/* USE_BPF */
