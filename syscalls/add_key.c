/*
 * SYSCALL_DEFINE5(add_key, const char __user *, _type,
	const char __user *, _description,
	const void __user *, _payload,
	size_t, plen,
	key_serial_t, ringid)
 *
 * On success add_key() returns the serial number of the key it created or updated.
 * On error, the value -1 will be returned and errno will have been set to an appropriate error.
 */
#include <linux/keyctl.h>
#include <stdio.h>
#include <string.h>
#include "name-pool.h"
#include "random.h"
#include "rnd.h"
#include "sanitise.h"
#include "trinity.h"

/*
 * Diversify what we hand to add_key().  The kernel routes the payload
 * through key_type->instantiate() at creation time, so every later
 * keyctl op on the resulting key (READ / DESCRIBE / SEARCH /
 * INSTANTIATE / UPDATE / etc.) reads payload bytes whose structure is
 * dictated by the type.  Always passing type="user" + a fixed
 * "test_payload" string drives those compare-heavy code paths
 * (user_key_payload, asymmetric subtype dispatch + x509/pkcs7 parse,
 * encrypted/logon validators, big_key tmpfs fallback) over identical
 * bytes on every call and yields ~zero new edges.  Mix in different
 * type strings, randomized descriptions, and per-type payload shapes
 * so subsequent keyctl ops land in distinct instantiate()/read()
 * branches.
 */

/* Pool of description prefixes; the actual description is one of these
 * plus an underscore plus 8 random hex digits, so dcache comparisons in
 * keyring_search_iterator hit different cache slots from call to call. */
static const char *desc_prefixes[] = {
	"trinity_key",
	"trinity_ring",
	"fuzz_key",
	"tk",
	"k",
	"a_very_long_trinity_key_description_to_stress_keyring_name_compares",
	"x",
	"trinity:scratch",
};

/* Logon-type descriptions must begin with "<subtype>:".  Rotating a
 * handful of real kernel subtypes (afs, ceph, cifs, dns_resolver)
 * alongside our fake "trinity:" namespace keeps the subtype-registration
 * lookup landing in different slots instead of the same "trinity:"
 * bucket on every call. */
static const char *logon_subtypes[] = {
	"trinity:",
	"afs:",
	"cifs:",
	"ceph:",
	"dns_resolver:",
};

/* Three short, deliberately-malformed blobs that look enough like a
 * key blob to drive the asymmetric subtype dispatch and x509/pkcs7
 * parse paths.  We are not trying to make them parse; the parse-error
 * branches are themselves edge-rich.  Sizes range from ~32 to ~256
 * bytes so the parser scans different amounts before giving up. */
static const unsigned char asym_blob_a[] = {
	0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01,
	0x00, 0xc1, 0x4d, 0xa3, 0x55, 0x9f, 0x10, 0x2b,
	0x7b, 0xe9, 0x2e, 0x44, 0x77, 0x11, 0xa2, 0xff,
	0x9d, 0x42, 0x18, 0xc3, 0x60, 0x84, 0xee, 0xbb,
	0xa1, 0x55, 0x09, 0x33, 0x8c, 0x55, 0x12, 0x4f,
};
static const unsigned char asym_blob_b[] = {
	'-','-','-','-','-','B','E','G','I','N',' ',
	'C','E','R','T','I','F','I','C','A','T','E',
	'-','-','-','-','-','\n',
	'M','I','I','B','I','j','A','N','B','g','k','q','h','k','i','G','9','w','0','B',
	'A','Q','E','F','A','A','O','C','A','Q','8','A','M','I','I','B','C','g','K','C',
	'\n',
	'-','-','-','-','-','E','N','D',' ','C','E','R','T','I','F','I','C','A','T','E',
	'-','-','-','-','-','\n',
};
static const unsigned char asym_blob_c[] = {
	0x30, 0x80, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86,
	0xf7, 0x0d, 0x01, 0x07, 0x02, 0xa0, 0x80, 0x30,
	0x80, 0x02, 0x01, 0x01, 0x31, 0x00, 0x30, 0x80,
	0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d,
	0x01, 0x07, 0x01, 0xa0, 0x80, 0x24, 0x80, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
	0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
};

static const struct {
	const unsigned char *data;
	size_t len;
} asym_blobs[] = {
	{ asym_blob_a, sizeof(asym_blob_a) },
	{ asym_blob_b, sizeof(asym_blob_b) },
	{ asym_blob_c, sizeof(asym_blob_c) },
};

/* Write a description into buf: "<prefix>_<8 hex digits>".  buf must be
 * at least 96 bytes; the longest prefix is ~68 chars + underscore + 8
 * hex + NUL.  For logon-type keys the kernel requires the description
 * to be prefixed by "<subtype>:" — caller passes a non-NULL ns_prefix
 * for those. */
static void build_description(char *buf, size_t bufsz, const char *ns_prefix)
{
	const char *prefix;
	unsigned int suffix;
	int wrote;
	size_t len;

	/* Minority arm: replay a previously-recorded description (possibly
	 * mutated) so a later add_key call can collide with an earlier one
	 * in keyring_search_iterator / __key_link_check_live_key paths --
	 * those only light up when two descriptions share dcache slots,
	 * which fresh "<prefix>_<8 hex>" almost never does.  The pool is
	 * shared across key types: a draw can hand a logon-type
	 * "trinity:foo" description to a user-type call (and vice versa),
	 * so keyring_search's (type, description) compare walks over
	 * matching names with mismatched types instead of short-circuiting
	 * on the name alone.  For logon the kernel requires the description
	 * to begin with "<subtype>:"; if the drawn bytes lack a prefix,
	 * prepend one so the call stays on the valid path. */
	if (ONE_IN(4)) {
		size_t got = name_pool_draw_mutated(NAME_KIND_KEY_DESC,
						    buf, bufsz);

		if (got > 0) {
			if (got >= bufsz)
				got = bufsz - 1;
			buf[got] = '\0';
			if (ns_prefix != NULL) {
				size_t plen = strlen(ns_prefix);

				if (strncmp(buf, ns_prefix, plen) != 0 &&
				    got + plen + 1 <= bufsz) {
					memmove(buf + plen, buf, got + 1);
					memcpy(buf, ns_prefix, plen);
				}
			}
			return;
		}
		/* empty pool -- fall through to fresh generation */
	}

	prefix = desc_prefixes[rnd_modulo_u32(ARRAY_SIZE(desc_prefixes))];
	suffix = rnd_u32();

	if (ns_prefix)
		wrote = snprintf(buf, bufsz, "%s%s_%08x",
				 ns_prefix, prefix, suffix);
	else
		wrote = snprintf(buf, bufsz, "%s_%08x", prefix, suffix);

	if (wrote <= 0)
		return;
	len = (size_t)wrote;
	if (len >= bufsz)
		len = bufsz - 1;
	name_pool_record(NAME_KIND_KEY_DESC, buf, len);
}

static void set_user_payload(struct syscallrecord *rec)
{
	unsigned int len = 8 + rnd_modulo_u32(256 - 8 + 1);	/* [8, 256] */
	unsigned char *buf;

	buf = (unsigned char *) get_writable_address(len);
	if (buf == NULL) {
		rec->a3 = 0;
		rec->a4 = 0;
		return;
	}
	generate_rand_bytes(buf, len);
	rec->a3 = (unsigned long) buf;
	rec->a4 = len;
	avoid_shared_buffer_inout(&rec->a3, len);
}

static void set_keyring_payload(struct syscallrecord *rec)
{
	/* keyring type rejects any non-NULL payload */
	rec->a3 = 0;
	rec->a4 = 0;
}

static void set_big_key_payload(struct syscallrecord *rec)
{
	/* > 4096 pushes big_key onto the tmpfs-backed slow path */
	unsigned int len = 4097 + rnd_modulo_u32(65536 - 4097 + 1);
	unsigned char *buf;

	buf = (unsigned char *) get_writable_address(len);
	if (buf == NULL) {
		/* Fall back to a small payload — still exercises the
		 * inline path rather than failing the call outright. */
		buf = (unsigned char *) get_writable_address(64);
		if (buf == NULL) {
			rec->a3 = 0;
			rec->a4 = 0;
			return;
		}
		generate_rand_bytes(buf, 64);
		rec->a3 = (unsigned long) buf;
		rec->a4 = 64;
		avoid_shared_buffer_inout(&rec->a3, 64);
		return;
	}
	generate_rand_bytes(buf, len);
	rec->a3 = (unsigned long) buf;
	rec->a4 = len;
	avoid_shared_buffer_inout(&rec->a3, len);
}

static void set_asymmetric_payload(struct syscallrecord *rec)
{
	unsigned int idx = rnd_modulo_u32(ARRAY_SIZE(asym_blobs));
	size_t len = asym_blobs[idx].len;
	unsigned char *buf;

	buf = (unsigned char *) get_writable_address(len);
	if (buf == NULL) {
		rec->a3 = 0;
		rec->a4 = 0;
		return;
	}
	memcpy(buf, asym_blobs[idx].data, len);
	rec->a3 = (unsigned long) buf;
	rec->a4 = len;
	avoid_shared_buffer_inout(&rec->a3, len);
}

static void set_encrypted_payload(struct syscallrecord *rec)
{
	/* Per Documentation/security/keys/trusted-encrypted.rst the
	 * encrypted-type payload is an ASCII command string, e.g.
	 *   "new user:<masterdesc> <hex-bytes>"
	 * "new" hits the alloc-and-fill path; the master-key lookup and
	 * hex-decode both run before the payload is rejected. */
	char *buf;
	unsigned int hex_bytes = 32 + rnd_modulo_u32(33);	/* [32, 64] */
	unsigned int i, len;

	buf = (char *) get_writable_address(256);
	if (buf == NULL) {
		rec->a3 = 0;
		rec->a4 = 0;
		return;
	}
	len = snprintf(buf, 256, "new user:trinity_master_%08x ", rnd_u32());
	for (i = 0; i < hex_bytes && len < 255; i++)
		len += snprintf(buf + len, 256 - len, "%02x", RAND_BYTE());
	rec->a3 = (unsigned long) buf;
	rec->a4 = len;
	avoid_shared_buffer_inout(&rec->a3, 256);
}

/* Weighted type picker.  Weights sum to 100; tweak as coverage data
 * comes in.  user/logon/keyring dominate because they are the common
 * paths; big_key/asymmetric/encrypted are occasional because each
 * pulls in a heavier kernel subsystem (tmpfs, asymmetric_keys + x509
 * parser, trusted/encrypted + hmac/aes). */
static const char *pick_type_and_payload(struct syscallrecord *rec, const char **out_ns_prefix)
{
	unsigned int r = rnd_modulo_u32(100);

	*out_ns_prefix = NULL;

	if (r < 35) {
		set_user_payload(rec);
		return "user";
	}
	if (r < 55) {
		set_user_payload(rec);
		*out_ns_prefix = logon_subtypes[rnd_modulo_u32(ARRAY_SIZE(logon_subtypes))];
		return "logon";
	}
	if (r < 73) {
		set_keyring_payload(rec);
		return "keyring";
	}
	if (r < 83) {
		set_big_key_payload(rec);
		return "big_key";
	}
	if (r < 90) {
		set_asymmetric_payload(rec);
		return "asymmetric";
	}
	if (r < 97) {
		set_encrypted_payload(rec);
		return "encrypted";
	}
	/* .preserved: internal key-type slot; the type-lookup path itself
	 * is worth touching even when the kernel has no matching
	 * key_type registered (returns -ENODEV before payload use). */
	set_user_payload(rec);
	return ".preserved";
}

/* Description-length extremes.  The kernel calls strndup_user() with a
 * PAGE_SIZE cap on the description, so the interesting boundaries are
 * 0-length (rejected by the empty-string check), exactly PAGE_SIZE
 * bytes including NUL (fits the cap by one), and PAGE_SIZE+2 (past the
 * cap -- forces the truncation branch).  Returns 1 when it has taken
 * over the description slot, 0 to leave the default build_description
 * path to run. */
static int try_extreme_description(struct syscallrecord *rec,
				   const char *ns_prefix)
{
	unsigned int r;
	size_t sz;
	char *buf;
	size_t plen;

	if (!ONE_IN(20))
		return 0;

	r = rnd_modulo_u32(3);
	if (r == 0)
		sz = 1;			/* 0-length description */
	else if (r == 1)
		sz = 4096;		/* PAGE_SIZE: 4095 chars + NUL */
	else
		sz = 4098;		/* PAGE_SIZE + 2: past the cap */

	buf = (char *) get_writable_address(sz);
	if (buf == NULL)
		return 0;

	if (sz == 1) {
		buf[0] = '\0';
	} else {
		memset(buf, 'A', sz - 1);
		buf[sz - 1] = '\0';
		if (ns_prefix != NULL) {
			plen = strlen(ns_prefix);
			if (plen < sz - 1)
				memcpy(buf, ns_prefix, plen);
		}
	}
	rec->a2 = (unsigned long) buf;
	avoid_shared_buffer_inout(&rec->a2, sz);
	return 1;
}

static void sanitise_add_key(struct syscallrecord *rec)
{
	const char *type;
	const char *ns_prefix;
	char *type_buf;
	char *desc_buf;

	type = pick_type_and_payload(rec, &ns_prefix);

	type_buf = (char *) get_writable_address(32);
	if (type_buf == NULL) {
		rec->a1 = 0;
		rec->a2 = 0;
		return;
	}
	strncpy(type_buf, type, 31);
	type_buf[31] = '\0';
	rec->a1 = (unsigned long) type_buf;
	/* get_writable_address() draws from the tracked map pool, which
	 * overlaps the shared-region range; the post-sanitise blanket
	 * scrub would otherwise relocate this ARG_ADDRESS slot WITHOUT
	 * copying the curated bytes, leaving the kernel's strndup_user()
	 * to read pool garbage and the key_type lookup to bounce on
	 * -EINVAL.  Move each input into a fresh pool slot with the
	 * curated bytes intact; the blanket pass then no-ops here. */
	avoid_shared_buffer_inout(&rec->a1, 32);

	if (try_extreme_description(rec, ns_prefix))
		return;

	desc_buf = (char *) get_writable_address(128);
	if (desc_buf == NULL) {
		rec->a2 = 0;
		return;
	}
	build_description(desc_buf, 128, ns_prefix);
	rec->a2 = (unsigned long) desc_buf;
	avoid_shared_buffer_inout(&rec->a2, 128);
}

static unsigned long addkey_ringids[] = {
	KEY_SPEC_THREAD_KEYRING,
	KEY_SPEC_PROCESS_KEYRING,
	KEY_SPEC_SESSION_KEYRING,
	KEY_SPEC_USER_KEYRING,
	KEY_SPEC_USER_SESSION_KEYRING,
	KEY_SPEC_GROUP_KEYRING,
	KEY_SPEC_REQKEY_AUTH_KEY,
	KEY_SPEC_REQUESTOR_KEYRING,
};

struct syscallentry syscall_add_key = {
	.name = "add_key",
	.num_args = 5,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_ADDRESS, [2] = ARG_ADDRESS, [3] = ARG_LEN, [4] = ARG_OP },
	.argname = { [0] = "_type", [1] = "_description", [2] = "_payload", [3] = "plen", [4] = "ringid" },
	.arg_params[4].list = ARGLIST(addkey_ringids),
	.rettype = RET_KEY_SERIAL_T,
	.ret_objtype = OBJ_KEY_SERIAL,
	.sanitise = sanitise_add_key,
	.group = GROUP_IPC,
};
