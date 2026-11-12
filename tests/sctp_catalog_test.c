/*
 * Self-check for the SCTP rows of the setsockopt catalog, which fill an
 * option's payload ahead of its builder: on a one-to-many socket an option
 * refuses an assoc_id that names none of the socket's associations with
 * -EINVAL, but for SCTP_FUTURE_ASSOC and, for about half of the options,
 * SCTP_CURRENT_ASSOC and SCTP_ALL_ASSOC (net/sctp/socket.c), so most fills
 * carry one of those three.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/sctp.h>

#include "debug.h"		/* BUG */
#include "struct_catalog.h"
#include "utils-macros.h"	/* ARRAY_SIZE */

#include "kernel/sctp.h"

#define SCTP_CATALOG_ROUNDS	64

void sctp_catalog_self_check(void);
void sctp_catalog_self_check(void)
{
	/* The rows whose struct carries an assoc_id, and where it sits. */
	static const struct {
		enum struct_catalog_idx row;
		size_t id_offset;
	} rows[] = {
		{ SC_SCTP_RTOINFO, offsetof(struct sctp_rtoinfo, srto_assoc_id) },
		{ SC_SCTP_ASSOCPARAMS,
		  offsetof(struct sctp_assocparams, sasoc_assoc_id) },
		{ SC_SCTP_ASSOC_VALUE, offsetof(struct sctp_assoc_value, assoc_id) },
		{ SC_SCTP_SNDINFO, offsetof(struct sctp_sndinfo, snd_assoc_id) },
		{ SC_SCTP_SNDRCVINFO,
		  offsetof(struct sctp_sndrcvinfo, sinfo_assoc_id) },
		{ SC_SCTP_SACK_INFO, offsetof(struct sctp_sack_info, sack_assoc_id) },
		{ SC_SCTP_AUTHKEYID, offsetof(struct sctp_authkeyid, scact_assoc_id) },
		{ SC_SCTP_DEFAULT_PRINFO,
		  offsetof(struct sctp_default_prinfo, pr_assoc_id) },
		{ SC_SCTP_ADD_STREAMS,
		  offsetof(struct sctp_add_streams, sas_assoc_id) },
		{ SC_SCTP_STREAM_VALUE, offsetof(struct sctp_stream_value, assoc_id) },
		{ SC_SCTP_EVENT, offsetof(struct sctp_event, se_assoc_id) },
		{ SC_SCTP_PADDRTHLDS, offsetof(struct sctp_paddrthlds, spt_assoc_id) },
		{ SC_SCTP_PADDRTHLDS_V2,
		  offsetof(struct sctp_paddrthlds_v2, spt_assoc_id) },
		{ SC_SCTP_UDPENCAPS, offsetof(struct sctp_udpencaps, sue_assoc_id) },
		{ SC_SCTP_PADDRPARAMS,
		  offsetof(struct sctp_paddrparams, spp_assoc_id) },
		{ SC_SCTP_PROBEINTERVAL,
		  offsetof(struct sctp_probeinterval, spi_assoc_id) },
		{ SC_SCTP_PRIM, offsetof(struct sctp_prim, ssp_assoc_id) },
	};
	unsigned char buf[512];
	unsigned int i, r, filled = 0, special = 0;

	for (r = 0; r < SCTP_CATALOG_ROUNDS; r++) {
		for (i = 0; i < ARRAY_SIZE(rows); i++) {
			const struct struct_desc *desc =
				&struct_catalog[rows[i].row];
			sctp_assoc_t id;

			if (desc->struct_size > sizeof(buf))
				BUG("sctp: a catalog row outgrows the test's buffer");
			memset(buf, 0, sizeof(buf));
			struct_field_fill_schema_aware(buf, desc->struct_size,
						       desc, NULL);
			memcpy(&id, buf + rows[i].id_offset, sizeof(id));
			filled++;
			if (id == SCTP_FUTURE_ASSOC || id == SCTP_CURRENT_ASSOC ||
			    id == SCTP_ALL_ASSOC)
				special++;
		}
	}

	if (special < filled * 3 / 4 || special == filled)
		BUG("sctp: the catalog's assoc_ids a one-to-many socket takes are rare, or the only ones");
}
