#include <stddef.h>
#include "stats-internal.h"

/* rpl_clone_fidelity: the ipv6-rpl-clone-fidelity oracle childop injects
 * an RPL type-3 SRH frame and compares the bytes received by the raw6
 * clone socket and the AF_PACKET full-frame listener against the original
 * transmission.  srh_mutated counts frames where ipv6_rpl_srh_rcv()
 * mutated segments_left or rpl_segaddr bytes in the shared clone data;
 * daddr_mutated counts independent confirmation via the IPv6 header. */
static const struct stat_field rpl_clone_fidelity_fields[] = {
	STAT_FIELD_SUB(rpl_clone_fidelity, srh_mutated),
	STAT_FIELD_SUB(rpl_clone_fidelity, daddr_mutated),
};

const struct stat_category rpl_clone_fidelity_category =
	STAT_CATEGORY("rpl_clone_fidelity",
	              rpl_clone_fidelity.srh_mutated,
	              rpl_clone_fidelity_fields);
