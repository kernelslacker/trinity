/*
 * Self-check for the SCTP option payloads: on a one-to-many socket an
 * option refuses an assoc_id that names none of the socket's associations
 * with -EINVAL, but for SCTP_FUTURE_ASSOC and, for about half of the
 * options, SCTP_CURRENT_ASSOC and SCTP_ALL_ASSOC (net/sctp/socket.c), so
 * most payloads carry one of those three.  The options checked are the
 * ones whose payload starts with the id.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/sctp.h>

#include "debug.h"		/* BUG */
#include "net.h"		/* struct sockopt, sctp_setsockopt */
#include "utils-macros.h"	/* ARRAY_SIZE */

#include "kernel/sctp.h"

#define SCTP_ROUNDS	8000
#define SCTP_OPTVAL_LEN	4096

static bool id_leads_payload(unsigned long optname)
{
	static const unsigned long optnames[] = {
		SCTP_RTOINFO, SCTP_ASSOCINFO, SCTP_SET_PEER_PRIMARY_ADDR,
		SCTP_PRIMARY_ADDR, SCTP_PEER_ADDR_PARAMS, SCTP_AUTH_KEY,
		SCTP_AUTH_ACTIVE_KEY, SCTP_AUTH_DELETE_KEY,
		SCTP_AUTH_DEACTIVATE_KEY, SCTP_DELAYED_ACK_TIME, SCTP_CONTEXT,
		SCTP_MAX_BURST, SCTP_DEFAULT_PRINFO, SCTP_EVENT,
		SCTP_PEER_ADDR_THLDS, SCTP_ADD_STREAMS, SCTP_RESET_STREAMS,
	};
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(optnames); i++) {
		if (optnames[i] == optname)
			return true;
	}
	return false;
}

void sctp_sockopt_self_check(void);
void sctp_sockopt_self_check(void)
{
	unsigned int i, checked = 0, special = 0;
	unsigned char *optval;

	optval = calloc(1, SCTP_OPTVAL_LEN);
	if (optval == NULL)
		BUG("sctp: no buffer for the option payload");

	for (i = 0; i < SCTP_ROUNDS; i++) {
		struct sockopt so = { .optval = (unsigned long) optval };
		sctp_assoc_t id;

		memset(optval, 0xa5, SCTP_OPTVAL_LEN);
		sctp_setsockopt(&so, NULL);
		if (!id_leads_payload(so.optname))
			continue;

		checked++;
		memcpy(&id, optval, sizeof(id));
		if (id == SCTP_FUTURE_ASSOC || id == SCTP_CURRENT_ASSOC ||
		    id == SCTP_ALL_ASSOC)
			special++;
	}
	free(optval);

	if (checked == 0)
		BUG("sctp: no option drawn whose payload starts with an assoc_id");
	if (special < checked * 3 / 4 || special == checked)
		BUG("sctp: the assoc_ids a one-to-many socket takes are rare, or the only ones");
}
