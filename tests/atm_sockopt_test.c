/*
 * Self-check for the ATM PVC option builder: pvc_setsockopt() hands the
 * option to vcc_setsockopt() (net/atm/common.c), which takes SO_SETCLP as
 * a flag and SO_ATMQOS when check_qos() passes, each only at an optlen of
 * the size its name encodes, and refuses every other option.
 */

#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/atm.h>

#include "debug.h"		/* BUG */
#include "net.h"		/* proto_atmpvc, struct sockopt */

#define ATM_ROUNDS	4000
#define ATM_OPTVAL_LEN	4096

/* check_tp() and check_qos() of net/atm/common.c. */
static bool tp_taken(const struct atm_trafprm *tp)
{
	if (tp->traffic_class > ATM_ANYCLASS)
		return false;
	if (!tp->traffic_class || tp->traffic_class == ATM_ANYCLASS)
		return true;
	if (tp->traffic_class != ATM_UBR && !tp->min_pcr && !tp->pcr &&
	    !tp->max_pcr)
		return false;
	if (tp->min_pcr == ATM_MAX_PCR)
		return false;
	if (tp->min_pcr && tp->max_pcr && tp->max_pcr != ATM_MAX_PCR &&
	    tp->min_pcr > tp->max_pcr)
		return false;
	return true;
}

static bool qos_taken(const struct atm_qos *qos)
{
	if (!qos->txtp.traffic_class && !qos->rxtp.traffic_class)
		return false;
	if (qos->txtp.traffic_class != qos->rxtp.traffic_class &&
	    qos->txtp.traffic_class && qos->rxtp.traffic_class &&
	    qos->txtp.traffic_class != ATM_ANYCLASS &&
	    qos->rxtp.traffic_class != ATM_ANYCLASS)
		return false;
	return tp_taken(&qos->txtp) && tp_taken(&qos->rxtp);
}

void atm_sockopt_self_check(void);
void atm_sockopt_self_check(void)
{
	struct socket_triplet pvc = {
		.family = PF_ATMPVC, .type = SOCK_DGRAM,
	};
	static unsigned char optval[ATM_OPTVAL_LEN];
	unsigned int i, on = 0, off = 0, qos = 0, qos_ok = 0;

	for (i = 0; i < ATM_ROUNDS; i++) {
		struct sockopt so = { .optval = (unsigned long) optval };
		int val;

		memset(optval, 0, sizeof(optval));
		proto_atmpvc.setsockopt(&so, &pvc);
		if (so.level != SOL_ATM)
			BUG("atm: an option at another level than SOL_ATM");
		if (so.optlen != __SO_SIZE(so.optname))
			BUG("atm: an optlen other than the size the option encodes");

		switch (so.optname) {
		case SO_SETCLP:
			memcpy(&val, optval, sizeof(val));
			if (val != 0)
				on++;
			else
				off++;
			break;
		case SO_ATMQOS:
			qos++;
			qos_ok += qos_taken((const struct atm_qos *) optval);
			break;
		default:
			BUG("atm: an option vcc_setsockopt() refuses on a PVC");
		}
	}

	if (on == 0 || off == 0)
		BUG("atm: SO_SETCLP never turns both on and off");
	if (qos == 0 || qos_ok < qos * 3 / 4)
		BUG("atm: the QoS check_qos() takes is rare");
}
