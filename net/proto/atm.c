#include <linux/atmdev.h>
#include <linux/atm.h>
#include <sys/socket.h>
#include <sys/un.h>
#include "net.h"
#include "random.h"
#include "rnd.h"

static void atmpvc_gen_sockaddr(__unused__ struct socket_triplet *triplet, struct sockaddr **addr, socklen_t *addrlen)
{
	struct sockaddr_atmpvc *atmpvc;

	atmpvc = zmalloc_tracked(sizeof(struct sockaddr_atmpvc));

	atmpvc->sap_family = PF_ATMPVC;
	atmpvc->sap_addr.itf = rnd_u32();
	atmpvc->sap_addr.vpi = rnd_u32();
	atmpvc->sap_addr.vci = rnd_u32();
	*addr = (struct sockaddr *) atmpvc;
	*addrlen = sizeof(struct sockaddr_atmpvc);
}

/*
 * The options pvc_setsockopt() takes.  vcc_setsockopt() (net/atm/common.c)
 * refuses every other on a PVC: SO_ATMSAP and SO_MULTIPOINT are an SVC's,
 * and SO_ATMPVC only getsockopt answers.
 */
static const unsigned int atmpvc_opts[] = {
	SO_SETCLP, SO_ATMQOS,
};

/*
 * One direction of a QoS that check_tp() takes: a class other than UBR,
 * none or any needs some PCR, and min_pcr may be neither ATM_MAX_PCR nor
 * above max_pcr.  353207 cells/s is OC-3's line rate.
 */
static void atm_fill_trafprm(struct atm_trafprm *tp, unsigned char traffic_class)
{
	tp->traffic_class = traffic_class;
	if (traffic_class == ATM_NONE || traffic_class == ATM_ANYCLASS)
		return;
	tp->max_pcr = ONE_IN(4) ? ATM_MAX_PCR : (int) RAND_RANGE(1, 353207);
	tp->min_pcr = rnd_modulo_u32(tp->max_pcr == ATM_MAX_PCR ?
				     353207 : (unsigned int) tp->max_pcr + 1);
	tp->pcr = RAND_RANGE(1, 353207);
	tp->max_sdu = RAND_RANGE(1, 65535);
}

/*
 * check_qos() wants a class on one direction at least, the same class on
 * both unless one carries none or any.  One QoS in eight has any class
 * bytes, for its refusals.
 */
static void atm_fill_qos(struct atm_qos *qos)
{
	static const unsigned char classes[] = {
		ATM_UBR, ATM_CBR, ATM_VBR, ATM_ABR, ATM_ANYCLASS,
	};
	unsigned char tx, rx;

	tx = rx = RAND_ARRAY(classes);
	switch (rnd_modulo_u32(4)) {
	case 0: tx = ATM_NONE; break;
	case 1: rx = ATM_NONE; break;
	}
	atm_fill_trafprm(&qos->txtp, tx);
	atm_fill_trafprm(&qos->rxtp, rx);
	if (ONE_IN(8)) {
		qos->txtp.traffic_class = rnd_modulo_u32(8);
		qos->rxtp.traffic_class = rnd_modulo_u32(8);
	}
	qos->aal = RAND_BOOL() ? ATM_AAL5 : ATM_AAL0;
}

static void atmpvc_setsockopt(struct sockopt *so, __unused__ struct socket_triplet *triplet)
{
	so->level = SOL_ATM;
	so->optname = RAND_ARRAY(atmpvc_opts);
	/* vcc_setsockopt() takes a SOL_ATM option only at the size its
	 * name encodes. */
	so->optlen = __SO_SIZE(so->optname);

	switch (so->optname) {
	case SO_SETCLP:
		*(int *) so->optval = RAND_BOOL();
		break;
	case SO_ATMQOS:
		atm_fill_qos((struct atm_qos *) so->optval);
		break;
	}
}

static struct socket_triplet atmpvc_triplet[] = {
	{ .family = PF_ATMPVC, .protocol = 0, .type = SOCK_DGRAM },
};

const struct netproto proto_atmpvc = {
	.name = "atmpvc",
	.setsockopt = atmpvc_setsockopt,
	.gen_sockaddr = atmpvc_gen_sockaddr,
	.valid_triplets = atmpvc_triplet,
	.nr_triplets = ARRAY_SIZE(atmpvc_triplet),
};
