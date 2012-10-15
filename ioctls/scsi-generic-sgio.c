#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <scsi/scsi.h>
#include <scsi/scsi_ioctl.h>
#include <scsi/sg.h>

#include "sanitise.h"
#include "shm.h"
#include "trinity.h"

struct sgio {
	sg_io_hdr_t ioh;
	unsigned char data[512];
	unsigned char cmd[12];
	unsigned char sense[252];
};

void sanitise_ioctl_sg_io(int childno)
{
	struct sgio *sgio;

	sgio = (struct sgio *) page_rand;

	sgio->cmd[0] = 0x12;
	sgio->cmd[3] = 0x2;

	sgio->ioh.interface_id = 'S';

	switch (rand() % 4) {
	case 0:	sgio->ioh.dxfer_direction = SG_DXFER_NONE;	break;
	case 1:	sgio->ioh.dxfer_direction = SG_DXFER_TO_DEV;	break;
	case 2:	sgio->ioh.dxfer_direction = SG_DXFER_FROM_DEV;	break;
	case 3:	sgio->ioh.dxfer_direction = SG_DXFER_TO_FROM_DEV;	break;
	default: break;
	}

	sgio->ioh.dxferp = sgio->data;

	switch (rand() % 3) {
	case 0: sgio->ioh.dxfer_len = rand() % page_size;	break;
	case 1: sgio->ioh.dxfer_len = get_interesting_value();	break;
	case 2: sgio->ioh.dxfer_len = rand() % 512;		break;
	default: break;
	}

	sgio->ioh.cmdp = sgio->cmd;
	sgio->ioh.cmd_len = 6;
	sgio->ioh.mx_sb_len = sizeof(sgio->sense);
	sgio->ioh.sbp = sgio->sense;
	sgio->ioh.timeout = UINT_MAX;
	sgio->ioh.usr_ptr = NULL;
	sgio->ioh.flags |= SG_FLAG_DIRECT_IO;

	shm->a3[childno] = (unsigned long) page_rand;
}
