	{
		.name = "UBI_IOCMKVOL",
		_IOC(_IOC_NONE,UBI_IOC_MAGIC,0,0),
	},
	{
		.name = "UBI_IOCRMVOL",
		_IOC(_IOC_NONE,UBI_IOC_MAGIC,1,0),
	},
	{
		.name = "UBI_IOCRSVOL",
		_IOC(_IOC_NONE,UBI_IOC_MAGIC,2,0),
	},
	{
		.name = "UBI_IOCRNVOL",
		_IOC(_IOC_NONE,UBI_IOC_MAGIC,3,0),
	},
	{
		.name = "UBI_IOCATT",
		_IOC(_IOC_NONE,UBI_CTRL_IOC_MAGIC,64,0),
	},
	{
		.name = "UBI_IOCDET",
		_IOC(_IOC_NONE,UBI_CTRL_IOC_MAGIC,65,0),
	},
	{
		.name = "UBI_IOCVOLUP",
		_IOC(_IOC_NONE,UBI_VOL_IOC_MAGIC,0,0),
	},
	{
		.name = "UBI_IOCEBER",
		_IOC(_IOC_NONE,UBI_VOL_IOC_MAGIC,1,0),
	},
	{
		.name = "UBI_IOCEBCH",
		_IOC(_IOC_NONE,UBI_VOL_IOC_MAGIC,2,0),
	},
	{
		.name = "UBI_IOCEBMAP",
		_IOC(_IOC_NONE,UBI_VOL_IOC_MAGIC,3,0),
	},
	{
		.name = "UBI_IOCEBUNMAP",
		_IOC(_IOC_NONE,UBI_VOL_IOC_MAGIC,4,0),
	},
	{
		.name = "UBI_IOCEBISMAP",
		_IOC(_IOC_NONE,UBI_VOL_IOC_MAGIC,5,0),
	},
	{
		.name = "UBI_IOCSETPROP",
		_IOC(_IOC_NONE,UBI_VOL_IOC_MAGIC,6,0),
	},
	{
		.name = "FBIOGET_CONTRAST",
		_IOC(_IOC_NONE,'F',1,0),
	},
	{
		.name = "FBIOPUT_CONTRAST",
		_IOC(_IOC_NONE,'F',2,0),
	},
	{
		.name = "FBIGET_BRIGHTNESS",
		_IOC(_IOC_NONE,'F',3,0),
	},
	{
		.name = "FBIPUT_BRIGHTNESS",
		_IOC(_IOC_NONE,'F',3,0),
	},
	{
		.name = "FBIGET_COLOR",
		_IOC(_IOC_NONE,'F',5,0),
	},
	{
		.name = "FBIPUT_COLOR",
		_IOC(_IOC_NONE,'F',6,0),
	},
	{
		.name = "FBIPUT_HSYNC",
		_IOC(_IOC_NONE,'F',9,0),
	},
	{
		.name = "FBIPUT_VSYNC",
		_IOC(_IOC_NONE,'F',10,0),
	},
	{
		.name = "MBXFB_IOCX_OVERLAY",
		_IOC(_IOC_NONE,0xF4,0x00,0),
	},
	{
		.name = "MBXFB_IOCG_ALPHA",
		_IOC(_IOC_NONE,0xF4,0x01,0),
	},
	{
		.name = "MBXFB_IOCS_ALPHA",
		_IOC(_IOC_NONE,0xF4,0x02,0),
	},
	{
		.name = "MBXFB_IOCS_PLANEORDER",
		_IOC(_IOC_NONE,0xF4,0x03,0),
	},
	{
		.name = "MBXFB_IOCS_REG",
		_IOC(_IOC_NONE,0xF4,0x04,0),
	},
	{
		.name = "MBXFB_IOCX_REG",
		_IOC(_IOC_NONE,0xF4,0x05,0),
	},
	{
		.name = "SSTFB_SET_VGAPASS",
		_IOC(_IOC_NONE,'F',0xdd,0),
	},
	{
		.name = "SSTFB_GET_VGAPASS",
		_IOC(_IOC_NONE,'F',0xdd,0),
	},
	{
		.name = "RAID_VERSION",
		_IOC(_IOC_NONE,MD_MAJOR,0x10,0),
	},
	{
		.name = "GET_ARRAY_INFO",
		_IOC(_IOC_NONE,MD_MAJOR,0x11,0),
	},
	{
		.name = "GET_DISK_INFO",
		_IOC(_IOC_NONE,MD_MAJOR,0x12,0),
	},
	{
		.name = "PRINT_RAID_DEBUG",
		_IOC(_IOC_NONE,MD_MAJOR,0x13,0),
	},
	{
		.name = "RAID_AUTORUN",
		_IOC(_IOC_NONE,MD_MAJOR,0x14,0),
	},
	{
		.name = "GET_BITMAP_FILE",
		_IOC(_IOC_NONE,MD_MAJOR,0x15,0),
	},
	{
		.name = "CLEAR_ARRAY",
		_IOC(_IOC_NONE,MD_MAJOR,0x20,0),
	},
	{
		.name = "ADD_NEW_DISK",
		_IOC(_IOC_NONE,MD_MAJOR,0x21,0),
	},
	{
		.name = "HOT_REMOVE_DISK",
		_IOC(_IOC_NONE,MD_MAJOR,0x22,0),
	},
	{
		.name = "SET_ARRAY_INFO",
		_IOC(_IOC_NONE,MD_MAJOR,0x23,0),
	},
	{
		.name = "SET_DISK_INFO",
		_IOC(_IOC_NONE,MD_MAJOR,0x24,0),
	},
	{
		.name = "WRITE_RAID_INFO",
		_IOC(_IOC_NONE,MD_MAJOR,0x25,0),
	},
	{
		.name = "UNPROTECT_ARRAY",
		_IOC(_IOC_NONE,MD_MAJOR,0x26,0),
	},
	{
		.name = "PROTECT_ARRAY",
		_IOC(_IOC_NONE,MD_MAJOR,0x27,0),
	},
	{
		.name = "HOT_ADD_DISK",
		_IOC(_IOC_NONE,MD_MAJOR,0x28,0),
	},
	{
		.name = "SET_DISK_FAULTY",
		_IOC(_IOC_NONE,MD_MAJOR,0x29,0),
	},
	{
		.name = "HOT_GENERATE_ERROR",
		_IOC(_IOC_NONE,MD_MAJOR,0x2a,0),
	},
	{
		.name = "SET_BITMAP_FILE",
		_IOC(_IOC_NONE,MD_MAJOR,0x2b,0),
	},
	{
		.name = "RUN_ARRAY",
		_IOC(_IOC_NONE,MD_MAJOR,0x30,0),
	},
	{
		.name = "STOP_ARRAY",
		_IOC(_IOC_NONE,MD_MAJOR,0x32,0),
	},
	{
		.name = "STOP_ARRAY_RO",
		_IOC(_IOC_NONE,MD_MAJOR,0x33,0),
	},
	{
		.name = "RESTART_ARRAY_RW",
		_IOC(_IOC_NONE,MD_MAJOR,0x34,0),
	},
	{
		.name = "AGPIOC_INFO",
		_IOC(_IOC_NONE,AGPIOC_BASE,0,0),
	},
	{
		.name = "AGPIOC_ACQUIRE",
		_IOC(_IOC_NONE,AGPIOC_BASE,1,0),
	},
	{
		.name = "AGPIOC_RELEASE",
		_IOC(_IOC_NONE,AGPIOC_BASE,2,0),
	},
	{
		.name = "AGPIOC_SETUP",
		_IOC(_IOC_NONE,AGPIOC_BASE,3,0),
	},
	{
		.name = "AGPIOC_RESERVE",
		_IOC(_IOC_NONE,AGPIOC_BASE,4,0),
	},
	{
		.name = "AGPIOC_PROTECT",
		_IOC(_IOC_NONE,AGPIOC_BASE,5,0),
	},
	{
		.name = "AGPIOC_ALLOCATE",
		_IOC(_IOC_NONE,AGPIOC_BASE,6,0),
	},
	{
		.name = "AGPIOC_DEALLOCATE",
		_IOC(_IOC_NONE,AGPIOC_BASE,7,0),
	},
	{
		.name = "AGPIOC_BIND",
		_IOC(_IOC_NONE,AGPIOC_BASE,8,0),
	},
	{
		.name = "AGPIOC_UNBIND",
		_IOC(_IOC_NONE,AGPIOC_BASE,9,0),
	},
	{
		.name = "AGPIOC_CHIPSET_FLUSH",
		_IOC(_IOC_NONE,AGPIOC_BASE,10,0),
	},
	{
		.name = "APM_IOC_STANDBY",
		_IOC(_IOC_NONE,'A',1,0),
	},
	{
		.name = "APM_IOC_SUSPEND",
		_IOC(_IOC_NONE,'A',2,0),
	},
	{
		.name = "FBIO_WAITEVENT",
		_IOC(_IOC_NONE,'F',0x88,0),
	},
	{
		.name = "FBIO_GETCONTROL2",
		_IOC(_IOC_NONE,'F',0x89,0),
	},
	{
		.name = "ATMARPD_CTRL",
		_IOC(_IOC_NONE,'a',ATMIOC_CLIP+1,0),
	},
	{
		.name = "ATMARP_MKIP",
		_IOC(_IOC_NONE,'a',ATMIOC_CLIP+2,0),
	},
	{
		.name = "ATMARP_SETENTRY",
		_IOC(_IOC_NONE,'a',ATMIOC_CLIP+3,0),
	},
	{
		.name = "ATMARP_ENCAP",
		_IOC(_IOC_NONE,'a',ATMIOC_CLIP+5,0),
	},
	{
		.name = "BR2684_SETFILT",
		_IOC(_IOC_NONE, 'a',ATMIOC_BACKEND + 0,0),
	},
	{
		.name = "SIOCMKCLIP",
		_IOC(_IOC_NONE,'a',ATMIOC_CLIP,0),
	},
	{
		.name = "ATM_GETLINKRATE",
		_IOC(_IOC_NONE,'a',ATMIOC_ITF+1,0),
	},
	{
		.name = "ATM_GETNAMES",
		_IOC(_IOC_NONE,'a',ATMIOC_ITF+3,0),
	},
	{
		.name = "ATM_GETTYPE",
		_IOC(_IOC_NONE,'a',ATMIOC_ITF+4,0),
	},
	{
		.name = "ATM_GETESI",
		_IOC(_IOC_NONE,'a',ATMIOC_ITF+5,0),
	},
	{
		.name = "ATM_GETADDR",
		_IOC(_IOC_NONE,'a',ATMIOC_ITF+6,0),
	},
	{
		.name = "ATM_RSTADDR",
		_IOC(_IOC_NONE,'a',ATMIOC_ITF+7,0),
	},
	{
		.name = "ATM_ADDADDR",
		_IOC(_IOC_NONE,'a',ATMIOC_ITF+8,0),
	},
	{
		.name = "ATM_DELADDR",
		_IOC(_IOC_NONE,'a',ATMIOC_ITF+9,0),
	},
	{
		.name = "ATM_GETCIRANGE",
		_IOC(_IOC_NONE,'a',ATMIOC_ITF+10,0),
	},
	{
		.name = "ATM_SETCIRANGE",
		_IOC(_IOC_NONE,'a',ATMIOC_ITF+11,0),
	},
	{
		.name = "ATM_SETESI",
		_IOC(_IOC_NONE,'a',ATMIOC_ITF+12,0),
	},
	{
		.name = "ATM_SETESIF",
		_IOC(_IOC_NONE,'a',ATMIOC_ITF+13,0),
	},
	{
		.name = "ATM_ADDLECSADDR",
		_IOC(_IOC_NONE,'a',ATMIOC_ITF+14,0),
	},
	{
		.name = "ATM_DELLECSADDR",
		_IOC(_IOC_NONE,'a',ATMIOC_ITF+15,0),
	},
	{
		.name = "ATM_GETLECSADDR",
		_IOC(_IOC_NONE,'a',ATMIOC_ITF+16,0),
	},
	{
		.name = "ATM_GETSTAT",
		_IOC(_IOC_NONE,'a',ATMIOC_SARCOM+0,0),
	},
	{
		.name = "ATM_GETSTATZ",
		_IOC(_IOC_NONE,'a',ATMIOC_SARCOM+1,0),
	},
	{
		.name = "ATM_GETLOOP",
		_IOC(_IOC_NONE,'a',ATMIOC_SARCOM+2,0),
	},
	{
		.name = "ATM_SETLOOP",
		_IOC(_IOC_NONE,'a',ATMIOC_SARCOM+3,0),
	},
	{
		.name = "ATM_QUERYLOOP",
		_IOC(_IOC_NONE,'a',ATMIOC_SARCOM+4,0),
	},
	{
		.name = "ATM_SETSC",
		_IOC(_IOC_NONE,'a',ATMIOC_SPECIAL+1,0),
	},
	{
		.name = "ATM_SETBACKEND",
		_IOC(_IOC_NONE,'a',ATMIOC_SPECIAL+2,0),
	},
	{
		.name = "ATM_NEWBACKENDIF",
		_IOC(_IOC_NONE,'a',ATMIOC_SPECIAL+3,0),
	},
	{
		.name = "ATM_ADDPARTY",
		_IOC(_IOC_NONE,'a',ATMIOC_SPECIAL+4,0),
	},
	{
		.name = "COMPAT_ATM_ADDPARTY",
		_IOC(_IOC_NONE,'a',ATMIOC_SPECIAL+4,0),
	},
	{
		.name = "ATM_DROPPARTY",
		_IOC(_IOC_NONE,'a',ATMIOC_SPECIAL+5,0),
	},
	{
		.name = "ENI_MEMDUMP",
		_IOC(_IOC_NONE,'a',ATMIOC_SARPRV,0),
	},
	{
		.name = "ENI_SETMULT",
		_IOC(_IOC_NONE,'a',ATMIOC_SARPRV+7,0),
	},
	{
		.name = "HE_GET_REG",
		_IOC(_IOC_NONE,'a',ATMIOC_SARPRV,0),
	},
	{
		.name = "IDT77105_GETSTAT",
		_IOC(_IOC_NONE,'a',ATMIOC_PHYPRV+2,0),
	},
	{
		.name = "IDT77105_GETSTATZ",
		_IOC(_IOC_NONE,'a',ATMIOC_PHYPRV+3,0),
	},
	{
		.name = "ATMLEC_CTRL",
		_IOC(_IOC_NONE,'a',ATMIOC_LANE,0),
	},
	{
		.name = "ATMLEC_DATA",
		_IOC(_IOC_NONE,'a',ATMIOC_LANE+1,0),
	},
	{
		.name = "ATMLEC_MCAST",
		_IOC(_IOC_NONE,'a',ATMIOC_LANE+2,0),
	},
	{
		.name = "ATMMPC_CTRL",
		_IOC(_IOC_NONE,'a',ATMIOC_MPOA,0),
	},
	{
		.name = "ATMMPC_DATA",
		_IOC(_IOC_NONE,'a',ATMIOC_MPOA+1,0),
	},
	{
		.name = "NS_GETPSTAT",
		_IOC(_IOC_NONE,'a',ATMIOC_SARPRV+1,0),
	},
	{
		.name = "NS_SETBUFLEV",
		_IOC(_IOC_NONE,'a',ATMIOC_SARPRV+2,0),
	},
	{
		.name = "NS_ADJBUFLEV",
		_IOC(_IOC_NONE,'a',ATMIOC_SARPRV+3,0),
	},
	{
		.name = "ATMSIGD_CTRL",
		_IOC(_IOC_NONE,'a',ATMIOC_SPECIAL,0),
	},
	{
		.name = "SIOCSIFATMTCP",
		_IOC(_IOC_NONE,'a',ATMIOC_ITF,0),
	},
	{
		.name = "ATMTCP_CREATE",
		_IOC(_IOC_NONE,'a',ATMIOC_ITF+14,0),
	},
	{
		.name = "ATMTCP_REMOVE",
		_IOC(_IOC_NONE,'a',ATMIOC_ITF+15,0),
	},
	{
		.name = "ZATM_GETPOOL",
		_IOC(_IOC_NONE,'a',ATMIOC_SARPRV+1,0),
	},
	{
		.name = "ZATM_GETPOOLZ",
		_IOC(_IOC_NONE,'a',ATMIOC_SARPRV+2,0),
	},
	{
		.name = "ZATM_SETPOOL",
		_IOC(_IOC_NONE,'a',ATMIOC_SARPRV+3,0),
	},
	{
		.name = "AUTOFS_IOC_EXPIRE_MULTI",
		_IOC(_IOC_NONE,0x93,0x66,0),
	},
	{
		.name = "AUTOFS_IOC_PROTOSUBVER",
		_IOC(_IOC_NONE,0x93,0x67,0),
	},
	{
		.name = "AUTOFS_IOC_ASKUMOUNT",
		_IOC(_IOC_NONE,0x93,0x70,0),
	},
	{
		.name = "AUTOFS_IOC_READY",
		_IOC(_IOC_NONE,0x93,0x60,0),
	},
	{
		.name = "AUTOFS_IOC_FAIL",
		_IOC(_IOC_NONE,0x93,0x61,0),
	},
	{
		.name = "AUTOFS_IOC_CATATONIC",
		_IOC(_IOC_NONE,0x93,0x62,0),
	},
	{
		.name = "AUTOFS_IOC_PROTOVER",
		_IOC(_IOC_NONE,0x93,0x63,0),
	},
	{
		.name = "AUTOFS_IOC_SETTIMEOUT32",
		_IOC(_IOC_NONE,0x93,0x64,0),
	},
	{
		.name = "AUTOFS_IOC_SETTIMEOUT",
		_IOC(_IOC_NONE,0x93,0x64,0),
	},
	{
		.name = "AUTOFS_IOC_EXPIRE",
		_IOC(_IOC_NONE,0x93,0x65,0),
	},
	{
		.name = "BLKPG",
		_IOC(_IOC_NONE,0x12,105,0),
	},
	{
		.name = "BLKTRACESETUP32",
		_IOC(_IOC_NONE,0x12,115,0),
	},
	{
		.name = "CAPI_REGISTER",
		_IOC(_IOC_NONE,'C',0x01,0),
	},
	{
		.name = "CAPI_GET_MANUFACTURER",
		_IOC(_IOC_NONE,'C',0x06,0),
	},
	{
		.name = "CAPI_GET_VERSION",
		_IOC(_IOC_NONE,'C',0x07,0),
	},
	{
		.name = "CAPI_GET_SERIAL",
		_IOC(_IOC_NONE,'C',0x08,0),
	},
	{
		.name = "CAPI_GET_PROFILE",
		_IOC(_IOC_NONE,'C',0x09,0),
	},
	{
		.name = "CAPI_MANUFACTURER_CMD",
		_IOC(_IOC_NONE,'C',0x20,0),
	},
	{
		.name = "CAPI_GET_ERRCODE",
		_IOC(_IOC_NONE,'C',0x21,0),
	},
	{
		.name = "CAPI_INSTALLED",
		_IOC(_IOC_NONE,'C',0x22,0),
	},
	{
		.name = "CAPI_GET_FLAGS",
		_IOC(_IOC_NONE,'C',0x23,0),
	},
	{
		.name = "CAPI_SET_FLAGS",
		_IOC(_IOC_NONE,'C',0x24,0),
	},
	{
		.name = "CAPI_CLR_FLAGS",
		_IOC(_IOC_NONE,'C',0x25,0),
	},
	{
		.name = "CAPI_NCCI_OPENCOUNT",
		_IOC(_IOC_NONE,'C',0x26,0),
	},
	{
		.name = "CAPI_NCCI_GETUNIT",
		_IOC(_IOC_NONE,'C',0x27,0),
	},
	{
		.name = "CCISS_GETPCIINFO",
		_IOC(_IOC_NONE,CCISS_IOC_MAGIC,1,0),
	},
	{
		.name = "CCISS_GETINTINFO",
		_IOC(_IOC_NONE,CCISS_IOC_MAGIC,2,0),
	},
	{
		.name = "CCISS_SETINTINFO",
		_IOC(_IOC_NONE,CCISS_IOC_MAGIC,3,0),
	},
	{
		.name = "CCISS_GETNODENAME",
		_IOC(_IOC_NONE,CCISS_IOC_MAGIC,4,0),
	},
	{
		.name = "CCISS_SETNODENAME",
		_IOC(_IOC_NONE,CCISS_IOC_MAGIC,5,0),
	},
	{
		.name = "CCISS_GETHEARTBEAT",
		_IOC(_IOC_NONE,CCISS_IOC_MAGIC,6,0),
	},
	{
		.name = "CCISS_GETBUSTYPES",
		_IOC(_IOC_NONE,CCISS_IOC_MAGIC,7,0),
	},
	{
		.name = "CCISS_GETFIRMVER",
		_IOC(_IOC_NONE,CCISS_IOC_MAGIC,8,0),
	},
	{
		.name = "CCISS_GETDRIVVER",
		_IOC(_IOC_NONE,CCISS_IOC_MAGIC,9,0),
	},
	{
		.name = "CCISS_REVALIDVOLS",
		_IOC(_IOC_NONE,CCISS_IOC_MAGIC,10,0),
	},
	{
		.name = "CCISS_PASSTHRU",
		_IOC(_IOC_NONE,CCISS_IOC_MAGIC,11,0),
	},
	{
		.name = "CCISS_DEREGDISK",
		_IOC(_IOC_NONE,CCISS_IOC_MAGIC,12,0),
	},
	{
		.name = "CCISS_REGNEWDISK",
		_IOC(_IOC_NONE,CCISS_IOC_MAGIC,13,0),
	},
	{
		.name = "CCISS_REGNEWD",
		_IOC(_IOC_NONE,CCISS_IOC_MAGIC,14,0),
	},
	{
		.name = "CCISS_RESCANDISK",
		_IOC(_IOC_NONE,CCISS_IOC_MAGIC,16,0),
	},
	{
		.name = "CCISS_GETLUNINFO",
		_IOC(_IOC_NONE,CCISS_IOC_MAGIC,17,0),
	},
	{
		.name = "CCISS_BIG_PASSTHRU",
		_IOC(_IOC_NONE,CCISS_IOC_MAGIC,18,0),
	},
	{
		.name = "CCISS_PASSTHRU32",
		_IOC(_IOC_NONE,CCISS_IOC_MAGIC,11,0),
	},
	{
		.name = "CCISS_BIG_PASSTHRU32",
		_IOC(_IOC_NONE,CCISS_IOC_MAGIC,18,0),
	},
	{
		.name = "STL_BINTR",
		_IOC(_IOC_NONE,'s',20,0),
	},
	{
		.name = "STL_BSTART",
		_IOC(_IOC_NONE,'s',21,0),
	},
	{
		.name = "STL_BSTOP",
		_IOC(_IOC_NONE,'s',22,0),
	},
	{
		.name = "STL_BRESET",
		_IOC(_IOC_NONE,'s',23,0),
	},
	{
		.name = "STL_GETPFLAG",
		_IOC(_IOC_NONE,'s',80,0),
	},
	{
		.name = "STL_SETPFLAG",
		_IOC(_IOC_NONE,'s',81,0),
	},
	{
		.name = "CHIOMOVE",
		_IOC(_IOC_NONE,'c',1,0),
	},
	{
		.name = "CHIOEXCHANGE",
		_IOC(_IOC_NONE,'c',2,0),
	},
	{
		.name = "CHIOPOSITION",
		_IOC(_IOC_NONE,'c',3,0),
	},
	{
		.name = "CHIOGPICKER",
		_IOC(_IOC_NONE,'c',4,0),
	},
	{
		.name = "CHIOSPICKER",
		_IOC(_IOC_NONE,'c',5,0),
	},
	{
		.name = "CHIOGPARAMS",
		_IOC(_IOC_NONE,'c',6,0),
	},
	{
		.name = "CHIOGSTATUS",
		_IOC(_IOC_NONE,'c',8,0),
	},
	{
		.name = "CHIOGELEM",
		_IOC(_IOC_NONE,'c',16,0),
	},
	{
		.name = "CHIOINITELEM",
		_IOC(_IOC_NONE,'c',17,0),
	},
	{
		.name = "CHIOSVOLTAG",
		_IOC(_IOC_NONE,'c',18,0),
	},
	{
		.name = "CHIOGVPARAMS",
		_IOC(_IOC_NONE,'c',19,0),
	},
	{
		.name = "CM_IOCGSTATUS",
		_IOC(_IOC_NONE,CM_IOC_MAGIC,0,0),
	},
	{
		.name = "CM_IOCGATR",
		_IOC(_IOC_NONE,CM_IOC_MAGIC,1,0),
	},
	{
		.name = "CM_IOCSPTS",
		_IOC(_IOC_NONE,CM_IOC_MAGIC,2,0),
	},
	{
		.name = "CM_IOCSRDR",
		_IOC(_IOC_NONE,CM_IOC_MAGIC,3,0),
	},
	{
		.name = "CM_IOCARDOFF",
		_IOC(_IOC_NONE,CM_IOC_MAGIC,4,0),
	},
	{
		.name = "CM_IOSDBGLVL",
		_IOC(_IOC_NONE,CM_IOC_MAGIC,250,0),
	},
	{
		.name = "CIOC_KERNEL_VERSION",
		_IOC(_IOC_NONE,'c',10,0),
	},
	{
		.name = "COM_GETPORTSTATS",
		_IOC(_IOC_NONE,'c',30,0),
	},
	{
		.name = "COM_CLRPORTSTATS",
		_IOC(_IOC_NONE,'c',31,0),
	},
	{
		.name = "COM_GETBRDSTATS",
		_IOC(_IOC_NONE,'c',32,0),
	},
	{
		.name = "COM_READPORT",
		_IOC(_IOC_NONE,'c',40,0),
	},
	{
		.name = "COM_READBOARD",
		_IOC(_IOC_NONE,'c',41,0),
	},
	{
		.name = "COM_READPANEL",
		_IOC(_IOC_NONE,'c',42,0),
	},
	{
		.name = "DM_VERSION",
		_IOC(_IOC_NONE,DM_IOCTL,DM_VERSION_CMD,0),
	},
	{
		.name = "DM_REMOVE_ALL",
		_IOC(_IOC_NONE,DM_IOCTL,DM_REMOVE_ALL_CMD,0),
	},
	{
		.name = "DM_LIST_DEVICES",
		_IOC(_IOC_NONE,DM_IOCTL,DM_LIST_DEVICES_CMD,0),
	},
	{
		.name = "DM_DEV_CREATE",
		_IOC(_IOC_NONE,DM_IOCTL,DM_DEV_CREATE_CMD,0),
	},
	{
		.name = "DM_DEV_REMOVE",
		_IOC(_IOC_NONE,DM_IOCTL,DM_DEV_REMOVE_CMD,0),
	},
	{
		.name = "DM_DEV_RENAME",
		_IOC(_IOC_NONE,DM_IOCTL,DM_DEV_RENAME_CMD,0),
	},
	{
		.name = "DM_DEV_SUSPEND",
		_IOC(_IOC_NONE,DM_IOCTL,DM_DEV_SUSPEND_CMD,0),
	},
	{
		.name = "DM_DEV_STATUS",
		_IOC(_IOC_NONE,DM_IOCTL,DM_DEV_STATUS_CMD,0),
	},
	{
		.name = "DM_DEV_WAIT",
		_IOC(_IOC_NONE,DM_IOCTL,DM_DEV_WAIT_CMD,0),
	},
	{
		.name = "DM_TABLE_LOAD",
		_IOC(_IOC_NONE,DM_IOCTL,DM_TABLE_LOAD_CMD,0),
	},
	{
		.name = "DM_TABLE_CLEAR",
		_IOC(_IOC_NONE,DM_IOCTL,DM_TABLE_CLEAR_CMD,0),
	},
	{
		.name = "DM_TABLE_DEPS",
		_IOC(_IOC_NONE,DM_IOCTL,DM_TABLE_DEPS_CMD,0),
	},
	{
		.name = "DM_TABLE_STATUS",
		_IOC(_IOC_NONE,DM_IOCTL,DM_TABLE_STATUS_CMD,0),
	},
	{
		.name = "DM_LIST_VERSIONS",
		_IOC(_IOC_NONE,DM_IOCTL,DM_LIST_VERSIONS_CMD,0),
	},
	{
		.name = "DM_TARGET_MSG",
		_IOC(_IOC_NONE,DM_IOCTL,DM_TARGET_MSG_CMD,0),
	},
	{
		.name = "DM_DEV_SET_GEOMETRY",
		_IOC(_IOC_NONE,DM_IOCTL,DM_DEV_SET_GEOMETRY_CMD,0),
	},
	{
		.name = "SIOCSNETADDR",
		_IOC(_IOC_NONE,DECNET_IOCTL_BASE,0xe0,0),
	},
	{
		.name = "SIOCGNETADDR",
		_IOC(_IOC_NONE,DECNET_IOCTL_BASE,0xe1,0),
	},
	{
		.name = "OSIOCSNETADDR",
		_IOC(_IOC_NONE,DECNET_IOCTL_BASE,0xe0,0),
	},
	{
		.name = "OSIOCGNETADDR",
		_IOC(_IOC_NONE,DECNET_IOCTL_BASE,0xe1,0),
	},
	{
		.name = "EXT2_IOC_GETRSVSZ",
		_IOC(_IOC_NONE,'f',5,0),
	},
	{
		.name = "EXT2_IOC_SETRSVSZ",
		_IOC(_IOC_NONE,'f',6,0),
	},
	{
		.name = "EXT3_IOC_GETVERSION",
		_IOC(_IOC_NONE,'f',3,0),
	},
	{
		.name = "EXT3_IOC_SETVERSION",
		_IOC(_IOC_NONE,'f',4,0),
	},
	{
		.name = "EXT3_IOC_GROUP_EXTEND",
		_IOC(_IOC_NONE,'f',7,0),
	},
	{
		.name = "EXT3_IOC_GROUP_ADD",
		_IOC(_IOC_NONE,'f',8,0),
	},
	{
		.name = "EXT3_IOC_WAIT_FOR_READONLY",
		_IOC(_IOC_NONE,'f',99,0),
	},
	{
		.name = "EXT3_IOC_GETRSVSZ",
		_IOC(_IOC_NONE,'f',5,0),
	},
	{
		.name = "EXT3_IOC_SETRSVSZ",
		_IOC(_IOC_NONE,'f',6,0),
	},
	{
		.name = "EXT3_IOC32_GETVERSION",
		_IOC(_IOC_NONE,'f',3,0),
	},
	{
		.name = "EXT3_IOC32_SETVERSION",
		_IOC(_IOC_NONE,'f',4,0),
	},
	{
		.name = "EXT3_IOC32_GETRSVSZ",
		_IOC(_IOC_NONE,'f',5,0),
	},
	{
		.name = "EXT3_IOC32_SETRSVSZ",
		_IOC(_IOC_NONE,'f',6,0),
	},
	{
		.name = "EXT3_IOC32_GROUP_EXTEND",
		_IOC(_IOC_NONE,'f',7,0),
	},
	{
		.name = "EXT3_IOC32_WAIT_FOR_READONLY",
		_IOC(_IOC_NONE,'f',99,0),
	},
	{
		.name = "FS_IOC_RESVSP",
		_IOC(_IOC_NONE,'X',40,0),
	},
	{
		.name = "FS_IOC_RESVSP64",
		_IOC(_IOC_NONE,'X',42,0),
	},
	{
		.name = "FBIO_CURSOR",
		_IOC(_IOC_NONE,'F',0x08,0),
	},
	{
		.name = "FBIO_CURSOR",
		_IOC(_IOC_NONE,'F',0x08,0),
	},
	{
		.name = "FBIOGET_VBLANK",
		_IOC(_IOC_NONE,'F',0x12,0),
	},
	{
		.name = "FBIO_WAITFORVSYNC",
		_IOC(_IOC_NONE,'F',0x20,0),
	},
	{
		.name = "FDCLRPRM",
		_IOC(_IOC_NONE,2,0x41,0),
	},
	{
		.name = "FDSETPRM",
		_IOC(_IOC_NONE,2,0x42,0),
	},
	{
		.name = "FDDEFPRM",
		_IOC(_IOC_NONE,2,0x43,0),
	},
	{
		.name = "FDGETPRM",
		_IOC(_IOC_NONE,2,0x04,0),
	},
	{
		.name = "FDMSGON",
		_IOC(_IOC_NONE,2,0x45,0),
	},
	{
		.name = "FDMSGOFF",
		_IOC(_IOC_NONE,2,0x46,0),
	},
	{
		.name = "FDFMTBEG",
		_IOC(_IOC_NONE,2,0x47,0),
	},
	{
		.name = "FDFMTTRK",
		_IOC(_IOC_NONE,2,0x48,0),
	},
	{
		.name = "FDFMTEND",
		_IOC(_IOC_NONE,2,0x49,0),
	},
	{
		.name = "FDSETEMSGTRESH",
		_IOC(_IOC_NONE,2,0x4a,0),
	},
	{
		.name = "FDFLUSH",
		_IOC(_IOC_NONE,2,0x4b,0),
	},
	{
		.name = "FDSETMAXERRS",
		_IOC(_IOC_NONE,2,0x4c,0),
	},
	{
		.name = "FDGETMAXERRS",
		_IOC(_IOC_NONE,2,0x0e,0),
	},
	{
		.name = "FDGETDRVTYP",
		_IOC(_IOC_NONE,2,0x0f,0),
	},
	{
		.name = "FDSETDRVPRM",
		_IOC(_IOC_NONE,2,0x90,0),
	},
	{
		.name = "FDGETDRVPRM",
		_IOC(_IOC_NONE,2,0x11,0),
	},
	{
		.name = "FDGETDRVSTAT",
		_IOC(_IOC_NONE,2,0x12,0),
	},
	{
		.name = "FDPOLLDRVSTAT",
		_IOC(_IOC_NONE,2,0x13,0),
	},
	{
		.name = "FDRESET",
		_IOC(_IOC_NONE,2,0x54,0),
	},
	{
		.name = "FDGETFDCSTAT",
		_IOC(_IOC_NONE,2,0x15,0),
	},
	{
		.name = "FDWERRORCLR",
		_IOC(_IOC_NONE,2,0x56,0),
	},
	{
		.name = "FDWERRORGET",
		_IOC(_IOC_NONE,2,0x17,0),
	},
	{
		.name = "FDRAWCMD",
		_IOC(_IOC_NONE,2,0x58,0),
	},
	{
		.name = "FDTWADDLE",
		_IOC(_IOC_NONE,2,0x59,0),
	},
	{
		.name = "FDEJECT",
		_IOC(_IOC_NONE,2,0x5a,0),
	},
	{
		.name = "FW_CDEV_IOC_GET_INFO",
		_IOC(_IOC_NONE,'#',0x00,0),
	},
	{
		.name = "FW_CDEV_IOC_SEND_REQUEST",
		_IOC(_IOC_NONE,'#',0x01,0),
	},
	{
		.name = "FW_CDEV_IOC_ALLOCATE",
		_IOC(_IOC_NONE,'#',0x02,0),
	},
	{
		.name = "FW_CDEV_IOC_DEALLOCATE",
		_IOC(_IOC_NONE,'#',0x03,0),
	},
	{
		.name = "FW_CDEV_IOC_SEND_RESPONSE",
		_IOC(_IOC_NONE,'#',0x04,0),
	},
	{
		.name = "FW_CDEV_IOC_INITIATE_BUS_RESET",
		_IOC(_IOC_NONE,'#',0x05,0),
	},
	{
		.name = "FW_CDEV_IOC_ADD_DESCRIPTOR",
		_IOC(_IOC_NONE,'#',0x06,0),
	},
	{
		.name = "FW_CDEV_IOC_REMOVE_DESCRIPTOR",
		_IOC(_IOC_NONE,'#',0x07,0),
	},
	{
		.name = "FW_CDEV_IOC_CREATE_ISO_CONTEXT",
		_IOC(_IOC_NONE,'#',0x08,0),
	},
	{
		.name = "FW_CDEV_IOC_QUEUE_ISO",
		_IOC(_IOC_NONE,'#',0x09,0),
	},
	{
		.name = "FW_CDEV_IOC_START_ISO",
		_IOC(_IOC_NONE,'#',0x0a,0),
	},
	{
		.name = "FW_CDEV_IOC_STOP_ISO",
		_IOC(_IOC_NONE,'#',0x0b,0),
	},
	{
		.name = "FW_CDEV_IOC_GET_CYCLE_TIMER",
		_IOC(_IOC_NONE,'#',0x0c,0),
	},
	{
		.name = "FW_CDEV_IOC_ALLOCATE_ISO_RESOURCE",
		_IOC(_IOC_NONE,'#',0x0d,0),
	},
	{
		.name = "FW_CDEV_IOC_DEALLOCATE_ISO_RESOURCE",
		_IOC(_IOC_NONE,'#',0x0e,0),
	},
	{
		.name = "FW_CDEV_IOC_ALLOCATE_ISO_RESOURCE_ONCE",
		_IOC(_IOC_NONE,'#',0x0f,0),
	},
	{
		.name = "FW_CDEV_IOC_DEALLOCATE_ISO_RESOURCE_ONCE",
		_IOC(_IOC_NONE,'#',0x10,0),
	},
	{
		.name = "FW_CDEV_IOC_GET_SPEED",
		_IOC(_IOC_NONE,'#',0x11,0),
	},
	{
		.name = "FW_CDEV_IOC_SEND_BROADCAST_REQUEST",
		_IOC(_IOC_NONE,'#',0x12,0),
	},
	{
		.name = "FW_CDEV_IOC_SEND_STREAM_PACKET",
		_IOC(_IOC_NONE,'#',0x13,0),
	},
	{
		.name = "FW_CDEV_IOC_GET_CYCLE_TIMER2",
		_IOC(_IOC_NONE,'#',0x14,0),
	},
	{
		.name = "FW_CDEV_IOC_SEND_PHY_PACKET",
		_IOC(_IOC_NONE,'#',0x15,0),
	},
	{
		.name = "FW_CDEV_IOC_RECEIVE_PHY_PACKETS",
		_IOC(_IOC_NONE,'#',0x16,0),
	},
	{
		.name = "FW_CDEV_IOC_SET_ISO_CHANNELS",
		_IOC(_IOC_NONE,'#',0x17,0),
	},
	{
		.name = "BLKROSET",
		_IOC(_IOC_NONE,0x12,93,0),
	},
	{
		.name = "BLKROGET",
		_IOC(_IOC_NONE,0x12,94,0),
	},
	{
		.name = "BLKRRPART",
		_IOC(_IOC_NONE,0x12,95,0),
	},
	{
		.name = "BLKGETSIZE",
		_IOC(_IOC_NONE,0x12,96,0),
	},
	{
		.name = "BLKFLSBUF",
		_IOC(_IOC_NONE,0x12,97,0),
	},
	{
		.name = "BLKRASET",
		_IOC(_IOC_NONE,0x12,98,0),
	},
	{
		.name = "BLKRAGET",
		_IOC(_IOC_NONE,0x12,99,0),
	},
	{
		.name = "BLKFRASET",
		_IOC(_IOC_NONE,0x12,100,0),
	},
	{
		.name = "BLKFRAGET",
		_IOC(_IOC_NONE,0x12,101,0),
	},
	{
		.name = "BLKSECTSET",
		_IOC(_IOC_NONE,0x12,102,0),
	},
	{
		.name = "BLKSECTGET",
		_IOC(_IOC_NONE,0x12,103,0),
	},
	{
		.name = "BLKSSZGET",
		_IOC(_IOC_NONE,0x12,104,0),
	},
	{
		.name = "BLKPG",
		_IOC(_IOC_NONE,0x12,105,0),
	},
	{
		.name = "BLKELVGET",
		_IOC(_IOC_NONE,0x12,106,0),
	},
	{
		.name = "BLKELVSET",
		_IOC(_IOC_NONE,0x12,107,0),
	},
	{
		.name = "BLKBSZGET",
		_IOC(_IOC_NONE,0x12,112,0),
	},
	{
		.name = "BLKBSZSET",
		_IOC(_IOC_NONE,0x12,113,0),
	},
	{
		.name = "BLKGETSIZE64",
		_IOC(_IOC_NONE,0x12,114,0),
	},
	{
		.name = "BLKTRACESETUP",
		_IOC(_IOC_NONE,0x12,115,0),
	},
	{
		.name = "BLKTRACESTART",
		_IOC(_IOC_NONE,0x12,116,0),
	},
	{
		.name = "BLKTRACESTOP",
		_IOC(_IOC_NONE,0x12,117,0),
	},
	{
		.name = "BLKTRACETEARDOWN",
		_IOC(_IOC_NONE,0x12,118,0),
	},
	{
		.name = "BLKDISCARD",
		_IOC(_IOC_NONE,0x12,119,0),
	},
	{
		.name = "BLKIOMIN",
		_IOC(_IOC_NONE,0x12,120,0),
	},
	{
		.name = "BLKIOOPT",
		_IOC(_IOC_NONE,0x12,121,0),
	},
	{
		.name = "BLKALIGNOFF",
		_IOC(_IOC_NONE,0x12,122,0),
	},
	{
		.name = "BLKPBSZGET",
		_IOC(_IOC_NONE,0x12,123,0),
	},
	{
		.name = "BLKDISCARDZEROES",
		_IOC(_IOC_NONE,0x12,124,0),
	},
	{
		.name = "BLKSECDISCARD",
		_IOC(_IOC_NONE,0x12,125,0),
	},
	{
		.name = "FIBMAP",
		_IOC(_IOC_NONE,0x00,1,0),
	},
	{
		.name = "FIGETBSZ",
		_IOC(_IOC_NONE,0x00,2,0),
	},
	{
		.name = "FIFREEZE",
		_IOC(_IOC_NONE,'X',119,0),
	},
	{
		.name = "FITHAW",
		_IOC(_IOC_NONE,'X',120,0),
	},
	{
		.name = "FITRIM",
		_IOC(_IOC_NONE,'X',121,0),
	},
	{
		.name = "FS_IOC_GETFLAGS",
		_IOC(_IOC_NONE,'f',1,0),
	},
	{
		.name = "FS_IOC_SETFLAGS",
		_IOC(_IOC_NONE,'f',2,0),
	},
	{
		.name = "FS_IOC_GETVERSION",
		_IOC(_IOC_NONE,'v',1,0),
	},
	{
		.name = "FS_IOC_SETVERSION",
		_IOC(_IOC_NONE,'v',2,0),
	},
	{
		.name = "FS_IOC_FIEMAP",
		_IOC(_IOC_NONE,'f',11,0),
	},
	{
		.name = "FS_IOC32_GETFLAGS",
		_IOC(_IOC_NONE,'f',1,0),
	},
	{
		.name = "FS_IOC32_SETFLAGS",
		_IOC(_IOC_NONE,'f',2,0),
	},
	{
		.name = "FS_IOC32_GETVERSION",
		_IOC(_IOC_NONE,'v',1,0),
	},
	{
		.name = "FS_IOC32_SETVERSION",
		_IOC(_IOC_NONE,'v',2,0),
	},
	{
		.name = "MFB_SET_CHROMA_KEY",
		_IOC(_IOC_NONE,'M',1,0),
	},
	{
		.name = "MFB_SET_BRIGHTNESS",
		_IOC(_IOC_NONE,'M',3,0),
	},
	{
		.name = "GIGASET_REDIR",
		_IOC(_IOC_NONE,GIGASET_IOCTL,0,0),
	},
	{
		.name = "GIGASET_CONFIG",
		_IOC(_IOC_NONE,GIGASET_IOCTL,1,0),
	},
	{
		.name = "GIGASET_BRKCHARS",
		_IOC(_IOC_NONE,GIGASET_IOCTL,2,0),
	},
	{
		.name = "GIGASET_VERSION",
		_IOC(_IOC_NONE,GIGASET_IOCTL,3,0),
	},
	{
		.name = "GSMIOC_GETCONF",
		_IOC(_IOC_NONE,'G',0,0),
	},
	{
		.name = "GSMIOC_SETCONF",
		_IOC(_IOC_NONE,'G',1,0),
	},
	{
		.name = "HIDIOCGVERSION",
		_IOC(_IOC_NONE,'H',0x01,0),
	},
	{
		.name = "HIDIOCAPPLICATION",
		_IOC(_IOC_NONE,'H',0x02,0),
	},
	{
		.name = "HIDIOCGDEVINFO",
		_IOC(_IOC_NONE,'H',0x03,0),
	},
	{
		.name = "HIDIOCGSTRING",
		_IOC(_IOC_NONE,'H',0x04,0),
	},
	{
		.name = "HIDIOCINITREPORT",
		_IOC(_IOC_NONE,'H',0x05,0),
	},
	{
		.name = "HIDIOCGREPORT",
		_IOC(_IOC_NONE,'H',0x07,0),
	},
	{
		.name = "HIDIOCSREPORT",
		_IOC(_IOC_NONE,'H',0x08,0),
	},
	{
		.name = "HIDIOCGREPORTINFO",
		_IOC(_IOC_NONE,'H',0x09,0),
	},
	{
		.name = "HIDIOCGFIELDINFO",
		_IOC(_IOC_NONE,'H',0x0A,0),
	},
	{
		.name = "HIDIOCGUSAGE",
		_IOC(_IOC_NONE,'H',0x0B,0),
	},
	{
		.name = "HIDIOCSUSAGE",
		_IOC(_IOC_NONE,'H',0x0C,0),
	},
	{
		.name = "HIDIOCGUCODE",
		_IOC(_IOC_NONE,'H',0x0D,0),
	},
	{
		.name = "HIDIOCGFLAG",
		_IOC(_IOC_NONE,'H',0x0E,0),
	},
	{
		.name = "HIDIOCSFLAG",
		_IOC(_IOC_NONE,'H',0x0F,0),
	},
	{
		.name = "HIDIOCGCOLLECTIONINDEX",
		_IOC(_IOC_NONE,'H',0x10,0),
	},
	{
		.name = "HIDIOCGCOLLECTIONINFO",
		_IOC(_IOC_NONE,'H',0x11,0),
	},
	{
		.name = "HIDIOCGUSAGES",
		_IOC(_IOC_NONE,'H',0x13,0),
	},
	{
		.name = "HIDIOCSUSAGES",
		_IOC(_IOC_NONE,'H',0x14,0),
	},
	{
		.name = "HIDIOCGRDESCSIZE",
		_IOC(_IOC_NONE,'H',0x01,0),
	},
	{
		.name = "HIDIOCGRDESC",
		_IOC(_IOC_NONE,'H',0x02,0),
	},
	{
		.name = "HIDIOCGRAWINFO",
		_IOC(_IOC_NONE,'H',0x03,0),
	},
	{
		.name = "HPET_IE_ON",
		_IOC(_IOC_NONE,'h',0x01,0),
	},
	{
		.name = "HPET_IE_OFF",
		_IOC(_IOC_NONE,'h',0x02,0),
	},
	{
		.name = "HPET_INFO",
		_IOC(_IOC_NONE,'h',0x03,0),
	},
	{
		.name = "HPET_EPI",
		_IOC(_IOC_NONE,'h',0x04,0),
	},
	{
		.name = "HPET_DPI",
		_IOC(_IOC_NONE,'h',0x05,0),
	},
	{
		.name = "HPET_IRQFREQ",
		_IOC(_IOC_NONE,'h',0x6,0),
	},
	{
		.name = "I2OGETIOPS",
		_IOC(_IOC_NONE,I2O_MAGIC_NUMBER,0,0),
	},
	{
		.name = "I2OHRTGET",
		_IOC(_IOC_NONE,I2O_MAGIC_NUMBER,1,0),
	},
	{
		.name = "I2OLCTGET",
		_IOC(_IOC_NONE,I2O_MAGIC_NUMBER,2,0),
	},
	{
		.name = "I2OPARMSET",
		_IOC(_IOC_NONE,I2O_MAGIC_NUMBER,3,0),
	},
	{
		.name = "I2OPARMGET",
		_IOC(_IOC_NONE,I2O_MAGIC_NUMBER,4,0),
	},
	{
		.name = "I2OSWDL",
		_IOC(_IOC_NONE,I2O_MAGIC_NUMBER,5,0),
	},
	{
		.name = "I2OSWUL",
		_IOC(_IOC_NONE,I2O_MAGIC_NUMBER,6,0),
	},
	{
		.name = "I2OSWDEL",
		_IOC(_IOC_NONE,I2O_MAGIC_NUMBER,7,0),
	},
	{
		.name = "I2OVALIDATE",
		_IOC(_IOC_NONE,I2O_MAGIC_NUMBER,8,0),
	},
	{
		.name = "I2OHTML",
		_IOC(_IOC_NONE,I2O_MAGIC_NUMBER,9,0),
	},
	{
		.name = "I2OEVTREG",
		_IOC(_IOC_NONE,I2O_MAGIC_NUMBER,10,0),
	},
	{
		.name = "I2OEVTGET",
		_IOC(_IOC_NONE,I2O_MAGIC_NUMBER,11,0),
	},
	{
		.name = "I2OPASSTHRU",
		_IOC(_IOC_NONE,I2O_MAGIC_NUMBER,12,0),
	},
	{
		.name = "I2OPASSTHRU32",
		_IOC(_IOC_NONE,I2O_MAGIC_NUMBER,12,0),
	},
	{
		.name = "BLKI2OGRSTRAT",
		_IOC(_IOC_NONE,'2',1,0),
	},
	{
		.name = "BLKI2OGWSTRAT",
		_IOC(_IOC_NONE,'2',2,0),
	},
	{
		.name = "BLKI2OSRSTRAT",
		_IOC(_IOC_NONE,'2',3,0),
	},
	{
		.name = "BLKI2OSWSTRAT",
		_IOC(_IOC_NONE,'2',4,0),
	},
	{
		.name = "I8K_BIOS_VERSION",
		_IOC(_IOC_NONE,'i',0x80,0),
	},
	{
		.name = "I8K_MACHINE_ID",
		_IOC(_IOC_NONE,'i',0x81,0),
	},
	{
		.name = "I8K_POWER_STATUS",
		_IOC(_IOC_NONE,'i',0x82,0),
	},
	{
		.name = "I8K_FN_STATUS",
		_IOC(_IOC_NONE,'i',0x83,0),
	},
	{
		.name = "I8K_GET_TEMP",
		_IOC(_IOC_NONE,'i',0x84,0),
	},
	{
		.name = "I8K_GET_SPEED",
		_IOC(_IOC_NONE,'i',0x85,0),
	},
	{
		.name = "I8K_GET_FAN",
		_IOC(_IOC_NONE,'i',0x86,0),
	},
	{
		.name = "I8K_SET_FAN",
		_IOC(_IOC_NONE,'i',0x87,0),
	},
	{
		.name = "PPPIOCGFLAGS",
		_IOC(_IOC_NONE,'t',90,0),
	},
	{
		.name = "PPPIOCSFLAGS",
		_IOC(_IOC_NONE,'t',89,0),
	},
	{
		.name = "PPPIOCGASYNCMAP",
		_IOC(_IOC_NONE,'t',88,0),
	},
	{
		.name = "PPPIOCSASYNCMAP",
		_IOC(_IOC_NONE,'t',87,0),
	},
	{
		.name = "PPPIOCGUNIT",
		_IOC(_IOC_NONE,'t',86,0),
	},
	{
		.name = "PPPIOCGRASYNCMAP",
		_IOC(_IOC_NONE,'t',85,0),
	},
	{
		.name = "PPPIOCSRASYNCMAP",
		_IOC(_IOC_NONE,'t',84,0),
	},
	{
		.name = "PPPIOCGMRU",
		_IOC(_IOC_NONE,'t',83,0),
	},
	{
		.name = "PPPIOCSMRU",
		_IOC(_IOC_NONE,'t',82,0),
	},
	{
		.name = "PPPIOCSMAXCID",
		_IOC(_IOC_NONE,'t',81,0),
	},
	{
		.name = "PPPIOCGXASYNCMAP",
		_IOC(_IOC_NONE,'t',80,0),
	},
	{
		.name = "PPPIOCSXASYNCMAP",
		_IOC(_IOC_NONE,'t',79,0),
	},
	{
		.name = "PPPIOCXFERUNIT",
		_IOC(_IOC_NONE,'t',78,0),
	},
	{
		.name = "PPPIOCSCOMPRESS",
		_IOC(_IOC_NONE,'t',77,0),
	},
	{
		.name = "PPPIOCGNPMODE",
		_IOC(_IOC_NONE,'t',76,0),
	},
	{
		.name = "PPPIOCSNPMODE",
		_IOC(_IOC_NONE,'t',75,0),
	},
	{
		.name = "PPPIOCSPASS",
		_IOC(_IOC_NONE,'t',71,0),
	},
	{
		.name = "PPPIOCSACTIVE",
		_IOC(_IOC_NONE,'t',70,0),
	},
	{
		.name = "PPPIOCGDEBUG",
		_IOC(_IOC_NONE,'t',65,0),
	},
	{
		.name = "PPPIOCSDEBUG",
		_IOC(_IOC_NONE,'t',64,0),
	},
	{
		.name = "PPPIOCGIDLE",
		_IOC(_IOC_NONE,'t',63,0),
	},
	{
		.name = "PPPIOCNEWUNIT",
		_IOC(_IOC_NONE,'t',62,0),
	},
	{
		.name = "PPPIOCATTACH",
		_IOC(_IOC_NONE,'t',61,0),
	},
	{
		.name = "PPPIOCDETACH",
		_IOC(_IOC_NONE,'t',60,0),
	},
	{
		.name = "PPPIOCSMRRU",
		_IOC(_IOC_NONE,'t',59,0),
	},
	{
		.name = "PPPIOCCONNECT",
		_IOC(_IOC_NONE,'t',58,0),
	},
	{
		.name = "PPPIOCDISCONN",
		_IOC(_IOC_NONE,'t',57,0),
	},
	{
		.name = "PPPIOCATTCHAN",
		_IOC(_IOC_NONE,'t',56,0),
	},
	{
		.name = "PPPIOCGCHAN",
		_IOC(_IOC_NONE,'t',55,0),
	},
	{
		.name = "PPPIOCGL2TPSTATS",
		_IOC(_IOC_NONE,'t',54,0),
	},
	{
		.name = "PPPOEIOCSFWD",
		_IOC(_IOC_NONE,0xB1 ,0,0),
	},
	{
		.name = "PPPOEIOCDFWD",
		_IOC(_IOC_NONE,0xB1 ,1,0),
	},
	{
		.name = "TUNSETNOCSUM",
		_IOC(_IOC_NONE,'T',200,0),
	},
	{
		.name = "TUNSETDEBUG",
		_IOC(_IOC_NONE,'T',201,0),
	},
	{
		.name = "TUNSETIFF",
		_IOC(_IOC_NONE,'T',202,0),
	},
	{
		.name = "TUNSETPERSIST",
		_IOC(_IOC_NONE,'T',203,0),
	},
	{
		.name = "TUNSETOWNER",
		_IOC(_IOC_NONE,'T',204,0),
	},
	{
		.name = "TUNSETLINK",
		_IOC(_IOC_NONE,'T',205,0),
	},
	{
		.name = "TUNSETGROUP",
		_IOC(_IOC_NONE,'T',206,0),
	},
	{
		.name = "TUNGETFEATURES",
		_IOC(_IOC_NONE,'T',207,0),
	},
	{
		.name = "TUNSETOFFLOAD",
		_IOC(_IOC_NONE,'T',208,0),
	},
	{
		.name = "TUNSETTXFILTER",
		_IOC(_IOC_NONE,'T',209,0),
	},
	{
		.name = "TUNGETIFF",
		_IOC(_IOC_NONE,'T',210,0),
	},
	{
		.name = "TUNGETSNDBUF",
		_IOC(_IOC_NONE,'T',211,0),
	},
	{
		.name = "TUNSETSNDBUF",
		_IOC(_IOC_NONE,'T',212,0),
	},
	{
		.name = "TUNATTACHFILTER",
		_IOC(_IOC_NONE,'T',213,0),
	},
	{
		.name = "TUNDETACHFILTER",
		_IOC(_IOC_NONE,'T',214,0),
	},
	{
		.name = "TUNGETVNETHDRSZ",
		_IOC(_IOC_NONE,'T',215,0),
	},
	{
		.name = "TUNSETVNETHDRSZ",
		_IOC(_IOC_NONE,'T',216,0),
	},
	{
		.name = "EVIOCGVERSION",
		_IOC(_IOC_NONE,'E',0x01,0),
	},
	{
		.name = "EVIOCGID",
		_IOC(_IOC_NONE,'E',0x02,0),
	},
	{
		.name = "EVIOCGREP",
		_IOC(_IOC_NONE,'E',0x03,0),
	},
	{
		.name = "EVIOCSREP",
		_IOC(_IOC_NONE,'E',0x03,0),
	},
	{
		.name = "EVIOCGKEYCODE",
		_IOC(_IOC_NONE,'E',0x04,0),
	},
	{
		.name = "EVIOCSKEYCODE",
		_IOC(_IOC_NONE,'E',0x04,0),
	},
	{
		.name = "EVIOCRMFF",
		_IOC(_IOC_NONE,'E',0x81,0),
	},
	{
		.name = "EVIOCGEFFECTS",
		_IOC(_IOC_NONE,'E',0x84,0),
	},
	{
		.name = "EVIOCGRAB",
		_IOC(_IOC_NONE,'E',0x90,0),
	},
	{
		.name = "IPMICTL_SEND_COMMAND",
		_IOC(_IOC_NONE,IPMI_IOC_MAGIC,13,0),
	},
	{
		.name = "IPMICTL_SEND_COMMAND_SETTIME",
		_IOC(_IOC_NONE,IPMI_IOC_MAGIC,21,0),
	},
	{
		.name = "IPMICTL_RECEIVE_MSG",
		_IOC(_IOC_NONE,IPMI_IOC_MAGIC,12,0),
	},
	{
		.name = "IPMICTL_RECEIVE_MSG_TRUNC",
		_IOC(_IOC_NONE,IPMI_IOC_MAGIC,11,0),
	},
	{
		.name = "IPMICTL_REGISTER_FOR_CMD",
		_IOC(_IOC_NONE,IPMI_IOC_MAGIC,14,0),
	},
	{
		.name = "IPMICTL_UNREGISTER_FOR_CMD",
		_IOC(_IOC_NONE,IPMI_IOC_MAGIC,15,0),
	},
	{
		.name = "IPMICTL_REGISTER_FOR_CMD_CHANS",
		_IOC(_IOC_NONE,IPMI_IOC_MAGIC,28,0),
	},
	{
		.name = "IPMICTL_UNREGISTER_FOR_CMD_CHANS",
		_IOC(_IOC_NONE,IPMI_IOC_MAGIC,29,0),
	},
	{
		.name = "IPMICTL_SET_GETS_EVENTS_CMD",
		_IOC(_IOC_NONE,IPMI_IOC_MAGIC,16,0),
	},
	{
		.name = "IPMICTL_SET_MY_ADDRESS_CMD",
		_IOC(_IOC_NONE,IPMI_IOC_MAGIC,17,0),
	},
	{
		.name = "IPMICTL_GET_MY_ADDRESS_CMD",
		_IOC(_IOC_NONE,IPMI_IOC_MAGIC,18,0),
	},
	{
		.name = "IPMICTL_SET_MY_LUN_CMD",
		_IOC(_IOC_NONE,IPMI_IOC_MAGIC,19,0),
	},
	{
		.name = "IPMICTL_GET_MY_LUN_CMD",
		_IOC(_IOC_NONE,IPMI_IOC_MAGIC,20,0),
	},
	{
		.name = "IPMICTL_SET_TIMING_PARMS_CMD",
		_IOC(_IOC_NONE,IPMI_IOC_MAGIC,22,0),
	},
	{
		.name = "IPMICTL_GET_TIMING_PARMS_CMD",
		_IOC(_IOC_NONE,IPMI_IOC_MAGIC,23,0),
	},
	{
		.name = "IPMICTL_GET_MAINTENANCE_MODE_CMD",
		_IOC(_IOC_NONE,IPMI_IOC_MAGIC,30,0),
	},
	{
		.name = "IPMICTL_SET_MAINTENANCE_MODE_CMD",
		_IOC(_IOC_NONE,IPMI_IOC_MAGIC,31,0),
	},
	{
		.name = "IIOCNETAIF",
		_IOC(_IOC_NONE,'I',1,0),
	},
	{
		.name = "IIOCNETDIF",
		_IOC(_IOC_NONE,'I',2,0),
	},
	{
		.name = "IIOCNETSCF",
		_IOC(_IOC_NONE,'I',3,0),
	},
	{
		.name = "IIOCNETGCF",
		_IOC(_IOC_NONE,'I',4,0),
	},
	{
		.name = "IIOCNETANM",
		_IOC(_IOC_NONE,'I',5,0),
	},
	{
		.name = "IIOCNETDNM",
		_IOC(_IOC_NONE,'I',6,0),
	},
	{
		.name = "IIOCNETGNM",
		_IOC(_IOC_NONE,'I',7,0),
	},
	{
		.name = "IIOCGETSET",
		_IOC(_IOC_NONE,'I',8,0),
	},
	{
		.name = "IIOCSETSET",
		_IOC(_IOC_NONE,'I',9,0),
	},
	{
		.name = "IIOCSETVER",
		_IOC(_IOC_NONE,'I',10,0),
	},
	{
		.name = "IIOCNETHUP",
		_IOC(_IOC_NONE,'I',11,0),
	},
	{
		.name = "IIOCSETGST",
		_IOC(_IOC_NONE,'I',12,0),
	},
	{
		.name = "IIOCSETBRJ",
		_IOC(_IOC_NONE,'I',13,0),
	},
	{
		.name = "IIOCSIGPRF",
		_IOC(_IOC_NONE,'I',14,0),
	},
	{
		.name = "IIOCGETPRF",
		_IOC(_IOC_NONE,'I',15,0),
	},
	{
		.name = "IIOCSETPRF",
		_IOC(_IOC_NONE,'I',16,0),
	},
	{
		.name = "IIOCGETMAP",
		_IOC(_IOC_NONE,'I',17,0),
	},
	{
		.name = "IIOCSETMAP",
		_IOC(_IOC_NONE,'I',18,0),
	},
	{
		.name = "IIOCNETASL",
		_IOC(_IOC_NONE,'I',19,0),
	},
	{
		.name = "IIOCNETDIL",
		_IOC(_IOC_NONE,'I',20,0),
	},
	{
		.name = "IIOCGETCPS",
		_IOC(_IOC_NONE,'I',21,0),
	},
	{
		.name = "IIOCGETDVR",
		_IOC(_IOC_NONE,'I',22,0),
	},
	{
		.name = "IIOCNETLCR",
		_IOC(_IOC_NONE,'I',23,0),
	},
	{
		.name = "IIOCNETDWRSET",
		_IOC(_IOC_NONE,'I',24,0),
	},
	{
		.name = "IIOCNETALN",
		_IOC(_IOC_NONE,'I',32,0),
	},
	{
		.name = "IIOCNETDLN",
		_IOC(_IOC_NONE,'I',33,0),
	},
	{
		.name = "IIOCNETGPN",
		_IOC(_IOC_NONE,'I',34,0),
	},
	{
		.name = "IIOCDBGVAR",
		_IOC(_IOC_NONE,'I',127,0),
	},
	{
		.name = "IIOCDRVCTL",
		_IOC(_IOC_NONE,'I',128,0),
	},
	{
		.name = "PPPIOCGCALLINFO",
		_IOC(_IOC_NONE,'t',128,0),
	},
	{
		.name = "PPPIOCBUNDLE",
		_IOC(_IOC_NONE,'t',129,0),
	},
	{
		.name = "PPPIOCGMPFLAGS",
		_IOC(_IOC_NONE,'t',130,0),
	},
	{
		.name = "PPPIOCSMPFLAGS",
		_IOC(_IOC_NONE,'t',131,0),
	},
	{
		.name = "PPPIOCSMPMTU",
		_IOC(_IOC_NONE,'t',132,0),
	},
	{
		.name = "PPPIOCSMPMRU",
		_IOC(_IOC_NONE,'t',133,0),
	},
	{
		.name = "PPPIOCGCOMPRESSORS",
		_IOC(_IOC_NONE,'t',134,0),
	},
	{
		.name = "PPPIOCSCOMPRESSOR",
		_IOC(_IOC_NONE,'t',135,0),
	},
	{
		.name = "PPPIOCGIFNAME",
		_IOC(_IOC_NONE,'t',136,0),
	},
	{
		.name = "IVTVFB_IOC_DMA_FRAME",
		_IOC(_IOC_NONE,'V',BASE_VIDIOC_PRIVATE+0,0),
	},
	{
		.name = "IVTV_IOC_DMA_FRAME",
		_IOC(_IOC_NONE,'V',BASE_VIDIOC_PRIVATE+0,0),
	},
	{
		.name = "IXJCTL_DSP_RESET",
		_IOC(_IOC_NONE,'q',0xC0,0),
	},
	{
		.name = "IXJCTL_CARDTYPE",
		_IOC(_IOC_NONE,'q',0xC1,0),
	},
	{
		.name = "IXJCTL_SERIAL",
		_IOC(_IOC_NONE,'q',0xC2,0),
	},
	{
		.name = "IXJCTL_DSP_TYPE",
		_IOC(_IOC_NONE,'q',0xC3,0),
	},
	{
		.name = "IXJCTL_DSP_VERSION",
		_IOC(_IOC_NONE,'q',0xC4,0),
	},
	{
		.name = "IXJCTL_VERSION",
		_IOC(_IOC_NONE,'q',0xDA,0),
	},
	{
		.name = "IXJCTL_DSP_IDLE",
		_IOC(_IOC_NONE,'q',0xC5,0),
	},
	{
		.name = "IXJCTL_TESTRAM",
		_IOC(_IOC_NONE,'q',0xC6,0),
	},
	{
		.name = "IXJCTL_SET_FILTER",
		_IOC(_IOC_NONE,'q',0xC7,0),
	},
	{
		.name = "IXJCTL_SET_FILTER_RAW",
		_IOC(_IOC_NONE,'q',0xDD,0),
	},
	{
		.name = "IXJCTL_GET_FILTER_HIST",
		_IOC(_IOC_NONE,'q',0xC8,0),
	},
	{
		.name = "IXJCTL_FILTER_CADENCE",
		_IOC(_IOC_NONE,'q',0xD6,0),
	},
	{
		.name = "IXJCTL_PLAY_CID",
		_IOC(_IOC_NONE,'q',0xD7,0),
	},
	{
		.name = "IXJCTL_INIT_TONE",
		_IOC(_IOC_NONE,'q',0xC9,0),
	},
	{
		.name = "IXJCTL_TONE_CADENCE",
		_IOC(_IOC_NONE,'q',0xCA,0),
	},
	{
		.name = "IXJCTL_AEC_START",
		_IOC(_IOC_NONE,'q',0xCB,0),
	},
	{
		.name = "IXJCTL_AEC_STOP",
		_IOC(_IOC_NONE,'q',0xCC,0),
	},
	{
		.name = "IXJCTL_AEC_GET_LEVEL",
		_IOC(_IOC_NONE,'q',0xCD,0),
	},
	{
		.name = "IXJCTL_SET_LED",
		_IOC(_IOC_NONE,'q',0xCE,0),
	},
	{
		.name = "IXJCTL_MIXER",
		_IOC(_IOC_NONE,'q',0xCF,0),
	},
	{
		.name = "IXJCTL_DAA_COEFF_SET",
		_IOC(_IOC_NONE,'q',0xD0,0),
	},
	{
		.name = "IXJCTL_PORT",
		_IOC(_IOC_NONE,'q',0xD1,0),
	},
	{
		.name = "IXJCTL_DAA_AGAIN",
		_IOC(_IOC_NONE,'q',0xD2,0),
	},
	{
		.name = "IXJCTL_PSTN_LINETEST",
		_IOC(_IOC_NONE,'q',0xD3,0),
	},
	{
		.name = "IXJCTL_CID",
		_IOC(_IOC_NONE,'q',0xD4,0),
	},
	{
		.name = "IXJCTL_VMWI",
		_IOC(_IOC_NONE,'q',0xD8,0),
	},
	{
		.name = "IXJCTL_CIDCW",
		_IOC(_IOC_NONE,'q',0xD9,0),
	},
	{
		.name = "IXJCTL_POTS_PSTN",
		_IOC(_IOC_NONE,'q',0xD5,0),
	},
	{
		.name = "IXJCTL_HZ",
		_IOC(_IOC_NONE,'q',0xE0,0),
	},
	{
		.name = "IXJCTL_RATE",
		_IOC(_IOC_NONE,'q',0xE1,0),
	},
	{
		.name = "IXJCTL_FRAMES_READ",
		_IOC(_IOC_NONE,'q',0xE2,0),
	},
	{
		.name = "IXJCTL_FRAMES_WRITTEN",
		_IOC(_IOC_NONE,'q',0xE3,0),
	},
	{
		.name = "IXJCTL_READ_WAIT",
		_IOC(_IOC_NONE,'q',0xE4,0),
	},
	{
		.name = "IXJCTL_WRITE_WAIT",
		_IOC(_IOC_NONE,'q',0xE5,0),
	},
	{
		.name = "IXJCTL_DRYBUFFER_READ",
		_IOC(_IOC_NONE,'q',0xE6,0),
	},
	{
		.name = "IXJCTL_DRYBUFFER_CLEAR",
		_IOC(_IOC_NONE,'q',0xE7,0),
	},
	{
		.name = "IXJCTL_DTMF_PRESCALE",
		_IOC(_IOC_NONE,'q',0xE8,0),
	},
	{
		.name = "IXJCTL_SIGCTL",
		_IOC(_IOC_NONE,'q',0xE9,0),
	},
	{
		.name = "IXJCTL_SC_RXG",
		_IOC(_IOC_NONE,'q',0xEA,0),
	},
	{
		.name = "IXJCTL_SC_TXG",
		_IOC(_IOC_NONE,'q',0xEB,0),
	},
	{
		.name = "IXJCTL_INTERCOM_START",
		_IOC(_IOC_NONE,'q',0xFD,0),
	},
	{
		.name = "IXJCTL_INTERCOM_STOP",
		_IOC(_IOC_NONE,'q',0xFE,0),
	},
	{
		.name = "JSIOCGVERSION",
		_IOC(_IOC_NONE,'j',0x01,0),
	},
	{
		.name = "JSIOCGAXES",
		_IOC(_IOC_NONE,'j',0x11,0),
	},
	{
		.name = "JSIOCGBUTTONS",
		_IOC(_IOC_NONE,'j',0x12,0),
	},
	{
		.name = "JSIOCSCORR",
		_IOC(_IOC_NONE,'j',0x21,0),
	},
	{
		.name = "JSIOCGCORR",
		_IOC(_IOC_NONE,'j',0x22,0),
	},
	{
		.name = "JSIOCSAXMAP",
		_IOC(_IOC_NONE,'j',0x31,0),
	},
	{
		.name = "JSIOCGAXMAP",
		_IOC(_IOC_NONE,'j',0x32,0),
	},
	{
		.name = "JSIOCSBTNMAP",
		_IOC(_IOC_NONE,'j',0x33,0),
	},
	{
		.name = "JSIOCGBTNMAP",
		_IOC(_IOC_NONE,'j',0x34,0),
	},
	{
		.name = "KVM_GET_API_VERSION",
		_IOC(_IOC_NONE,KVMIO,0x00,0),
	},
	{
		.name = "KVM_CREATE_VM",
		_IOC(_IOC_NONE,KVMIO,0x01,0),
	},
	{
		.name = "KVM_GET_MSR_INDEX_LIST",
		_IOC(_IOC_NONE,KVMIO,0x02,0),
	},
	{
		.name = "KVM_S390_ENABLE_SIE",
		_IOC(_IOC_NONE,KVMIO,0x06,0),
	},
	{
		.name = "KVM_CHECK_EXTENSION",
		_IOC(_IOC_NONE,KVMIO,0x03,0),
	},
	{
		.name = "KVM_GET_VCPU_MMAP_SIZE",
		_IOC(_IOC_NONE,KVMIO,0x04,0),
	},
	{
		.name = "KVM_GET_SUPPORTED_CPUID",
		_IOC(_IOC_NONE,KVMIO,0x05,0),
	},
	{
		.name = "KVM_SET_MEMORY_REGION",
		_IOC(_IOC_NONE,KVMIO,0x40,0),
	},
	{
		.name = "KVM_CREATE_VCPU",
		_IOC(_IOC_NONE,KVMIO,0x41,0),
	},
	{
		.name = "KVM_GET_DIRTY_LOG",
		_IOC(_IOC_NONE,KVMIO,0x42,0),
	},
	{
		.name = "KVM_SET_MEMORY_ALIAS",
		_IOC(_IOC_NONE,KVMIO,0x43,0),
	},
	{
		.name = "KVM_SET_NR_MMU_PAGES",
		_IOC(_IOC_NONE,KVMIO,0x44,0),
	},
	{
		.name = "KVM_GET_NR_MMU_PAGES",
		_IOC(_IOC_NONE,KVMIO,0x45,0),
	},
	{
		.name = "KVM_SET_USER_MEMORY_REGION",
		_IOC(_IOC_NONE,KVMIO,0x46,0),
	},
	{
		.name = "KVM_SET_TSS_ADDR",
		_IOC(_IOC_NONE,KVMIO,0x47,0),
	},
	{
		.name = "KVM_SET_IDENTITY_MAP_ADDR",
		_IOC(_IOC_NONE,KVMIO,0x48,0),
	},
	{
		.name = "KVM_CREATE_IRQCHIP",
		_IOC(_IOC_NONE,KVMIO,0x60,0),
	},
	{
		.name = "KVM_IRQ_LINE",
		_IOC(_IOC_NONE,KVMIO,0x61,0),
	},
	{
		.name = "KVM_GET_IRQCHIP",
		_IOC(_IOC_NONE,KVMIO,0x62,0),
	},
	{
		.name = "KVM_SET_IRQCHIP",
		_IOC(_IOC_NONE,KVMIO,0x63,0),
	},
	{
		.name = "KVM_CREATE_PIT",
		_IOC(_IOC_NONE,KVMIO,0x64,0),
	},
	{
		.name = "KVM_GET_PIT",
		_IOC(_IOC_NONE,KVMIO,0x65,0),
	},
	{
		.name = "KVM_SET_PIT",
		_IOC(_IOC_NONE,KVMIO,0x66,0),
	},
	{
		.name = "KVM_IRQ_LINE_STATUS",
		_IOC(_IOC_NONE,KVMIO,0x67,0),
	},
	{
		.name = "KVM_ASSIGN_PCI_DEVICE",
		_IOC(_IOC_NONE,KVMIO,0x69,0),
	},
	{
		.name = "KVM_SET_GSI_ROUTING",
		_IOC(_IOC_NONE,KVMIO,0x6a,0),
	},
	{
		.name = "KVM_ASSIGN_DEV_IRQ",
		_IOC(_IOC_NONE,KVMIO,0x70,0),
	},
	{
		.name = "KVM_REINJECT_CONTROL",
		_IOC(_IOC_NONE,KVMIO,0x71,0),
	},
	{
		.name = "KVM_DEASSIGN_PCI_DEVICE",
		_IOC(_IOC_NONE,KVMIO,0x72,0),
	},
	{
		.name = "KVM_ASSIGN_SET_MSIX_NR",
		_IOC(_IOC_NONE,KVMIO,0x73,0),
	},
	{
		.name = "KVM_ASSIGN_SET_MSIX_ENTRY",
		_IOC(_IOC_NONE,KVMIO,0x74,0),
	},
	{
		.name = "KVM_DEASSIGN_DEV_IRQ",
		_IOC(_IOC_NONE,KVMIO,0x75,0),
	},
	{
		.name = "KVM_IRQFD",
		_IOC(_IOC_NONE,KVMIO,0x76,0),
	},
	{
		.name = "KVM_CREATE_PIT2",
		_IOC(_IOC_NONE,KVMIO,0x77,0),
	},
	{
		.name = "KVM_SET_BOOT_CPU_ID",
		_IOC(_IOC_NONE,KVMIO,0x78,0),
	},
	{
		.name = "KVM_IOEVENTFD",
		_IOC(_IOC_NONE,KVMIO,0x79,0),
	},
	{
		.name = "KVM_XEN_HVM_CONFIG",
		_IOC(_IOC_NONE,KVMIO,0x7a,0),
	},
	{
		.name = "KVM_SET_CLOCK",
		_IOC(_IOC_NONE,KVMIO,0x7b,0),
	},
	{
		.name = "KVM_GET_CLOCK",
		_IOC(_IOC_NONE,KVMIO,0x7c,0),
	},
	{
		.name = "KVM_GET_PIT2",
		_IOC(_IOC_NONE,KVMIO,0x9f,0),
	},
	{
		.name = "KVM_SET_PIT2",
		_IOC(_IOC_NONE,KVMIO,0xa0,0),
	},
	{
		.name = "KVM_PPC_GET_PVINFO",
		_IOC(_IOC_NONE,KVMIO,0xa1,0),
	},
	{
		.name = "KVM_RUN",
		_IOC(_IOC_NONE,KVMIO,0x80,0),
	},
	{
		.name = "KVM_GET_REGS",
		_IOC(_IOC_NONE,KVMIO,0x81,0),
	},
	{
		.name = "KVM_SET_REGS",
		_IOC(_IOC_NONE,KVMIO,0x82,0),
	},
	{
		.name = "KVM_GET_SREGS",
		_IOC(_IOC_NONE,KVMIO,0x83,0),
	},
	{
		.name = "KVM_SET_SREGS",
		_IOC(_IOC_NONE,KVMIO,0x84,0),
	},
	{
		.name = "KVM_TRANSLATE",
		_IOC(_IOC_NONE,KVMIO,0x85,0),
	},
	{
		.name = "KVM_INTERRUPT",
		_IOC(_IOC_NONE,KVMIO,0x86,0),
	},
	{
		.name = "KVM_GET_MSRS",
		_IOC(_IOC_NONE,KVMIO,0x88,0),
	},
	{
		.name = "KVM_SET_MSRS",
		_IOC(_IOC_NONE,KVMIO,0x89,0),
	},
	{
		.name = "KVM_SET_CPUID",
		_IOC(_IOC_NONE,KVMIO,0x8a,0),
	},
	{
		.name = "KVM_SET_SIGNAL_MASK",
		_IOC(_IOC_NONE,KVMIO,0x8b,0),
	},
	{
		.name = "KVM_GET_FPU",
		_IOC(_IOC_NONE,KVMIO,0x8c,0),
	},
	{
		.name = "KVM_SET_FPU",
		_IOC(_IOC_NONE,KVMIO,0x8d,0),
	},
	{
		.name = "KVM_GET_LAPIC",
		_IOC(_IOC_NONE,KVMIO,0x8e,0),
	},
	{
		.name = "KVM_SET_LAPIC",
		_IOC(_IOC_NONE,KVMIO,0x8f,0),
	},
	{
		.name = "KVM_SET_CPUID2",
		_IOC(_IOC_NONE,KVMIO,0x90,0),
	},
	{
		.name = "KVM_GET_CPUID2",
		_IOC(_IOC_NONE,KVMIO,0x91,0),
	},
	{
		.name = "KVM_TPR_ACCESS_REPORTING",
		_IOC(_IOC_NONE,KVMIO,0x92,0),
	},
	{
		.name = "KVM_SET_VAPIC_ADDR",
		_IOC(_IOC_NONE,KVMIO,0x93,0),
	},
	{
		.name = "KVM_S390_INTERRUPT",
		_IOC(_IOC_NONE,KVMIO,0x94,0),
	},
	{
		.name = "KVM_S390_STORE_STATUS",
		_IOC(_IOC_NONE,KVMIO,0x95,0),
	},
	{
		.name = "KVM_S390_SET_INITIAL_PSW",
		_IOC(_IOC_NONE,KVMIO,0x96,0),
	},
	{
		.name = "KVM_S390_INITIAL_RESET",
		_IOC(_IOC_NONE,KVMIO,0x97,0),
	},
	{
		.name = "KVM_GET_MP_STATE",
		_IOC(_IOC_NONE,KVMIO,0x98,0),
	},
	{
		.name = "KVM_SET_MP_STATE",
		_IOC(_IOC_NONE,KVMIO,0x99,0),
	},
	{
		.name = "KVM_NMI",
		_IOC(_IOC_NONE,KVMIO,0x9a,0),
	},
	{
		.name = "KVM_SET_GUEST_DEBUG",
		_IOC(_IOC_NONE,KVMIO,0x9b,0),
	},
	{
		.name = "KVM_X86_SETUP_MCE",
		_IOC(_IOC_NONE,KVMIO,0x9c,0),
	},
	{
		.name = "KVM_X86_GET_MCE_CAP_SUPPORTED",
		_IOC(_IOC_NONE,KVMIO,0x9d,0),
	},
	{
		.name = "KVM_X86_SET_MCE",
		_IOC(_IOC_NONE,KVMIO,0x9e,0),
	},
	{
		.name = "KVM_IA64_VCPU_GET_STACK",
		_IOC(_IOC_NONE,KVMIO,0x9a,0),
	},
	{
		.name = "KVM_IA64_VCPU_SET_STACK",
		_IOC(_IOC_NONE,KVMIO,0x9b,0),
	},
	{
		.name = "KVM_GET_VCPU_EVENTS",
		_IOC(_IOC_NONE,KVMIO,0x9f,0),
	},
	{
		.name = "KVM_SET_VCPU_EVENTS",
		_IOC(_IOC_NONE,KVMIO,0xa0,0),
	},
	{
		.name = "KVM_GET_DEBUGREGS",
		_IOC(_IOC_NONE,KVMIO,0xa1,0),
	},
	{
		.name = "KVM_SET_DEBUGREGS",
		_IOC(_IOC_NONE,KVMIO,0xa2,0),
	},
	{
		.name = "KVM_ENABLE_CAP",
		_IOC(_IOC_NONE,KVMIO,0xa3,0),
	},
	{
		.name = "KVM_GET_XSAVE",
		_IOC(_IOC_NONE,KVMIO,0xa4,0),
	},
	{
		.name = "KVM_SET_XSAVE",
		_IOC(_IOC_NONE,KVMIO,0xa5,0),
	},
	{
		.name = "KVM_GET_XCRS",
		_IOC(_IOC_NONE,KVMIO,0xa6,0),
	},
	{
		.name = "KVM_SET_XCRS",
		_IOC(_IOC_NONE,KVMIO,0xa7,0),
	},
	{
		.name = "MATROXFB_SET_OUTPUT_MODE",
		_IOC(_IOC_NONE,'n',0xFA,0),
	},
	{
		.name = "MATROXFB_GET_OUTPUT_MODE",
		_IOC(_IOC_NONE,'n',0xFA,0),
	},
	{
		.name = "MATROXFB_SET_OUTPUT_CONNECTION",
		_IOC(_IOC_NONE,'n',0xF8,0),
	},
	{
		.name = "MATROXFB_GET_OUTPUT_CONNECTION",
		_IOC(_IOC_NONE,'n',0xF8,0),
	},
	{
		.name = "MATROXFB_GET_AVAILABLE_OUTPUTS",
		_IOC(_IOC_NONE,'n',0xF9,0),
	},
	{
		.name = "MATROXFB_GET_ALL_OUTPUTS",
		_IOC(_IOC_NONE,'n',0xFB,0),
	},
	{
		.name = "MEYEIOC_G_PARAMS",
		_IOC(_IOC_NONE,'v',BASE_VIDIOC_PRIVATE+0,0),
	},
	{
		.name = "MEYEIOC_S_PARAMS",
		_IOC(_IOC_NONE,'v',BASE_VIDIOC_PRIVATE+1,0),
	},
	{
		.name = "MEYEIOC_QBUF_CAPT",
		_IOC(_IOC_NONE,'v',BASE_VIDIOC_PRIVATE+2,0),
	},
	{
		.name = "MEYEIOC_SYNC",
		_IOC(_IOC_NONE,'v',BASE_VIDIOC_PRIVATE+3,0),
	},
	{
		.name = "MEYEIOC_STILLCAPT",
		_IOC(_IOC_NONE,'v',BASE_VIDIOC_PRIVATE+4,0),
	},
	{
		.name = "MEYEIOC_STILLJCAPT",
		_IOC(_IOC_NONE,'v',BASE_VIDIOC_PRIVATE+5,0),
	},
	{
		.name = "IMADDTIMER",
		_IOC(_IOC_NONE,'I',64,0),
	},
	{
		.name = "IMDELTIMER",
		_IOC(_IOC_NONE,'I',65,0),
	},
	{
		.name = "IMGETVERSION",
		_IOC(_IOC_NONE,'I',66,0),
	},
	{
		.name = "IMGETCOUNT",
		_IOC(_IOC_NONE,'I',67,0),
	},
	{
		.name = "IMGETDEVINFO",
		_IOC(_IOC_NONE,'I',68,0),
	},
	{
		.name = "IMCTRLREQ",
		_IOC(_IOC_NONE,'I',69,0),
	},
	{
		.name = "IMCLEAR_L2",
		_IOC(_IOC_NONE,'I',70,0),
	},
	{
		.name = "IMSETDEVNAME",
		_IOC(_IOC_NONE,'I',71,0),
	},
	{
		.name = "IMHOLD_L1",
		_IOC(_IOC_NONE,'I',72,0),
	},
	{
		.name = "MMTIMER_GETOFFSET",
		_IOC(_IOC_NONE,MMTIMER_IOCTL_BASE,0,0),
	},
	{
		.name = "MMTIMER_GETRES",
		_IOC(_IOC_NONE,MMTIMER_IOCTL_BASE,1,0),
	},
	{
		.name = "MMTIMER_GETFREQ",
		_IOC(_IOC_NONE,MMTIMER_IOCTL_BASE,2,0),
	},
	{
		.name = "MMTIMER_GETBITS",
		_IOC(_IOC_NONE,MMTIMER_IOCTL_BASE,4,0),
	},
	{
		.name = "MMTIMER_MMAPAVAIL",
		_IOC(_IOC_NONE,MMTIMER_IOCTL_BASE,6,0),
	},
	{
		.name = "MMTIMER_GETCOUNTER",
		_IOC(_IOC_NONE,MMTIMER_IOCTL_BASE,9,0),
	},
	{
		.name = "VFAT_IOCTL_READDIR_BOTH",
		_IOC(_IOC_NONE,'r',1,0),
	},
	{
		.name = "VFAT_IOCTL_READDIR_SHORT",
		_IOC(_IOC_NONE,'r',2,0),
	},
	{
		.name = "FAT_IOCTL_GET_ATTRIBUTES",
		_IOC(_IOC_NONE,'r',0x10,0),
	},
	{
		.name = "FAT_IOCTL_SET_ATTRIBUTES",
		_IOC(_IOC_NONE,'r',0x11,0),
	},
	{
		.name = "MSMFB_GRP_DISP",
		_IOC(_IOC_NONE,MSMFB_IOCTL_MAGIC,1,0),
	},
	{
		.name = "MSMFB_BLIT",
		_IOC(_IOC_NONE,MSMFB_IOCTL_MAGIC,2,0),
	},
	{
		.name = "MTIOCTOP",
		_IOC(_IOC_NONE,'m',1,0),
	},
	{
		.name = "MTIOCGET",
		_IOC(_IOC_NONE,'m',2,0),
	},
	{
		.name = "MTIOCPOS",
		_IOC(_IOC_NONE,'m',3,0),
	},
	{
		.name = "NBD_SET_SOCK",
		_IOC(_IOC_NONE, 0xab,0 ,0),
	},
	{
		.name = "NBD_SET_BLKSIZE",
		_IOC(_IOC_NONE, 0xab,1 ,0),
	},
	{
		.name = "NBD_SET_SIZE",
		_IOC(_IOC_NONE, 0xab,2 ,0),
	},
	{
		.name = "NBD_DO_IT",
		_IOC(_IOC_NONE, 0xab,3 ,0),
	},
	{
		.name = "NBD_CLEAR_SOCK",
		_IOC(_IOC_NONE, 0xab,4 ,0),
	},
	{
		.name = "NBD_CLEAR_QUE",
		_IOC(_IOC_NONE, 0xab,5 ,0),
	},
	{
		.name = "NBD_PRINT_DEBUG",
		_IOC(_IOC_NONE, 0xab,6 ,0),
	},
	{
		.name = "NBD_SET_SIZE_BLOCKS",
		_IOC(_IOC_NONE, 0xab,7 ,0),
	},
	{
		.name = "NBD_DISCONNECT",
		_IOC(_IOC_NONE, 0xab,8 ,0),
	},
	{
		.name = "NBD_SET_TIMEOUT",
		_IOC(_IOC_NONE, 0xab,9 ,0),
	},
	{
		.name = "NCP_IOC_NCPREQUEST",
		_IOC(_IOC_NONE,'n',1,0),
	},
	{
		.name = "NCP_IOC_GETMOUNTUID",
		_IOC(_IOC_NONE,'n',2,0),
	},
	{
		.name = "NCP_IOC_GETMOUNTUID2",
		_IOC(_IOC_NONE,'n',2,0),
	},
	{
		.name = "NCP_IOC_CONN_LOGGED_IN",
		_IOC(_IOC_NONE,'n',3,0),
	},
	{
		.name = "NCP_IOC_GET_FS_INFO",
		_IOC(_IOC_NONE,'n',4,0),
	},
	{
		.name = "NCP_IOC_GET_FS_INFO_V2",
		_IOC(_IOC_NONE,'n',4,0),
	},
	{
		.name = "NCP_IOC_SIGN_INIT",
		_IOC(_IOC_NONE,'n',5,0),
	},
	{
		.name = "NCP_IOC_SIGN_WANTED",
		_IOC(_IOC_NONE,'n',6,0),
	},
	{
		.name = "NCP_IOC_SET_SIGN_WANTED",
		_IOC(_IOC_NONE,'n',6,0),
	},
	{
		.name = "NCP_IOC_LOCKUNLOCK",
		_IOC(_IOC_NONE,'n',7,0),
	},
	{
		.name = "NCP_IOC_GETROOT",
		_IOC(_IOC_NONE,'n',8,0),
	},
	{
		.name = "NCP_IOC_SETROOT",
		_IOC(_IOC_NONE,'n',8,0),
	},
	{
		.name = "NCP_IOC_GETOBJECTNAME",
		_IOC(_IOC_NONE,'n',9,0),
	},
	{
		.name = "NCP_IOC_SETOBJECTNAME",
		_IOC(_IOC_NONE,'n',9,0),
	},
	{
		.name = "NCP_IOC_GETPRIVATEDATA",
		_IOC(_IOC_NONE,'n',10,0),
	},
	{
		.name = "NCP_IOC_SETPRIVATEDATA",
		_IOC(_IOC_NONE,'n',10,0),
	},
	{
		.name = "NCP_IOC_GETCHARSETS",
		_IOC(_IOC_NONE,'n',11,0),
	},
	{
		.name = "NCP_IOC_SETCHARSETS",
		_IOC(_IOC_NONE,'n',11,0),
	},
	{
		.name = "NCP_IOC_GETDENTRYTTL",
		_IOC(_IOC_NONE,'n',12,0),
	},
	{
		.name = "NCP_IOC_SETDENTRYTTL",
		_IOC(_IOC_NONE,'n',12,0),
	},
	{
		.name = "NVRAM_INIT",
		_IOC(_IOC_NONE,'p',0x40,0),
	},
	{
		.name = "NVRAM_SETCKS",
		_IOC(_IOC_NONE,'p',0x41,0),
	},
	{
		.name = "PERF_EVENT_IOC_ENABLE",
		_IOC(_IOC_NONE,'$',0,0),
	},
	{
		.name = "PERF_EVENT_IOC_DISABLE",
		_IOC(_IOC_NONE,'$',1,0),
	},
	{
		.name = "PERF_EVENT_IOC_REFRESH",
		_IOC(_IOC_NONE,'$',2,0),
	},
	{
		.name = "PERF_EVENT_IOC_RESET",
		_IOC(_IOC_NONE,'$',3,0),
	},
	{
		.name = "PERF_EVENT_IOC_PERIOD",
		_IOC(_IOC_NONE,'$',4,0),
	},
	{
		.name = "PERF_EVENT_IOC_SET_OUTPUT",
		_IOC(_IOC_NONE,'$',5,0),
	},
	{
		.name = "PERF_EVENT_IOC_SET_FILTER",
		_IOC(_IOC_NONE,'$',6,0),
	},
	{
		.name = "PHN_GET_REG",
		_IOC(_IOC_NONE,PH_IOC_MAGIC,0,0),
	},
	{
		.name = "PHN_SET_REG",
		_IOC(_IOC_NONE,PH_IOC_MAGIC,1,0),
	},
	{
		.name = "PHN_GET_REGS",
		_IOC(_IOC_NONE,PH_IOC_MAGIC,2,0),
	},
	{
		.name = "PHN_SET_REGS",
		_IOC(_IOC_NONE,PH_IOC_MAGIC,3,0),
	},
	{
		.name = "PHN_NOT_OH",
		_IOC(_IOC_NONE,PH_IOC_MAGIC,4,0),
	},
	{
		.name = "PHN_GETREG",
		_IOC(_IOC_NONE,PH_IOC_MAGIC,5,0),
	},
	{
		.name = "PHN_SETREG",
		_IOC(_IOC_NONE,PH_IOC_MAGIC,6,0),
	},
	{
		.name = "PHN_GETREGS",
		_IOC(_IOC_NONE,PH_IOC_MAGIC,7,0),
	},
	{
		.name = "PHN_SETREGS",
		_IOC(_IOC_NONE,PH_IOC_MAGIC,8,0),
	},
	{
		.name = "PACKET_CTRL_CMD",
		_IOC(_IOC_NONE,PACKET_IOCTL_MAGIC,1,0),
	},
	{
		.name = "PMU_IOC_SLEEP",
		_IOC(_IOC_NONE,'B',0,0),
	},
	{
		.name = "PMU_IOC_GET_BACKLIGHT",
		_IOC(_IOC_NONE,'B',1,0),
	},
	{
		.name = "PMU_IOC_SET_BACKLIGHT",
		_IOC(_IOC_NONE,'B',2,0),
	},
	{
		.name = "PMU_IOC_GET_MODEL",
		_IOC(_IOC_NONE,'B',3,0),
	},
	{
		.name = "PMU_IOC_HAS_ADB",
		_IOC(_IOC_NONE,'B',4,0),
	},
	{
		.name = "PMU_IOC_CAN_SLEEP",
		_IOC(_IOC_NONE,'B',5,0),
	},
	{
		.name = "PMU_IOC_GRAB_BACKLIGHT",
		_IOC(_IOC_NONE,'B',6,0),
	},
	{
		.name = "PPSETMODE",
		_IOC(_IOC_NONE,PP_IOCTL,0x80,0),
	},
	{
		.name = "PPRSTATUS",
		_IOC(_IOC_NONE,PP_IOCTL,0x81,0),
	},
	{
		.name = "PPRCONTROL",
		_IOC(_IOC_NONE,PP_IOCTL,0x83,0),
	},
	{
		.name = "PPWCONTROL",
		_IOC(_IOC_NONE,PP_IOCTL,0x84,0),
	},
	{
		.name = "PPFCONTROL",
		_IOC(_IOC_NONE,PP_IOCTL,0x8e,0),
	},
	{
		.name = "PPRDATA",
		_IOC(_IOC_NONE,PP_IOCTL,0x85,0),
	},
	{
		.name = "PPWDATA",
		_IOC(_IOC_NONE,PP_IOCTL,0x86,0),
	},
	{
		.name = "PPCLAIM",
		_IOC(_IOC_NONE,PP_IOCTL,0x8b,0),
	},
	{
		.name = "PPRELEASE",
		_IOC(_IOC_NONE,PP_IOCTL,0x8c,0),
	},
	{
		.name = "PPYIELD",
		_IOC(_IOC_NONE,PP_IOCTL,0x8d,0),
	},
	{
		.name = "PPEXCL",
		_IOC(_IOC_NONE,PP_IOCTL,0x8f,0),
	},
	{
		.name = "PPDATADIR",
		_IOC(_IOC_NONE,PP_IOCTL,0x90,0),
	},
	{
		.name = "PPNEGOT",
		_IOC(_IOC_NONE,PP_IOCTL,0x91,0),
	},
	{
		.name = "PPWCTLONIRQ",
		_IOC(_IOC_NONE,PP_IOCTL,0x92,0),
	},
	{
		.name = "PPCLRIRQ",
		_IOC(_IOC_NONE,PP_IOCTL,0x93,0),
	},
	{
		.name = "PPSETPHASE",
		_IOC(_IOC_NONE,PP_IOCTL,0x94,0),
	},
	{
		.name = "PPGETTIME",
		_IOC(_IOC_NONE,PP_IOCTL,0x95,0),
	},
	{
		.name = "PPSETTIME",
		_IOC(_IOC_NONE,PP_IOCTL,0x96,0),
	},
	{
		.name = "PPGETMODES",
		_IOC(_IOC_NONE,PP_IOCTL,0x97,0),
	},
	{
		.name = "PPGETMODE",
		_IOC(_IOC_NONE,PP_IOCTL,0x98,0),
	},
	{
		.name = "PPGETPHASE",
		_IOC(_IOC_NONE,PP_IOCTL,0x99,0),
	},
	{
		.name = "PPGETFLAGS",
		_IOC(_IOC_NONE,PP_IOCTL,0x9a,0),
	},
	{
		.name = "PPSETFLAGS",
		_IOC(_IOC_NONE,PP_IOCTL,0x9b,0),
	},
	{
		.name = "PPS_GETPARAMS",
		_IOC(_IOC_NONE,'p',0xa1,0),
	},
	{
		.name = "PPS_SETPARAMS",
		_IOC(_IOC_NONE,'p',0xa2,0),
	},
	{
		.name = "PPS_GETCAP",
		_IOC(_IOC_NONE,'p',0xa3,0),
	},
	{
		.name = "PPS_FETCH",
		_IOC(_IOC_NONE,'p',0xa4,0),
	},
	{
		.name = "FBIO_RADEON_GET_MIRROR",
		_IOC(_IOC_NONE,'@',3,0),
	},
	{
		.name = "FBIO_RADEON_SET_MIRROR",
		_IOC(_IOC_NONE,'@',4,0),
	},
	{
		.name = "RNDGETENTCNT",
		_IOC(_IOC_NONE, 'R',0x00,0),
	},
	{
		.name = "RNDADDTOENTCNT",
		_IOC(_IOC_NONE, 'R',0x01,0),
	},
	{
		.name = "RNDGETPOOL",
		_IOC(_IOC_NONE, 'R',0x02,0),
	},
	{
		.name = "RNDADDENTROPY",
		_IOC(_IOC_NONE, 'R',0x03,0),
	},
	{
		.name = "RNDZAPENTCNT",
		_IOC(_IOC_NONE, 'R',0x04 ,0),
	},
	{
		.name = "RNDCLEARPOOL",
		_IOC(_IOC_NONE, 'R',0x06 ,0),
	},
	{
		.name = "RAW_SETBIND",
		_IOC(_IOC_NONE, 0xac,0 ,0),
	},
	{
		.name = "RAW_GETBIND",
		_IOC(_IOC_NONE, 0xac,1 ,0),
	},
	{
		.name = "REISERFS_IOC_UNPACK",
		_IOC(_IOC_NONE,0xCD,1,0),
	},
	{
		.name = "REISERFS_IOC32_UNPACK",
		_IOC(_IOC_NONE,0xCD,1,0),
	},
	{
		.name = "RFKILL_IOCTL_NOINPUT",
		_IOC(_IOC_NONE,RFKILL_IOC_MAGIC,RFKILL_IOC_NOINPUT,0),
	},
	{
		.name = "RTC_AIE_ON",
		_IOC(_IOC_NONE,'p',0x01,0),
	},
	{
		.name = "RTC_AIE_OFF",
		_IOC(_IOC_NONE,'p',0x02,0),
	},
	{
		.name = "RTC_UIE_ON",
		_IOC(_IOC_NONE,'p',0x03,0),
	},
	{
		.name = "RTC_UIE_OFF",
		_IOC(_IOC_NONE,'p',0x04,0),
	},
	{
		.name = "RTC_PIE_ON",
		_IOC(_IOC_NONE,'p',0x05,0),
	},
	{
		.name = "RTC_PIE_OFF",
		_IOC(_IOC_NONE,'p',0x06,0),
	},
	{
		.name = "RTC_WIE_ON",
		_IOC(_IOC_NONE,'p',0x0f,0),
	},
	{
		.name = "RTC_WIE_OFF",
		_IOC(_IOC_NONE,'p',0x10,0),
	},
	{
		.name = "RTC_ALM_SET",
		_IOC(_IOC_NONE,'p',0x07,0),
	},
	{
		.name = "RTC_ALM_READ",
		_IOC(_IOC_NONE,'p',0x08,0),
	},
	{
		.name = "RTC_RD_TIME",
		_IOC(_IOC_NONE,'p',0x09,0),
	},
	{
		.name = "RTC_SET_TIME",
		_IOC(_IOC_NONE,'p',0x0a,0),
	},
	{
		.name = "RTC_IRQP_READ",
		_IOC(_IOC_NONE,'p',0x0b,0),
	},
	{
		.name = "RTC_IRQP_SET",
		_IOC(_IOC_NONE,'p',0x0c,0),
	},
	{
		.name = "RTC_EPOCH_READ",
		_IOC(_IOC_NONE,'p',0x0d,0),
	},
	{
		.name = "RTC_EPOCH_SET",
		_IOC(_IOC_NONE,'p',0x0e,0),
	},
	{
		.name = "RTC_WKALM_SET",
		_IOC(_IOC_NONE,'p',0x0f,0),
	},
	{
		.name = "RTC_WKALM_RD",
		_IOC(_IOC_NONE,'p',0x10,0),
	},
	{
		.name = "RTC_PLL_GET",
		_IOC(_IOC_NONE,'p',0x11,0),
	},
	{
		.name = "RTC_PLL_SET",
		_IOC(_IOC_NONE,'p',0x12,0),
	},
	{
		.name = "SPIOCSTYPE",
		_IOC(_IOC_NONE,'q',0x01,0),
	},
	{
		.name = "SONET_GETSTAT",
		_IOC(_IOC_NONE,'a',ATMIOC_PHYTYP,0),
	},
	{
		.name = "SONET_GETSTATZ",
		_IOC(_IOC_NONE,'a',ATMIOC_PHYTYP+1,0),
	},
	{
		.name = "SONET_SETDIAG",
		_IOC(_IOC_NONE,'a',ATMIOC_PHYTYP+2,0),
	},
	{
		.name = "SONET_CLRDIAG",
		_IOC(_IOC_NONE,'a',ATMIOC_PHYTYP+3,0),
	},
	{
		.name = "SONET_GETDIAG",
		_IOC(_IOC_NONE,'a',ATMIOC_PHYTYP+4,0),
	},
	{
		.name = "SONET_SETFRAMING",
		_IOC(_IOC_NONE,'a',ATMIOC_PHYTYP+5,0),
	},
	{
		.name = "SONET_GETFRAMING",
		_IOC(_IOC_NONE,'a',ATMIOC_PHYTYP+6,0),
	},
	{
		.name = "SONET_GETFRSENSE",
		_IOC(_IOC_NONE,'a',ATMIOC_PHYTYP+7,0),
	},
	{
		.name = "SONYPI_IOCGBRT",
		_IOC(_IOC_NONE,'v',0,0),
	},
	{
		.name = "SONYPI_IOCSBRT",
		_IOC(_IOC_NONE,'v',0,0),
	},
	{
		.name = "SONYPI_IOCGBAT1CAP",
		_IOC(_IOC_NONE,'v',2,0),
	},
	{
		.name = "SONYPI_IOCGBAT1REM",
		_IOC(_IOC_NONE,'v',3,0),
	},
	{
		.name = "SONYPI_IOCGBAT2CAP",
		_IOC(_IOC_NONE,'v',4,0),
	},
	{
		.name = "SONYPI_IOCGBAT2REM",
		_IOC(_IOC_NONE,'v',5,0),
	},
	{
		.name = "SONYPI_IOCGBATFLAGS",
		_IOC(_IOC_NONE,'v',7,0),
	},
	{
		.name = "SONYPI_IOCGBLUE",
		_IOC(_IOC_NONE,'v',8,0),
	},
	{
		.name = "SONYPI_IOCSBLUE",
		_IOC(_IOC_NONE,'v',9,0),
	},
	{
		.name = "SONYPI_IOCGFAN",
		_IOC(_IOC_NONE,'v',10,0),
	},
	{
		.name = "SONYPI_IOCSFAN",
		_IOC(_IOC_NONE,'v',11,0),
	},
	{
		.name = "SONYPI_IOCGTEMP",
		_IOC(_IOC_NONE,'v',12,0),
	},
	{
		.name = "SNDCTL_SEQ_RESET",
		_IOC(_IOC_NONE,'Q',0,0),
	},
	{
		.name = "SNDCTL_SEQ_SYNC",
		_IOC(_IOC_NONE,'Q',1,0),
	},
	{
		.name = "SNDCTL_SYNTH_INFO",
		_IOC(_IOC_NONE,'Q',2,0),
	},
	{
		.name = "SNDCTL_SEQ_CTRLRATE",
		_IOC(_IOC_NONE,'Q',3,0),
	},
	{
		.name = "SNDCTL_SEQ_GETOUTCOUNT",
		_IOC(_IOC_NONE,'Q',4,0),
	},
	{
		.name = "SNDCTL_SEQ_GETINCOUNT",
		_IOC(_IOC_NONE,'Q',5,0),
	},
	{
		.name = "SNDCTL_SEQ_PERCMODE",
		_IOC(_IOC_NONE,'Q',6,0),
	},
	{
		.name = "SNDCTL_FM_LOAD_INSTR",
		_IOC(_IOC_NONE,'Q',7,0),
	},
	{
		.name = "SNDCTL_SEQ_TESTMIDI",
		_IOC(_IOC_NONE,'Q',8,0),
	},
	{
		.name = "SNDCTL_SEQ_RESETSAMPLES",
		_IOC(_IOC_NONE,'Q',9,0),
	},
	{
		.name = "SNDCTL_SEQ_NRSYNTHS",
		_IOC(_IOC_NONE,'Q',10,0),
	},
	{
		.name = "SNDCTL_SEQ_NRMIDIS",
		_IOC(_IOC_NONE,'Q',11,0),
	},
	{
		.name = "SNDCTL_MIDI_INFO",
		_IOC(_IOC_NONE,'Q',12,0),
	},
	{
		.name = "SNDCTL_SEQ_THRESHOLD",
		_IOC(_IOC_NONE,'Q',13,0),
	},
	{
		.name = "SNDCTL_SYNTH_MEMAVL",
		_IOC(_IOC_NONE,'Q',14,0),
	},
	{
		.name = "SNDCTL_FM_4OP_ENABLE",
		_IOC(_IOC_NONE,'Q',15,0),
	},
	{
		.name = "SNDCTL_SEQ_PANIC",
		_IOC(_IOC_NONE,'Q',17,0),
	},
	{
		.name = "SNDCTL_SEQ_OUTOFBAND",
		_IOC(_IOC_NONE,'Q',18,0),
	},
	{
		.name = "SNDCTL_SEQ_GETTIME",
		_IOC(_IOC_NONE,'Q',19,0),
	},
	{
		.name = "SNDCTL_SYNTH_ID",
		_IOC(_IOC_NONE,'Q',20,0),
	},
	{
		.name = "SNDCTL_SYNTH_CONTROL",
		_IOC(_IOC_NONE,'Q',21,0),
	},
	{
		.name = "SNDCTL_SYNTH_REMOVESAMPLE",
		_IOC(_IOC_NONE,'Q',22,0),
	},
	{
		.name = "SNDCTL_TMR_TIMEBASE",
		_IOC(_IOC_NONE,'T',1,0),
	},
	{
		.name = "SNDCTL_TMR_START",
		_IOC(_IOC_NONE,'T',2,0),
	},
	{
		.name = "SNDCTL_TMR_STOP",
		_IOC(_IOC_NONE,'T',3,0),
	},
	{
		.name = "SNDCTL_TMR_CONTINUE",
		_IOC(_IOC_NONE,'T',4,0),
	},
	{
		.name = "SNDCTL_TMR_TEMPO",
		_IOC(_IOC_NONE,'T',5,0),
	},
	{
		.name = "SNDCTL_TMR_SOURCE",
		_IOC(_IOC_NONE,'T',6,0),
	},
	{
		.name = "SNDCTL_TMR_METRONOME",
		_IOC(_IOC_NONE,'T',7,0),
	},
	{
		.name = "SNDCTL_TMR_SELECT",
		_IOC(_IOC_NONE,'T',8,0),
	},
	{
		.name = "SNDCTL_MIDI_PRETIME",
		_IOC(_IOC_NONE,'m',0,0),
	},
	{
		.name = "SNDCTL_MIDI_MPUMODE",
		_IOC(_IOC_NONE,'m',1,0),
	},
	{
		.name = "SNDCTL_MIDI_MPUCMD",
		_IOC(_IOC_NONE,'m',2,0),
	},
	{
		.name = "SNDCTL_DSP_RESET",
		_IOC(_IOC_NONE,'P',0,0),
	},
	{
		.name = "SNDCTL_DSP_SYNC",
		_IOC(_IOC_NONE,'P',1,0),
	},
	{
		.name = "SNDCTL_DSP_SPEED",
		_IOC(_IOC_NONE,'P',2,0),
	},
	{
		.name = "SNDCTL_DSP_STEREO",
		_IOC(_IOC_NONE,'P',3,0),
	},
	{
		.name = "SNDCTL_DSP_GETBLKSIZE",
		_IOC(_IOC_NONE,'P',4,0),
	},
	{
		.name = "SNDCTL_DSP_CHANNELS",
		_IOC(_IOC_NONE,'P',6,0),
	},
	{
		.name = "SOUND_PCM_WRITE_FILTER",
		_IOC(_IOC_NONE,'P',7,0),
	},
	{
		.name = "SNDCTL_DSP_POST",
		_IOC(_IOC_NONE,'P',8,0),
	},
	{
		.name = "SNDCTL_DSP_SUBDIVIDE",
		_IOC(_IOC_NONE,'P',9,0),
	},
	{
		.name = "SNDCTL_DSP_SETFRAGMENT",
		_IOC(_IOC_NONE,'P',10,0),
	},
	{
		.name = "SNDCTL_DSP_GETFMTS",
		_IOC(_IOC_NONE,'P',11,0),
	},
	{
		.name = "SNDCTL_DSP_SETFMT",
		_IOC(_IOC_NONE,'P',5,0),
	},
	{
		.name = "SNDCTL_DSP_GETOSPACE",
		_IOC(_IOC_NONE,'P',12,0),
	},
	{
		.name = "SNDCTL_DSP_GETISPACE",
		_IOC(_IOC_NONE,'P',13,0),
	},
	{
		.name = "SNDCTL_DSP_NONBLOCK",
		_IOC(_IOC_NONE,'P',14,0),
	},
	{
		.name = "SNDCTL_DSP_GETCAPS",
		_IOC(_IOC_NONE,'P',15,0),
	},
	{
		.name = "SNDCTL_DSP_GETTRIGGER",
		_IOC(_IOC_NONE,'P',16,0),
	},
	{
		.name = "SNDCTL_DSP_SETTRIGGER",
		_IOC(_IOC_NONE,'P',16,0),
	},
	{
		.name = "SNDCTL_DSP_GETIPTR",
		_IOC(_IOC_NONE,'P',17,0),
	},
	{
		.name = "SNDCTL_DSP_GETOPTR",
		_IOC(_IOC_NONE,'P',18,0),
	},
	{
		.name = "SNDCTL_DSP_MAPINBUF",
		_IOC(_IOC_NONE,'P',19,0),
	},
	{
		.name = "SNDCTL_DSP_MAPOUTBUF",
		_IOC(_IOC_NONE,'P',20,0),
	},
	{
		.name = "SNDCTL_DSP_SETSYNCRO",
		_IOC(_IOC_NONE,'P',21,0),
	},
	{
		.name = "SNDCTL_DSP_SETDUPLEX",
		_IOC(_IOC_NONE,'P',22,0),
	},
	{
		.name = "SNDCTL_DSP_GETODELAY",
		_IOC(_IOC_NONE,'P',23,0),
	},
	{
		.name = "SNDCTL_DSP_GETCHANNELMASK",
		_IOC(_IOC_NONE,'P',64,0),
	},
	{
		.name = "SNDCTL_DSP_BIND_CHANNEL",
		_IOC(_IOC_NONE,'P',65,0),
	},
	{
		.name = "SNDCTL_DSP_SETSPDIF",
		_IOC(_IOC_NONE,'P',66,0),
	},
	{
		.name = "SNDCTL_DSP_GETSPDIF",
		_IOC(_IOC_NONE,'P',67,0),
	},
	{
		.name = "SNDCTL_DSP_PROFILE",
		_IOC(_IOC_NONE,'P',23,0),
	},
	{
		.name = "SOUND_PCM_READ_RATE",
		_IOC(_IOC_NONE,'P',2,0),
	},
	{
		.name = "SOUND_PCM_READ_CHANNELS",
		_IOC(_IOC_NONE,'P',6,0),
	},
	{
		.name = "SOUND_PCM_READ_BITS",
		_IOC(_IOC_NONE,'P',5,0),
	},
	{
		.name = "SOUND_PCM_READ_FILTER",
		_IOC(_IOC_NONE,'P',7,0),
	},
	{
		.name = "SNDCTL_COPR_RESET",
		_IOC(_IOC_NONE,'C',0,0),
	},
	{
		.name = "SNDCTL_COPR_LOAD",
		_IOC(_IOC_NONE,'C',1,0),
	},
	{
		.name = "SNDCTL_COPR_RDATA",
		_IOC(_IOC_NONE,'C',2,0),
	},
	{
		.name = "SNDCTL_COPR_RCODE",
		_IOC(_IOC_NONE,'C',3,0),
	},
	{
		.name = "SNDCTL_COPR_WDATA",
		_IOC(_IOC_NONE,'C',4,0),
	},
	{
		.name = "SNDCTL_COPR_WCODE",
		_IOC(_IOC_NONE,'C',5,0),
	},
	{
		.name = "SNDCTL_COPR_RUN",
		_IOC(_IOC_NONE,'C',6,0),
	},
	{
		.name = "SNDCTL_COPR_HALT",
		_IOC(_IOC_NONE,'C',7,0),
	},
	{
		.name = "SNDCTL_COPR_SENDMSG",
		_IOC(_IOC_NONE,'C',8,0),
	},
	{
		.name = "SNDCTL_COPR_RCVMSG",
		_IOC(_IOC_NONE,'C',9,0),
	},
	{
		.name = "SOUND_MIXER_INFO",
		_IOC(_IOC_NONE,'M',101,0),
	},
	{
		.name = "SOUND_OLD_MIXER_INFO",
		_IOC(_IOC_NONE,'M',101,0),
	},
	{
		.name = "SOUND_MIXER_ACCESS",
		_IOC(_IOC_NONE,'M',102,0),
	},
	{
		.name = "SOUND_MIXER_AGC",
		_IOC(_IOC_NONE,'M',103,0),
	},
	{
		.name = "SOUND_MIXER_3DSE",
		_IOC(_IOC_NONE,'M',104,0),
	},
	{
		.name = "SOUND_MIXER_PRIVATE1",
		_IOC(_IOC_NONE,'M',111,0),
	},
	{
		.name = "SOUND_MIXER_PRIVATE2",
		_IOC(_IOC_NONE,'M',112,0),
	},
	{
		.name = "SOUND_MIXER_PRIVATE3",
		_IOC(_IOC_NONE,'M',113,0),
	},
	{
		.name = "SOUND_MIXER_PRIVATE4",
		_IOC(_IOC_NONE,'M',114,0),
	},
	{
		.name = "SOUND_MIXER_PRIVATE5",
		_IOC(_IOC_NONE,'M',115,0),
	},
	{
		.name = "SOUND_MIXER_GETLEVELS",
		_IOC(_IOC_NONE,'M',116,0),
	},
	{
		.name = "SOUND_MIXER_SETLEVELS",
		_IOC(_IOC_NONE,'M',117,0),
	},
	{
		.name = "OSS_GETVERSION",
		_IOC(_IOC_NONE,'M',118,0),
	},
	{
		.name = "SNAPSHOT_FREEZE",
		_IOC(_IOC_NONE,SNAPSHOT_IOC_MAGIC,1,0),
	},
	{
		.name = "SNAPSHOT_UNFREEZE",
		_IOC(_IOC_NONE,SNAPSHOT_IOC_MAGIC,2,0),
	},
	{
		.name = "SNAPSHOT_ATOMIC_RESTORE",
		_IOC(_IOC_NONE,SNAPSHOT_IOC_MAGIC,4,0),
	},
	{
		.name = "SNAPSHOT_FREE",
		_IOC(_IOC_NONE,SNAPSHOT_IOC_MAGIC,5,0),
	},
	{
		.name = "SNAPSHOT_FREE_SWAP_PAGES",
		_IOC(_IOC_NONE,SNAPSHOT_IOC_MAGIC,9,0),
	},
	{
		.name = "SNAPSHOT_S2RAM",
		_IOC(_IOC_NONE,SNAPSHOT_IOC_MAGIC,11,0),
	},
	{
		.name = "SNAPSHOT_SET_SWAP_AREA",
		_IOC(_IOC_NONE,SNAPSHOT_IOC_MAGIC,13,0),
	},
	{
		.name = "SNAPSHOT_GET_IMAGE_SIZE",
		_IOC(_IOC_NONE,SNAPSHOT_IOC_MAGIC,14,0),
	},
	{
		.name = "SNAPSHOT_PLATFORM_SUPPORT",
		_IOC(_IOC_NONE,SNAPSHOT_IOC_MAGIC,15,0),
	},
	{
		.name = "SNAPSHOT_POWER_OFF",
		_IOC(_IOC_NONE,SNAPSHOT_IOC_MAGIC,16,0),
	},
	{
		.name = "SNAPSHOT_CREATE_IMAGE",
		_IOC(_IOC_NONE,SNAPSHOT_IOC_MAGIC,17,0),
	},
	{
		.name = "SNAPSHOT_PREF_IMAGE_SIZE",
		_IOC(_IOC_NONE,SNAPSHOT_IOC_MAGIC,18,0),
	},
	{
		.name = "SNAPSHOT_AVAIL_SWAP_SIZE",
		_IOC(_IOC_NONE,SNAPSHOT_IOC_MAGIC,19,0),
	},
	{
		.name = "SNAPSHOT_ALLOC_SWAP_PAGE",
		_IOC(_IOC_NONE,SNAPSHOT_IOC_MAGIC,20,0),
	},
	{
		.name = "MGSL_IOCSPARAMS",
		_IOC(_IOC_NONE,MGSL_MAGIC_IOC,0,0),
	},
	{
		.name = "MGSL_IOCGPARAMS",
		_IOC(_IOC_NONE,MGSL_MAGIC_IOC,1,0),
	},
	{
		.name = "MGSL_IOCSTXIDLE",
		_IOC(_IOC_NONE,MGSL_MAGIC_IOC,2,0),
	},
	{
		.name = "MGSL_IOCGTXIDLE",
		_IOC(_IOC_NONE,MGSL_MAGIC_IOC,3,0),
	},
	{
		.name = "MGSL_IOCTXENABLE",
		_IOC(_IOC_NONE,MGSL_MAGIC_IOC,4,0),
	},
	{
		.name = "MGSL_IOCRXENABLE",
		_IOC(_IOC_NONE,MGSL_MAGIC_IOC,5,0),
	},
	{
		.name = "MGSL_IOCTXABORT",
		_IOC(_IOC_NONE,MGSL_MAGIC_IOC,6,0),
	},
	{
		.name = "MGSL_IOCGSTATS",
		_IOC(_IOC_NONE,MGSL_MAGIC_IOC,7,0),
	},
	{
		.name = "MGSL_IOCWAITEVENT",
		_IOC(_IOC_NONE,MGSL_MAGIC_IOC,8,0),
	},
	{
		.name = "MGSL_IOCCLRMODCOUNT",
		_IOC(_IOC_NONE,MGSL_MAGIC_IOC,15,0),
	},
	{
		.name = "MGSL_IOCLOOPTXDONE",
		_IOC(_IOC_NONE,MGSL_MAGIC_IOC,9,0),
	},
	{
		.name = "MGSL_IOCSIF",
		_IOC(_IOC_NONE,MGSL_MAGIC_IOC,10,0),
	},
	{
		.name = "MGSL_IOCGIF",
		_IOC(_IOC_NONE,MGSL_MAGIC_IOC,11,0),
	},
	{
		.name = "MGSL_IOCSGPIO",
		_IOC(_IOC_NONE,MGSL_MAGIC_IOC,16,0),
	},
	{
		.name = "MGSL_IOCGGPIO",
		_IOC(_IOC_NONE,MGSL_MAGIC_IOC,17,0),
	},
	{
		.name = "MGSL_IOCWAITGPIO",
		_IOC(_IOC_NONE,MGSL_MAGIC_IOC,18,0),
	},
	{
		.name = "MGSL_IOCSXSYNC",
		_IOC(_IOC_NONE,MGSL_MAGIC_IOC,19,0),
	},
	{
		.name = "MGSL_IOCGXSYNC",
		_IOC(_IOC_NONE,MGSL_MAGIC_IOC,20,0),
	},
	{
		.name = "MGSL_IOCSXCTRL",
		_IOC(_IOC_NONE,MGSL_MAGIC_IOC,21,0),
	},
	{
		.name = "MGSL_IOCGXCTRL",
		_IOC(_IOC_NONE,MGSL_MAGIC_IOC,22,0),
	},
	{
		.name = "MGSL_IOCSPARAMS32",
		_IOC(_IOC_NONE,MGSL_MAGIC_IOC,0,0),
	},
	{
		.name = "MGSL_IOCGPARAMS32",
		_IOC(_IOC_NONE,MGSL_MAGIC_IOC,1,0),
	},
	{
		.name = "PHONE_CAPABILITIES",
		_IOC(_IOC_NONE,'q',0x80,0),
	},
	{
		.name = "PHONE_CAPABILITIES_LIST",
		_IOC(_IOC_NONE,'q',0x81,0),
	},
	{
		.name = "PHONE_CAPABILITIES_CHECK",
		_IOC(_IOC_NONE,'q',0x82,0),
	},
	{
		.name = "PHONE_RING",
		_IOC(_IOC_NONE,'q',0x83,0),
	},
	{
		.name = "PHONE_HOOKSTATE",
		_IOC(_IOC_NONE,'q',0x84,0),
	},
	{
		.name = "PHONE_MAXRINGS",
		_IOC(_IOC_NONE,'q',0x85,0),
	},
	{
		.name = "PHONE_RING_CADENCE",
		_IOC(_IOC_NONE,'q',0x86,0),
	},
	{
		.name = "OLD_PHONE_RING_START",
		_IOC(_IOC_NONE,'q',0x87,0),
	},
	{
		.name = "PHONE_RING_START",
		_IOC(_IOC_NONE,'q',0x87,0),
	},
	{
		.name = "PHONE_RING_STOP",
		_IOC(_IOC_NONE,'q',0x88,0),
	},
	{
		.name = "PHONE_REC_CODEC",
		_IOC(_IOC_NONE,'q',0x89,0),
	},
	{
		.name = "PHONE_REC_START",
		_IOC(_IOC_NONE,'q',0x8A,0),
	},
	{
		.name = "PHONE_REC_STOP",
		_IOC(_IOC_NONE,'q',0x8B,0),
	},
	{
		.name = "PHONE_REC_DEPTH",
		_IOC(_IOC_NONE,'q',0x8C,0),
	},
	{
		.name = "PHONE_FRAME",
		_IOC(_IOC_NONE,'q',0x8D,0),
	},
	{
		.name = "PHONE_REC_VOLUME",
		_IOC(_IOC_NONE,'q',0x8E,0),
	},
	{
		.name = "PHONE_REC_VOLUME_LINEAR",
		_IOC(_IOC_NONE,'q',0xDB,0),
	},
	{
		.name = "PHONE_REC_LEVEL",
		_IOC(_IOC_NONE,'q',0x8F,0),
	},
	{
		.name = "PHONE_PLAY_CODEC",
		_IOC(_IOC_NONE,'q',0x90,0),
	},
	{
		.name = "PHONE_PLAY_START",
		_IOC(_IOC_NONE,'q',0x91,0),
	},
	{
		.name = "PHONE_PLAY_STOP",
		_IOC(_IOC_NONE,'q',0x92,0),
	},
	{
		.name = "PHONE_PLAY_DEPTH",
		_IOC(_IOC_NONE,'q',0x93,0),
	},
	{
		.name = "PHONE_PLAY_VOLUME",
		_IOC(_IOC_NONE,'q',0x94,0),
	},
	{
		.name = "PHONE_PLAY_VOLUME_LINEAR",
		_IOC(_IOC_NONE,'q',0xDC,0),
	},
	{
		.name = "PHONE_PLAY_LEVEL",
		_IOC(_IOC_NONE,'q',0x95,0),
	},
	{
		.name = "PHONE_DTMF_READY",
		_IOC(_IOC_NONE,'q',0x96,0),
	},
	{
		.name = "PHONE_GET_DTMF",
		_IOC(_IOC_NONE,'q',0x97,0),
	},
	{
		.name = "PHONE_GET_DTMF_ASCII",
		_IOC(_IOC_NONE,'q',0x98,0),
	},
	{
		.name = "PHONE_DTMF_OOB",
		_IOC(_IOC_NONE,'q',0x99,0),
	},
	{
		.name = "PHONE_EXCEPTION",
		_IOC(_IOC_NONE,'q',0x9A,0),
	},
	{
		.name = "PHONE_PLAY_TONE",
		_IOC(_IOC_NONE,'q',0x9B,0),
	},
	{
		.name = "PHONE_SET_TONE_ON_TIME",
		_IOC(_IOC_NONE,'q',0x9C,0),
	},
	{
		.name = "PHONE_SET_TONE_OFF_TIME",
		_IOC(_IOC_NONE,'q',0x9D,0),
	},
	{
		.name = "PHONE_GET_TONE_ON_TIME",
		_IOC(_IOC_NONE,'q',0x9E,0),
	},
	{
		.name = "PHONE_GET_TONE_OFF_TIME",
		_IOC(_IOC_NONE,'q',0x9F,0),
	},
	{
		.name = "PHONE_GET_TONE_STATE",
		_IOC(_IOC_NONE,'q',0xA0,0),
	},
	{
		.name = "PHONE_BUSY",
		_IOC(_IOC_NONE,'q',0xA1,0),
	},
	{
		.name = "PHONE_RINGBACK",
		_IOC(_IOC_NONE,'q',0xA2,0),
	},
	{
		.name = "PHONE_DIALTONE",
		_IOC(_IOC_NONE,'q',0xA3,0),
	},
	{
		.name = "PHONE_CPT_STOP",
		_IOC(_IOC_NONE,'q',0xA4,0),
	},
	{
		.name = "PHONE_PSTN_SET_STATE",
		_IOC(_IOC_NONE,'q',0xA4,0),
	},
	{
		.name = "PHONE_PSTN_GET_STATE",
		_IOC(_IOC_NONE,'q',0xA5,0),
	},
	{
		.name = "PHONE_WINK_DURATION",
		_IOC(_IOC_NONE,'q',0xA6,0),
	},
	{
		.name = "PHONE_WINK",
		_IOC(_IOC_NONE,'q',0xAA,0),
	},
	{
		.name = "PHONE_QUERY_CODEC",
		_IOC(_IOC_NONE,'q',0xA7,0),
	},
	{
		.name = "PHONE_PSTN_LINETEST",
		_IOC(_IOC_NONE,'q',0xA8,0),
	},
	{
		.name = "PHONE_VAD",
		_IOC(_IOC_NONE,'q',0xA9,0),
	},
	{
		.name = "TOSH_SMM",
		_IOC(_IOC_NONE,'t',0x90,0),
	},
	{
		.name = "UDF_GETEASIZE",
		_IOC(_IOC_NONE,'l',0x40,0),
	},
	{
		.name = "UDF_GETEABLOCK",
		_IOC(_IOC_NONE,'l',0x41,0),
	},
	{
		.name = "UDF_GETVOLIDENT",
		_IOC(_IOC_NONE,'l',0x42,0),
	},
	{
		.name = "UDF_RELOCATE_BLOCKS",
		_IOC(_IOC_NONE,'l',0x43,0),
	},
	{
		.name = "UI_DEV_CREATE",
		_IOC(_IOC_NONE,UINPUT_IOCTL_BASE,1,0),
	},
	{
		.name = "UI_DEV_DESTROY",
		_IOC(_IOC_NONE,UINPUT_IOCTL_BASE,2,0),
	},
	{
		.name = "UI_SET_EVBIT",
		_IOC(_IOC_NONE,UINPUT_IOCTL_BASE,100,0),
	},
	{
		.name = "UI_SET_KEYBIT",
		_IOC(_IOC_NONE,UINPUT_IOCTL_BASE,101,0),
	},
	{
		.name = "UI_SET_RELBIT",
		_IOC(_IOC_NONE,UINPUT_IOCTL_BASE,102,0),
	},
	{
		.name = "UI_SET_ABSBIT",
		_IOC(_IOC_NONE,UINPUT_IOCTL_BASE,103,0),
	},
	{
		.name = "UI_SET_MSCBIT",
		_IOC(_IOC_NONE,UINPUT_IOCTL_BASE,104,0),
	},
	{
		.name = "UI_SET_LEDBIT",
		_IOC(_IOC_NONE,UINPUT_IOCTL_BASE,105,0),
	},
	{
		.name = "UI_SET_SNDBIT",
		_IOC(_IOC_NONE,UINPUT_IOCTL_BASE,106,0),
	},
	{
		.name = "UI_SET_FFBIT",
		_IOC(_IOC_NONE,UINPUT_IOCTL_BASE,107,0),
	},
	{
		.name = "UI_SET_PHYS",
		_IOC(_IOC_NONE,UINPUT_IOCTL_BASE,108,0),
	},
	{
		.name = "UI_SET_SWBIT",
		_IOC(_IOC_NONE,UINPUT_IOCTL_BASE,109,0),
	},
	{
		.name = "UI_BEGIN_FF_UPLOAD",
		_IOC(_IOC_NONE,UINPUT_IOCTL_BASE,200,0),
	},
	{
		.name = "UI_END_FF_UPLOAD",
		_IOC(_IOC_NONE,UINPUT_IOCTL_BASE,201,0),
	},
	{
		.name = "UI_BEGIN_FF_ERASE",
		_IOC(_IOC_NONE,UINPUT_IOCTL_BASE,202,0),
	},
	{
		.name = "UI_END_FF_ERASE",
		_IOC(_IOC_NONE,UINPUT_IOCTL_BASE,203,0),
	},
	{
		.name = "USBDEVFS_CONTROL",
		_IOC(_IOC_NONE,'U',0,0),
	},
	{
		.name = "USBDEVFS_CONTROL32",
		_IOC(_IOC_NONE,'U',0,0),
	},
	{
		.name = "USBDEVFS_BULK",
		_IOC(_IOC_NONE,'U',2,0),
	},
	{
		.name = "USBDEVFS_BULK32",
		_IOC(_IOC_NONE,'U',2,0),
	},
	{
		.name = "USBDEVFS_RESETEP",
		_IOC(_IOC_NONE,'U',3,0),
	},
	{
		.name = "USBDEVFS_SETINTERFACE",
		_IOC(_IOC_NONE,'U',4,0),
	},
	{
		.name = "USBDEVFS_SETCONFIGURATION",
		_IOC(_IOC_NONE,'U',5,0),
	},
	{
		.name = "USBDEVFS_GETDRIVER",
		_IOC(_IOC_NONE,'U',8,0),
	},
	{
		.name = "USBDEVFS_SUBMITURB",
		_IOC(_IOC_NONE,'U',10,0),
	},
	{
		.name = "USBDEVFS_SUBMITURB32",
		_IOC(_IOC_NONE,'U',10,0),
	},
	{
		.name = "USBDEVFS_DISCARDURB",
		_IOC(_IOC_NONE,'U',11,0),
	},
	{
		.name = "USBDEVFS_REAPURB",
		_IOC(_IOC_NONE,'U',12,0),
	},
	{
		.name = "USBDEVFS_REAPURB32",
		_IOC(_IOC_NONE,'U',12,0),
	},
	{
		.name = "USBDEVFS_REAPURBNDELAY",
		_IOC(_IOC_NONE,'U',13,0),
	},
	{
		.name = "USBDEVFS_REAPURBNDELAY32",
		_IOC(_IOC_NONE,'U',13,0),
	},
	{
		.name = "USBDEVFS_DISCSIGNAL",
		_IOC(_IOC_NONE,'U',14,0),
	},
	{
		.name = "USBDEVFS_DISCSIGNAL32",
		_IOC(_IOC_NONE,'U',14,0),
	},
	{
		.name = "USBDEVFS_CLAIMINTERFACE",
		_IOC(_IOC_NONE,'U',15,0),
	},
	{
		.name = "USBDEVFS_RELEASEINTERFACE",
		_IOC(_IOC_NONE,'U',16,0),
	},
	{
		.name = "USBDEVFS_CONNECTINFO",
		_IOC(_IOC_NONE,'U',17,0),
	},
	{
		.name = "USBDEVFS_IOCTL",
		_IOC(_IOC_NONE,'U',18,0),
	},
	{
		.name = "USBDEVFS_IOCTL32",
		_IOC(_IOC_NONE,'U',18,0),
	},
	{
		.name = "USBDEVFS_HUB_PORTINFO",
		_IOC(_IOC_NONE,'U',19,0),
	},
	{
		.name = "USBDEVFS_RESET",
		_IOC(_IOC_NONE,'U',20,0),
	},
	{
		.name = "USBDEVFS_CLEAR_HALT",
		_IOC(_IOC_NONE,'U',21,0),
	},
	{
		.name = "USBDEVFS_DISCONNECT",
		_IOC(_IOC_NONE,'U',22,0),
	},
	{
		.name = "USBDEVFS_CONNECT",
		_IOC(_IOC_NONE,'U',23,0),
	},
	{
		.name = "USBDEVFS_CLAIM_PORT",
		_IOC(_IOC_NONE,'U',24,0),
	},
	{
		.name = "USBDEVFS_RELEASE_PORT",
		_IOC(_IOC_NONE,'U',25,0),
	},
	{
		.name = "VHOST_GET_FEATURES",
		_IOC(_IOC_NONE,VHOST_VIRTIO,0x00,0),
	},
	{
		.name = "VHOST_SET_FEATURES",
		_IOC(_IOC_NONE,VHOST_VIRTIO,0x00,0),
	},
	{
		.name = "VHOST_SET_OWNER",
		_IOC(_IOC_NONE,VHOST_VIRTIO,0x01,0),
	},
	{
		.name = "VHOST_RESET_OWNER",
		_IOC(_IOC_NONE,VHOST_VIRTIO,0x02,0),
	},
	{
		.name = "VHOST_SET_MEM_TABLE",
		_IOC(_IOC_NONE,VHOST_VIRTIO,0x03,0),
	},
	{
		.name = "VHOST_SET_LOG_BASE",
		_IOC(_IOC_NONE,VHOST_VIRTIO,0x04,0),
	},
	{
		.name = "VHOST_SET_LOG_FD",
		_IOC(_IOC_NONE,VHOST_VIRTIO,0x07,0),
	},
	{
		.name = "VHOST_SET_VRING_NUM",
		_IOC(_IOC_NONE,VHOST_VIRTIO,0x10,0),
	},
	{
		.name = "VHOST_SET_VRING_ADDR",
		_IOC(_IOC_NONE,VHOST_VIRTIO,0x11,0),
	},
	{
		.name = "VHOST_SET_VRING_BASE",
		_IOC(_IOC_NONE,VHOST_VIRTIO,0x12,0),
	},
	{
		.name = "VHOST_GET_VRING_BASE",
		_IOC(_IOC_NONE,VHOST_VIRTIO,0x12,0),
	},
	{
		.name = "VHOST_SET_VRING_KICK",
		_IOC(_IOC_NONE,VHOST_VIRTIO,0x20,0),
	},
	{
		.name = "VHOST_SET_VRING_CALL",
		_IOC(_IOC_NONE,VHOST_VIRTIO,0x21,0),
	},
	{
		.name = "VHOST_SET_VRING_ERR",
		_IOC(_IOC_NONE,VHOST_VIRTIO,0x22,0),
	},
	{
		.name = "VHOST_NET_SET_BACKEND",
		_IOC(_IOC_NONE,VHOST_VIRTIO,0x30,0),
	},
	{
		.name = "VIDIOC_QUERYCAP",
		_IOC(_IOC_NONE,'V',0,0),
	},
	{
		.name = "VIDIOC_RESERVED",
		_IOC(_IOC_NONE,'V',1,0),
	},
	{
		.name = "VIDIOC_ENUM_FMT",
		_IOC(_IOC_NONE,'V',2,0),
	},
	{
		.name = "VIDIOC_G_FMT",
		_IOC(_IOC_NONE,'V',4,0),
	},
	{
		.name = "VIDIOC_S_FMT",
		_IOC(_IOC_NONE,'V',5,0),
	},
	{
		.name = "VIDIOC_REQBUFS",
		_IOC(_IOC_NONE,'V',8,0),
	},
	{
		.name = "VIDIOC_QUERYBUF",
		_IOC(_IOC_NONE,'V',9,0),
	},
	{
		.name = "VIDIOC_G_FBUF",
		_IOC(_IOC_NONE,'V',10,0),
	},
	{
		.name = "VIDIOC_S_FBUF",
		_IOC(_IOC_NONE,'V',11,0),
	},
	{
		.name = "VIDIOC_OVERLAY",
		_IOC(_IOC_NONE,'V',14,0),
	},
	{
		.name = "VIDIOC_QBUF",
		_IOC(_IOC_NONE,'V',15,0),
	},
	{
		.name = "VIDIOC_DQBUF",
		_IOC(_IOC_NONE,'V',17,0),
	},
	{
		.name = "VIDIOC_STREAMON",
		_IOC(_IOC_NONE,'V',18,0),
	},
	{
		.name = "VIDIOC_STREAMOFF",
		_IOC(_IOC_NONE,'V',19,0),
	},
	{
		.name = "VIDIOC_G_PARM",
		_IOC(_IOC_NONE,'V',21,0),
	},
	{
		.name = "VIDIOC_S_PARM",
		_IOC(_IOC_NONE,'V',22,0),
	},
	{
		.name = "VIDIOC_G_STD",
		_IOC(_IOC_NONE,'V',23,0),
	},
	{
		.name = "VIDIOC_S_STD",
		_IOC(_IOC_NONE,'V',24,0),
	},
	{
		.name = "VIDIOC_ENUMSTD",
		_IOC(_IOC_NONE,'V',25,0),
	},
	{
		.name = "VIDIOC_ENUMINPUT",
		_IOC(_IOC_NONE,'V',26,0),
	},
	{
		.name = "VIDIOC_G_CTRL",
		_IOC(_IOC_NONE,'V',27,0),
	},
	{
		.name = "VIDIOC_S_CTRL",
		_IOC(_IOC_NONE,'V',28,0),
	},
	{
		.name = "VIDIOC_G_TUNER",
		_IOC(_IOC_NONE,'V',29,0),
	},
	{
		.name = "VIDIOC_S_TUNER",
		_IOC(_IOC_NONE,'V',30,0),
	},
	{
		.name = "VIDIOC_G_AUDIO",
		_IOC(_IOC_NONE,'V',33,0),
	},
	{
		.name = "VIDIOC_S_AUDIO",
		_IOC(_IOC_NONE,'V',34,0),
	},
	{
		.name = "VIDIOC_QUERYCTRL",
		_IOC(_IOC_NONE,'V',36,0),
	},
	{
		.name = "VIDIOC_QUERYMENU",
		_IOC(_IOC_NONE,'V',37,0),
	},
	{
		.name = "VIDIOC_G_INPUT",
		_IOC(_IOC_NONE,'V',38,0),
	},
	{
		.name = "VIDIOC_S_INPUT",
		_IOC(_IOC_NONE,'V',39,0),
	},
	{
		.name = "VIDIOC_G_OUTPUT",
		_IOC(_IOC_NONE,'V',46,0),
	},
	{
		.name = "VIDIOC_S_OUTPUT",
		_IOC(_IOC_NONE,'V',47,0),
	},
	{
		.name = "VIDIOC_ENUMOUTPUT",
		_IOC(_IOC_NONE,'V',48,0),
	},
	{
		.name = "VIDIOC_G_AUDOUT",
		_IOC(_IOC_NONE,'V',49,0),
	},
	{
		.name = "VIDIOC_S_AUDOUT",
		_IOC(_IOC_NONE,'V',50,0),
	},
	{
		.name = "VIDIOC_G_MODULATOR",
		_IOC(_IOC_NONE,'V',54,0),
	},
	{
		.name = "VIDIOC_S_MODULATOR",
		_IOC(_IOC_NONE,'V',55,0),
	},
	{
		.name = "VIDIOC_G_FREQUENCY",
		_IOC(_IOC_NONE,'V',56,0),
	},
	{
		.name = "VIDIOC_S_FREQUENCY",
		_IOC(_IOC_NONE,'V',57,0),
	},
	{
		.name = "VIDIOC_CROPCAP",
		_IOC(_IOC_NONE,'V',58,0),
	},
	{
		.name = "VIDIOC_G_CROP",
		_IOC(_IOC_NONE,'V',59,0),
	},
	{
		.name = "VIDIOC_S_CROP",
		_IOC(_IOC_NONE,'V',60,0),
	},
	{
		.name = "VIDIOC_G_JPEGCOMP",
		_IOC(_IOC_NONE,'V',61,0),
	},
	{
		.name = "VIDIOC_S_JPEGCOMP",
		_IOC(_IOC_NONE,'V',62,0),
	},
	{
		.name = "VIDIOC_QUERYSTD",
		_IOC(_IOC_NONE,'V',63,0),
	},
	{
		.name = "VIDIOC_TRY_FMT",
		_IOC(_IOC_NONE,'V',64,0),
	},
	{
		.name = "VIDIOC_ENUMAUDIO",
		_IOC(_IOC_NONE,'V',65,0),
	},
	{
		.name = "VIDIOC_ENUMAUDOUT",
		_IOC(_IOC_NONE,'V',66,0),
	},
	{
		.name = "VIDIOC_G_PRIORITY",
		_IOC(_IOC_NONE,'V',67,0),
	},
	{
		.name = "VIDIOC_S_PRIORITY",
		_IOC(_IOC_NONE,'V',68,0),
	},
	{
		.name = "VIDIOC_G_SLICED_VBI_CAP",
		_IOC(_IOC_NONE,'V',69,0),
	},
	{
		.name = "VIDIOC_LOG_STATUS",
		_IOC(_IOC_NONE,'V',70,0),
	},
	{
		.name = "VIDIOC_G_EXT_CTRLS",
		_IOC(_IOC_NONE,'V',71,0),
	},
	{
		.name = "VIDIOC_S_EXT_CTRLS",
		_IOC(_IOC_NONE,'V',72,0),
	},
	{
		.name = "VIDIOC_TRY_EXT_CTRLS",
		_IOC(_IOC_NONE,'V',73,0),
	},
	{
		.name = "VIDIOC_ENUM_FRAMESIZES",
		_IOC(_IOC_NONE,'V',74,0),
	},
	{
		.name = "VIDIOC_ENUM_FRAMEINTERVALS",
		_IOC(_IOC_NONE,'V',75,0),
	},
	{
		.name = "VIDIOC_G_ENC_INDEX",
		_IOC(_IOC_NONE,'V',76,0),
	},
	{
		.name = "VIDIOC_ENCODER_CMD",
		_IOC(_IOC_NONE,'V',77,0),
	},
	{
		.name = "VIDIOC_TRY_ENCODER_CMD",
		_IOC(_IOC_NONE,'V',78,0),
	},
	{
		.name = "VIDIOC_DBG_S_REGISTER",
		_IOC(_IOC_NONE,'V',79,0),
	},
	{
		.name = "VIDIOC_DBG_G_REGISTER",
		_IOC(_IOC_NONE,'V',80,0),
	},
	{
		.name = "VIDIOC_DBG_G_CHIP_IDENT",
		_IOC(_IOC_NONE,'V',81,0),
	},
	{
		.name = "VIDIOC_S_HW_FREQ_SEEK",
		_IOC(_IOC_NONE,'V',82,0),
	},
	{
		.name = "VIDIOC_ENUM_DV_PRESETS",
		_IOC(_IOC_NONE,'V',83,0),
	},
	{
		.name = "VIDIOC_S_DV_PRESET",
		_IOC(_IOC_NONE,'V',84,0),
	},
	{
		.name = "VIDIOC_G_DV_PRESET",
		_IOC(_IOC_NONE,'V',85,0),
	},
	{
		.name = "VIDIOC_QUERY_DV_PRESET",
		_IOC(_IOC_NONE,'V',86,0),
	},
	{
		.name = "VIDIOC_S_DV_TIMINGS",
		_IOC(_IOC_NONE,'V',87,0),
	},
	{
		.name = "VIDIOC_G_DV_TIMINGS",
		_IOC(_IOC_NONE,'V',88,0),
	},
	{
		.name = "VIDIOC_DQEVENT",
		_IOC(_IOC_NONE,'V',89,0),
	},
	{
		.name = "VIDIOC_SUBSCRIBE_EVENT",
		_IOC(_IOC_NONE,'V',90,0),
	},
	{
		.name = "VIDIOC_UNSUBSCRIBE_EVENT",
		_IOC(_IOC_NONE,'V',91,0),
	},
	{
		.name = "VIDIOC_OVERLAY_OLD",
		_IOC(_IOC_NONE,'V',14,0),
	},
	{
		.name = "VIDIOC_S_PARM_OLD",
		_IOC(_IOC_NONE,'V',22,0),
	},
	{
		.name = "VIDIOC_S_CTRL_OLD",
		_IOC(_IOC_NONE,'V',28,0),
	},
	{
		.name = "VIDIOC_G_AUDIO_OLD",
		_IOC(_IOC_NONE,'V',33,0),
	},
	{
		.name = "VIDIOC_G_AUDOUT_OLD",
		_IOC(_IOC_NONE,'V',49,0),
	},
	{
		.name = "VIDIOC_CROPCAP_OLD",
		_IOC(_IOC_NONE,'V',58,0),
	},
	{
		.name = "VIDIOCGMBUF",
		_IOC(_IOC_NONE,'v',20,0),
	},
	{
		.name = "VIDIOCGCAP",
		_IOC(_IOC_NONE,'v',1,0),
	},
	{
		.name = "VIDIOCGCHAN",
		_IOC(_IOC_NONE,'v',2,0),
	},
	{
		.name = "VIDIOCSCHAN",
		_IOC(_IOC_NONE,'v',3,0),
	},
	{
		.name = "VIDIOCGTUNER",
		_IOC(_IOC_NONE,'v',4,0),
	},
	{
		.name = "VIDIOCSTUNER",
		_IOC(_IOC_NONE,'v',5,0),
	},
	{
		.name = "VIDIOCGPICT",
		_IOC(_IOC_NONE,'v',6,0),
	},
	{
		.name = "VIDIOCSPICT",
		_IOC(_IOC_NONE,'v',7,0),
	},
	{
		.name = "VIDIOCCAPTURE",
		_IOC(_IOC_NONE,'v',8,0),
	},
	{
		.name = "VIDIOCGWIN",
		_IOC(_IOC_NONE,'v',9,0),
	},
	{
		.name = "VIDIOCSWIN",
		_IOC(_IOC_NONE,'v',10,0),
	},
	{
		.name = "VIDIOCGFBUF",
		_IOC(_IOC_NONE,'v',11,0),
	},
	{
		.name = "VIDIOCSFBUF",
		_IOC(_IOC_NONE,'v',12,0),
	},
	{
		.name = "VIDIOCKEY",
		_IOC(_IOC_NONE,'v',13,0),
	},
	{
		.name = "VIDIOCGFREQ",
		_IOC(_IOC_NONE,'v',14,0),
	},
	{
		.name = "VIDIOCSFREQ",
		_IOC(_IOC_NONE,'v',15,0),
	},
	{
		.name = "VIDIOCGAUDIO",
		_IOC(_IOC_NONE,'v',16,0),
	},
	{
		.name = "VIDIOCSAUDIO",
		_IOC(_IOC_NONE,'v',17,0),
	},
	{
		.name = "VIDIOCSYNC",
		_IOC(_IOC_NONE,'v',18,0),
	},
	{
		.name = "VIDIOCMCAPTURE",
		_IOC(_IOC_NONE,'v',19,0),
	},
	{
		.name = "VIDIOCGMBUF",
		_IOC(_IOC_NONE,'v',20,0),
	},
	{
		.name = "VIDIOCGUNIT",
		_IOC(_IOC_NONE,'v',21,0),
	},
	{
		.name = "VIDIOCGCAPTURE",
		_IOC(_IOC_NONE,'v',22,0),
	},
	{
		.name = "VIDIOCSCAPTURE",
		_IOC(_IOC_NONE,'v',23,0),
	},
	{
		.name = "VIDIOCSPLAYMODE",
		_IOC(_IOC_NONE,'v',24,0),
	},
	{
		.name = "VIDIOCSWRITEMODE",
		_IOC(_IOC_NONE,'v',25,0),
	},
	{
		.name = "VIDIOCGPLAYINFO",
		_IOC(_IOC_NONE,'v',26,0),
	},
	{
		.name = "VIDIOCSMICROCODE",
		_IOC(_IOC_NONE,'v',27,0),
	},
	{
		.name = "VIDIOCGVBIFMT",
		_IOC(_IOC_NONE,'v',28,0),
	},
	{
		.name = "VIDIOCSVBIFMT",
		_IOC(_IOC_NONE,'v',29,0),
	},
	{
		.name = "WDIOC_GETSUPPORT",
		_IOC(_IOC_NONE,WATCHDOG_IOCTL_BASE,0,0),
	},
	{
		.name = "WDIOC_GETSTATUS",
		_IOC(_IOC_NONE,WATCHDOG_IOCTL_BASE,1,0),
	},
	{
		.name = "WDIOC_GETBOOTSTATUS",
		_IOC(_IOC_NONE,WATCHDOG_IOCTL_BASE,2,0),
	},
	{
		.name = "WDIOC_GETTEMP",
		_IOC(_IOC_NONE,WATCHDOG_IOCTL_BASE,3,0),
	},
	{
		.name = "WDIOC_SETOPTIONS",
		_IOC(_IOC_NONE,WATCHDOG_IOCTL_BASE,4,0),
	},
	{
		.name = "WDIOC_KEEPALIVE",
		_IOC(_IOC_NONE,WATCHDOG_IOCTL_BASE,5,0),
	},
	{
		.name = "WDIOC_SETTIMEOUT",
		_IOC(_IOC_NONE,WATCHDOG_IOCTL_BASE,6,0),
	},
	{
		.name = "WDIOC_GETTIMEOUT",
		_IOC(_IOC_NONE,WATCHDOG_IOCTL_BASE,7,0),
	},
	{
		.name = "WDIOC_SETPRETIMEOUT",
		_IOC(_IOC_NONE,WATCHDOG_IOCTL_BASE,8,0),
	},
	{
		.name = "WDIOC_GETPRETIMEOUT",
		_IOC(_IOC_NONE,WATCHDOG_IOCTL_BASE,9,0),
	},
	{
		.name = "WDIOC_GETTIMELEFT",
		_IOC(_IOC_NONE,WATCHDOG_IOCTL_BASE,10,0),
	},
	{
		.name = "AUDIO_STOP",
		_IOC(_IOC_NONE,'o',1,0),
	},
	{
		.name = "AUDIO_PLAY",
		_IOC(_IOC_NONE,'o',2,0),
	},
	{
		.name = "AUDIO_PAUSE",
		_IOC(_IOC_NONE,'o',3,0),
	},
	{
		.name = "AUDIO_CONTINUE",
		_IOC(_IOC_NONE,'o',4,0),
	},
	{
		.name = "AUDIO_SELECT_SOURCE",
		_IOC(_IOC_NONE,'o',5,0),
	},
	{
		.name = "AUDIO_SET_MUTE",
		_IOC(_IOC_NONE,'o',6,0),
	},
	{
		.name = "AUDIO_SET_AV_SYNC",
		_IOC(_IOC_NONE,'o',7,0),
	},
	{
		.name = "AUDIO_SET_BYPASS_MODE",
		_IOC(_IOC_NONE,'o',8,0),
	},
	{
		.name = "AUDIO_CHANNEL_SELECT",
		_IOC(_IOC_NONE,'o',9,0),
	},
	{
		.name = "AUDIO_GET_STATUS",
		_IOC(_IOC_NONE,'o',10,0),
	},
	{
		.name = "AUDIO_GET_CAPABILITIES",
		_IOC(_IOC_NONE,'o',11,0),
	},
	{
		.name = "AUDIO_CLEAR_BUFFER",
		_IOC(_IOC_NONE,'o',12,0),
	},
	{
		.name = "AUDIO_SET_ID",
		_IOC(_IOC_NONE,'o',13,0),
	},
	{
		.name = "AUDIO_SET_MIXER",
		_IOC(_IOC_NONE,'o',14,0),
	},
	{
		.name = "AUDIO_SET_STREAMTYPE",
		_IOC(_IOC_NONE,'o',15,0),
	},
	{
		.name = "AUDIO_SET_EXT_ID",
		_IOC(_IOC_NONE,'o',16,0),
	},
	{
		.name = "AUDIO_SET_ATTRIBUTES",
		_IOC(_IOC_NONE,'o',17,0),
	},
	{
		.name = "AUDIO_SET_KARAOKE",
		_IOC(_IOC_NONE,'o',18,0),
	},
	{
		.name = "AUDIO_GET_PTS",
		_IOC(_IOC_NONE,'o',19,0),
	},
	{
		.name = "AUDIO_BILINGUAL_CHANNEL_SELECT",
		_IOC(_IOC_NONE,'o',20,0),
	},
	{
		.name = "CA_RESET",
		_IOC(_IOC_NONE,'o',128,0),
	},
	{
		.name = "CA_GET_CAP",
		_IOC(_IOC_NONE,'o',129,0),
	},
	{
		.name = "CA_GET_SLOT_INFO",
		_IOC(_IOC_NONE,'o',130,0),
	},
	{
		.name = "CA_GET_DESCR_INFO",
		_IOC(_IOC_NONE,'o',131,0),
	},
	{
		.name = "CA_GET_MSG",
		_IOC(_IOC_NONE,'o',132,0),
	},
	{
		.name = "CA_SEND_MSG",
		_IOC(_IOC_NONE,'o',133,0),
	},
	{
		.name = "CA_SET_DESCR",
		_IOC(_IOC_NONE,'o',134,0),
	},
	{
		.name = "CA_SET_PID",
		_IOC(_IOC_NONE,'o',135,0),
	},
	{
		.name = "DMX_START",
		_IOC(_IOC_NONE,'o',41,0),
	},
	{
		.name = "DMX_STOP",
		_IOC(_IOC_NONE,'o',42,0),
	},
	{
		.name = "DMX_SET_FILTER",
		_IOC(_IOC_NONE,'o',43,0),
	},
	{
		.name = "DMX_SET_PES_FILTER",
		_IOC(_IOC_NONE,'o',44,0),
	},
	{
		.name = "DMX_SET_BUFFER_SIZE",
		_IOC(_IOC_NONE,'o',45,0),
	},
	{
		.name = "DMX_GET_PES_PIDS",
		_IOC(_IOC_NONE,'o',47,0),
	},
	{
		.name = "DMX_GET_CAPS",
		_IOC(_IOC_NONE,'o',48,0),
	},
	{
		.name = "DMX_SET_SOURCE",
		_IOC(_IOC_NONE,'o',49,0),
	},
	{
		.name = "DMX_GET_STC",
		_IOC(_IOC_NONE,'o',50,0),
	},
	{
		.name = "DMX_ADD_PID",
		_IOC(_IOC_NONE,'o',51,0),
	},
	{
		.name = "DMX_REMOVE_PID",
		_IOC(_IOC_NONE,'o',52,0),
	},
	{
		.name = "FE_SET_PROPERTY",
		_IOC(_IOC_NONE,'o',82,0),
	},
	{
		.name = "FE_GET_PROPERTY",
		_IOC(_IOC_NONE,'o',83,0),
	},
	{
		.name = "FE_GET_INFO",
		_IOC(_IOC_NONE,'o',61,0),
	},
	{
		.name = "FE_DISEQC_RESET_OVERLOAD",
		_IOC(_IOC_NONE,'o',62,0),
	},
	{
		.name = "FE_DISEQC_SEND_MASTER_CMD",
		_IOC(_IOC_NONE,'o',63,0),
	},
	{
		.name = "FE_DISEQC_RECV_SLAVE_REPLY",
		_IOC(_IOC_NONE,'o',64,0),
	},
	{
		.name = "FE_DISEQC_SEND_BURST",
		_IOC(_IOC_NONE,'o',65,0),
	},
	{
		.name = "FE_SET_TONE",
		_IOC(_IOC_NONE,'o',66,0),
	},
	{
		.name = "FE_SET_VOLTAGE",
		_IOC(_IOC_NONE,'o',67,0),
	},
	{
		.name = "FE_ENABLE_HIGH_LNB_VOLTAGE",
		_IOC(_IOC_NONE,'o',68,0),
	},
	{
		.name = "FE_READ_STATUS",
		_IOC(_IOC_NONE,'o',69,0),
	},
	{
		.name = "FE_READ_BER",
		_IOC(_IOC_NONE,'o',70,0),
	},
	{
		.name = "FE_READ_SIGNAL_STRENGTH",
		_IOC(_IOC_NONE,'o',71,0),
	},
	{
		.name = "FE_READ_SNR",
		_IOC(_IOC_NONE,'o',72,0),
	},
	{
		.name = "FE_READ_UNCORRECTED_BLOCKS",
		_IOC(_IOC_NONE,'o',73,0),
	},
	{
		.name = "FE_SET_FRONTEND",
		_IOC(_IOC_NONE,'o',76,0),
	},
	{
		.name = "FE_GET_FRONTEND",
		_IOC(_IOC_NONE,'o',77,0),
	},
	{
		.name = "FE_SET_FRONTEND_TUNE_MODE",
		_IOC(_IOC_NONE,'o',81,0),
	},
	{
		.name = "FE_GET_EVENT",
		_IOC(_IOC_NONE,'o',78,0),
	},
	{
		.name = "FE_DISHNETWORK_SEND_LEGACY_CMD",
		_IOC(_IOC_NONE,'o',80,0),
	},
	{
		.name = "NET_ADD_IF",
		_IOC(_IOC_NONE,'o',52,0),
	},
	{
		.name = "NET_REMOVE_IF",
		_IOC(_IOC_NONE,'o',53,0),
	},
	{
		.name = "NET_GET_IF",
		_IOC(_IOC_NONE,'o',54,0),
	},
	{
		.name = "OSD_SEND_CMD",
		_IOC(_IOC_NONE,'o',160,0),
	},
	{
		.name = "OSD_GET_CAPABILITY",
		_IOC(_IOC_NONE,'o',161,0),
	},
	{
		.name = "VIDEO_STOP",
		_IOC(_IOC_NONE,'o',21,0),
	},
	{
		.name = "VIDEO_PLAY",
		_IOC(_IOC_NONE,'o',22,0),
	},
	{
		.name = "VIDEO_FREEZE",
		_IOC(_IOC_NONE,'o',23,0),
	},
	{
		.name = "VIDEO_CONTINUE",
		_IOC(_IOC_NONE,'o',24,0),
	},
	{
		.name = "VIDEO_SELECT_SOURCE",
		_IOC(_IOC_NONE,'o',25,0),
	},
	{
		.name = "VIDEO_SET_BLANK",
		_IOC(_IOC_NONE,'o',26,0),
	},
	{
		.name = "VIDEO_GET_STATUS",
		_IOC(_IOC_NONE,'o',27,0),
	},
	{
		.name = "VIDEO_GET_EVENT",
		_IOC(_IOC_NONE,'o',28,0),
	},
	{
		.name = "VIDEO_SET_DISPLAY_FORMAT",
		_IOC(_IOC_NONE,'o',29,0),
	},
	{
		.name = "VIDEO_STILLPICTURE",
		_IOC(_IOC_NONE,'o',30,0),
	},
	{
		.name = "VIDEO_FAST_FORWARD",
		_IOC(_IOC_NONE,'o',31,0),
	},
	{
		.name = "VIDEO_SLOWMOTION",
		_IOC(_IOC_NONE,'o',32,0),
	},
	{
		.name = "VIDEO_GET_CAPABILITIES",
		_IOC(_IOC_NONE,'o',33,0),
	},
	{
		.name = "VIDEO_CLEAR_BUFFER",
		_IOC(_IOC_NONE,'o',34,0),
	},
	{
		.name = "VIDEO_SET_ID",
		_IOC(_IOC_NONE,'o',35,0),
	},
	{
		.name = "VIDEO_SET_STREAMTYPE",
		_IOC(_IOC_NONE,'o',36,0),
	},
	{
		.name = "VIDEO_SET_FORMAT",
		_IOC(_IOC_NONE,'o',37,0),
	},
	{
		.name = "VIDEO_SET_SYSTEM",
		_IOC(_IOC_NONE,'o',38,0),
	},
	{
		.name = "VIDEO_SET_HIGHLIGHT",
		_IOC(_IOC_NONE,'o',39,0),
	},
	{
		.name = "VIDEO_SET_SPU",
		_IOC(_IOC_NONE,'o',50,0),
	},
	{
		.name = "VIDEO_SET_SPU_PALETTE",
		_IOC(_IOC_NONE,'o',51,0),
	},
	{
		.name = "VIDEO_GET_NAVI",
		_IOC(_IOC_NONE,'o',52,0),
	},
	{
		.name = "VIDEO_SET_ATTRIBUTES",
		_IOC(_IOC_NONE,'o',53,0),
	},
	{
		.name = "VIDEO_GET_SIZE",
		_IOC(_IOC_NONE,'o',55,0),
	},
	{
		.name = "VIDEO_GET_FRAME_RATE",
		_IOC(_IOC_NONE,'o',56,0),
	},
	{
		.name = "VIDEO_GET_PTS",
		_IOC(_IOC_NONE,'o',57,0),
	},
	{
		.name = "VIDEO_GET_FRAME_COUNT",
		_IOC(_IOC_NONE,'o',58,0),
	},
	{
		.name = "VIDEO_COMMAND",
		_IOC(_IOC_NONE,'o',59,0),
	},
	{
		.name = "VIDEO_TRY_COMMAND",
		_IOC(_IOC_NONE,'o',60,0),
	},
	{
		.name = "FUNCTIONFS_FIFO_STATUS",
		_IOC(_IOC_NONE,'g',1,0),
	},
	{
		.name = "FUNCTIONFS_FIFO_FLUSH",
		_IOC(_IOC_NONE,'g',2,0),
	},
	{
		.name = "FUNCTIONFS_CLEAR_HALT",
		_IOC(_IOC_NONE,'g',3,0),
	},
	{
		.name = "FUNCTIONFS_INTERFACE_REVMAP",
		_IOC(_IOC_NONE,'g',128,0),
	},
	{
		.name = "FUNCTIONFS_ENDPOINT_REVMAP",
		_IOC(_IOC_NONE,'g',129,0),
	},
	{
		.name = "GADGETFS_FIFO_STATUS",
		_IOC(_IOC_NONE,'g',1,0),
	},
	{
		.name = "GADGETFS_FIFO_FLUSH",
		_IOC(_IOC_NONE,'g',2,0),
	},
	{
		.name = "GADGETFS_CLEAR_HALT",
		_IOC(_IOC_NONE,'g',3,0),
	},
	{
		.name = "GADGET_GET_PRINTER_STATUS",
		_IOC(_IOC_NONE,'g',0x21,0),
	},
	{
		.name = "GADGET_SET_PRINTER_STATUS",
		_IOC(_IOC_NONE,'g',0x22,0),
	},
	{
		.name = "USBTMC_IOCTL_INDICATOR_PULSE",
		_IOC(_IOC_NONE,USBTMC_IOC_NR,1,0),
	},
	{
		.name = "USBTMC_IOCTL_CLEAR",
		_IOC(_IOC_NONE,USBTMC_IOC_NR,2,0),
	},
	{
		.name = "USBTMC_IOCTL_ABORT_BULK_OUT",
		_IOC(_IOC_NONE,USBTMC_IOC_NR,3,0),
	},
	{
		.name = "USBTMC_IOCTL_ABORT_BULK_IN",
		_IOC(_IOC_NONE,USBTMC_IOC_NR,4,0),
	},
	{
		.name = "USBTMC_IOCTL_CLEAR_OUT_HALT",
		_IOC(_IOC_NONE,USBTMC_IOC_NR,6,0),
	},
	{
		.name = "USBTMC_IOCTL_CLEAR_IN_HALT",
		_IOC(_IOC_NONE,USBTMC_IOC_NR,7,0),
	},
	{
		.name = "SPI_IOC_RD_MODE",
		_IOC(_IOC_NONE,SPI_IOC_MAGIC,1,0),
	},
	{
		.name = "SPI_IOC_WR_MODE",
		_IOC(_IOC_NONE,SPI_IOC_MAGIC,1,0),
	},
	{
		.name = "SPI_IOC_RD_LSB_FIRST",
		_IOC(_IOC_NONE,SPI_IOC_MAGIC,2,0),
	},
	{
		.name = "SPI_IOC_WR_LSB_FIRST",
		_IOC(_IOC_NONE,SPI_IOC_MAGIC,2,0),
	},
	{
		.name = "SPI_IOC_RD_BITS_PER_WORD",
		_IOC(_IOC_NONE,SPI_IOC_MAGIC,3,0),
	},
	{
		.name = "SPI_IOC_WR_BITS_PER_WORD",
		_IOC(_IOC_NONE,SPI_IOC_MAGIC,3,0),
	},
	{
		.name = "SPI_IOC_RD_MAX_SPEED_HZ",
		_IOC(_IOC_NONE,SPI_IOC_MAGIC,4,0),
	},
	{
		.name = "SPI_IOC_WR_MAX_SPEED_HZ",
		_IOC(_IOC_NONE,SPI_IOC_MAGIC,4,0),
	},
	{
		.name = "IB_USER_MAD_REGISTER_AGENT",
		_IOC(_IOC_NONE,IB_IOCTL_MAGIC,1,0),
	},
	{
		.name = "IB_USER_MAD_UNREGISTER_AGENT",
		_IOC(_IOC_NONE,IB_IOCTL_MAGIC,2,0),
	},
	{
		.name = "IB_USER_MAD_ENABLE_PKEY",
		_IOC(_IOC_NONE,IB_IOCTL_MAGIC,3,0),
	},
	{
		.name = "TCGETS2",
		_IOC(_IOC_NONE,'T',0x2A,0),
	},
	{
		.name = "TCSETS2",
		_IOC(_IOC_NONE,'T',0x2B,0),
	},
	{
		.name = "TCSETSW2",
		_IOC(_IOC_NONE,'T',0x2C,0),
	},
	{
		.name = "TCSETSF2",
		_IOC(_IOC_NONE,'T',0x2D,0),
	},
	{
		.name = "TIOCGPTN",
		_IOC(_IOC_NONE,'T',0x30,0),
	},
	{
		.name = "TIOCSPTLCK",
		_IOC(_IOC_NONE,'T',0x31,0),
	},
	{
		.name = "TIOCSIG",
		_IOC(_IOC_NONE,'T',0x36,0),
	},

