/*
{
	.name = "SG_EMULATED_HOST",
	.request = 0x2203,
},
{
	.name = "SG_SET_TRANSFORM",
	.request = 0x2204,
},
{
	.name = "SG_GET_TRANSFORM",
	.request = 0x2205,
},
{
	.name = "SG_SET_RESERVED_SIZE",
	.request = 0x2275,
},
{
	.name = "SG_GET_RESERVED_SIZE",
	.request = 0x2272,
},
{
	.name = "SG_GET_SCSI_ID",
	.request = 0x2276,
},
{
	.name = "SG_SET_FORCE_LOW_DMA",
	.request = 0x2279,
},
{
	.name = "SG_GET_LOW_DMA",
	.request = 0x227a,
},
{
	.name = "SG_SET_FORCE_PACK_ID",
	.request = 0x227b,
},
{
	.name = "SG_GET_PACK_ID",
	.request = 0x227c,
},
{
	.name = "SG_GET_NUM_WAITING",
	.request = 0x227d,
},
{
	.name = "SG_GET_SG_TABLESIZE",
	.request = 0x227F,
},
{
	.name = "SG_GET_VERSION_NUM",
	.request = 0x2282,
},
{
	.name = "SG_SCSI_RESET",
	.request = 0x2284,
},
*/
{
	.name = "SG_IO",
	.request = 0x2285,
	.sanitise = sanitise_ioctl_sg_io,
},
/*
{
	.name = "SG_GET_REQUEST_TABLE",
	.request = 0x2286,
},
{
	.name = "SG_SET_KEEP_ORPHAN",
	.request = 0x2287,
},
{
	.name = "SG_GET_KEEP_ORPHAN",
	.request = 0x2288,
},
{
	.name = "SG_GET_ACCESS_COUNT",
	.request = 0x2289,
},
{
	.name = "SG_SET_TIMEOUT",
	.request = 0x2201,
},
{
	.name = "SG_GET_TIMEOUT",
	.request = 0x2202,
},
{
	.name = "SG_GET_COMMAND_Q",
	.request = 0x2270,
},
{
	.name = "SG_SET_COMMAND_Q",
	.request = 0x2271,
},
{
	.name = "SG_SET_DEBUG",
	.request = 0x227e,
},
{
	.name = "SG_NEXT_CMD_LEN",
	.request = 0x2283,
},
*/
