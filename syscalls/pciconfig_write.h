/*
   sys_pciconfig_write (unsigned long bus, unsigned long dfn, unsigned long off, unsigned long len,
                        void *buf)
 */
{
	.name = "pciconfig_write",
	.num_args = 5,
	.arg1name = "bus",
	.arg2name = "dfn",
	.arg3name = "off",
	.arg4name = "len",
	.arg5name = "buf",
	.arg5type = ARG_ADDRESS,
},
