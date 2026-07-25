	/*
	 * userfaultfd ioctl argument structs.  Attribution-only: ioctls
	 * do not resolve through syscall_struct_args[] and the bespoke
	 * sanitisers in ioctls/userfaultfd.c own every live fill.  These
	 * entries let struct_field_for_cmp() name the specific u64 slot
	 * (dst / src / len / mode / features / ...) a KCOV-CMP-learned
	 * constant fell out of.  Consumers reach the descriptors via
	 * struct_catalog_lookup() on the struct name.
	 */
	[SC_UFFDIO_RANGE] = {
		.name		= "uffdio_range",
		.struct_size	= sizeof(struct uffdio_range),
		.fields		= uffdio_range_fields,
		.num_fields	= ARRAY_SIZE(uffdio_range_fields),
	},
	[SC_UFFDIO_API] = {
		.name		= "uffdio_api",
		.struct_size	= sizeof(struct uffdio_api),
		.fields		= uffdio_api_fields,
		.num_fields	= ARRAY_SIZE(uffdio_api_fields),
	},
	[SC_UFFDIO_REGISTER] = {
		.name		= "uffdio_register",
		.struct_size	= sizeof(struct uffdio_register),
		.fields		= uffdio_register_fields,
		.num_fields	= ARRAY_SIZE(uffdio_register_fields),
	},
	[SC_UFFDIO_COPY] = {
		.name		= "uffdio_copy",
		.struct_size	= sizeof(struct uffdio_copy),
		.fields		= uffdio_copy_fields,
		.num_fields	= ARRAY_SIZE(uffdio_copy_fields),
	},
	[SC_UFFDIO_ZEROPAGE] = {
		.name		= "uffdio_zeropage",
		.struct_size	= sizeof(struct uffdio_zeropage),
		.fields		= uffdio_zeropage_fields,
		.num_fields	= ARRAY_SIZE(uffdio_zeropage_fields),
	},
