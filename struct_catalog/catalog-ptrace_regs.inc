	/*
	 * ptrace register-set descriptors -- per-arch shapes for the
	 * PTRACE_{GET,SET}REGS and PTRACE_{GET,SET}REGSET arms in
	 * syscalls/ptrace.c.  Attribution-only: arg4 stays ARG_UNDEFINED
	 * so the schema-aware fill never allocates against these sizes;
	 * consumers reach the descriptors via struct_catalog_lookup() on
	 * the struct name and struct_field_for_cmp() steers KCOV-CMP
	 * learned constants at the named register slot.  aarch64 exposes
	 * struct user_pt_regs (kernel-side struct pt_regs is not uapi on
	 * arm64) so the SC_PT_REGS slot's .name diverges by arch; the
	 * enum slot stays the same shape either way.
	 */
#if defined(__x86_64__)
	[SC_PT_REGS] = {
		.name		= "pt_regs",
		.struct_size	= sizeof(struct pt_regs),
		.fields		= pt_regs_fields,
		.num_fields	= ARRAY_SIZE(pt_regs_fields),
	},
	[SC_USER_REGS_STRUCT] = {
		.name		= "user_regs_struct",
		.struct_size	= sizeof(struct user_regs_struct),
		.fields		= user_regs_struct_fields,
		.num_fields	= ARRAY_SIZE(user_regs_struct_fields),
	},
#elif defined(__aarch64__)
	[SC_PT_REGS] = {
		.name		= "user_pt_regs",
		.struct_size	= sizeof(struct user_pt_regs),
		.fields		= pt_regs_fields,
		.num_fields	= ARRAY_SIZE(pt_regs_fields),
	},
	[SC_USER_REGS_STRUCT] = {
		.name		= "user_regs_struct",
		.struct_size	= sizeof(struct user_regs_struct),
		.fields		= user_regs_struct_fields,
		.num_fields	= ARRAY_SIZE(user_regs_struct_fields),
	},
#endif
