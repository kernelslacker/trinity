#ifdef USE_IF_ALG
	/*
	 * struct af_alg_iv: sendmsg(SOL_ALG, ALG_SET_IV) ancillary payload.
	 * Attribution-only -- AF_ALG IV cmsgs are built by the bespoke
	 * childops/net af-alg walker rather than the schema-aware fill, so
	 * consumers reach the descriptor via struct_catalog_lookup() on the
	 * struct name and struct_field_for_cmp() names the ivlen slot on a
	 * KCOV-CMP-learned constant instead of guessing off width alone.
	 * struct_size covers only the fixed __u32 head; the iv[] flexible
	 * tail is intentionally uncataloged (same shape as file_handle).
	 */
	[SC_AF_ALG_IV] = {
		.name		= "af_alg_iv",
		.struct_size	= sizeof(struct af_alg_iv),
		.fields		= af_alg_iv_fields,
		.num_fields	= ARRAY_SIZE(af_alg_iv_fields),
	},
#endif
