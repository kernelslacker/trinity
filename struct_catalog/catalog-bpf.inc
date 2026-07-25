#ifdef USE_BPF
	[SC_BPF_ATTR] = {
		.name			= "bpf_attr",
		.struct_size		= sizeof(union bpf_attr),
		/*
		 * Shared prefix is empty: every bpf cmd lives in its own
		 * anonymous union arm with no truly-common fields.  The
		 * tagged-union path takes over via discrim_arg_idx == 1
		 * (bpf cmd lives in rec->a1).
		 */
		.fields			= NULL,
		.num_fields		= 0,
		.discrim_arg_idx	= 1,
		.variants		= bpf_attr_variants,
		.num_variants		= ARRAY_SIZE(bpf_attr_variants),
	},
	/*
	 * bpf_insn registered for name lookup only -- kept as a CMP-
	 * attribution shape (code / off / imm) so KCOV-compare learned
	 * constants can be attributed to the right field.  No
	 * syscall_struct_args entry; PROG_LOAD's insns now flows through
	 * FT_BPF_PROGRAM rather than FT_PTR_ARRAY.elem_struct.
	 */
	[SC_BPF_INSN] = {
		.name		= "bpf_insn",
		.struct_size	= sizeof(struct bpf_insn),
		.fields		= bpf_insn_fields,
		.num_fields	= ARRAY_SIZE(bpf_insn_fields),
	},
#endif
