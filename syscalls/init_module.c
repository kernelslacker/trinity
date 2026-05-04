/*
 * SYSCALL_DEFINE3(init_module, void __user *, umod,
	 unsigned long, len, const char __user *, uargs)
 */
#include <elf.h>
#include <string.h>
#include "arch.h"
#include "random.h"
#include "sanitise.h"
#include "deferred-free.h"
#include "shm.h"
#include "trinity.h"
#include "utils.h"

/*
 * Build a minimal-but-plausible ELF module image so the kernel gets past
 * the initial magic check and exercises the ELF parsing code paths
 * (section header validation, string table lookup, relocation parsing, etc.).
 *
 * We allocate a buffer large enough for:
 *   - ELF header
 *   - 1-8 random section headers
 *   - a small string table (.shstrtab)
 *   - some random payload bytes
 */

/* Minimal .shstrtab: "\0.shstrtab\0.text\0.data\0.bss\0.rodata\0" */
static const char shstrtab[] =
	"\0.shstrtab\0.text\0.data\0.bss\0.rodata\0";

/* Offsets into shstrtab for each section name */
#define SHNAME_SHSTRTAB	1
#define SHNAME_TEXT	11
#define SHNAME_DATA	17
#define SHNAME_BSS	23
#define SHNAME_RODATA	28

static const unsigned int section_names[] = {
	SHNAME_TEXT, SHNAME_DATA, SHNAME_BSS, SHNAME_RODATA,
};

static const char *module_params[] = {
	"param1=val",
	"debug=1",
	"timeout=30 verbose=y",
	"mode=0644",
	"",
};

static void sanitise_init_module(struct syscallrecord *rec)
{
	unsigned int nr_shdrs, shstrtab_idx;
	unsigned int ehdr_sz, shdrs_sz, strtab_sz, payload_sz, total_sz;
	unsigned char *buf;
	Elf64_Ehdr *ehdr;
	Elf64_Shdr *shdr;
	unsigned int i;

	nr_shdrs = 2 + (rand() % 7);	/* 2-8 sections (idx 0 is SHN_UNDEF) */
	shstrtab_idx = 1;		/* section 1 = .shstrtab */

	ehdr_sz = sizeof(Elf64_Ehdr);
	shdrs_sz = nr_shdrs * sizeof(Elf64_Shdr);
	strtab_sz = sizeof(shstrtab);
	payload_sz = 64 + (rand() % 256);
	total_sz = ehdr_sz + shdrs_sz + strtab_sz + payload_sz;

	buf = zmalloc(total_sz);
	generate_rand_bytes(buf, total_sz);

	/* ELF header */
	ehdr = (Elf64_Ehdr *) buf;
	memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
	ehdr->e_ident[EI_CLASS] = ELFCLASS64;
	ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
	ehdr->e_ident[EI_VERSION] = EV_CURRENT;
	ehdr->e_ident[EI_OSABI] = ELFOSABI_NONE;
	ehdr->e_type = ET_REL;			/* relocatable — kernel modules are ET_REL */
	ehdr->e_machine = EM_X86_64;
	ehdr->e_version = EV_CURRENT;
	ehdr->e_entry = 0;
	ehdr->e_phoff = 0;
	ehdr->e_shoff = ehdr_sz;		/* section headers right after ELF header */
	ehdr->e_flags = 0;
	ehdr->e_ehsize = ehdr_sz;
	ehdr->e_phentsize = 0;
	ehdr->e_phnum = 0;
	ehdr->e_shentsize = sizeof(Elf64_Shdr);
	ehdr->e_shnum = nr_shdrs;
	ehdr->e_shstrndx = shstrtab_idx;

	/* Occasionally corrupt a field to exercise error paths */
	if (ONE_IN(4))
		ehdr->e_shnum = rand() % 256;
	if (ONE_IN(4))
		ehdr->e_shstrndx = rand() % 256;
	if (ONE_IN(8))
		ehdr->e_shoff = rand() % total_sz;

	/* Section headers start at buf + ehdr_sz */
	shdr = (Elf64_Shdr *)(buf + ehdr_sz);

	/* Section 0: SHN_UNDEF (required by ELF spec) */
	memset(&shdr[0], 0, sizeof(Elf64_Shdr));

	/* Section 1: .shstrtab */
	memset(&shdr[1], 0, sizeof(Elf64_Shdr));
	shdr[1].sh_name = SHNAME_SHSTRTAB;
	shdr[1].sh_type = SHT_STRTAB;
	shdr[1].sh_offset = ehdr_sz + shdrs_sz;
	shdr[1].sh_size = strtab_sz;

	/* Copy the string table into the buffer */
	memcpy(buf + ehdr_sz + shdrs_sz, shstrtab, strtab_sz);

	/* Remaining sections: random types with names from our table */
	for (i = 2; i < nr_shdrs; i++) {
		memset(&shdr[i], 0, sizeof(Elf64_Shdr));
		shdr[i].sh_name = RAND_ARRAY(section_names);
		switch (rand() % 5) {
		case 0: shdr[i].sh_type = SHT_PROGBITS; break;
		case 1: shdr[i].sh_type = SHT_NOBITS; break;
		case 2: shdr[i].sh_type = SHT_RELA; break;
		case 3: shdr[i].sh_type = SHT_SYMTAB; break;
		case 4: shdr[i].sh_type = SHT_NOTE; break;
		}
		shdr[i].sh_flags = rand() & (SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR);
		shdr[i].sh_offset = ehdr_sz + shdrs_sz + strtab_sz;
		shdr[i].sh_size = rand() % payload_sz;
		shdr[i].sh_addralign = 1 << (rand() % 5);	/* 1, 2, 4, 8, or 16 */

		/* Occasionally point offset way out of bounds */
		if (ONE_IN(8))
			shdr[i].sh_offset = rand() % (total_sz * 4);
	}

	rec->a1 = (unsigned long) buf;
	rec->a2 = total_sz;

	/* arg3: uargs — NUL-terminated module parameter string */
	rec->a3 = (unsigned long) RAND_ARRAY(module_params);

	/* Snapshot for the post handler -- a1 may be scribbled by a sibling
	 * syscall before post_init_module() runs. */
	rec->post_state = (unsigned long) buf;
}

static void post_init_module(struct syscallrecord *rec)
{
	void *umod = (void *) rec->post_state;

	if (umod == NULL)
		return;

	if (looks_like_corrupted_ptr(rec, umod)) {
		outputerr("post_init_module: rejected suspicious umod=%p (pid-scribbled?)\n", umod);
		rec->a1 = 0;
		rec->post_state = 0;
		return;
	}

	rec->a1 = 0;
	deferred_freeptr(&rec->post_state);
}

struct syscallentry syscall_init_module = {
	.name = "init_module",
	.num_args = 3,
	.argtype = { [0] = ARG_ADDRESS, [1] = ARG_LEN, [2] = ARG_ADDRESS },
	.argname = { [0] = "umod", [1] = "len", [2] = "uargs" },
	.group = GROUP_PROCESS,
	.flags = NEEDS_ROOT,
	.sanitise = sanitise_init_module,
	.post = post_init_module,
};
