
#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <libelf.h>
#include <gelf.h>

static
int
ldelf_addresses(int nfind, const char * const *findnames, size_t *addrs)
{
	elf_version(EV_CURRENT);
	const char *filename = "/usr/lib/debug/libexec/ld-elf.so.1.debug";
	for (int j = 0; j < nfind; j++) addrs[j] = 0;
	int fd = open(filename, O_RDONLY);
	if (fd==-1) return 1;
	Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf) goto failure;
	elf_errno();
	if (elf_kind(elf)!=ELF_K_ELF) goto failure;
	GElf_Ehdr ehdr;
	elf_errno();
	if (!gelf_getehdr(elf, &ehdr)) goto failure;
	Elf_Scn *scn;
	GElf_Shdr shdr;
	scn = elf_getscn(elf, 0);
	while (scn) {
	    if (!gelf_getshdr(scn, &shdr)) goto failure;
	    if (shdr.sh_type==SHT_SYMTAB) break;
	    scn = elf_nextscn(elf, scn);
	}
	if (!scn) goto failure;
	size_t snsize = shdr.sh_size;
	size_t snentsize = shdr.sh_entsize;
	size_t snlen = snsize/snentsize;
	elf_errno();
	Elf_Data * data = elf_getdata(scn, NULL);
	if (!data) goto failure;
	for (size_t i = 0; i < snlen; i++) {
	    GElf_Sym sym;
	    if (!gelf_getsym(data, i, &sym)) goto failure;
	    if (GELF_ST_TYPE(sym.st_info)!=STT_FUNC) continue;
	    const char *name = elf_strptr(elf, shdr.sh_link, sym.st_name);
	    if (!name) continue;
	    for (int j = 0; j < nfind; j++) {
		if (strcmp(name, findnames[j])) continue;
		addrs[j] = sym.st_value;
	    }
	}
	elf_end(elf);
	close(fd);
	return 0;
	failure:
	    fprintf(stderr, "ELF error: %s\n", elf_errmsg(elf_errno()));
	    elf_end(elf);
	    close(fd);
	    return 1;
}
