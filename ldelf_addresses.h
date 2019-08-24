/*-
 * SPDX-License-Identifier: BSD-2-Clause-FreeBSD
 *
 * Copyright (c) 2019 Theron Tarigo <theron@FreeBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdint.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <libelf.h>
#include <gelf.h>

static
int
ldelf_addresses(int nfind, const char *const *findnames, size_t *addrs)
{
	elf_version(EV_CURRENT);
	const char *filename = "/usr/lib/debug/libexec/ld-elf.so.1.debug";
	for (int j = 0; j < nfind; j++) addrs[j] = 0;
	int fd = open(filename, O_RDONLY);
	if (fd == -1) return 1;
	Elf *elf = elf_begin(fd, ELF_C_READ, NULL);
	if (!elf) goto failure;
	elf_errno();
	if (elf_kind(elf) != ELF_K_ELF) goto failure;
	GElf_Ehdr ehdr;
	elf_errno();
	if (!gelf_getehdr(elf, &ehdr)) goto failure;
	Elf_Scn *scn;
	GElf_Shdr shdr;
	scn = elf_getscn(elf, 0);
	while (scn) {
		if (!gelf_getshdr(scn, &shdr)) goto failure;
		if (shdr.sh_type == SHT_SYMTAB) break;
		scn = elf_nextscn(elf, scn);
	}
	if (!scn) goto failure;
	size_t snsize = shdr.sh_size;
	size_t snentsize = shdr.sh_entsize;
	size_t snlen = snsize / snentsize;
	elf_errno();
	Elf_Data *data = elf_getdata(scn, NULL);
	if (!data) goto failure;
	for (size_t i = 0; i < snlen; i++) {
		GElf_Sym sym;
		if (!gelf_getsym(data, i, &sym)) goto failure;
		if (GELF_ST_TYPE(sym.st_info) != STT_FUNC) continue;
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
