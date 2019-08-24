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
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <libelf.h>
#include <gelf.h>

#include "userns.h"

#include "exe_runpath.h"

USERNS_PRIVATE
int
exe_runpath(int fd, char **ret_runpath, char **ret_rpath)
{
	elf_version(EV_CURRENT);
	if (fd == -1 || !ret_runpath || !ret_rpath) {
		errno = EINVAL;
		return -1;
	}
	char *runpath = NULL;
	char *rpath = NULL;
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
		if (shdr.sh_type == SHT_DYNAMIC) break;
		scn = elf_nextscn(elf, scn);
	}
	if (!scn) {
		/* No shared section */
		elf_end(elf);
		return EXE_RUNPATH_NOSHARED;
	}
	size_t snsize = shdr.sh_size;
	size_t snentsize = shdr.sh_entsize;
	size_t snlen = snsize / snentsize;
	elf_errno();
	Elf_Data *data = elf_getdata(scn, NULL);
	if (!data) goto failure;
	for (size_t i = 0; i < snlen; i++) {
		GElf_Dyn dyn;
		if (!gelf_getdyn(data, i, &dyn)) goto failure;
		if (dyn.d_tag != DT_RUNPATH && dyn.d_tag != DT_RPATH) continue;
		const char *name =
		    elf_strptr(elf, shdr.sh_link, dyn.d_un.d_val);
		if (!name) continue;
		if (dyn.d_tag == DT_RUNPATH && !runpath) {
			runpath = malloc(strlen(name) + 1);
			strcpy(runpath, name);
		}
		if (dyn.d_tag == DT_RPATH && !rpath) {
			rpath = malloc(strlen(name) + 1);
			strcpy(rpath, name);
		}
	}
	elf_end(elf);
	*ret_runpath = runpath;
	*ret_rpath = rpath;
	return EXE_RUNPATH_SUCCESS;
failure:
	fprintf(stderr, "ELF error: %s\n", elf_errmsg(elf_errno()));
	free(runpath);
	free(rpath);
	elf_end(elf);
	return EXE_RUNPATH_ELFERROR;
}
