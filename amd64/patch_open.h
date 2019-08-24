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

#include "ldelf_addresses.h"

static void
patch_jmp(void *fnaddr, void *newfn)
{
	if (fnaddr < (void *)0x0000000800000000) return;
	long jmprel = (long)(newfn - fnaddr);
	size_t inst_len = 5;
	/*
	 * amd64: 5 bytes for short (relative) jump instruction
	 *        14 bytes for long (absolute) jump instruction
	 */
	if ((jmprel - inst_len) & 0xFFFFFFFF00000000) inst_len = 14;

	/* allow overwriting code */
	if (mprotect(fnaddr, inst_len, PROT_READ | PROT_WRITE)) {
		fprintf(stderr, "mprotect failed: %s\n", strerror(errno));
		return;
	}

	if (inst_len == 5) {
		/* JMP 32 bit relative */
		((char *)fnaddr)[0] = 0xe9;
		int jmprel32 = (int)(jmprel - 5);
		memcpy(fnaddr + 1, &jmprel32, 4);
	} else {
		/*
		 * JMP 64 bit absolute, address follows instruction. warning:
		 * a disassembler will see the address as garbage code
		 */
		memcpy(fnaddr, (char[]){0xff, 0x25, 0,0,0,0}, 6);
		void *jmpabs64 = newfn;
		memcpy(fnaddr + 6, &jmpabs64, 8);
	}

	/* return code to protected state */
	if (mprotect(fnaddr, inst_len, PROT_READ | PROT_EXEC)) {
		fprintf(stderr, "mprotect failed: %s\n", strerror(errno));
		return;
	}
}

static void
patch_open()
{
	void *rtld_dlopen = (dlopen);
	if (rtld_dlopen < (void *)0x0000000800000000) return;
	const char *fnnames[] = { "dlopen", "open", "_openat" };
	struct { size_t dlopen, open, _openat; } ldelf;
	if (ldelf_addresses(3, fnnames, (size_t *)&ldelf)) return;
	if (!ldelf.dlopen) return;
	if (ldelf.open) {
		void *openaddr = (rtld_dlopen) + (ldelf.open - ldelf.dlopen);
		patch_jmp(openaddr, _open);
	}
	if (ldelf._openat) {
		void *openataddr = (rtld_dlopen) +
		    (ldelf._openat - ldelf.dlopen);
		patch_jmp(openataddr, openat);
	}
}
