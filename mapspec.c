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

#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "userns.h"

#include "mapspec.h"

USERNS_PRIVATE struct maptabent *maptable = NULL;
USERNS_PRIVATE size_t maptable_len = 0;

/*
 * Fill the path mapping table from the specification provided in the
 * environment.
 * This is meant to run once per process startup.
 * There is no mechanism to clear the mapping table and free the associated
 * memory.
 */
USERNS_PRIVATE
void
mapspec_read()
{
	maptable_len = 0;
	maptable = NULL;
	char *mapspec = getenv("FILEPATHMAP");
	if (!mapspec) {
		fprintf(stderr, "FILEPATHMAP undefined\n");
		_exit(-1);
	}
	char entsep = ':';
	char mapsep = '%';
	while (mapspec && *mapspec) {
		char *end = strchr(mapspec, entsep);
		if (!end) end = strchr(mapspec, '\0');
		char *sep = strchr(mapspec, mapsep);
		if (!sep || sep > end) {
			fprintf(stderr, "Bad FILEPATHMAP: %s\n", mapspec);
			_exit(-1);
		}
		size_t len_src = sep - mapspec;
		size_t len_dst = end - (sep + 1);
		char *src = malloc(len_src + 1);
		char *dst = malloc(len_dst + 1);
		strncpy(src, mapspec, len_src);
		strncpy(dst, sep + 1, len_dst);
		src[len_src] = '\0';
		dst[len_dst] = '\0';
		maptable = realloc(maptable,
		    (++maptable_len) * sizeof(*maptable));
		maptable[maptable_len - 1] = (struct maptabent){src, dst};
		if (end && *end == entsep) ++end;
		mapspec = end;
	}
}
