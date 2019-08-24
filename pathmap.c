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
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/param.h>

#include "userns.h"
#include "dbglog.h"
#include "mapspec.h"

#include "pathmap.h"

USERNS_PRIVATE
void
pathmapabs(const char *path, char *dstpath)
{
	dstpath[0] = '\0';
	for (size_t i = 0; i < maptable_len; i++) {
		const char *src = maptable[i].src;
		/* path cannot contain src */
		    size_t src_len = strlen(src);
		if (src_len && src[src_len - 1] == '/') src_len -= 1;
		if (strlen(path) < src_len) continue;
		/* path does not begin with src */
		if (strncmp(path, src, src_len)) continue;
		if (!(path[src_len] == 0 || path[src_len] == '/')) continue;
		const char *dst = maptable[i].dst;
		if (strlen(dst) + strlen(path) - strlen(src) >= PATH_MAX)
			return;
		strcpy(dstpath, dst);
		strcpy(dstpath + strlen(dst), path + strlen(src));
		dstpath[strlen(dst) + strlen(path) - strlen(src)] = '\0';
		if (DBG_OUTOPEN && dbg_log_pathmap) {
			DBG_LOG("Path \"%s\" resolved to \"%s\"\n",
			    path, dstpath);
		}

		/*
		 * The special destination "/nonexistant" may be used to cause
		 * path resolution to fail immediately.
		 */
		if (!strcmp(dst, "/nonexistant")) break;

		/*
		 * The special destination "/nonexistantFATAL" may be used to
		 * cause an immediate failure of a process attempting to
		 * access a path mapped to this destination.
		 */
		if (!strcmp(dst, "/nonexistantFATAL")) {
			DBG_LOG("Path \"%s\" not found in namespace - "
			    "FATAL\n", path);
			dprintf(2, "Path \"%s\" not found in namespace - "
			    "FATAL\n", path);
			__builtin_trap();
		}
		return;
	}
	DBG_LOG("Path \"%s\" not found in namespace\n", path);
	return;
}

/* path must have capacity PATH_MAX */

USERNS_PRIVATE
void
pathmapat(int fd, const char *path, int *rfd, char *pbuf, const char **rpath)
{
	if (rfd) *rfd = fd;
	/*
	 * given absolute path: map in all cases
	 * given relative path: path and fd may remain unmodified by mapping,
	 *   in case it does not cross a mapping boundary
	 */
	if (!path || (fd != -100 && fd <= 0)) {
		*rpath = NULL;
		return;
	}
	if (path[0] == '/') {
		pathmapabs(path, pbuf);
		*rpath = pbuf;
		return;
	}
	*rpath = path;
}
