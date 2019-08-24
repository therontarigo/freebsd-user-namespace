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

#ifndef _DBGLOG_H_
#define _DBGLOG_H_

#include <stdbool.h>
#include <unistd.h>
#include <stdio.h>

#include "userns.h"

extern bool	 dbg_log_calls;
extern int	 dbg_out_fd;
extern char	*dbg_log_filepath;
extern bool	 dbg_log_pathmap;

#define DBG_OUTOPEN (dbg_out_fd>=0)

#define DBG_LOG(...) do {						\
	if (dbg_out_fd==-2) {						\
		/* Reopen dbg output because it was closed */		\
		dbg_openlog();						\
	}								\
	if (DBG_OUTOPEN) {						\
		dprintf(dbg_out_fd, "INTERCEPT %5d: ", getpid());	\
		dprintf(dbg_out_fd, __VA_ARGS__);			\
	}								\
} while(0)

#define DBG_LOGCALL(...) do {						\
	if (dbg_log_calls) DBG_LOG(__VA_ARGS__);			\
} while (0)

void dbg_openlog();
void dbg_closelog();

#endif /* !_DBGLOG_H_ */
