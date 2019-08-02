
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
	    dprintf(dbg_out_fd, "INTERCEPT %5d: ", getpid());		\
	    dprintf(dbg_out_fd, __VA_ARGS__);				\
	}								\
} while(0)

#define DBG_LOGCALL(...) do {						\
	if (dbg_log_calls) DBG_LOG(__VA_ARGS__);			\
} while (0)

void	dbg_openlog();
void	dbg_closelog();

#endif /* !_DBGLOG_H_ */
