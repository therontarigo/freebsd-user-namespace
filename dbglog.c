
#include <stdbool.h>
#include <fcntl.h>
#include <unistd.h>

#include "userns.h"

#include "dbglog.h"

USERNS_PRIVATE bool	 dbg_log_calls		= false;
USERNS_PRIVATE int	 dbg_out_fd		= -1;
USERNS_PRIVATE char	*dbg_log_filepath	= NULL;
USERNS_PRIVATE bool	 dbg_log_pathmap	= false;

USERNS_PRIVATE
void
dbg_openlog()
{
	dbg_out_fd=-1;
	if (dbg_log_filepath) {
	    dbg_out_fd = __sys_open(dbg_log_filepath,
		O_WRONLY|O_CREAT|O_APPEND, 0660);
	}
}

USERNS_PRIVATE
void
dbg_closelog()
{
	close(dbg_out_fd);
	dbg_out_fd = -2;
}
