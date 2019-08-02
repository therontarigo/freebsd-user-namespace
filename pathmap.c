
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

	/* Expand the path to absolute using realpath.
	     This is still a path inside the virtual namespace,
	     since readlink is also intercepted. */
	// Note: pathmap -> realpath -> readlink -> pathmap: pathmap is reentrant

/* Path mapping behavior should be identical to:
	 - expand virtual path to full path using virtual curdir
	 - map virtual full path to corresponding real full path
	 - (?) simplify real full path to real relative path using real curdir

	 chdir:
	 - map virtual path to corresponding real path
	 -> relative virtual paths become identical relative real paths unless
	      crossing boundary of mappings
*/

USERNS_PRIVATE
void
pathmapabs(const char *path, char *dstpath)
{
	dstpath[0] = '\0';
	for (size_t i = 0; i < maptable_len; i++) {
	    const char *src = maptable[i].src;
	    // path cannot contain src
	    size_t src_len = strlen(src);
	    if (src_len && src[src_len-1]=='/') src_len-=1;
	    if (strlen(path)<src_len) continue;
	    // path does not begin with src
	    if (strncmp(path,src,src_len)) continue;
	    if (!(path[src_len]==0 || path[src_len]=='/')) continue;
	    const char *dst = maptable[i].dst;
	    if (strlen(dst)+strlen(path)-strlen(src) >= PATH_MAX) return;
	    strcpy(dstpath,dst);
	    strcpy(dstpath+strlen(dst),path+strlen(src));
	    dstpath[strlen(dst)+strlen(path)-strlen(src)] = '\0';
	    if (DBG_OUTOPEN && dbg_log_pathmap) {
	        DBG_LOG("Path \"%s\" resolved to \"%s\"\n", path, dstpath);
	    }

	    /*
	     * The special destination "/nonexistant" may be used to cause path
	     * resolution to fail immediately.
	     */
	    if (!strcmp(dst, "/nonexistant")) break;

	    /*
	     * The special destination "/nonexistantFATAL" may be used to cause
	     * an immediate failure of a process attempting to access a path
	     * mapped to this destination.
	     */
	    if (!strcmp(dst, "/nonexistantFATAL")) {
		DBG_LOG("Path \"%s\" not found in namespace - FATAL\n", path);
		dprintf(2, "Path \"%s\" not found in namespace - FATAL\n",
		  path);
		__builtin_trap();
	    }
	    return;
	}
	DBG_LOG("Path \"%s\" not found in namespace\n", path);
	return;
}

// path must have capacity PATH_MAX
USERNS_PRIVATE
void
pathmapat(int fd, const char *path, int *rfd, char *pbuf, const char **rpath)
{
	if (rfd) *rfd = fd;
	// absolute path: map in all cases
	// relative path: path and fd may remain unmodified by mapping,
	//     in case it does not cross a mapping boundary
	if (!path || (fd!=-100 && fd<=0)) {
	    *rpath = NULL;
	    return;
	}
	if (path[0]=='/') {
	    pathmapabs(path, pbuf);
	    *rpath = pbuf;
	    return;
	}
	*rpath = path;
}
