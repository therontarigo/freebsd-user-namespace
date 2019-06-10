#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/param.h>

static struct maptabent {
	// src: location in virtual namespace
	// dst: location on real filesystem
	const char *src;
	const char *dst;
} * maptable;
size_t maptable_len;

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

bool dbg_log_pathmap = false;

void pathmapabs (const char *path, char *dstpath) {
	dstpath[0] = '\0';
	for (size_t i = 0; i < maptable_len; i++) {
	    const char *src = maptable[i].src;
	    // path cannot contain src
	    if (strlen(path)<strlen(src)) continue;
	    // path does not beigin with src
	    if (strncmp(path,src,strlen(src))) continue;
	    const char *dst = maptable[i].dst;
	    if (strlen(dst)+strlen(path)-strlen(src) >= PATH_MAX) return;
	    strcpy(dstpath,dst);
	    strcpy(dstpath+strlen(dst),path+strlen(src));
	    dstpath[strlen(dst)+strlen(path)-strlen(src)] = '\0';
	    if (dbg_log_pathmap)
	        fprintf(stderr, "Path \"%s\" resolved to \"%s\"\n",
		    path, dstpath);
	    return;
	}
	fprintf(stderr, "Path \"%s\" not found in namespace\n", path);
	return;
}

// path must have capacity PATH_MAX
static void
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
