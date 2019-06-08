#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

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

static char * pathmapabs (const char *path) {
	for (size_t i = 0; i < maptable_len; i++) {
	    const char *src = maptable[i].src;
	    // path cannot contain src
	    if (strlen(path)<strlen(src)) continue;
	    // path does not beigin with src
	    if (strncmp(path,src,strlen(src))) continue;
	    const char *dst = maptable[i].dst;
	    char *dstpath = malloc(strlen(dst)+strlen(path)-strlen(src)+1);
	    strcpy(dstpath,dst);
	    strcpy(dstpath+strlen(dst),path+strlen(src));
	    dstpath[strlen(dst)+strlen(path)-strlen(src)] = '\0';
	    fprintf(stderr, "Path \"%s\" resolved to \"%s\"\n", path, dstpath);
	    return dstpath;
	}
	fprintf(stderr, "Path \"%s\" not found in namespace\n", path);
	// path not found
	return NULL;
}

