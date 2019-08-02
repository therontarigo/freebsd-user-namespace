
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include "userns.h"

#include "mapspec.h"

USERNS_PRIVATE struct	maptabent *maptable	= NULL;
USERNS_PRIVATE size_t	maptable_len		= 0;

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
	    size_t len_src = sep-mapspec;
	    size_t len_dst = end-(sep+1);
	    char *src = malloc(len_src+1);
	    char *dst = malloc(len_dst+1);
	    strncpy(src, mapspec, len_src);
	    strncpy(dst, sep+1, len_dst);
	    src[len_src] = '\0';
	    dst[len_dst] = '\0';
	    maptable = realloc(maptable, (++maptable_len)*sizeof(*maptable));
	    maptable[maptable_len-1] = (struct maptabent){src, dst};
	    if (end && *end==entsep) ++end;
	    mapspec = end;
	}
}
