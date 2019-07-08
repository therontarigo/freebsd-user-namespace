
static struct maptabent {
        // src: location in virtual namespace
        // dst: location on real filesystem
        const char *src;
        const char *dst;
} * maptable;
size_t maptable_len;

static void mapspec_read() {
	maptable_len=0;
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
