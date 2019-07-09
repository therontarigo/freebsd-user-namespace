
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/param.h>
#include <unistd.h>
#include <libgen.h>
extern char **environ;

const char * const pathoptions[] = {
	"-L",
	"-I",
	NULL
};

int main (int argc, char * *argv) {

	const char *pathmap = getenv("INTERCEPT_CC_MAP");
	if (!pathmap) {
	    fprintf(stderr, "INTERCEPT_CC_MAP not set\n");
	    return 1;
	}
	char *match = malloc(strlen(pathmap)+1);
	strcpy(match, pathmap);
	char *sep = strchr(match, '%');
	if (!sep) {
	    fprintf(stderr, "Invalid INTERCEPT_CC_MAP: missing separator\n");
	    return 1;
	}
	*sep = '\0';
	const char *root = sep+1;

	if (!argc) return 1;

	/* Don't load intercept lib into any dynamically linked parts of the
	 * toolchain invoked. */
	unsetenv("LD_PRELOAD");

	char * *argv2 = malloc((argc+1)*sizeof(*argv2));
	for (int iarg = 1; iarg < argc; iarg++) {
	    char *arg = argv[iarg];
	    argv2[iarg] = arg;
	    const char * const *flagpref = pathoptions;
	    while (*flagpref) {
		if (!strncmp(*flagpref, arg, strlen(*flagpref))) break;
		flagpref++;
	    }
	    /* now arg possibly begins with a file path */
	    const char *argval = arg;
	    if (*flagpref) {
	        argval = arg + strlen(*flagpref);
	        if (strlen(arg)==strlen(*flagpref)) {
	            /* if whole arg is a path flag, next arg is the path to
		     * possibly rewrite */
	            iarg+=1; argval = arg = argv[iarg];
	            flagpref = NULL;
	            argv2[iarg] = arg;
	        }
	    }
	    size_t match_len = strlen(match);
	    if (match_len && match[match_len-1]=='/') match_len--;
	    if (strncmp(argval, match, match_len)) continue;
	    if (argval[match_len] && argval[match_len]!='/') continue;
	    char path[PATH_MAX];
	    snprintf(path, PATH_MAX, "%s%s%s",
	        (flagpref&&*flagpref)?(*flagpref):"", root, argval+match_len);
	    argv2[iarg] = malloc(strlen(path)+1);
	    strcpy(argv2[iarg], path);
	}
	argv2[0] = malloc(PATH_MAX);
	/* When invoked as $0=${CC}, run /usr/bin/${CC} instead. */
	snprintf(argv2[0], PATH_MAX, "%s%s", "/usr/bin/", basename(argv[0]));
	argv2[argc] = NULL;

#ifdef INTERCEPT_CC_DBG
	FILE *dbg_out = fopen("/tmp/intercept.log", "a");
	for (int iarg = 0; iarg < argc; iarg++) {
	    fprintf(dbg_out, "argv2[%d] = \"%s\"\n", iarg, argv2[iarg]);
	}
	fclose(dbg_out);
#endif

	return execve(argv2[0], argv2, environ);
}
