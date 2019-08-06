
static const int EXE_RUNPATH_SUCCESS	= 0;
static const int EXE_RUNPATH_ELFERROR	= 1;
static const int EXE_RUNPATH_NOSHARED	= 2;

int exe_runpath(int fd, char **ret_runpath, char **ret_rpath);
