
#include <stdio.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <stdbool.h>

#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/mount.h>
#include "/usr/src/lib/libc/include/libc_private.h" // should be removed

#define shm_unlink _shm_unlink
#include <sys/mman.h> // mprotect
#undef shm_unlink

#define MAXSHELLCMDLEN  PAGE_SIZE

typedef int	(*fn_open_t)	(const char *, int, mode_t);
typedef int	(*fn_openat_t)	(int, const char *, int, mode_t);
typedef int	(*fn_link_t)	(const char *, const char *);
typedef int	(*fn_linkat_t)	(int, const char *, int, const char *, int);
typedef int	(*fn_unlink_t)	(const char *);
typedef int	(*fn_unlinkat_t)	(int, const char *, int);
typedef int	(*fn_chdir_t)	(const char *);
typedef int	(*fn_mknod_t)	(const char *, mode_t, dev_t);
typedef int	(*fn_mknodat_t)	(int, const char *, mode_t, dev_t);
typedef int	(*fn_chmod_t)	(const char *, mode_t);
typedef int	(*fn_lchmod_t)	(const char *, mode_t);
typedef int	(*fn_fchmodat_t)	(int, const char *, mode_t, int);
typedef int	(*fn_chown_t)	(const char *, uid_t, gid_t);
typedef int	(*fn_lchown_t)	(const char *, uid_t, gid_t);
typedef int	(*fn_fchownat_t)	(int, const char *, uid_t, gid_t, int);
typedef int	(*fn_accept_t)	(int, struct sockaddr * restrict, socklen_t * restrict);
typedef int	(*fn_accept4_t)	(int, struct sockaddr * restrict, socklen_t * restrict, int);
typedef int	(*fn_access_t)	(const char *, int);
typedef int	(*fn_eaccess_t)	(const char *, int);
typedef int	(*fn_faccessat_t)	(int, const char *, int, int);
typedef int	(*fn_chflags_t)	(const char *, unsigned long);
typedef int	(*fn_lchflags_t)	(const char *, unsigned long);
typedef int	(*fn_chflagsat_t)	(int, const char *, unsigned long, int);
typedef int	(*fn_ktrace_t)	(const char *, int, int, int);
typedef int	(*fn_acct_t)	(const char *);
typedef int	(*fn_revoke_t)	(const char *);
typedef int	(*fn_symlink_t)	(const char *, const char *);
typedef int	(*fn_symlinkat_t)	(const char *, int, const char *);
typedef ssize_t	(*fn_readlink_t)	(const char *restrict, char *restrict, size_t bufsiz);
typedef ssize_t	(*fn_readlinkat_t)	(int, const char *restrict, char *restrict, size_t bufsiz);
typedef int	(*fn_execve_t)	(const char *, char *const [], char * const []);
typedef int	(*fn_chroot_t)	(const char *);
typedef int	(*fn_connect_t)	(int, const struct sockaddr *, socklen_t);
typedef int	(*fn_connectat_t)	(int, int, const struct sockaddr *, socklen_t);
typedef int	(*fn_bind_t)	(int, const struct sockaddr *, socklen_t);
typedef int	(*fn_bindat_t)	(int, int, const struct sockaddr *, socklen_t);
typedef int	(*fn_rename_t)	(const char *, const char *);
typedef int	(*fn_renameat_t)	(int, const char *, int, const char *);
typedef int	(*fn_mkfifo_t)	(const char *, mode_t);
typedef int	(*fn_mkfifoat_t)	(int, const char *, mode_t);
typedef int	(*fn_sendto_t)	(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
typedef int	(*fn_mkdir_t)	(const char *, mode_t);
typedef int	(*fn_mkdirat_t)	(int fd, const char *, mode_t);
typedef int	(*fn_rmdir_t)	(const char *);
typedef int	(*fn_utimes_t)	(const char *, const struct timeval *);
typedef int	(*fn_lutimes_t)	(const char *, const struct timeval *);
typedef int	(*fn_futimesat_t)	(int fd, const char *, const struct timeval[2]);
typedef int	(*fn_statfs_t)	(const char *, struct statfs *);
typedef int	(*fn_getfh_t)	(const char *, fhandle_t *);
typedef int	(*fn_lgetfh_t)	(const char *, fhandle_t *);
typedef int	(*fn_stat_t)	(const char * restrict, struct stat * restrict);
typedef int	(*fn_lstat_t)	(const char * restrict, struct stat * restrict);
typedef int	(*fn_fstatat_t)	(int fd, const char *path, struct stat *buf, int flag);
typedef long	(*fn_pathconf_t)	(const char *, int);
typedef long	(*fn_lpathconf_t)	(const char *, int);
typedef int	(*fn_truncate_t)	(const char *, off_t);
typedef int	(*fn_undelete_t)	(const char *);
typedef int	(*fn_auditctl_t)	(const char *);
typedef int	(*fn_shm_open_t)	(const char *, int, mode_t);
typedef int	(*fn_shm_unlink_t)	(const char *);
typedef int	(*fn_utimensat_t)	(int, const char *, const struct timespec[2], int);

typedef fn_open_t fn__open_t;

static struct {
	fn_open_t	open, _open;
	fn_openat_t	openat;
	fn_link_t	link;
	fn_linkat_t	linkat;
	fn_unlink_t	unlink;
	fn_unlinkat_t	unlinkat;
	fn_chdir_t	chdir;
	fn_mknod_t	mknod;
	fn_mknodat_t	mknodat;
	fn_chmod_t	chmod;
	fn_lchmod_t	lchmod;
	fn_fchmodat_t	fchmodat;
	fn_chown_t	chown;
	fn_lchown_t	lchown;
	fn_fchownat_t	fchownat;
	fn_accept_t	accept;
	fn_accept4_t	accept4;
	fn_access_t	access;
	fn_eaccess_t	eaccess;
	fn_faccessat_t	faccessat;
	fn_chflags_t	chflags;
	fn_lchflags_t	lchflags;
	fn_chflagsat_t	chflagsat;
	fn_ktrace_t	ktrace;
	fn_acct_t	acct;
	fn_revoke_t	revoke;
	fn_symlink_t	symlink;
	fn_symlinkat_t	symlinkat;
	fn_readlink_t	readlink;
	fn_readlinkat_t	readlinkat;
	fn_execve_t	execve;
	fn_chroot_t	chroot;
	fn_connect_t	connect;
	fn_connectat_t	connectat;
	fn_bind_t	bind;
	fn_bindat_t	bindat;
	fn_rename_t	rename;
	fn_renameat_t	renameat;
	fn_mkfifo_t	mkfifo;
	fn_mkfifoat_t	mkfifoat;
	fn_sendto_t	sendto;
	fn_mkdir_t	mkdir;
	fn_mkdirat_t	mkdirat;
	fn_rmdir_t	rmdir;
	fn_utimes_t	utimes;
	fn_lutimes_t	lutimes;
	fn_futimesat_t	futimesat;
	fn_statfs_t	statfs;
	fn_getfh_t	getfh;
	fn_lgetfh_t	lgetfh;
	fn_stat_t	stat;
	fn_lstat_t	lstat;
	fn_fstatat_t	fstatat;
	fn_pathconf_t	pathconf;
	fn_lpathconf_t	lpathconf;
	fn_truncate_t	truncate;
	fn_undelete_t	undelete;
	fn_auditctl_t	auditctl;
	fn_shm_open_t	shm_open;
	fn_shm_unlink_t	shm_unlink;
	fn_utimensat_t	utimensat;

} fntable = {0};

bool dbg_log_calls = false;
bool dbg_out_flush = true;
FILE *dbg_out = NULL;

#include "pathmap.h"

ssize_t
__sys_readlink(const char *restrict path, char *restrict buf, size_t bufsiz);

int
__sys_open (const char *path, int flags, ...);

void
dbg_openlog() {
	dbg_out = NULL;
	char *dbg_log_filepath = getenv("INTERCEPT_DBGLOGFILE");
	if (dbg_log_filepath) {
	    int fd = __sys_open(dbg_log_filepath,
		O_WRONLY|O_CREAT|O_APPEND, 0660);
	    if (-1==fd) {
		fprintf(stderr, "Failed to open INTERCEPT_DBGLOGFILE \"%s\":"
		    "%s\n", dbg_log_filepath, strerror(errno));
		return;
	    }
	    dbg_out = fdopen(fd, "a");
	}
}

#define DBG_LOGCALL(...) \
	if (dbg_out && dbg_log_calls) { \
	    fprintf(dbg_out, __VA_ARGS__); \
	    if (dbg_out_flush) fflush(dbg_out); }

#include "patch_open.h"

__attribute__((constructor))
static void init() {

	void *libc = dlopen("/lib/libc.so.7", RTLD_NOW);

	#define FINDSYM(name,sym)					\
	    {								\
		fntable.name = (fn_##name##_t)dlfunc(libc, #sym);	\
		if (!fntable.name) {					\
		    fprintf(stderr, "fatal: %s not found\n", #sym);	\
		    exit(-1);						\
		}							\
	    }

	FINDSYM(_open, __sys_open)
	FINDSYM(open, open)
	FINDSYM(openat, __sys_openat)
	FINDSYM(link, __sys_link)
	FINDSYM(linkat,linkat)
	FINDSYM(unlink,unlink)
	FINDSYM(unlinkat,unlinkat)
	FINDSYM(chdir,__sys_chdir)
	FINDSYM(mknod,mknod)
	FINDSYM(mknodat,mknodat)
	FINDSYM(chmod,chmod)
	FINDSYM(lchmod,lchmod)
	FINDSYM(fchmodat,fchmodat)
	FINDSYM(chown,__sys_chown)
	FINDSYM(lchown,__sys_lchown)
	FINDSYM(fchownat,fchownat)
	FINDSYM(accept,accept)
	FINDSYM(accept4,accept4)
	FINDSYM(access,access)
	FINDSYM(eaccess,eaccess)
	FINDSYM(faccessat,faccessat)
	FINDSYM(chflags,chflags)
	FINDSYM(lchflags,lchflags)
	FINDSYM(chflagsat,chflagsat)
	FINDSYM(ktrace,ktrace)
	FINDSYM(acct,acct)
	FINDSYM(revoke,revoke)
	FINDSYM(symlink,symlink)
	FINDSYM(symlinkat,symlinkat)
	FINDSYM(readlink,readlink)
	FINDSYM(readlinkat,readlinkat)
	FINDSYM(execve,__sys_execve)
	FINDSYM(chroot,chroot)
	FINDSYM(connect,connect)
	FINDSYM(connectat,connectat)
	FINDSYM(bind,bind)
	FINDSYM(bindat,bindat)
	FINDSYM(rename,rename)
	FINDSYM(renameat,renameat)
	FINDSYM(mkfifo,mkfifo)
	FINDSYM(mkfifoat,mkfifoat)
	FINDSYM(sendto,__sys_sendto)
	FINDSYM(mkdir,mkdir)
	FINDSYM(mkdirat,mkdirat)
	FINDSYM(rmdir,rmdir)
	FINDSYM(utimes,utimes)
	FINDSYM(lutimes,lutimes)
	FINDSYM(futimesat,futimesat)
	FINDSYM(statfs,statfs)
	FINDSYM(getfh,getfh)
	FINDSYM(lgetfh,lgetfh)
	FINDSYM(stat,stat)
	FINDSYM(lstat,lstat)
	FINDSYM(fstatat,fstatat)
	FINDSYM(pathconf,pathconf)
	FINDSYM(lpathconf,lpathconf)
	FINDSYM(truncate,truncate)
	FINDSYM(undelete,undelete)
	FINDSYM(auditctl,auditctl)
	FINDSYM(shm_open,shm_open)
	FINDSYM(shm_unlink,shm_unlink)
	FINDSYM(utimensat,utimensat)

	#undef FINDSYM

	dbg_openlog();
	dbg_log_calls=(NULL!=getenv("INTERCEPT_LOG_CALLS"));
	dbg_log_pathmap=(NULL!=getenv("INTERCEPT_LOG_PATHMAP"));

	maptable_len=0;
	maptable = NULL;
	char *mapspec = getenv("FILEPATHMAP");
	if (!mapspec) {
	    fprintf(stderr, "FILEPATHMAP undefined\n");
	    exit(-1);
	}
	char entsep = ':';
	char mapsep = '%';
	while (mapspec && *mapspec) {
	    char *end = strchr(mapspec, entsep);
	    if (!end) end = strchr(mapspec, '\0');
	    char *sep = strchr(mapspec, mapsep);
	    if (!sep || sep > end) {
		fprintf(stderr, "Bad FILEPATHMAP: %s\n", mapspec);
		exit(-1);
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
	patch_open();
	// Now if rtld-elf calls our open, and open calls an unresolved
	// function, rtld would be reentered and would hang on acquiring its
	// own lock.  The library must be compiled with -znow linker option to
	// avoid this.
}

int
__sys_syscall(int number, ...)
{
	fprintf(stderr, "fatal: use of __sys_syscall(\n");
	exit(-1);
}

/*
 * disable, taking the chance that programs may use syscall(...) for file
 * operations, until an appropriate mechanism for forwarding these calls to the
 * existing wrappers is determined.
 */
/*int
syscall(int number, ...)
{
	fprintf(stderr, "syscall(%d, ...)\n", number);
}*/

int
_syscall(int number, ...)
{
	DBG_LOGCALL("_syscall(%d, ...)\n", number);
	fprintf(stderr, "fatal: use of _syscall(\n");
	exit(-1);
}

off_t
__syscall(quad_t number, ...)
{
	DBG_LOGCALL("__syscall(%lu, ...)\n", number);
	fprintf(stderr, "fatal: use of __syscall(\n");
	exit(-1);
}

off_t
___syscall(quad_t number, ...)
{
	DBG_LOGCALL("___syscall(%lu, ...)\n", number);
	fprintf(stderr, "fatal: use of ___syscall(\n");
	exit(-1);
}

off_t
__sys___syscall(quad_t number, ...)
{
	fprintf(stderr, "fatal: use of __sys___syscall(\n");
	exit(-1);
}

int
open (const char *path, int flags, ...)
{
	va_list ap;
	mode_t mode = (mode_t){0};
	if (flags & O_CREAT) {
	    va_start(ap, flags);
	    mode = va_arg(ap, int);
	    va_end(ap);
	}
	DBG_LOGCALL("open(path=\"%s\",flags=%x)\n", path, flags);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.open(rpath,flags,mode);
}

// open and _open are different implementations
// possibly open doesn't need interception because it wraps openat(...) ?
int
_open (const char *path, int flags, ...)
{
	va_list ap;
	mode_t mode = (mode_t){0};
	if (flags & O_CREAT) {
	    va_start(ap, flags);
	    mode = va_arg(ap, int);
	    va_end(ap);
	}
	DBG_LOGCALL("open(path=\"%s\",flags=%x)\n", path, flags);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable._open(rpath,flags,mode);
}

int
__sys_openat (int fd, const char *path, int flags, ...)
{
	mode_t mode = (mode_t){0};
	if (flags & O_CREAT) {
	    va_list ap;
	    va_start(ap, flags);
	    mode = va_arg(ap, int);
	    va_end(ap);
	}
	DBG_LOGCALL("openat(fd=%d, path=\"%s\",flags=%x)\n", fd, path, flags);
	char pbuf[PATH_MAX];
	const char *rpath;
	int rfd;
	pathmapat(fd, path, &rfd, pbuf, &rpath);
	return fntable.openat(rfd,rpath,flags,mode);
}

int
openat (int fd, const char *path, int flags, ...)
{
	mode_t mode = (mode_t){0};
	if (flags & O_CREAT) {
	    va_list ap;
	    va_start(ap, flags);
	    mode = va_arg(ap, int);
	    va_end(ap);
	}
	return __sys_openat(fd, path, flags, mode);
}

int
_openat (int fd, const char *path, int flags, ...)
{
	mode_t mode = (mode_t){0};
	if (flags & O_CREAT) {
	    va_list ap;
	    va_start(ap, flags);
	    mode = va_arg(ap, int);
	    va_end(ap);
	}
	return __sys_openat(fd, path, flags, mode);
}

int
__sys_link(const char *name1, const char *name2)
{
	DBG_LOGCALL("link(name1=\"%s\", name2=\"%s\")\n", name1, name2);
	char pbuf1[PATH_MAX];
	char pbuf2[PATH_MAX];
	const char *rname1;
	const char *rname2;
	pathmapat(AT_FDCWD, name1, NULL, pbuf1, &rname1);
	pathmapat(AT_FDCWD, name2, NULL, pbuf2, &rname2);
	return fntable.link(rname1, rname2);
}

// q: why is there only linkat and no __sys_linkat ?
// libc.a (linkat.o) contains __sys_linkat
// why does it not exist in libc.so ?
int
linkat(int fd1, const char *name1, int fd2, const char *name2, int flag)
{
	DBG_LOGCALL(
	    "linkat(fd1=%d, name1=\"%s\", fd2=%d, name2=\"%s\", flag=%x)\n",
	    fd1, name1, fd2, name2, flag);
	char pbuf1[PATH_MAX];
	char pbuf2[PATH_MAX];
	const char *rname1;
	const char *rname2;
	int rfd1, rfd2;
	pathmapat(fd1, name1, &rfd1, pbuf1, &rname1);
	pathmapat(fd2, name2, &rfd2, pbuf2, &rname2);
	return fntable.linkat(rfd1, rname1, rfd2, rname2, flag);
}

// unlink is used internally by libc
//   (bt_open, hash_page, sem_new, tmpfile, remove)
int
unlink(const char *path)
{
	DBG_LOGCALL("unlink(\"%s\")\n", path);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.unlink(rpath);
}

// unlinkat is not used by libc
int
unlinkat(int fd, const char *path, int flag)
{
	DBG_LOGCALL("unlink(%d, \"%s\", flag=%x)\n", fd, path, flag);
	char pbuf[PATH_MAX];
	const char *rpath;
	int rfd;
	pathmapat(fd, path, &rfd, pbuf, &rpath);
	return fntable.unlinkat(rfd, rpath, flag);
}

int
chdir(const char *path)
{
	DBG_LOGCALL("chdir(\"%s\")\n", path);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.chdir(rpath);
}

// might need to know about fchdir

// mknod is wrapper for __sys_mknodat
// mknod is not a syscall on fbsd12+
int
mknod(const char *path, mode_t mode, dev_t dev)
{
	DBG_LOGCALL("mknod(\"%s\", mode=%x, dev=%lx)\n", path, mode, dev);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.mknod(rpath, mode, dev);
}

int
mknodat(int fd, const char *path, mode_t mode, dev_t dev)
{
	DBG_LOGCALL("mknodat(fd=%d, path=\"%s\", mode=%x, dev=%lx)\n",
	    fd, path, mode, dev);
	char pbuf[PATH_MAX];
	const char *rpath;
	int rfd;
	pathmapat(fd, path, &rfd, pbuf, &rpath);
	return fntable.mknodat(fd, rpath, mode, dev);
}

// chmod is not used by libc
int
chmod(const char *path, mode_t mode)
{
	DBG_LOGCALL("chown(\"%s\", mode=%x)\n", path, mode);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.chmod(rpath, mode);
}

// lchmod is not used by libc
int
lchmod(const char *path, mode_t mode)
{
	DBG_LOGCALL("lchown(\"%s\", mode=%x)\n", path, mode);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.lchmod(rpath, mode);
}

// fchmodat is not used by libc
int
fchmodat(int fd, const char *path, mode_t mode, int flag)
{
	DBG_LOGCALL("fchmodat(%d, \"%s\", mode=%x, flag=%x)\n",
	    fd, path, mode, flag);
	char pbuf[PATH_MAX];
	const char *rpath;
	int rfd;
	pathmapat(fd, path, &rfd, pbuf, &rpath);
	return fntable.fchmodat(rfd, rpath, mode, flag);
}

// chown is not used by libc
int
chown(const char *path, uid_t owner, gid_t group)
{
	DBG_LOGCALL("chown(\"%s\", owner=%x, group=%x)\n", path, owner, group);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.chown(rpath, owner, group);
}

// lchown is not used by libc
int
lchown(const char *path, uid_t owner, gid_t group)
{
	DBG_LOGCALL("lchown(\"%s\", owner=%x, group=%x)\n",
	    path, owner, group);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.lchown(rpath, owner, group);
}

// fchownat is not used by libc
int
fchownat(int fd, const char *path, uid_t owner, gid_t group, int flag)
{
	DBG_LOGCALL(
	    "fchownat(fd=%d, path=\"%s\", owner=%x, group=%x, flag=%x)\n",
	    fd, path, owner, group, flag);
	char pbuf[PATH_MAX];
	const char *rpath;
	int rfd;
	pathmapat(fd, path, &rfd, pbuf, &rpath);
	return fntable.fchownat(rfd, rpath, owner, group, flag);
}

// mount should not be used
int
mount(const char *type, const char *dir, int flags, void *data)
{
	fprintf(stderr, "fatal: use of mount(\n");
	exit(-1);
}

// unmount should not be used
int
unmount(const char *dir, int flags)
{
	fprintf(stderr, "fatal: use of unmount(\n");
	exit(-1);
}

// nmount should not be used
int
nmount(struct iovec *iov, u_int niov, int flags)
{
	fprintf(stderr, "fatal: use of nmount(\n");
	exit(-1);
}

// accept is not used by libc
int
accept(int s, struct sockaddr * restrict addr, socklen_t * restrict addrlen)
{
	DBG_LOGCALL("accept(...)\n");
	int ret = fntable.accept(s, addr, addrlen);
	// need to rewrite sockaddr if it contains a path
	return ret;
}

// accept4 is not used by libc
int
accept4(int s, struct sockaddr * restrict addr, socklen_t * restrict addrlen,
        int flags)
{
	DBG_LOGCALL("accept(...)\n");
	int ret = fntable.accept4(s, addr, addrlen, flags);
	// need to rewrite sockaddr if it contains a path
	return ret;
}

// access is not used by libc (?)
int
access(const char *path, int mode)
{
	DBG_LOGCALL("access(\"%s\", mode=%x)\n", path, mode);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.access(rpath, mode);
}

// eaccess is not used by libc
int
eaccess(const char *path, int mode)
{
	DBG_LOGCALL("eaccess(\"%s\", mode=%x)\n", path, mode);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.eaccess(rpath, mode);
}

// faccessat is not used by libc
int faccessat(int fd, const char *path, int mode, int flag)
{
	DBG_LOGCALL("faccessat(fd=%d, \"%s\", mode=%x, flag=%x)\n",
	    fd, path, mode, flag);
	char pbuf[PATH_MAX];
	const char *rpath;
	int rfd;
	pathmapat(fd, path, &rfd, pbuf, &rpath);
	return fntable.faccessat(rfd, rpath, mode, flag);
}

// *chflags* are not usd by libc
int
chflags(const char *path, unsigned long flags)
{
	DBG_LOGCALL("chflags(\"%s\", flags=%lu)\n", path, flags);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.chflags(rpath, flags);
}

int
lchflags(const char *path, unsigned long flags)
{
	DBG_LOGCALL("lchflags(\"%s\", flags=%lu)\n", path, flags);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.lchflags(rpath, flags);
}

int
chflagsat(int fd, const char *path, unsigned long flags, int atflag)
{
	DBG_LOGCALL("lchflags(fd=%d, \"%s\", flags=%lu), atflag=%x\n",
	    fd, path, flags, atflag);
	char pbuf[PATH_MAX];
	const char *rpath;
	int rfd;
	pathmapat(fd, path, &rfd, pbuf, &rpath);
	return fntable.chflagsat(rfd, rpath, flags, atflag);
}

// ktrace is not used by libc
int
ktrace(const char *tracefile, int ops, int trpoints, int pid)
{
	DBG_LOGCALL("ktrace(tracefile=\"%s\", ops=%d, trpoints=%x, pid=%d)\n",
	    tracefile, ops, trpoints, pid);
	char pbuf[PATH_MAX];
	const char *res_tracefile;
	pathmapat(AT_FDCWD, tracefile, NULL, pbuf, &res_tracefile);
	return fntable.ktrace(res_tracefile, ops, trpoints, pid);
}

// acct is not used by libc
int
acct(const char *file)
{
	DBG_LOGCALL("acct(\"%s\")\n", file);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, file, NULL, pbuf, &rpath);
	return fntable.acct(rpath);
}

// is ioctl needed?

// revoke is not used by libc
int
revoke(const char *path)
{
	DBG_LOGCALL("revoke(\"%s\")\n", path);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.revoke(rpath);
}

// symlink* are not used by libc

int
symlink(const char *name1, const char *name2)
{
	DBG_LOGCALL("symlink(target=\"%s\", linkfile=\"%s\")\n",
		name1, name2);
	char pbuf[PATH_MAX];
	const char *rname2;
	pathmapat(AT_FDCWD, name2, NULL, pbuf, &rname2);
	return fntable.symlink(name1, rname2);
}

int
symlinkat(const char *name1, int fd, const char *name2)
{
	DBG_LOGCALL("symlinkat(target=\"%s\", fd=%d, linkfile=\"%s\")\n",
	    name1, fd, name2);
	char pbuf[PATH_MAX];
	const char *rname2;
	int rfd;
	pathmapat(fd, name2, &rfd, pbuf, &rname2);
	return fntable.symlinkat(name1, rfd, rname2);
}

// readlink is used in implementation of realpath
ssize_t
readlink(const char *restrict path, char *restrict buf, size_t bufsiz)
{
	DBG_LOGCALL("readlink(\"%s\", ...)\n", path);

	// readlink is needed by dynamic linker before init() is reached
	// fprintf is also not working, using it might cause problems
	if (!fntable.readlink) fntable.readlink = __sys_readlink;

	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.readlink(rpath, buf, bufsiz);
}

// readlinkat is not used by libc
ssize_t
readlinkat(int fd, const char *restrict path, char *restrict buf, size_t bufsiz)
{
	DBG_LOGCALL("readlinkat(fd=%d, \"%s\", ...)\n", fd, path);
	char pbuf[PATH_MAX];
	const char *rpath;
	int rfd;
	pathmapat(fd, path, &rfd, pbuf, &rpath);
	return fntable.readlinkat(rfd, rpath, buf, bufsiz);
}

// execve is used internally by libc (exect,  exec, popen, posix_spawn)
// exect: execve. others: _execve
// Need to check: the source file has #!?  Then need to exec interpreter
//   ourselves, to rewrite interpreter path.
int
execve(const char *path, char *const argv[], char *const envp[])
{
	DBG_LOGCALL("execve(\"%s\", ...)\n", path);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	char * const *argve = argv;
	char * *argv2 = NULL;
	char magic[MAXSHELLCMDLEN];
	int fd = _openat(AT_FDCWD, rpath, O_RDONLY);
	if (fd==-1) return -1;
	struct stat st;
	if (fstat(fd, &st)) goto failure;
	bool exec = false;
	if (st.st_uid == geteuid()) {
	    if (st.st_mode & S_IXUSR) exec = true;
	} else if (st.st_gid ==getegid()) {
	    if (st.st_mode & S_IXGRP) exec = true;
	} else {
	    if (st.st_mode & S_IXOTH) exec = true;
	}
	if (!exec) { errno = EACCES; goto failure; }
	ssize_t readlen = read(fd, magic, MAXSHELLCMDLEN);
	if (readlen<0) { errno = EIO; goto failure; }
	if (readlen>=2 && !memcmp(magic, "#!", 2)) {
	    char *interp = magic+2;
	    char *endl = memchr(magic, '\n', readlen);
	    if (!endl) { errno = ENOEXEC; goto failure; }
	    while (isspace(*interp)) interp++;
	    char *arg = memchr(interp, ' ', readlen);
	    if (arg>endl) arg = NULL;
	    *endl = 0;
	    if (arg) { *arg = 0; arg+=1; }
	    close(fd);
	    pathmapat(AT_FDCWD, interp, NULL, pbuf, &rpath);
	    fd = _openat(AT_FDCWD, rpath, O_RDONLY);
	    if (fd==-1) return -1;
	    // rewrite argv
	    size_t arglen = 0;
	    while (argv[arglen]) arglen++;
	    if (arg) {
	        argv2 = malloc((arglen+3)*sizeof(*argv2));
		argv2[0] = interp;
		argv2[1] = arg;
		memcpy(argv2+2, argv, (arglen+1)*sizeof(*argv));
	    } else {
	        argv2 = malloc((arglen+2)*sizeof(*argv2));
		argv2[0] = interp;
		memcpy(argv2+1, argv, (arglen+1)*sizeof(*argv));
	    }
	    argve = argv2;
	}
	FILE *dbg_out_save = dbg_out;
	// exec'd process writes to wrong fd for debug output unless dbg_out
	// is cleared.  Why?
	dbg_out = NULL;
	fexecve(fd, argve, envp);
	dbg_out = dbg_out_save;
	int err;
	failure:
	    // save errno from above and restore before return
	    err = errno;
	    if (argv2) free(argv2);
	    close(fd);
	    errno = err;
	    return -1;
}

int
_execve(const char *path, char *const argv[], char *const envp[])
{
	return execve(path, argv, envp);
}

// chroot should not be used
int
chroot(const char *dirname)
{
	fprintf(stderr, "fatal: use of chroot(\n");
	exit(-1);
}

// swapon/swapoff should not be used
int
swapon(const char *special)
{
	fprintf(stderr, "fatal: use of swapon(\n");
	exit(-1);
}

int
swapoff(const char *special)
{
	fprintf(stderr, "fatal: use of swapon(\n");
	exit(-1);
}

// _connect is used internally by libc
// connect wraps the syscall through interposing table
int
connect(int s, const struct sockaddr *name, socklen_t namelen)
{
	// need to rewrite paths in sockaddrs
	return fntable.connect(s, name, namelen);
}

// connectat is not used by libc
int
connectat(int fd, int s, const struct sockaddr *name, socklen_t namelen)
{
	DBG_LOGCALL("connectat(...)\n");
	return fntable.connectat(fd, s, name, namelen);
}

// _bind is used internally by libc
// bind is normal unwrapped syscall
int
bind(int s, const struct sockaddr *addr, socklen_t addrlen)
{
	// need to rewrite paths in sockaddrs
	return fntable.bind(s, addr, addrlen);
}

// bindat is not used by libc
int
bindat(int fd, int s, const struct sockaddr *addr, socklen_t addrlen)
{
	DBG_LOGCALL("bindat(...)\n");
	return fntable.bindat(fd, s, addr, addrlen);
}

// setsockopt ?

/*
 * posix.1e
 *   __acl_* use file paths - will implement these later
 *   extattr* use file paths
 *   mac_get_file uses file paths
*/

// rename is not used by libc
int
rename(const char *from, const char *to)
{
	DBG_LOGCALL("rename(\"%s\", \"%s\")\n", from, to);
	char pbuf1[PATH_MAX];
	char pbuf2[PATH_MAX];
	const char *rfrom;
	const char *rto;
	pathmapat(AT_FDCWD, from, NULL, pbuf1, &rfrom);
	pathmapat(AT_FDCWD, to, NULL, pbuf2, &rto);
	return fntable.rename(rfrom, rto);
}

// renameat is not used by libc
int
renameat(int fromfd, const char *from, int tofd, const char *to)
{
	DBG_LOGCALL("rename(%d, \"%s\", %d, \"%s\")\n",
	    fromfd, from, tofd, to);
	char pbuf1[PATH_MAX];
	char pbuf2[PATH_MAX];
	const char *rfrom;
	const char *rto;
	int rfromfd, rtofd;
	pathmapat(fromfd, from, &rfromfd, pbuf1, &rfrom);
	pathmapat(tofd, to, &rtofd, pbuf2, &rto);
	return fntable.renameat(rfromfd, rfrom, rtofd, rto);
}

// mkfifo is not used by libc
int
mkfifo(const char *path, mode_t mode)
{
	DBG_LOGCALL("mkfifo(\"%s\", mode=%x)\n", path, mode);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.mkfifo(rpath, mode);
}

// mkfifoat is not used by libc
int
mkfifoat(int fd, const char *path, mode_t mode)
{
	DBG_LOGCALL("mkfifoat(%d, \"%s\", mode=%x)\n", fd, path, mode);
	char pbuf[PATH_MAX];
	const char *rpath;
	int rfd;
	pathmapat(fd, path, &rfd, pbuf, &rpath);
	return fntable.mkfifoat(rfd, rpath, mode);
}

// sendto and _sendto are different implementations
// sendto is used internally by libc (send, res_send, clnt_bcast, clnt_df, rtime, svc_fg, auth_time)
ssize_t
sendto(int s, const void *msg, size_t len, int flags, const struct sockaddr *to, socklen_t tolen)
{
	DBG_LOGCALL("__sys_sendto(...)\n");
	return fntable.sendto(s, msg, len, flags, to, tolen);
}

// mkdir is not used by libc
int
mkdir(const char *path, mode_t mode)
{
	DBG_LOGCALL("mkdir(\"%s\", mode=%x)\n", path, mode);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.mkdir(rpath, mode);
}

// mkdirat is not used by libc
int
mkdirat(int fd, const char *path, mode_t mode)
{
	DBG_LOGCALL("mkdirat(%d, \"%s\", mode=%x)\n", fd, path, mode);
	char pbuf[PATH_MAX];
	const char *rpath;
	int rfd;
	pathmapat(fd, path, &rfd, pbuf, &rpath);
	return fntable.mkdirat(rfd, rpath, mode);
}

// rmdir is used internally by libc (remove)
int
rmdir(const char *path)
{
	DBG_LOGCALL("rmdir(\"%s\")\n", path);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.rmdir(rpath);
}

// utimes is used internally by libc (utime)
int
utimes(const char *path, const struct timeval *times)
{
	DBG_LOGCALL("utimes(\"%s\", ...)\n", path);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.utimes(rpath, times);
}

// lutimes is used internally by libc (utime)
int
lutimes(const char *path, const struct timeval *times)
{
	DBG_LOGCALL("lutimes(\"%s\", ...)\n", path);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.lutimes(rpath, times);
}

// futimesat is not used by libc
int
futimesat(int fd, const char *path, const struct timeval times[2])
{
	DBG_LOGCALL("futimesat(%d, \"%s\", ...)\n", fd, path);
	char pbuf[PATH_MAX];
	const char *rpath;
	int rfd;
	pathmapat(fd, path, &rfd, pbuf, &rpath);
	return fntable.futimesat(rfd, rpath, times);
}

// getsockname returns a sockaddr, might need to rewrite path

// statfs is implemented by libc
// _statfs is a syscall, possibly unused (fbsd4 compat)
int
statfs(const char *path, struct statfs *buf)
{
	DBG_LOGCALL("statfs(\"%s\", ...)\n", path);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.statfs(rpath, buf);
}

// getfh is not used by libc
int
getfh(const char *path, fhandle_t *fhp)
{
	DBG_LOGCALL("getfh(\"%s\", ...)\n", path);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.getfh(rpath, fhp);
}

// lgetfh is not used by libc
int
lgetfh(const char *path, fhandle_t *fhp)
{
	DBG_LOGCALL("lgetfh(\"%s\", ...)\n", path);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.lgetfh(rpath, fhp);
}


/*int
sysarch(int number, void *args)
{
	fprintf(stderr, "fatal: use of sysarch(\n");
	exit(-1);
}*/

int
_sysarch(int number, void *args)
{
	fprintf(stderr, "fatal: use of sysarch(\n");
	exit(-1);
}

int
__sys_sysarch(int number, void *args)
{
	fprintf(stderr, "fatal: use of sysarch(\n");
	exit(-1);
}

// should be intercepting *stat* family in a manner which works correctly
// regardless of pre(i.e. freebsd11)/post ino64 changes to libc
// stat is wrapper for __sys_fstatat
int
stat(const char * restrict path, struct stat * restrict sb)
{
	DBG_LOGCALL("stat(\"%s\", ...)\n", path);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.stat(rpath, sb);
}

// lstat is wrapper for __sys_fstatat
int
lstat(const char * restrict path, struct stat * restrict sb)
{
	DBG_LOGCALL("lstat(\"%s\", ...)\n", path);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.lstat(rpath, sb);
}

// fstatat is a wrapper for __sys_fstatat
int
fstatat(int fd, const char *path, struct stat *buf, int flag)
{
	DBG_LOGCALL("fstatat(%d, \"%s\", ...)\n", fd, path);
	char pbuf[PATH_MAX];
	const char *rpath;
	int rfd;
	pathmapat(fd, path, &rfd, pbuf, &rpath);
	return fntable.fstatat(rfd, rpath, buf, flag);
}

// pathconf is used internally by libc (sysconf, statvfs)
long
pathconf(const char *path, int name)
{
	DBG_LOGCALL("pathconf(\"%s\", name=%d)\n", path, name);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.pathconf(rpath, name);
}

// lpathconf is not used by libc
long
lpathconf(const char *path, int name)
{
	DBG_LOGCALL("lpathconf(\"%s\", name=%d)\n", path, name);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.lpathconf(rpath, name);
}

// truncate is used internally by libc (pututxline)
int
truncate(const char *path, off_t length)
{
	DBG_LOGCALL("truncate(\"%s\", length=%ld)\n", path, length);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.truncate(rpath, length);
}

// undelete is not used by libc
int
undelete(const char *path)
{
	DBG_LOGCALL("undelete(\"%s\")\n", path);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.undelete(rpath);
}

// what is nstat and who uses it?

// auditctl is not used by libc
int
auditctl(const char *path)
{
	DBG_LOGCALL("auditctl(\"%s\")\n", path);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.auditctl(rpath);
}

// shm_open is not used by libc
int
shm_open(const char *path, int flags, mode_t mode)
{
	DBG_LOGCALL("shm_open(\"%s\", flags=%x, mode=%x)\n",
	    path, flags, mode);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.shm_open(rpath, flags, mode);
}

// shm_unlink is not used by libc
int
shm_unlink(const char *path, int flags, mode_t mode)
{
	DBG_LOGCALL("shm_unlink(\"%s\")\n", path);
	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	return fntable.shm_unlink(rpath);
}

// utimensat is not used by libc
int
utimensat(int fd, const char *path, const struct timespec times[2], int flag)
{
	DBG_LOGCALL("utimensat(%d, \"%s\", ...)\n", fd, path);
	char pbuf[PATH_MAX];
	const char *rpath;
	int rfd;
	pathmapat(fd, path, &rfd, pbuf, &rpath);
	return fntable.utimensat(rfd, rpath, times, flag);
}

