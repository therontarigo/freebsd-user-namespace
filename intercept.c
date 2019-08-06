
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

#define shm_unlink _shm_unlink
#include <sys/mman.h> // mprotect
#undef shm_unlink

#include "userns.h"
#include "dbglog.h"
#include "mapspec.h"
#include "pathmap.h"
#include "exe_runpath.h"

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
typedef int	(*fn_fexecve_t)	(int fd, char *const [], char * const []);
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

typedef pid_t	(*fn_fork_t)	(void);
typedef int	(*fn_dprintf_t)	(int fd, const char * restrict format, ...);

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
	fn_fexecve_t	fexecve;
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
	fn_fork_t	fork;
} fntable = {0};

ssize_t
__sys_readlink(const char *restrict path, char *restrict buf, size_t bufsiz);

int
_open(const char *path, int flags, ...);

#include "patch_open.h"

__attribute__((constructor))
static void
intercept_doinit()
{
	/*
	 * dprintf: call once such that all lazy-resolved symbols it requires
	 * become resolved, so that a lock over rtld does not later occur.
	 * Important: string cannot be empty
	 */
	dprintf(-1, " ");
	char *dbg_log_filepath_env = getenv("INTERCEPT_DBGLOGFILE");
	/*
	 * Save dbg file path in case the file later needs to be reopened, as
	 * in case of fork.  This also avoids any further getenv, which could
	 * fail since some program such as env(1) might unset it
	 */
	if (dbg_log_filepath_env) {
	    dbg_log_filepath = malloc(strlen(dbg_log_filepath_env)+1);
	    strcpy(dbg_log_filepath, dbg_log_filepath_env);
	}

	void *libc = dlopen("/lib/libc.so.7", RTLD_NOW);

	#define FINDSYM(name,sym)					\
	    {								\
		fntable.name = (fn_##name##_t)dlfunc(libc, #sym);	\
		if (!fntable.name) {					\
		    fprintf(stderr, "fatal: %s not found\n", #sym);	\
		    _exit(-1);						\
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
	FINDSYM(fexecve,fexecve)
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
	FINDSYM(fork,fork)

	#undef FINDSYM

	dbg_openlog();
	dbg_log_calls=(NULL!=getenv("INTERCEPT_LOG_CALLS"));
	dbg_log_pathmap=(NULL!=getenv("INTERCEPT_LOG_PATHMAP"));

	mapspec_read();
	patch_open();
	/*
	 * patch_open: Now if rtld-elf calls our open, and open calls an
	 * unresolved function, rtld would be reentered and would hang on
	 * acquiring its own lock.  The library must be compiled with -znow
	 * linker option to avoid this.
	 */
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

	// readlink is needed by dynamic linker before init() is reached
	// fprintf is also not working, using it might cause problems
	if (!fntable.readlink)
	    return __sys_readlink(path, buf, bufsiz);

	DBG_LOGCALL("readlink(\"%s\", ...)\n", path);

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

pid_t
fork(void)
{
	/*
	 * Close outputs before fork, since some programs incl. /bin/sh make
	 * assumptions about file descriptors which can't otherwise be met.
	 */
	dbg_closelog();
	return fntable.fork();
}

int
fexecve(int fd, char *const argv[], char *const envp[])
{
	return fntable.fexecve(fd, argv, envp);
}

void
prevfork(void)
{
	/* Close output before vfork, as for fork */
	dbg_closelog();
}

#include "jump_vfork.h"

// execve is used internally by libc (exect,  exec, popen, posix_spawn)
// exect: execve. others: _execve
// Need to check: the source file has #!?  Then need to exec interpreter
//   ourselves, to rewrite interpreter path.
// libc: execve and _execve are same.
int
execve(const char *path, char *const argv[], char *const envp[])
{
	/* in case of exec without fork */
	if (DBG_OUTOPEN) dbg_closelog();
	/* now reopen output with fd which needn't be preserved */
	dbg_openlog();
	DBG_LOGCALL("execve(\"%s\", ...)\n", path);

#ifdef INTERCEPT_DBG_EXEC_ARGS
	for (int iarg=0; argv[iarg]; iarg++) {
	    DBG_LOGCALL("execve:  argv[%d] = \"%s\"\n", iarg, argv[iarg]);
	}
#ifdef INTERCEPT_DBG_EXEC_ENV
	for (int iarg=0; envp[iarg]; iarg++) {
	    DBG_LOGCALL("execve:  envp[%d] = \"%s\"\n", iarg, envp[iarg]);
	}
#endif
#endif

	char pbuf[PATH_MAX];
	const char *rpath;
	pathmapat(AT_FDCWD, path, NULL, pbuf, &rpath);
	char * const *argve = argv; /* potentially modified argv */
	char * const *envpe = envp; /* potentially modified envp */
	char * *argv2 = NULL;
	char * *envp2 = NULL;
	char *scriptpath = NULL;
	char *libmap = NULL;
	char magic[MAXSHELLCMDLEN];
	int fd = fntable.openat(AT_FDCWD, rpath, O_RDONLY, 0);
	if (fd==-1) goto failure;
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
	if (readlen>0 && magic[0] >= 0x7f) {
	    /*
	     * Executable file with ELF magic number or greater is potentially
	     * an ELF object; try to read it as such.
	     */
	    char *ldrunpath;
	    char *ldrpath;
	    /*
	     * Read the ELF headers of the executable.  If it uses RUNPATH or
	     * RPATH, translate the paths as needed and create LD_LIBMAP
	     * mappings to handle path mappings.
	     *
	     * BUG: The executable may require library objects which themselves
	     * use RUNPATH.  This case is not checked.  A proper solution would
	     * be to recursively look up all required libraries, duplicating
	     * much of the functionality of ld-elf.so.1.
	     *
	     * BUG: LD_LIBMAP is unconditionally appended to environment.  This
	     * is not correct behavior for the case of LD_LIBMAP already
	     * existing in the environment.
	     *
	     * Existing LD_LIBRARY_PATH in environment should also be handled
	     * similarly to DT_RUNPATH.  This is not implemented.
	     */
	    int ret = exe_runpath(fd, &ldrunpath, &ldrpath);
	    /* If ELF but no shared section */
	    if (ret == EXE_RUNPATH_NOSHARED) goto nofixes;
	    /* Otherwise invalid ELF header */
	    if (ret != EXE_RUNPATH_SUCCESS) {
		/*
		 * Intercept Library is known to work only with ELF executables
		 * (and by extension various scripting interpreters), so if
		 * the executable file is neither, fail now rather than wait
		 * for trouble.
		 */
		errno = ENOEXEC; goto failure;
	    }
	    if (!ldrunpath && !ldrpath) goto nofixes;
	    const char *libmap_prefix = "LD_LIBMAP=";
	    ssize_t libmap_end = strlen(libmap_prefix) - 1;
	    libmap = malloc(libmap_end + 2);
	    strcpy(libmap, libmap_prefix);
	    for (char *pn, *p = ldrunpath; p; p = pn) {
		/* p: path; rp: resolved path */
		pn = strchr(p, ':');
		if (pn) { *pn = '\0'; pn++; }
		char pbuf[PATH_MAX];
		const char *rp;
	        pathmapat(AT_FDCWD, p, NULL, pbuf, &rp);
		size_t p_len = strlen(p);
		size_t rp_len = strlen(rp);
		/* format: ",${p}=${rp}" -> +3 chars: ',' '=' '\0' */
		libmap = realloc(libmap, libmap_end + p_len + rp_len + 3);
		char *wr = libmap + libmap_end;
		if (*wr != '=') *wr = ',';
		wr += 1;
		int nw = snprintf(wr, p_len + rp_len + 2, "%s=%s", p, rp);
		if (nw > 0) libmap_end += nw;
	    }
	    free(ldrunpath);
	    free(ldrpath);
	} else /* !(magic[0] >= 0x7f) */ {
	    /*
	     * Magic number in printable range identifies a script.
	     * This block is also reached for case of empty file, which is
	     * assumed under FreeBSD to be a /bin/sh script, as is done here.
	     */
	    char *interp;
	    char *arg;
	    if (readlen>=2 && !memcmp(magic, "#!", 2)) {
	        interp = magic+2;
	        char *endl = memchr(magic, '\n', readlen);
	        if (!endl) { errno = ENOEXEC; goto failure; }
	        while (isspace(*interp)) interp++;
	        arg = memchr(interp, ' ', readlen);
	        if (arg>endl) arg = NULL;
	        *endl = 0;
	        if (arg) { *arg = 0; arg+=1; }
	        close(fd);
	        pathmapat(AT_FDCWD, interp, NULL, pbuf, &rpath);
	    } else {
		arg = NULL;
		strcpy(pbuf, "/bin/sh");
		interp = pbuf;
		rpath = pbuf;
	    }
	    fd = fntable.openat(AT_FDCWD, rpath, O_RDONLY, 0);
	    if (fd==-1) goto failure;
	    scriptpath = malloc(strlen(path)+1);
	    strcpy(scriptpath, path);
	    size_t arglen = 0;
	    while (argv[arglen]) arglen++;
	    if (arg) {
	        argv2 = malloc((arglen+3)*sizeof(*argv2));
		argv2[0] = interp;
		argv2[1] = arg;
		argv2[2] = scriptpath;
		memcpy(argv2+3, argv+1, (arglen)*sizeof(*argv));
	    } else {
	        argv2 = malloc((arglen+2)*sizeof(*argv2));
		argv2[0] = interp;
		argv2[1] = scriptpath;
		memcpy(argv2+2, argv+1, (arglen)*sizeof(*argv));
	    }
	    argve = argv2;
	}
	nofixes:

	if (libmap) {
	    size_t envlen = 0;
	    while (envp[envlen]) envlen++;
	    envp2 = malloc((envlen + 2) * sizeof(*envp2));
	    memcpy(envp2, envp, envlen * sizeof(*envp));
	    envp2[envlen] = libmap;
	    envp2[envlen + 1] = NULL;
	    envpe = envp2;
	}

	dbg_closelog();
	fexecve(fd, argve, envpe);

	int err;
	failure:
	    // save errno from above and restore before return
	    err = errno;
	    if (argv2) free(argv2);
	    if (envp2) free(envp2);
	    if (libmap) free(libmap);
	    if (scriptpath) free(scriptpath);
	    close(fd);
	    dbg_closelog();
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


/*
getdirentries: Need to show overlay of real fs and namespace.
Need also a fake fd system for allowing ghost directories to be openable.
procedure:
  make an empty list of directory entries
  for each path mapping:
    look up the target in the path mapping
    get its directory entries
    for each entry which does is not present in the list:
      add the entry to the list
  return the list of directory entries.
*/

// should be intercepting *stat* family in a manner which works correctly
// regardless of pre(i.e. freebsd11)/post ino64 changes to libc

/*
Stat procedure:
  Map the path.
  If the path resolves to a target which exists, stat it and return.
  Otherwise:
  For each path mapping entry:
    If the path matches all but the last component of the entry:
      Return stat structure for a directory.
  (Don't need to check for all components matching, since that would have
   succeeded above)
  Otherwise: return no ent error
*/

// fstatat is a wrapper for __sys_fstatat
int
fstatat(int fd, const char *path, struct stat *buf, int flag)
{
	DBG_LOGCALL("fstatat(%d, \"%s\", ...)\n", fd, path);
	char pbuf[PATH_MAX];
	const char *rpath;
	int rfd;
	pathmapat(fd, path, &rfd, pbuf, &rpath);
	if (0==fntable.fstatat(rfd, rpath, buf, flag)) return 0;
	if (errno!=ENOENT) return -1;
	size_t path_len = strlen(path);
        for (size_t i = 0; i <= maptable_len; i++) {
	    if (i==maptable_len) {
		errno = ENOENT;
		return -1;
	    }
	    const char *src = maptable[i].src;
	    if (strlen(src)<path_len) continue;
	    if (strncmp(src, path, path_len)) continue;
	    if (!(src[path_len]==0 || src[path_len]=='/')) continue;
	    break;
	}
	memset(buf, 0, sizeof(*buf));
	buf->st_dev = -1;
	buf->st_ino = -1;
	buf->st_uid = getuid();
	buf->st_gid = getgid();
	buf->st_mode |= S_IFDIR;
	buf->st_mode |= S_IRUSR | S_IXUSR;
	buf->st_mode |= S_IRGRP | S_IXGRP;
	buf->st_mode |= S_IROTH | S_IXOTH;
	return 0;
}

// stat is wrapper for fstatat
int
stat(const char * restrict path, struct stat * restrict sb)
{
	return fstatat(AT_FDCWD, path, sb, 0);
}

// lstat is wrapper for fstatat
int
lstat(const char * restrict path, struct stat * restrict sb)
{
	return fstatat(AT_FDCWD, path, sb, AT_SYMLINK_NOFOLLOW);
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

