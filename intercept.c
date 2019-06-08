#include "pathmap.h"

#include <stdio.h>
#include <dlfcn.h>

#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/mount.h>
#include "/usr/src/lib/libc/include/libc_private.h" // should be removed

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

static struct {
	fn_open_t	open;
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

bool dbg_log_calls;

ssize_t
__sys_readlink(const char *restrict path, char *restrict buf, size_t bufsiz);

__attribute__((constructor))
static void init() {

	void *libc = dlopen("/lib/libc.so.7", RTLD_NOW);
	fprintf(stderr, "Opened libc at %p\n", libc);

	#define FINDSYM(name,sym)					\
	    {								\
		fntable.name = (fn_##name##_t)dlfunc(libc, #sym);	\
		if (!fntable.name) {					\
		    fprintf(stderr, "fatal: %s not found\n", #sym);	\
		    exit(-1);						\
		}							\
	    }

	FINDSYM(open, __sys_open)
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

	dbg_log_calls=(NULL!=getenv("INTERCEPT_LOG_CALLS"));

	// Initialize path map table
	maptable_len=1;
	maptable = malloc(maptable_len*sizeof(*maptable));
	maptable[1]=(struct maptabent){"/","/"};
}

int
__sys_syscall(int number, ...)
{
	fprintf(stderr, "fatal: use of __sys_syscall(\n");
	exit(-1);
}

int
syscall(int number, ...)
{
	fprintf(stderr, "fatal: use of syscall(\n");
	exit(-1);
}

int
_syscall(int number, ...)
{
	fprintf(stderr, "fatal: use of _syscall(\n");
	exit(-1);
}

off_t
__syscall(quad_t number, ...)
{
	fprintf(stderr, "fatal: use of __syscall(\n");
	exit(-1);
}

off_t
___syscall(quad_t number, ...)
{
	fprintf(stderr, "fatal: use of ___syscall(\n");
	exit(-1);
}

off_t
__sys___syscall(quad_t number, ...)
{
	fprintf(stderr, "fatal: use of __sys___syscall(\n");
	exit(-1);
}

// open and _open are different implementations
int
_open (const char *path, int flags, ...)
{
	mode_t mode = (mode_t){0};
	if (flags & O_CREAT) {
	    va_list ap;
	    va_start(ap, flags);
	    mode = va_arg(ap, int);
	    va_end(ap);
	}
	if (dbg_log_calls)
	    fprintf(stderr, "open(path=\"%s\",flags=%x)\n", path, flags);
	return fntable.open(path,flags,mode);
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
	if (dbg_log_calls)
	    fprintf(stderr, "openat(fd=%d, path=\"%s\",flags=%x)\n",
		fd, path, flags);
	return fntable.openat(fd,path,flags,mode);
}

int
__sys_link(const char *name1, const char *name2)
{
	if (dbg_log_calls)
	    fprintf(stderr, "link(name1=\"%s\", name2=\"%s\")\n",
		name1, name2);
	return fntable.link(name1, name2);
}

// q: why is there only linkat and no __sys_linkat ?
// libc.a (linkat.o) contains __sys_linkat
// why does it not exist in libc.so ?
int
linkat(int fd1, const char *name1, int fd2, const char *name2, int flag)
{
	if (dbg_log_calls)
	    fprintf(stderr,
	        "linkat(fd1=%d, name1=\"%s\", fd2=%d, name2=\"%s\", flag=%x)\n"
		, fd1, name1, fd2, name2, flag);
	return fntable.linkat(fd1, name1, fd2, name2, flag);
}

// unlink is used internally by libc
//   (bt_open, hash_page, sem_new, tmpfile, remove)
int
unlink(const char *path)
{
	if (dbg_log_calls)
	    fprintf(stderr, "unlink(\"%s\")\n", path);
	return fntable.unlink(path);
}

// unlinkat is not used by libc
int
unlinkat(int fd, const char *path, int flag)
{
	if (dbg_log_calls)
	    fprintf(stderr, "unlink(%d, \"%s\", flag=%x)\n", fd, path, flag);
	return fntable.unlinkat(fd, path, flag);
}

int
chdir(const char *path)
{
	if (dbg_log_calls)
	    fprintf(stderr, "chdir(\"%s\")\n", path);
	return fntable.chdir(path);
}

// mknod is wrapper for __sys_mknodat
// mknod is not a syscall on fbsd12+
int
mknod(const char *path, mode_t mode, dev_t dev)
{
	if (dbg_log_calls)
	    fprintf(stderr, "mknod(\"%s\", mode=%x, dev=%lx)\n", path, mode, dev);
	return fntable.mknod(path, mode, dev);
}

int
mknodat(int fd, const char *path, mode_t mode, dev_t dev)
{
	if (dbg_log_calls)
	    fprintf(stderr, "mknodat(fd=%d, path=\"%s\", mode=%x, dev=%lx)\n",
	      fd, path, mode, dev);
	return fntable.mknodat(fd, path, mode, dev);
}

// chmod is not used by libc
int
chmod(const char *path, mode_t mode)
{
	if (dbg_log_calls)
	    fprintf(stderr, "chown(\"%s\", mode=%x)\n", path, mode);
	return fntable.chmod(path, mode);
}

// lchmod is not used by libc
int
lchmod(const char *path, mode_t mode)
{
	if (dbg_log_calls)
	    fprintf(stderr, "lchown(\"%s\", mode=%x)\n", path, mode);
	return fntable.lchmod(path, mode);
}

// fchmodat is not used by libc
int
fchmodat(int fd, const char *path, mode_t mode, int flag)
{
	if (dbg_log_calls)
	    fprintf(stderr, "fchmodat(%d, \"%s\", mode=%x, flag=%x)\n",
		fd, path, mode, flag);
	return fntable.fchmodat(fd, path, mode, flag);
}

// chown is not used by libc
int
chown(const char *path, uid_t owner, gid_t group)
{
	if (dbg_log_calls)
	    fprintf(stderr, "chown(\"%s\", owner=%x, group=%x)\n", path, owner, group);
	return fntable.chown(path, owner, group);
}

// lchown is not used by libc
int
lchown(const char *path, uid_t owner, gid_t group)
{
	if (dbg_log_calls)
	    fprintf(stderr, "lchown(\"%s\", owner=%x, group=%x)\n", path, owner, group);
	return fntable.lchown(path, owner, group);
}

// fchownat is not used by libc
int
fchownat(int fd, const char *path, uid_t owner, gid_t group, int flag)
{
	if (dbg_log_calls)
	    fprintf(stderr,
	      "fchownat(fd=%d, path=\"%s\", owner=%x, group=%x, flag=%x)\n",
	      fd, path, owner, group, flag);
	return fntable.fchownat(fd, path, owner, group, flag);
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
	if (dbg_log_calls)
	    fprintf(stderr, "accept(...)\n");
	int ret = fntable.accept(s, addr, addrlen);
	// need to rewrite sockaddr if it contains a path
	return ret;
}

// accept4 is not used by libc
int
accept4(int s, struct sockaddr * restrict addr, socklen_t * restrict addrlen,
        int flags)
{
	if (dbg_log_calls)
	    fprintf(stderr, "accept(...)\n");
	int ret = fntable.accept4(s, addr, addrlen, flags);
	// need to rewrite sockaddr if it contains a path
	return ret;
}

// access is not used by libc (?)
int
access(const char *path, int mode)
{
	if (dbg_log_calls)
	    fprintf(stderr, "access(\"%s\", mode=%x)\n", path, mode);
	return fntable.access(path, mode);
}

// eaccess is not used by libc
int
eaccess(const char *path, int mode)
{
	if (dbg_log_calls)
	    fprintf(stderr, "eaccess(\"%s\", mode=%x)\n", path, mode);
	return fntable.eaccess(path, mode);
}

// faccessat is not used by libc
int faccessat(int fd, const char *path, int mode, int flag)
{
	if (dbg_log_calls)
	    fprintf(stderr, "faccessat(fd=%d, \"%s\", mode=%x, flag=%x)\n",
	      fd, path, mode, flag);
	return fntable.faccessat(fd, path, mode, flag);
}

// *chflags* are not usd by libc
int
chflags(const char *path, unsigned long flags)
{
	if (dbg_log_calls)
	    fprintf(stderr, "chflags(\"%s\", flags=%lu)\n", path, flags);
	return fntable.chflags(path, flags);
}

int
lchflags(const char *path, unsigned long flags)
{
	if (dbg_log_calls)
	    fprintf(stderr, "lchflags(\"%s\", flags=%lu)\n", path, flags);
	return fntable.lchflags(path, flags);
}

int
chflagsat(int fd, const char *path, unsigned long flags, int atflag)
{
	if (dbg_log_calls)
	    fprintf(stderr, "lchflags(fd=%d, \"%s\", flags=%lu), atflag=%x\n",
	      fd, path, flags, atflag);
	return fntable.chflagsat(fd, path, flags, atflag);
}

// ktrace is not used by libc
int
ktrace(const char *tracefile, int ops, int trpoints, int pid)
{
	if (dbg_log_calls)
	    fprintf(stderr, "ktrace(tracefile=\"%s\", ops=%d, trpoints=%x, pid=%d)\n",
	      tracefile, ops, trpoints, pid);
	return fntable.ktrace(tracefile, ops, trpoints, pid);
}

// acct is not used by libc
int
acct(const char *file)
{
	if (dbg_log_calls)
	    fprintf(stderr, "acct(\"%s\")\n", file);
	return fntable.acct(file);
}

// is ioctl needed?

// revoke is not used by libc
int
revoke(const char *path)
{
	if (dbg_log_calls)
	    fprintf(stderr, "revoke(\"%s\")\n", path);
	return fntable.revoke(path);
}

// symlink* are not used by libc

int
symlink(const char *name1, const char *name2)
{
	if (dbg_log_calls)
	    fprintf(stderr, "symlink(target=\"%s\", linkfile=\"%s\")\n", name1, name2);
	return fntable.symlink(name1, name2);
}

int
symlinkat(const char *name1, int fd, const char *name2)
{
	if (dbg_log_calls)
	    fprintf(stderr, "symlinkat(target=\"%s\", fd=%d, linkfile=\"%s\")\n",
	      name1, fd, name2);
	return fntable.symlinkat(name1, fd, name2);
}

// readlink is used in implementation of realpath
ssize_t
readlink(const char *restrict path, char *restrict buf, size_t bufsiz)
{
	if (dbg_log_calls)
	    fprintf(stderr, "readlink(\"%s\", ...)\n", path);

	// readlink is needed by dynamic linker before init() is reached
	// fprintf is also not working, using it might cause problems
	if (!fntable.readlink) fntable.readlink = __sys_readlink;

	return fntable.readlink(path, buf, bufsiz);
//  return __sys_readlink(path, buf, bufsiz);
}

// readlinkat is not used by libc
ssize_t
readlinkat(int fd, const char *restrict path, char *restrict buf, size_t bufsiz)
{
	if (dbg_log_calls)
	    fprintf(stderr, "readlinkat(fd=%d, \"%s\", ...)\n", fd, path);
	return fntable.readlinkat(fd, path, buf, bufsiz);
}

// execve is used internally by libc (exect,  exec, popen, posix_spawn)
// exect: execve. others: _execve
int
execve(const char *path, char *const argv[], char *const envp[])
{
	if (dbg_log_calls)
	    fprintf(stderr, "execve(\"%s\", ...)\n", path);
	return fntable.execve(path, argv, envp);
}

// chroot is not used by libc
int
chroot(const char *dirname)
{
	if (dbg_log_calls)
	    fprintf(stderr, "chroot(\"%s\")\n", dirname);
	return fntable.chroot(dirname);
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
	if (dbg_log_calls)
	    fprintf(stderr, "connectat(...)\n");
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
	if (dbg_log_calls)
	    fprintf(stderr, "bindat(...)\n");
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
	if (dbg_log_calls)
	    fprintf(stderr, "rename(\"%s\", \"%s\")\n", from, to);
	return fntable.rename(from, to);
}

// renameat is not used by libc
int
renameat(int fromfd, const char *from, int tofd, const char *to)
{
	if (dbg_log_calls)
	    fprintf(stderr, "rename(%d, \"%s\", %d, \"%s\")\n",
	      fromfd, from, tofd, to);
	return fntable.renameat(fromfd, from, tofd, to);
}

// mkfifo is not used by libc
int
mkfifo(const char *path, mode_t mode)
{
	if (dbg_log_calls)
	    fprintf(stderr, "mkfifo(\"%s\", mode=%x)\n", path, mode);
	return fntable.mkfifo(path, mode);
}

// mkfifoat is not used by libc
int
mkfifoat(int fd, const char *path, mode_t mode)
{
	if (dbg_log_calls)
	    fprintf(stderr, "mkfifoat(%d, \"%s\", mode=%x)\n", fd, path, mode);
	return fntable.mkfifoat(fd, path, mode);
}

// sendto and _sendto are different implementations
// sendto is used internally by libc (send, res_send, clnt_bcast, clnt_df, rtime, svc_fg, auth_time)
ssize_t
sendto(int s, const void *msg, size_t len, int flags, const struct sockaddr *to, socklen_t tolen)
{
	if (dbg_log_calls)
	    fprintf(stderr, "__sys_sendto(...)\n");
	return fntable.sendto(s, msg, len, flags, to, tolen);
}

// mkdir is not used by libc
int
mkdir(const char *path, mode_t mode)
{
	if (dbg_log_calls)
	    fprintf(stderr, "mkdir(\"%s\", mode=%x)\n", path, mode);
	return fntable.mkdir(path, mode);
}

// mkdirat is not used by libc
int
mkdirat(int fd, const char *path, mode_t mode)
{
	if (dbg_log_calls)
	    fprintf(stderr, "mkdirat(%d, \"%s\", mode=%x)\n", fd, path, mode);
	return fntable.mkdirat(fd, path, mode);
}

// rmdir is used internally by libc (remove)
int
rmdir(const char *path)
{
	if (dbg_log_calls)
	    fprintf(stderr, "rmdir(\"%s\")\n", path);
	return fntable.rmdir(path);
}

// utimes is used internally by libc (utime)
int
utimes(const char *path, const struct timeval *times)
{
	if (dbg_log_calls)
	    fprintf(stderr, "utimes(\"%s\", ...)\n", path);
	return fntable.utimes(path, times);
}

// lutimes is used internally by libc (utime)
int
lutimes(const char *path, const struct timeval *times)
{
	if (dbg_log_calls)
	    fprintf(stderr, "lutimes(\"%s\", ...)\n", path);
	return fntable.lutimes(path, times);
}

// futimesat is not used by libc
int
futimesat(int fd, const char *path, const struct timeval times[2])
{
	if (dbg_log_calls)
	    fprintf(stderr, "futimesat(%d, \"%s\", ...)\n", fd, path);
	return fntable.futimesat(fd, path, times);
}

// getsockname returns a sockaddr, might need to rewrite path

// statfs is implemented by libc
// _statfs is a syscall, possibly unused (fbsd4 compat)
int
statfs(const char *path, struct statfs *buf)
{
	if (dbg_log_calls)
	    fprintf(stderr, "statfs(\"%s\", ...)\n", path);
	return fntable.statfs(path, buf);
}

// getfh is not used by libc
int
getfh(const char *path, fhandle_t *fhp)
{
	if (dbg_log_calls)
	    fprintf(stderr, "getfh(\"%s\", ...)\n", path);
	return fntable.getfh(path, fhp);
}

// lgetfh is not used by libc
int
lgetfh(const char *path, fhandle_t *fhp)
{
	if (dbg_log_calls)
	    fprintf(stderr, "lgetfh(\"%s\", ...)\n", path);
	return fntable.lgetfh(path, fhp);
}


int
sysarch(int number, void *args)
{
	fprintf(stderr, "fatal: use of sysarch(\n");
	exit(-1);
}

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
	if (dbg_log_calls)
	    fprintf(stderr, "stat(\"%s\", ...)\n", path);
	return fntable.stat(path, sb);
}

// lstat is wrapper for __sys_fstatat
int
lstat(const char * restrict path, struct stat * restrict sb)
{
	if (dbg_log_calls)
	    fprintf(stderr, "lstat(\"%s\", ...)\n", path);
	return fntable.lstat(path, sb);
}

// fstatat is a wrapper for __sys_fstatat
int
fstatat(int fd, const char *path, struct stat *buf, int flag)
{
	if (dbg_log_calls)
	    fprintf(stderr, "fstatat(%d, \"%s\", ...)\n", fd, path);
	return fntable.fstatat(fd, path, buf, flag);
}

// pathconf is used internally by libc (sysconf, statvfs)
long
pathconf(const char *path, int name)
{
	if (dbg_log_calls)
	    fprintf(stderr, "pathconf(\"%s\", name=%d)\n", path, name);
	return fntable.pathconf(path, name);
}

// lpathconf is not used by libc
long
lpathconf(const char *path, int name)
{
	if (dbg_log_calls)
	    fprintf(stderr, "lpathconf(\"%s\", name=%d)\n", path, name);
	return fntable.lpathconf(path, name);
}

// truncate is used internally by libc (pututxline)
int
truncate(const char *path, off_t length)
{
	if (dbg_log_calls)
	    fprintf(stderr, "truncate(\"%s\", length=%ld)\n", path, length);
	return fntable.truncate(path, length);
}

// undelete is not used by libc
int
undelete(const char *path)
{
	if (dbg_log_calls)
	    fprintf(stderr, "undelete(\"%s\")\n", path);
	return fntable.undelete(path);
}

// what is nstat and who uses it?

// auditctl is not used by libc
int
auditctl(const char *path)
{
	if (dbg_log_calls)
	    fprintf(stderr, "auditctl(\"%s\")\n", path);
	return fntable.auditctl(path);
}

// shm_open is not used by libc
int
shm_open(const char *path, int flags, mode_t mode)
{
	if (dbg_log_calls)
	    fprintf(stderr, "shm_open(\"%s\", flags=%x, mode=%x)\n",
		path, flags, mode);
	return fntable.shm_open(path, flags, mode);
}

// shm_unlink is not used by libc
int
shm_unlink(const char *path, int flags, mode_t mode)
{
	if (dbg_log_calls)
	    fprintf(stderr, "shm_unlink(\"%s\")\n", path);
	return fntable.shm_unlink(path);
}

// utimensat is not used by libc
int
utimensat(int fd, const char *path, const struct timespec times[2], int flag)
{
	if (dbg_log_calls)
	    fprintf(stderr, "utimensat(%d, \"%s\", ...)\n", fd, path);
	return fntable.utimensat(fd, path, times, flag);
}
