# freebsd-user-namespace
Userspace Filesystem Namespace

Intercepts libc filesystem operations to hide the real filesystem from the
process and provide instead a configurable namespace mapping virtual locations
to real locations.

This library cannot be used to restrict access to the underlying filesystem; a
program may trivially work around the interception mechanism.

To keep the implementation minimal, interception is performed as closely as
possible to the system call level.  As a result, the implementation is not
portable.

This tool is not intended for use by superuser; superuser-only syscalls are not
supported.

### Demonstration Usage
    make
    cc -o test2 test2.c
    cc -o test3 test3.c
    # enable logging of calls
    export INTERCEPT_LOG_CALLS=1
    export INTERCEPT_DBGLOGFILE=/dev/stderr
    # Map /usr/local to /tmp and / to /
    export FILEPATHMAP=/usr/local%/tmp:/%/
    # test a wild FreeBSD binary (uses fstat)
    env LD_PRELOAD=$PWD/intercept.so ls
    # test basic call interception
    env LD_PRELOAD=$PWD/intercept.so ./test2
    # test warning for unsupported superuser syscalls
    env LD_PRELOAD=$PWD/intercept.so ./test3
