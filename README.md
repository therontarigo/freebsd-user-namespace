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
    # enable logging of path translations
    export INTERCEPT_LOG_PATHMAP=1
    export INTERCEPT_DBGLOGFILE=/dev/stderr
    # Map /usr/local to /tmp and / to /
    export FILEPATHMAP=/usr/local%/tmp:/%/
    echo hello > /tmp/foo
    env LD_PRELOAD=$PWD/intercept/intercept.so cat /usr/local/foo

A more complex namespace may be built up through adding mappings to
FILEPATHMAP.

See doc/MANUAL.txt
