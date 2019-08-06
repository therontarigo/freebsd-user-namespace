
SRCDIR=	${.CURDIR}/..
.PATH: ${SRCDIR}

PROG=	intercept.so
SRCS=	intercept.c pathmap.c mapspec.c dbglog.c exe_runpath.c
MAN=

CFLAGS+=	-Wall -Werror
CFLAGS+=	-I${SRCDIR}/${MACHINE_ARCH} -I${SRCDIR}
CFLAGS+=	-shared -fPIC -Wl,-znow
LDADD+=		-lelf

.include <bsd.prog.mk>
