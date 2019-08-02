
SRCDIR=	${.CURDIR}/..
.PATH: ${SRCDIR}

PROG=	intercept.so
SRCS=	intercept.c
MAN=

CFLAGS+=	-I${SRCDIR}/${MACHINE_ARCH} -I${SRCDIR}
CFLAGS+=	-shared -fPIC -Wl,-znow
LDADD+=		-lelf

.include <bsd.prog.mk>
