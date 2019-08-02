BINDIR?=	${PREFIX}/libexec/userns
PREFIX?=	/usr/local
DIRS+=		BINDIR
beforeinstall: installdirs
