all: intercept.so cc

intercept.so: intercept.c pathmap.h ${MACHINE_ARCH}/patch_open.h
	${CC} -g -O0 -shared -fPIC -Wl,-znow -o ${.TARGET} intercept.c -I${MACHINE_ARCH} -Wall -Werror -Wno-error=unused-function

cc: cc.c
	${CC} -g -O0 -static -o ${.TARGET} cc.c -Wall -Werror

PREFIX?=/usr/local

install: all
	@mkdir -p ${DESTDIR}${PREFIX}/libexec/userns
	cp cc ${DESTDIR}${PREFIX}/libexec/userns/
	cp intercept.so ${DESTDIR}${PREFIX}/libexec/userns/
