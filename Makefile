all: intercept.so cc

test: ldelf_addresses.test
	./ldelf_addresses.test && echo pass || echo fail

intercept.so: intercept.c pathmap.h ${MACHINE_ARCH}/patch_open.h
	${CC} -g -O0 -shared -fPIC -Wl,-znow -o ${.TARGET} intercept.c -I. -I${MACHINE_ARCH} -Wall -Werror -Wno-error=unused-function -lelf

cc: cc.c
	${CC} -g -O0 -static -o ${.TARGET} cc.c -Wall -Werror

ldelf_addresses.test: ldelf_addresses.test.c ldelf_addresses.h
	${CC} -o ${.TARGET} ldelf_addresses.test.c -Wall -Werror -Wno-error=unused-function -lelf

PREFIX?=/usr/local

install: all
	@mkdir -p ${DESTDIR}${PREFIX}/libexec/userns
	cp cc ${DESTDIR}${PREFIX}/libexec/userns/
	cp intercept.so ${DESTDIR}${PREFIX}/libexec/userns/
