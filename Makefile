intercept.so: intercept.c ${MACHINE_ARCH}/patch_open.h
	cc -g -O0 -shared -fPIC -Wl,-znow -o ${.TARGET} intercept.c -I${MACHINE_ARCH} -Wall -Werror -Wno-error=unused-function
