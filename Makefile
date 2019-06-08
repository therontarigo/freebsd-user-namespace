intercept.so: intercept.c
	cc -shared -fPIC -o ${.TARGET} intercept.c -Wall -Werror -Wno-error=unused-function
