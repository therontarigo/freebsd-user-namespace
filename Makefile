intercept.so: intercept.c
	cc -g -O0 -shared -fPIC -o ${.TARGET} intercept.c -Wall -Werror -Wno-error=unused-function
