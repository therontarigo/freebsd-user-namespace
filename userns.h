
#ifndef _USERNS_H_
#define _USERNS_H_

#define USERNS_PRIVATE __attribute__((visibility("hidden")))

int	__sys_open (const char *path, int flags, ...);

#endif /* !_USERNS_H_ */
