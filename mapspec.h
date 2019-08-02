
#ifndef _MAPSPEC_H_
#define _MAPSPEC_H_

#include <stddef.h>

#include "userns.h"

extern struct maptabent {
        // src: location in virtual namespace
        // dst: location on real filesystem
        const char *src;
        const char *dst;
} * maptable;
extern size_t maptable_len;

void	mapspec_read();

#endif /* !_MAPSPEC_H_ */
