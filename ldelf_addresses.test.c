
#include <stdio.h>
#include "ldelf_addresses.h"

int
main(int argc, char **argv)
{

	const char *fnnames[] = { "dlopen", "open", "_openat" };
	struct { size_t dlopen, open, _openat; } addrs;

	if (ldelf_addresses(3, fnnames, (size_t *)&addrs)) {
		return 1;
	}

	printf("address of \"%s\": %016lx\n", "open", addrs.open);

	printf("(open-dlopen)   = %16lx\n", addrs.open - addrs.dlopen);
	printf("(openat-dlopen) = %16lx\n", addrs._openat - addrs.dlopen);

	return 0;
}
