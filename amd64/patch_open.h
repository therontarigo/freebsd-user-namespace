
static void patch_open() {
	void *rtld_dlopen = (dlopen);
	if (rtld_dlopen < (void *)0x0000000800000000) return; // plt
	// magic numbers: offset from dlopen to open in ld-elf.so
	void *openaddr = (rtld_dlopen) + (0x800223820 - 0x800215030);
	void *newopen = (open);
	long jmprel = (long)(newopen-openaddr);
	size_t inst_len = 5;
	if ((jmprel-inst_len)&0xFFFFFFFF00000000) inst_len = 14;

	// allow overwriting code
	if (mprotect(openaddr, inst_len, PROT_READ|PROT_WRITE)) {
	    fprintf(stderr, "mprotect failed: %s\n", strerror(errno));
	    return;
	}
	if (inst_len==5) {
	    // JMP 32 bit relative
	    ((char*)openaddr)[0] = 0xe9;
	    int jmprel32 = (int)(jmprel-5);
	    memcpy(openaddr+1, &jmprel32, 4);
	} else {
	    // JMP 64 bit absolute, address follows instruction
	    // warning: a disassembler will see the address as garbage code
	    memcpy(openaddr, (char[]){0xff, 0x25, 0,0,0,0}, 6);
	    memcpy(openaddr+6, &newopen, 8);
	}
	// return code to protected state
	if (mprotect(openaddr, inst_len, PROT_READ|PROT_EXEC)) {
	    fprintf(stderr, "mprotect failed: %s\n", strerror(errno));
	    return;
	}
}

