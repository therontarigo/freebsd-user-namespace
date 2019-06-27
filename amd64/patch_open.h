
static void patch_open() {
	// magic numbers: offset from dlopen to open in ld-elf.so
	void *openaddr = (dlopen) + 0x800223820 - 0x800215030;
	void *newopen = (open);
	long jmprel = (long)(newopen-openaddr);
	size_t inst_len = 5;
	if ((jmprel-inst_len)&0xFFFFFFFF00000000) {
	    //fprintf(stderr, "static rewrite failed: jump exceeds 32-bit\n");
	    return;
	    // something breaks otherwise,
	    // possibly by clobbering something after open(...),
	    // or 14 is not the right offset (does AMD64 jump from after the
	    // instruction or from after the address?)
	    inst_len = 14;
	}
	// allow overwriting code
	if (mprotect(openaddr, inst_len, PROT_READ|PROT_WRITE)) {
	    fprintf(stderr, "mprotect failed: %s\n", strerror(errno));
	    return;
	}
	if (inst_len==5) {
	    ((char*)openaddr)[0] = 0xe9; // JMP 32 bit relative
	    int jmprel32 = (int)(jmprel-inst_len);
	    memcpy(openaddr+1, &jmprel32, 4);
	} else {
	    // JMP 64 bit relative, address follows instruction
	    memcpy(openaddr, (char[]){0xff, 0x25, 0,0,0,0}, 6);
	    long jmprel64 = (long)(jmprel-inst_len);
	    memcpy(openaddr+6, &jmprel64, 8);
	}
	// return code to protected state
	if (mprotect(openaddr, inst_len, PROT_READ|PROT_EXEC)) {
	    fprintf(stderr, "mprotect failed: %s\n", strerror(errno));
	    return;
	}
}

