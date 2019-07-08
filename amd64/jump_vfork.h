// Can't return from caller of vfork, so jump instead of call
asm(" \n\
	.globl	vfork \n\
	.p2align	4, 0x90 \n\
	.type	vfork,@function \n\
vfork: \n\
	callq	prevfork \n\
	jmp	_vfork@PLT \n\
.Lfunc_end0: \n\
	.size	vfork, .Lfunc_end0-vfork \n\
");
