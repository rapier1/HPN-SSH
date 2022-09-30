#ifndef BASE_GCC_X86_S
#define BASE_GCC_X86_S

#define IS_X86_32 (defined(__i386__))
#define IS_X86_64 (defined(__x86_64__))
#define IS_ELF (defined(__ELF__))
#define IS_MACH (defined(__MACH__))
#define IS_WIN32 (IS_X86_32 && (defined(_WIN32) || defined(__CYGWIN__)))
#define IS_WIN64 (IS_X86_64 && (defined(_WIN64) || defined(__CYGWIN__)))

#if (IS_WIN64)
	/* handles 0-6 arguments and optional saving of the upper 8 xmm registers */
	.macro WIN64STUBFN name, args, xmmused
		\name:; _\name:;

		subq $(184), %rsp
		movdqa %xmm6, 0(%rsp)
		movdqa %xmm7, 16(%rsp)
		.if \xmmused > 8
			movdqa %xmm8, 32(%rsp)
			movdqa %xmm9, 48(%rsp)
			movdqa %xmm10, 64(%rsp)
			movdqa %xmm11, 80(%rsp)
			movdqa %xmm12, 96(%rsp)
			movdqa %xmm13, 112(%rsp)
			movdqa %xmm14, 128(%rsp)
			movdqa %xmm15, 144(%rsp)
		.endif
		movq %rdi, 160(%rsp)
		movq %rsi, 168(%rsp)
		movq %rcx, %rdi
		movq %rdx, %rsi
		movq %r8, %rdx
		movq %r9, %rcx
		.if \args >= 5
			movq 224(%rsp), %r8
		.endif
		.if \args >= 6
			movq 232(%rsp), %r9
		.endif
		call thunk_\name
		movdqa 0(%rsp), %xmm6
		movdqa 16(%rsp), %xmm7
		.if \xmmused > 8
			movdqa 32(%rsp), %xmm8
			movdqa 48(%rsp), %xmm9
			movdqa 64(%rsp), %xmm10
			movdqa 80(%rsp), %xmm11
			movdqa 96(%rsp), %xmm12
			movdqa 112(%rsp), %xmm13
			movdqa 128(%rsp), %xmm14
			movdqa 144(%rsp), %xmm15
		.endif
		movq 160(%rsp), %rdi
		movq 168(%rsp), %rsi
		addq $(184), %rsp
		ret
	thunk_\name:
	.endm

	.macro FN name
		WIN64STUBFN \name, 4, 16
	.endm

	.macro FN_EXT name, args, xmmused
		WIN64STUBFN \name, \args, \xmmused
	.endm

	.macro FN_END name
	.endm

	.macro HIDDEN name
	.endm
#elif (IS_WIN32)
	.macro FN name
		\name:
		_\name:
	.endm

	.macro FN_EXT name, args, xmmused
		FN \name
	.endm

	.macro FN_END name
	.endm

	.macro HIDDEN name
	.endm
#elif (IS_ELF)
	.macro FN name
		\name:
		_\name:
	.endm

	.macro FN_EXT name, args, xmmused
		FN \name
	.endm

	.macro FN_END name
		.size \name, .-\name
		.size _\name, .-_\name
		.type \name, @function
	 	.type _\name, @function
	.endm

	.macro HIDDEN name
		.hidden \name
		.hidden _\name
	.endm

	/* set NX for stack */
	.section .note.GNU-stack,"",@progbits
#elif (IS_MACH)
	.macro FN name
		\name:
		_\name:
	.endm

	.macro FN_EXT name, args, xmmused
		FN \name
	.endm

	.macro FN_END name
	.endm

	.macro HIDDEN name
		.private_extern \name
		.private_extern _\name
	.endm
#endif

/* put everything in the code segment to simplify things */
#if (IS_MACH)
	.macro SECTION_TEXT
		.section __TEXT,__text,regular
	.endm

	.macro SECTION_RODATA
		.section __TEXT,__text,regular
	.endm
#else
	/* put everything in the code segment to simplify things */
	.macro SECTION_TEXT
		.text
	.endm

	.macro SECTION_RODATA
		.text
	.endm
#endif

/* declare a global function */
.macro GLOBAL name
	.globl \name
	.globl _\name
.endm

.macro GLOBAL_HIDDEN_FN name
	GLOBAL \name
	HIDDEN \name
	FN \name
.endm

.macro GLOBAL_HIDDEN_FN_EXT name, args, xmmused
	GLOBAL \name
	HIDDEN \name
	FN_EXT \name, \args, \xmmused
.endm

/* pic support */
.macro LOAD_VAR_PIC var, reg
#if (IS_X86_32)
	call 1f
	1:
	popl \reg
	leal \var - 1b(\reg), \reg
#else
	leaq \var(%rip), \reg
#endif
.endm

#define INCLUDE_FILE_PARM "\file"


.macro INCLUDE file
	.include  INCLUDE_FILE_PARM
.endm

/* include the file with the variable(s) if variable 'name' is not already included */
.macro INCLUDE_VAR_FILE file, name
	.ifndef \name
		.include INCLUDE_FILE_PARM
	.endif
.endm

#endif /* BASE_GCC_X86_S */
