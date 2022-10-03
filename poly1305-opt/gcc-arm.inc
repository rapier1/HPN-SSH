#ifndef BASE_GCC_ARM_S
#define BASE_GCC_ARM_S

.syntax unified
.arm

#define IS_ARM32 (defined(__arm__))
#define IS_ARM64 (defined(__aarch64__))
#define IS_ELF (defined(__ELF__))
#define IS_MACH (defined(__MACH__))

#if (IS_ELF)
	.macro FN name
		.align 2
		\name:
		_\name:
	.endm

	.macro FN_END name
		.size \name, .-\name
		.type \name STT_FUNC
		.size _\name, .-_\name
		.type _\name STT_FUNC
	.endm

	.macro HIDDEN name
		.hidden \name
		.hidden _\name
	.endm

	/* set NX for stack */
	.section .note.GNU-stack,"",%progbits
#elif (IS_MACH)
	.macro FN name
		.align 2
		\name:
		_\name:
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

/* pic support */
.macro LOAD_VAR_PIC var, reg
#if (IS_ARM32)
		adrl \reg, \var
#elif (IS_ARM64)
		adr \reg, \var
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

#endif /* BASE_GCC_ARM_S */
