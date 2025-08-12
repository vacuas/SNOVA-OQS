	.file	"snova_opt_q.c"
	.text
	.p2align 4
	.type	gf_mat_det, @function
gf_mat_det:
.LFB6:
	.cfi_startproc
	pushq	%r15
	.cfi_def_cfa_offset 16
	.cfi_offset 15, -16
	pushq	%r14
	.cfi_def_cfa_offset 24
	.cfi_offset 14, -24
	pushq	%r13
	.cfi_def_cfa_offset 32
	.cfi_offset 13, -32
	pushq	%r12
	.cfi_def_cfa_offset 40
	.cfi_offset 12, -40
	pushq	%rbp
	.cfi_def_cfa_offset 48
	.cfi_offset 6, -48
	pushq	%rbx
	.cfi_def_cfa_offset 56
	.cfi_offset 3, -56
	movzbl	(%rdi), %esi
	movzbl	1(%rdi), %ecx
	movzbl	9(%rdi), %ebp
	movzbl	5(%rdi), %eax
	movzbl	4(%rdi), %r14d
	movl	%esi, %r13d
	movzbl	10(%rdi), %r8d
	imull	%eax, %r13d
	movzbl	11(%rdi), %ebx
	movzbl	15(%rdi), %r9d
	movl	%ebp, -4(%rsp)
	movl	%ecx, %ebp
	movzbl	14(%rdi), %r11d
	movzbl	2(%rdi), %r15d
	imull	%r14d, %ebp
	movl	%ebx, %r12d
	movzbl	6(%rdi), %r10d
	movzbl	13(%rdi), %edx
	imull	%r11d, %r12d
	movl	%r15d, -8(%rsp)
	subl	%ebp, %r13d
	movl	%r8d, %ebp
	imull	%r9d, %ebp
	subl	%r12d, %ebp
	movl	%r15d, %r12d
	movl	-4(%rsp), %r15d
	imull	%ebp, %r13d
	movl	%esi, %ebp
	imull	%r14d, %r12d
	imull	%r10d, %ebp
	imull	%r9d, %r15d
	subl	%r12d, %ebp
	movl	%ebx, %r12d
	imull	%edx, %r12d
	subl	%r15d, %r12d
	movl	%r8d, %r15d
	imull	%r12d, %ebp
	movzbl	7(%rdi), %r12d
	imull	%edx, %r15d
	imull	%r12d, %esi
	addl	%ebp, %r13d
	movzbl	3(%rdi), %ebp
	imull	%ebp, %r14d
	subl	%r14d, %esi
	movl	-4(%rsp), %r14d
	imull	%r11d, %r14d
	subl	%r15d, %r14d
	imull	%r14d, %esi
	movzbl	8(%rdi), %r14d
	imull	%r14d, %r9d
	addl	%r13d, %esi
	movzbl	12(%rdi), %r13d
	movl	-8(%rsp), %r15d
	movl	%ecx, %edi
	imull	%r10d, %edi
	imull	%r13d, %ebx
	imull	%eax, %r15d
	imull	%r12d, %ecx
	subl	%ebx, %r9d
	subl	%r15d, %edi
	imull	%r9d, %edi
	addl	%esi, %edi
	imull	%ebp, %eax
	movl	-4(%rsp), %esi
	imull	%r13d, %r8d
	imull	%r14d, %r11d
	subl	%eax, %ecx
	movl	-8(%rsp), %eax
	imull	%ebp, %r10d
	popq	%rbx
	.cfi_def_cfa_offset 48
	imull	%r14d, %edx
	popq	%rbp
	.cfi_def_cfa_offset 40
	imull	%r12d, %eax
	subl	%r11d, %r8d
	popq	%r12
	.cfi_def_cfa_offset 32
	imull	%r13d, %esi
	popq	%r13
	.cfi_def_cfa_offset 24
	imull	%r8d, %ecx
	popq	%r14
	.cfi_def_cfa_offset 16
	subl	%r10d, %eax
	popq	%r15
	.cfi_def_cfa_offset 8
	subl	%esi, %edx
	imull	%edx, %eax
	addl	%edi, %ecx
	addl	%ecx, %eax
	movslq	%eax, %rdx
	movl	%eax, %ecx
	imulq	$1808407283, %rdx, %rdx
	sarl	$31, %ecx
	sarq	$35, %rdx
	subl	%ecx, %edx
	leal	(%rdx,%rdx,8), %ecx
	leal	(%rdx,%rcx,2), %edx
	subl	%edx, %eax
	ret
	.cfi_endproc
.LFE6:
	.size	gf_mat_det, .-gf_mat_det
	.p2align 4
	.type	expand_public, @function
expand_public:
.LFB11:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	andq	$-32, %rsp
	subq	$346048, %rsp
	.cfi_offset 15, -24
	.cfi_offset 14, -32
	.cfi_offset 13, -40
	.cfi_offset 12, -48
	.cfi_offset 3, -56
	movq	%rdi, 40(%rsp)
	leaq	48(%rsp), %rdi
	movq	%fs:40, %rdx
	movq	%rdx, 346040(%rsp)
	movl	$16, %edx
	call	snova_pk_expander_init@PLT
	leaq	48(%rsp), %rdx
	movl	$172160, %esi
	leaq	1696(%rsp), %rdi
	call	snova_pk_expander@PLT
	movl	$2139062143, %ecx
	vmovdqa	.LC5(%rip), %xmm4
	movq	40(%rsp), %r8
	vmovd	%ecx, %xmm3
	leaq	173856(%rsp), %rdx
	leaq	1696(%rsp), %rax
	leaq	346016(%rsp), %rsi
	vpbroadcastd	%xmm3, %ymm3
.L5:
	vmovdqa	(%rax), %ymm2
	vpmovzxbw	%xmm4, %ymm5
	addq	$32, %rdx
	addq	$32, %rax
	vextracti128	$0x1, %ymm2, %xmm1
	vpmovzxbw	%xmm2, %ymm0
	vpmovzxbw	%xmm1, %ymm1
	vpmullw	%ymm5, %ymm0, %ymm0
	vpmullw	%ymm5, %ymm1, %ymm1
	vpsrlw	$8, %ymm0, %ymm0
	vpsrlw	$8, %ymm1, %ymm1
	vpackuswb	%ymm1, %ymm0, %ymm0
	vpermq	$216, %ymm0, %ymm0
	vpsrlw	$1, %ymm0, %ymm0
	vpand	%ymm0, %ymm3, %ymm0
	vpaddb	%ymm0, %ymm0, %ymm1
	vpaddb	%ymm1, %ymm1, %ymm1
	vpaddb	%ymm0, %ymm1, %ymm1
	vpaddb	%ymm1, %ymm1, %ymm1
	vpaddb	%ymm1, %ymm1, %ymm1
	vpsubb	%ymm0, %ymm1, %ymm0
	vpsubb	%ymm0, %ymm2, %ymm2
	vmovdqa	%ymm2, -32(%rdx)
	cmpq	%rsi, %rdx
	jne	.L5
	leaq	175232(%r8), %rax
	movq	$0, 24(%rsp)
	leaq	173856(%rsp), %r14
	movq	%rax, 16(%rsp)
	movq	$0, 8(%rsp)
	movq	%r8, 32(%rsp)
.L6:
	movq	8(%rsp), %rax
	movq	16(%rsp), %r12
	xorl	%ebx, %ebx
	movq	%rax, %r13
	movq	%rax, 40(%rsp)
	salq	$4, %r13
	addq	32(%rsp), %r13
.L9:
	movq	%r13, %rdi
	movl	$4, %r15d
	vzeroupper
.L7:
	movq	%r15, %rdx
	movq	%r14, %rsi
	decq	%r15
	call	memcpy@PLT
	leaq	1(%r14,%r15), %rdx
	movq	%rdx, %r14
	leaq	5(%rax), %rdi
	testq	%r15, %r15
	jne	.L7
	movl	%ebx, %r9d
	cmpl	$36, %ebx
	je	.L14
	cmpq	$35, %rbx
	je	.L37
	movl	$36, %r8d
	leaq	16(%r13), %rdi
	xorl	%eax, %eax
	subl	%ebx, %r8d
	movl	%r8d, %esi
	shrl	%esi
	salq	$5, %rsi
	.p2align 5
	.p2align 4,,10
	.p2align 3
.L12:
	vmovdqu	(%rdx,%rax), %ymm0
	vmovdqu	%ymm0, (%rdi,%rax)
	addq	$32, %rax
	cmpq	%rax, %rsi
	jne	.L12
	testb	$1, %r8b
	je	.L15
	andl	$-2, %r8d
.L11:
	movl	%r8d, %eax
	movq	%rax, %rsi
	salq	$4, %rsi
	vmovdqu	(%rdx,%rsi), %xmm0
	movq	40(%rsp), %rsi
	leaq	1(%rax,%rsi), %rax
	movq	32(%rsp), %rsi
	salq	$4, %rax
	vmovdqu	%xmm0, (%rsi,%rax)
.L15:
	movl	$36, %r10d
	subl	%r9d, %r10d
	salq	$4, %r10
	leaq	(%r10,%rdx), %r14
.L14:
	vmovdqu	(%r14), %ymm0
	incq	%rbx
	addq	$38, 40(%rsp)
	subq	$-128, %r14
	subq	$-128, %r12
	addq	$608, %r13
	vmovdqu	%ymm0, -128(%r12)
	vmovdqu	-96(%r14), %ymm0
	vmovdqu	%ymm0, -96(%r12)
	vmovdqu	-64(%r14), %ymm0
	vmovdqu	%ymm0, -64(%r12)
	vmovdqu	-32(%r14), %ymm0
	vmovdqu	%ymm0, -32(%r12)
	cmpq	$37, %rbx
	jne	.L9
	addq	$37, 24(%rsp)
	addq	$4736, 16(%rsp)
	addq	$1369, 8(%rsp)
	movq	24(%rsp), %rax
	cmpq	$296, %rax
	jne	.L6
	movq	32(%rsp), %r8
	movq	%r15, 24(%rsp)
	movq	%r14, %r10
	leaq	22496(%r8), %rdi
	leaq	197728(%r8), %r9
.L16:
	leaq	-22496(%rdi), %rax
.L17:
	movzbl	1(%rax), %edx
	addq	$608, %rax
	movb	%dl, -604(%rax)
	movzbl	-606(%rax), %edx
	movb	-602(%rax), %dh
	movw	%dx, -600(%rax)
	movzbl	-605(%rax), %edx
	movb	-601(%rax), %dh
	movw	%dx, -596(%rax)
	movzbl	-597(%rax), %edx
	movb	%dl, -594(%rax)
	cmpq	%rax, %rdi
	jne	.L17
	addq	$21904, %rdi
	cmpq	%rdi, %r9
	jne	.L16
	leaq	16(%r8), %rbx
	movq	%r10, 16(%rsp)
	vmovdqa	.LC3(%rip), %xmm2
	xorl	%r13d, %r13d
	movq	%rbx, 32(%rsp)
	vmovdqa	.LC2(%rip), %ymm1
	movl	$1, %eax
	movl	$592, %edx
	movl	$1369, %ecx
	leaq	-576(%r8), %r15
.L18:
	leaq	37(%r13), %rdi
	movq	%rax, 8(%rsp)
	leaq	20736(%rdx), %r12
	movl	%eax, %r14d
	movq	%rdi, 40(%rsp)
	leaq	(%r15,%rdx), %r11
	movq	%rax, %r10
	movq	%rdx, %rbx
	movq	%rdx, (%rsp)
	movl	$36, %r9d
.L27:
	leaq	36(%r10), %rax
	salq	$4, %rax
	cmpq	%rax, %rbx
	jle	.L41
	movq	%r10, %rax
	salq	$4, %rax
	cmpq	%rax, %r12
	jg	.L20
.L41:
	movl	%r9d, %r13d
	cmpl	$1, %r9d
	je	.L39
	movl	%r9d, %edi
	leaq	576(%r11), %rdx
	movq	%r11, %rax
	shrl	%edi
	salq	$5, %rdi
	addq	%r11, %rdi
	.p2align 6
	.p2align 4,,10
	.p2align 3
.L23:
	vmovdqu	(%rax), %ymm0
	addq	$32, %rax
	addq	$1184, %rdx
	vpshufb	%ymm1, %ymm0, %ymm0
	vmovdqu	%xmm0, -1184(%rdx)
	vextracti128	$0x1, %ymm0, -592(%rdx)
	cmpq	%rax, %rdi
	jne	.L23
	leaq	-1(%r9), %rdx
	testb	$1, %r13b
	je	.L26
	andl	$-2, %r13d
.L22:
	movl	%r13d, %edx
	leaq	(%r10,%rdx), %rax
	salq	$4, %rax
	vmovdqu	(%r8,%rax), %xmm0
	movq	40(%rsp), %rax
	subq	%r9, %rax
	vpshufb	%xmm2, %xmm0, %xmm0
	addq	%rdx, %rax
	movl	$36, %edx
	leaq	(%rax,%rax,8), %rdi
	subq	%r9, %rdx
	leaq	(%rax,%rdi,4), %rax
	addq	%rdx, %rax
	leaq	-1(%r9), %rdx
	salq	$4, %rax
	vmovdqu	%xmm0, (%r8,%rax)
.L26:
	addq	$38, %r10
	addq	$592, %rbx
	movq	%rdx, %r9
	addq	$16, %r12
	addl	$38, %r14d
	addq	$608, %r11
	cmpq	%rcx, %r10
	jne	.L27
	movq	8(%rsp), %rax
	movq	(%rsp), %rdx
	leaq	1369(%r10), %rcx
	addq	$21904, %rdx
	addq	$1369, %rax
	cmpq	$296, 40(%rsp)
	je	.L62
	movq	40(%rsp), %r13
	jmp	.L18
.L37:
	xorl	%r8d, %r8d
	jmp	.L11
.L20:
	movslq	%r14d, %r13
	leal	36(%r14), %edi
	leaq	-1(%r9), %rdx
	movq	%r13, %rax
	movslq	%edi, %rdi
	leaq	(%rdx,%r13), %r9
	salq	$4, %rax
	salq	$4, %rdi
	salq	$4, %r9
	addq	%r8, %rax
	addq	%r8, %rdi
	addq	32(%rsp), %r9
.L25:
	movzbl	(%rax), %r13d
	addq	$16, %rax
	addq	$592, %rdi
	movb	%r13b, -592(%rdi)
	movzbl	-15(%rax), %r13d
	movb	%r13b, -588(%rdi)
	movzbl	-14(%rax), %r13d
	movb	%r13b, -584(%rdi)
	movzbl	-13(%rax), %r13d
	movb	%r13b, -580(%rdi)
	movzbl	-12(%rax), %r13d
	movb	%r13b, -591(%rdi)
	movzbl	-11(%rax), %r13d
	movb	%r13b, -587(%rdi)
	movzbl	-10(%rax), %r13d
	movb	%r13b, -583(%rdi)
	movzbl	-9(%rax), %r13d
	movb	%r13b, -579(%rdi)
	movzbl	-8(%rax), %r13d
	movb	%r13b, -590(%rdi)
	movzbl	-7(%rax), %r13d
	movb	%r13b, -586(%rdi)
	movzbl	-6(%rax), %r13d
	movb	%r13b, -582(%rdi)
	movzbl	-5(%rax), %r13d
	movb	%r13b, -578(%rdi)
	movzbl	-4(%rax), %r13d
	movb	%r13b, -589(%rdi)
	movzbl	-3(%rax), %r13d
	movb	%r13b, -585(%rdi)
	movzbl	-2(%rax), %r13d
	movb	%r13b, -581(%rdi)
	movzbl	-1(%rax), %r13d
	movb	%r13b, -577(%rdi)
	cmpq	%r9, %rax
	jne	.L25
	jmp	.L26
.L39:
	xorl	%r13d, %r13d
	jmp	.L22
.L62:
	movq	16(%rsp), %r10
	vmovdqa	.LC2(%rip), %ymm1
	movl	$213120, %eax
	movl	$296, %r14d
	movq	24(%rsp), %rdi
	leaq	-37888(%r8), %rdx
	leaq	213120(%r8), %rsi
	movq	%r10, 32(%rsp)
.L28:
	movl	%edi, 40(%rsp)
	leaq	-37760(%rax), %r11
	leaq	(%rdx,%rax), %r10
	movl	%edi, %r12d
	movq	%rax, 24(%rsp)
	leaq	(%r8,%rax), %r9
	movq	%rax, %rbx
	xorl	%r13d, %r13d
	jmp	.L35
.L32:
	vmovdqu	(%r10), %ymm0
	vpshufb	%ymm1, %ymm0, %ymm0
	vmovdqu	%xmm0, (%r9)
	vextracti128	$0x1, %ymm0, 592(%r9)
	vmovdqu	32(%r10), %ymm0
	vpshufb	%ymm1, %ymm0, %ymm0
	vmovdqu	%xmm0, 1184(%r9)
	vextracti128	$0x1, %ymm0, 1776(%r9)
	vmovdqu	64(%r10), %ymm0
	vpshufb	%ymm1, %ymm0, %ymm0
	vmovdqu	%xmm0, 2368(%r9)
	vextracti128	$0x1, %ymm0, 2960(%r9)
	vmovdqu	96(%r10), %ymm0
	vpshufb	%ymm1, %ymm0, %ymm0
	vmovdqu	%xmm0, 3552(%r9)
	vextracti128	$0x1, %ymm0, 4144(%r9)
.L30:
	addl	$8, %r12d
	incl	%r13d
	addq	$16, %rbx
	subq	$-128, %r11
	subq	$-128, %r10
	addq	$16, %r9
	cmpl	%r14d, %r12d
	je	.L31
.L35:
	leaq	-128(%r11), %rcx
	leaq	4160(%rbx), %rax
	cmpq	%rax, %rcx
	jge	.L32
	cmpq	%r11, %rbx
	jge	.L32
	movl	40(%rsp), %eax
	movq	%rdx, 16(%rsp)
	leaq	(%r8,%r11), %r15
	leal	0(%r13,%rax), %ecx
	movq	%r10, %rax
	salq	$4, %rcx
	addq	%rsi, %rcx
.L29:
	movzbl	(%rax), %edx
	addq	$16, %rax
	addq	$592, %rcx
	movb	%dl, -592(%rcx)
	movzbl	-15(%rax), %edx
	movb	%dl, -588(%rcx)
	movzbl	-14(%rax), %edx
	movb	%dl, -584(%rcx)
	movzbl	-13(%rax), %edx
	movb	%dl, -580(%rcx)
	movzbl	-12(%rax), %edx
	movb	%dl, -591(%rcx)
	movzbl	-11(%rax), %edx
	movb	%dl, -587(%rcx)
	movzbl	-10(%rax), %edx
	movb	%dl, -583(%rcx)
	movzbl	-9(%rax), %edx
	movb	%dl, -579(%rcx)
	movzbl	-8(%rax), %edx
	movb	%dl, -590(%rcx)
	movzbl	-7(%rax), %edx
	movb	%dl, -586(%rcx)
	movzbl	-6(%rax), %edx
	movb	%dl, -582(%rcx)
	movzbl	-5(%rax), %edx
	movb	%dl, -578(%rcx)
	movzbl	-4(%rax), %edx
	movb	%dl, -589(%rcx)
	movzbl	-3(%rax), %edx
	movb	%dl, -585(%rcx)
	movzbl	-2(%rax), %edx
	movb	%dl, -581(%rcx)
	movzbl	-1(%rax), %edx
	movb	%dl, -577(%rcx)
	cmpq	%rax, %r15
	jne	.L29
	movq	16(%rsp), %rdx
	jmp	.L30
.L31:
	movq	24(%rsp), %rax
	leal	296(%r12), %r14d
	addq	$296, %rdi
	addq	$4736, %rax
	cmpl	$2368, %r12d
	jne	.L28
	movq	32(%rsp), %rsi
	leaq	251008(%r8), %rdi
	movl	$6400, %edx
	vzeroupper
	call	memcpy@PLT
	movq	346040(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L63
	leaq	-40(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	.cfi_remember_state
	.cfi_def_cfa 7, 8
	ret
.L63:
	.cfi_restore_state
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE11:
	.size	expand_public, .-expand_public
	.p2align 4
	.type	expand_T12, @function
expand_T12:
.LFB14:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	.cfi_offset 15, -24
	.cfi_offset 14, -32
	.cfi_offset 13, -40
	.cfi_offset 12, -48
	.cfi_offset 3, -56
	movq	%rdi, %rbx
	andq	$-32, %rsp
	subq	$2528, %rsp
	movq	%fs:40, %r12
	movq	%r12, 2520(%rsp)
	movq	%rsi, %r12
	leaq	1056(%rsp), %r13
	movq	%r13, %rdi
	call	shake256_init@PLT
	movl	$32, %edx
	movq	%r13, %rdi
	movq	%r12, %rsi
	xorl	%r12d, %r12d
	call	shake_absorb@PLT
	movq	%r13, %rdi
	call	shake_finalize@PLT
	movl	$32, %ecx
	jmp	.L66
.L68:
	movzbl	1280(%rsp,%rax), %esi
	leaq	1(%rax), %rcx
	movl	$27, %eax
	mulb	%sil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %edx
	leal	(%rax,%rdx,2), %eax
	movl	%esi, %edx
	subl	%eax, %edx
	xorl	%eax, %eax
	cmpb	$-10, %sil
	setbe	%al
	movb	%dl, 1312(%rsp,%r12)
	addq	%rax, %r12
	cmpq	$1184, %r12
	je	.L67
.L66:
	movq	%rcx, %rax
	cmpq	$32, %rcx
	jne	.L68
	movq	%r13, %rdx
	movl	$32, %esi
	leaq	1280(%rsp), %rdi
	call	shake_squeeze_keep@PLT
	movzbl	1280(%rsp), %ecx
	movl	$27, %eax
	mulb	%cl
	shrw	$9, %ax
	leal	(%rax,%rax,8), %edx
	leal	(%rax,%rdx,2), %eax
	movl	%ecx, %edx
	subl	%eax, %edx
	xorl	%eax, %eax
	cmpb	$-10, %cl
	setbe	%al
	movb	%dl, 1312(%rsp,%r12)
	addq	%rax, %r12
	cmpq	$1184, %r12
	je	.L67
	movl	$1, %eax
	jmp	.L68
.L67:
	movq	%r13, %rdi
	call	shake_release@PLT
	movl	$303174162, %ecx
	vmovdqa	.LC21(%rip), %ymm12
	leaq	1312(%rsp), %rax
	vmovd	%ecx, %xmm6
	movq	%rbx, %rdx
	leaq	9216(%rbx), %rsi
	vpbroadcastd	%xmm6, %ymm6
	vmovdqa	%ymm6, 416(%rsp)
.L69:
	vmovdqa	(%rax), %ymm1
	vmovdqa	32(%rax), %ymm8
	movl	$-678045803, %ecx
	addq	$1024, %rdx
	vmovdqa	64(%rax), %ymm4
	vmovdqa	96(%rax), %ymm5
	subq	$-128, %rax
	vpsrlw	$8, %ymm8, %ymm2
	vpsrlw	$8, %ymm1, %ymm0
	vpmovzxbw	.LC30(%rip), %ymm11
	vpsrlw	$8, %ymm5, %ymm3
	vpackuswb	%ymm2, %ymm0, %ymm0
	vpsrlw	$8, %ymm4, %ymm2
	vpermq	$216, %ymm0, %ymm0
	vpackuswb	%ymm3, %ymm2, %ymm2
	vpsrlw	$8, %ymm0, %ymm3
	vpermq	$216, %ymm2, %ymm2
	vpsrlw	$8, %ymm2, %ymm6
	vpackuswb	%ymm6, %ymm3, %ymm3
	vpermq	$216, %ymm3, %ymm6
	vpcmpeqd	%ymm3, %ymm3, %ymm3
	vpsrlw	$8, %ymm3, %ymm3
	vmovdqa	%ymm6, 960(%rsp)
	vpand	%ymm2, %ymm3, %ymm2
	vpand	%ymm0, %ymm3, %ymm0
	vpand	%ymm8, %ymm3, %ymm8
	vpand	%ymm5, %ymm3, %ymm5
	vpackuswb	%ymm2, %ymm0, %ymm0
	vpand	%ymm1, %ymm3, %ymm1
	vpand	%ymm4, %ymm3, %ymm4
	vpermq	$216, %ymm0, %ymm0
	vpackuswb	%ymm8, %ymm1, %ymm1
	vpmovzxbw	.LC32(%rip), %ymm8
	vpackuswb	%ymm5, %ymm4, %ymm4
	vpmovzxbw	%xmm0, %ymm7
	vpermq	$216, %ymm1, %ymm1
	vpermq	$216, %ymm4, %ymm4
	vpmullw	%ymm11, %ymm7, %ymm10
	vextracti128	$0x1, %ymm0, %xmm0
	vpmullw	.LC45(%rip), %ymm7, %ymm6
	vpsrlw	$8, %ymm4, %ymm5
	vpmullw	%ymm8, %ymm7, %ymm14
	vpmovzxbw	%xmm0, %ymm2
	vpsrlw	$8, %ymm1, %ymm0
	vpmullw	%ymm2, %ymm11, %ymm9
	vmovdqa	%ymm2, 992(%rsp)
	vpmullw	.LC45(%rip), %ymm2, %ymm15
	vpackuswb	%ymm5, %ymm0, %ymm0
	vpand	%ymm1, %ymm3, %ymm1
	vpand	%ymm4, %ymm3, %ymm3
	vpermq	$216, %ymm0, %ymm0
	vpackuswb	%ymm3, %ymm1, %ymm1
	vmovdqa	416(%rsp), %ymm3
	vpmovzxbw	%xmm0, %ymm5
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vpmullw	%ymm11, %ymm5, %ymm13
	vpmullw	%ymm11, %ymm0, %ymm11
	vpaddw	%ymm13, %ymm14, %ymm2
	vpmullw	992(%rsp), %ymm8, %ymm13
	vpaddw	%ymm11, %ymm13, %ymm13
	vpmovzxbw	.LC34(%rip), %ymm11
	vmovdqa	%ymm2, 448(%rsp)
	vmovdqa	%ymm13, 672(%rsp)
	vpmullw	%ymm11, %ymm5, %ymm13
	vpmullw	%ymm11, %ymm0, %ymm11
	vpaddw	%ymm9, %ymm11, %ymm2
	vpmovzxbw	.LC36(%rip), %ymm11
	vpaddw	%ymm10, %ymm13, %ymm14
	vmovdqa	%ymm2, 704(%rsp)
	vpmullw	%ymm11, %ymm5, %ymm13
	vpmullw	%ymm11, %ymm0, %ymm11
	vmovdqa	%ymm14, 736(%rsp)
	vpaddw	%ymm7, %ymm13, %ymm2
	vpaddw	992(%rsp), %ymm11, %ymm13
	vpmovzxbw	.LC38(%rip), %ymm11
	vmovdqa	%ymm13, 1024(%rsp)
	vpmullw	%ymm11, %ymm5, %ymm13
	vpmullw	%ymm11, %ymm0, %ymm11
	vpaddw	%ymm6, %ymm13, %ymm14
	vpaddw	%ymm15, %ymm11, %ymm13
	vpmovzxbw	.LC40(%rip), %ymm11
	vmovdqa	%ymm13, 544(%rsp)
	vpmullw	%ymm11, %ymm5, %ymm13
	vmovdqa	%ymm14, 576(%rsp)
	vpmullw	%ymm11, %ymm0, %ymm14
	vpaddw	%ymm13, %ymm10, %ymm10
	vmovdqa	%ymm10, 640(%rsp)
	vpaddw	%ymm14, %ymm9, %ymm10
	vpmovzxbw	.LC42(%rip), %ymm9
	vmovdqa	%ymm10, 608(%rsp)
	vpmullw	%ymm9, %ymm5, %ymm5
	vpmullw	%ymm9, %ymm0, %ymm0
	vpaddw	%ymm5, %ymm6, %ymm6
	vmovdqa	%ymm5, 864(%rsp)
	vpaddw	%ymm0, %ymm15, %ymm5
	vpermq	$216, %ymm1, %ymm15
	vmovdqa	%ymm0, 832(%rsp)
	vpsubb	%ymm15, %ymm3, %ymm0
	vpxor	%xmm3, %xmm3, %xmm3
	vmovdqa	%ymm15, 896(%rsp)
	vmovdqa	%ymm6, 512(%rsp)
	vmovdqa	%ymm5, 480(%rsp)
	vpcmpeqb	896(%rsp), %ymm3, %ymm1
	vmovdqa	960(%rsp), %ymm6
	vpcmpeqb	%ymm3, %ymm1, %ymm1
	vpsubb	%ymm1, %ymm0, %ymm1
	vpcmpeqb	%ymm6, %ymm3, %ymm0
	vpcmpeqb	%ymm3, %ymm0, %ymm0
	vpandn	%ymm1, %ymm0, %ymm0
	vpor	%ymm6, %ymm0, %ymm1
	vmovd	%ecx, %xmm0
	vpmovzxbw	%xmm1, %ymm6
	vpbroadcastd	%xmm0, %ymm0
	vextracti128	$0x1, %ymm1, 960(%rsp)
	vpmovzxbw	960(%rsp), %ymm5
	vpmullw	%ymm8, %ymm6, %ymm4
	vmovdqa	%xmm1, %xmm3
	vpmullw	%ymm8, %ymm5, %ymm8
	vpaddw	%ymm2, %ymm4, %ymm4
	vpmulhuw	%ymm0, %ymm4, %ymm10
	vpaddw	1024(%rsp), %ymm8, %ymm8
	vpsrlw	$4, %ymm10, %ymm10
	vpsllw	$2, %ymm10, %ymm9
	vpaddw	%ymm10, %ymm9, %ymm9
	vpsllw	$2, %ymm9, %ymm9
	vpsubw	%ymm10, %ymm9, %ymm9
	vpmulhuw	%ymm0, %ymm8, %ymm10
	vpsubw	%ymm9, %ymm4, %ymm4
	vpsrlw	$4, %ymm10, %ymm10
	vpsllw	$2, %ymm10, %ymm9
	vpaddw	%ymm10, %ymm9, %ymm9
	vpsllw	$2, %ymm9, %ymm9
	vpsubw	%ymm10, %ymm9, %ymm9
	vpsubw	%ymm9, %ymm8, %ymm15
	vpmovzxbw	.LC44(%rip), %ymm8
	vpmullw	%ymm8, %ymm6, %ymm9
	vpmullw	%ymm8, %ymm5, %ymm8
	vpaddw	%ymm13, %ymm9, %ymm9
	vpaddw	%ymm14, %ymm8, %ymm8
	vpmulhuw	%ymm0, %ymm9, %ymm11
	vpsrlw	$4, %ymm11, %ymm11
	vpsllw	$2, %ymm11, %ymm10
	vpaddw	%ymm11, %ymm10, %ymm10
	vpsllw	$2, %ymm10, %ymm10
	vpsubw	%ymm11, %ymm10, %ymm10
	vpmulhuw	%ymm0, %ymm8, %ymm11
	vpsubw	%ymm10, %ymm9, %ymm9
	vpsrlw	$4, %ymm11, %ymm11
	vpsllw	$2, %ymm11, %ymm10
	vpaddw	%ymm11, %ymm10, %ymm10
	vpsllw	$2, %ymm10, %ymm10
	vpsubw	%ymm11, %ymm10, %ymm10
	vpunpckhwd	%ymm4, %ymm9, %ymm11
	vpsubw	%ymm10, %ymm8, %ymm8
	vpunpcklwd	%ymm4, %ymm9, %ymm10
	vperm2i128	$32, %ymm11, %ymm10, %ymm1
	vmovdqa	%ymm1, 800(%rsp)
	vperm2i128	$49, %ymm11, %ymm10, %ymm1
	vpunpcklwd	%ymm15, %ymm8, %ymm10
	vpunpckhwd	%ymm15, %ymm8, %ymm11
	vperm2i128	$32, %ymm11, %ymm10, %ymm2
	vmovdqa	%ymm2, 384(%rsp)
	vperm2i128	$49, %ymm11, %ymm10, %ymm2
	vmovdqa	.LC57(%rip), %ymm10
	vpmullw	%ymm10, %ymm6, %ymm11
	vpmullw	%ymm10, %ymm5, %ymm10
	vpaddw	%ymm11, %ymm13, %ymm13
	vmovdqa	%ymm11, 1024(%rsp)
	vpaddw	%ymm10, %ymm14, %ymm11
	vpmulhuw	%ymm0, %ymm13, %ymm14
	vmovdqa	%ymm10, 928(%rsp)
	vpsrlw	$4, %ymm14, %ymm14
	vpsllw	$2, %ymm14, %ymm10
	vpaddw	%ymm14, %ymm10, %ymm10
	vpsllw	$2, %ymm10, %ymm10
	vpsubw	%ymm14, %ymm10, %ymm10
	vpmulhuw	%ymm0, %ymm11, %ymm14
	vpsubw	%ymm10, %ymm13, %ymm13
	vpsrlw	$4, %ymm14, %ymm14
	vpsllw	$2, %ymm14, %ymm10
	vpaddw	%ymm14, %ymm10, %ymm10
	vpsllw	$2, %ymm10, %ymm10
	vpsubw	%ymm14, %ymm10, %ymm10
	vpsubw	%ymm10, %ymm11, %ymm11
	vpunpcklwd	%ymm4, %ymm13, %ymm10
	vpunpckhwd	%ymm4, %ymm13, %ymm4
	vperm2i128	$32, %ymm4, %ymm10, %ymm14
	vmovdqa	%ymm14, 768(%rsp)
	vperm2i128	$49, %ymm4, %ymm10, %ymm14
	vpunpcklwd	%ymm15, %ymm11, %ymm4
	vmovdqa	1024(%rsp), %ymm10
	vpunpckhwd	%ymm15, %ymm11, %ymm15
	vmovdqa	%ymm14, 352(%rsp)
	vperm2i128	$32, %ymm15, %ymm4, %ymm14
	vpaddw	576(%rsp), %ymm10, %ymm10
	vperm2i128	$49, %ymm15, %ymm4, %ymm4
	vmovdqa	%ymm14, 320(%rsp)
	vmovdqa	928(%rsp), %ymm14
	vmovdqa	%ymm4, 288(%rsp)
	vpaddw	544(%rsp), %ymm14, %ymm15
	vpmulhuw	%ymm0, %ymm10, %ymm14
	vpsrlw	$4, %ymm14, %ymm14
	vpsllw	$2, %ymm14, %ymm4
	vpaddw	%ymm14, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm4
	vpsubw	%ymm14, %ymm4, %ymm4
	vpmulhuw	%ymm0, %ymm15, %ymm14
	vpsubw	%ymm4, %ymm10, %ymm10
	vpsrlw	$4, %ymm14, %ymm14
	vpsllw	$2, %ymm14, %ymm4
	vpaddw	%ymm14, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm4
	vpsubw	%ymm14, %ymm4, %ymm4
	vpunpcklwd	%ymm9, %ymm10, %ymm14
	vpunpckhwd	%ymm9, %ymm10, %ymm9
	vpsubw	%ymm4, %ymm15, %ymm4
	vperm2i128	$32, %ymm9, %ymm14, %ymm15
	vperm2i128	$49, %ymm9, %ymm14, %ymm9
	vmovdqa	%ymm9, 544(%rsp)
	vpunpcklwd	%ymm8, %ymm4, %ymm9
	vpunpckhwd	%ymm8, %ymm4, %ymm8
	vmovdqa	%ymm15, 576(%rsp)
	vperm2i128	$32, %ymm8, %ymm9, %ymm15
	vperm2i128	$49, %ymm8, %ymm9, %ymm8
	vmovdqa	%ymm8, 224(%rsp)
	vpunpcklwd	%ymm13, %ymm10, %ymm8
	vpunpckhwd	%ymm13, %ymm10, %ymm10
	vperm2i128	$32, %ymm10, %ymm8, %ymm13
	vperm2i128	$49, %ymm10, %ymm8, %ymm10
	vpunpcklwd	%ymm11, %ymm4, %ymm8
	vmovdqa	%ymm15, 256(%rsp)
	vpunpckhwd	%ymm11, %ymm4, %ymm4
	vmovdqa	%ymm10, 160(%rsp)
	vperm2i128	$32, %ymm4, %ymm8, %ymm11
	vperm2i128	$49, %ymm4, %ymm8, %ymm8
	vmovdqa	%ymm13, 192(%rsp)
	vpmullw	.LC45(%rip), %ymm5, %ymm13
	vmovdqa	%ymm11, 128(%rsp)
	vpmullw	.LC45(%rip), %ymm6, %ymm11
	vpaddw	736(%rsp), %ymm11, %ymm10
	vpaddw	704(%rsp), %ymm13, %ymm9
	vmovdqa	%ymm8, 96(%rsp)
	vpmulhuw	%ymm0, %ymm10, %ymm8
	vpsrlw	$4, %ymm8, %ymm8
	vpsllw	$2, %ymm8, %ymm4
	vpaddw	%ymm8, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm4
	vpsubw	%ymm8, %ymm4, %ymm4
	vpmulhuw	%ymm0, %ymm9, %ymm8
	vpsubw	%ymm4, %ymm10, %ymm10
	vpsrlw	$4, %ymm8, %ymm8
	vpsllw	$2, %ymm8, %ymm4
	vpaddw	%ymm8, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm4
	vpsubw	%ymm8, %ymm4, %ymm4
	vpaddw	640(%rsp), %ymm11, %ymm8
	vpsubw	%ymm4, %ymm9, %ymm9
	vpaddw	608(%rsp), %ymm13, %ymm13
	vmovdqa	896(%rsp), %ymm15
	vpmulhuw	%ymm0, %ymm8, %ymm11
	vpsrlw	$4, %ymm11, %ymm11
	vpsllw	$2, %ymm11, %ymm4
	vpaddw	%ymm11, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm4
	vpsubw	%ymm11, %ymm4, %ymm4
	vpmulhuw	%ymm0, %ymm13, %ymm11
	vpsubw	%ymm4, %ymm8, %ymm8
	vpsrlw	$4, %ymm11, %ymm11
	vpsllw	$2, %ymm11, %ymm4
	vpaddw	%ymm11, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm4
	vpsubw	%ymm11, %ymm4, %ymm4
	vpmovzxbw	%xmm15, %ymm11
	vpsubw	%ymm4, %ymm13, %ymm13
	vextracti128	$0x1, %ymm15, %xmm4
	vmovdqa	%ymm11, 928(%rsp)
	vpmovzxbw	%xmm4, %ymm15
	vmovdqa	.LC60(%rip), %ymm4
	vmovdqa	%ymm13, 1024(%rsp)
	vmovdqa	%ymm15, 896(%rsp)
	vpmullw	%ymm4, %ymm6, %ymm13
	vpmullw	%ymm4, %ymm5, %ymm4
	vpaddw	%ymm11, %ymm13, %ymm13
	vpaddw	%ymm15, %ymm4, %ymm4
	vpaddw	448(%rsp), %ymm13, %ymm13
	vpaddw	672(%rsp), %ymm4, %ymm4
	vpmulhuw	%ymm0, %ymm13, %ymm14
	vpsrlw	$4, %ymm14, %ymm14
	vpsllw	$2, %ymm14, %ymm11
	vpaddw	%ymm14, %ymm11, %ymm11
	vpsllw	$2, %ymm11, %ymm11
	vpsubw	%ymm14, %ymm11, %ymm11
	vpmulhuw	%ymm0, %ymm4, %ymm14
	vpsubw	%ymm11, %ymm13, %ymm13
	vpsrlw	$4, %ymm14, %ymm14
	vpsllw	$2, %ymm14, %ymm11
	vpaddw	%ymm14, %ymm11, %ymm11
	vpsllw	$2, %ymm11, %ymm11
	vpsubw	%ymm14, %ymm11, %ymm11
	vpsubw	%ymm11, %ymm4, %ymm4
	vpunpcklwd	%ymm13, %ymm10, %ymm11
	vpunpckhwd	%ymm13, %ymm10, %ymm13
	vpunpcklwd	%ymm4, %ymm9, %ymm15
	vpunpckhwd	%ymm4, %ymm9, %ymm4
	vperm2i128	$32, %ymm13, %ymm11, %ymm14
	vperm2i128	$49, %ymm13, %ymm11, %ymm11
	vperm2i128	$32, %ymm4, %ymm15, %ymm13
	vperm2i128	$49, %ymm4, %ymm15, %ymm15
	vmovdqa	768(%rsp), %ymm4
	vinserti128	$1, %xmm14, %ymm4, %ymm4
	vpermd	%ymm4, %ymm12, %ymm4
	vmovdqa	%ymm4, 736(%rsp)
	vmovdqa	768(%rsp), %ymm4
	vperm2i128	$49, %ymm14, %ymm4, %ymm4
	vmovdqa	352(%rsp), %ymm14
	vpermd	%ymm4, %ymm12, %ymm4
	vmovdqa	%ymm4, 768(%rsp)
	vinserti128	$1, %xmm11, %ymm14, %ymm4
	vpermd	%ymm4, %ymm12, %ymm4
	vmovdqa	%ymm4, 704(%rsp)
	vperm2i128	$49, %ymm11, %ymm14, %ymm4
	vmovdqa	928(%rsp), %ymm11
	vpermd	%ymm4, %ymm12, %ymm14
	vmovdqa	%ymm14, 672(%rsp)
	vmovdqa	320(%rsp), %ymm14
	vinserti128	$1, %xmm13, %ymm14, %ymm4
	vpermd	%ymm4, %ymm12, %ymm4
	vmovdqa	%ymm4, 640(%rsp)
	vperm2i128	$49, %ymm13, %ymm14, %ymm4
	vmovdqa	288(%rsp), %ymm14
	vpermd	%ymm4, %ymm12, %ymm13
	vinserti128	$1, %xmm15, %ymm14, %ymm4
	vmovdqa	%ymm13, 608(%rsp)
	vpermd	%ymm4, %ymm12, %ymm13
	vperm2i128	$49, %ymm15, %ymm14, %ymm4
	vmovdqa	896(%rsp), %ymm15
	vmovdqa	%ymm13, 448(%rsp)
	vpaddw	512(%rsp), %ymm11, %ymm13
	vpermd	%ymm4, %ymm12, %ymm14
	vmovdqa	%ymm14, 352(%rsp)
	vpaddw	480(%rsp), %ymm15, %ymm4
	vpmulhuw	%ymm0, %ymm13, %ymm14
	vpsrlw	$4, %ymm14, %ymm14
	vpsllw	$2, %ymm14, %ymm11
	vpaddw	%ymm14, %ymm11, %ymm11
	vpsllw	$2, %ymm11, %ymm11
	vpsubw	%ymm14, %ymm11, %ymm11
	vpmulhuw	%ymm0, %ymm4, %ymm14
	vpsubw	%ymm11, %ymm13, %ymm13
	vpsrlw	$4, %ymm14, %ymm14
	vpsllw	$2, %ymm14, %ymm11
	vpaddw	%ymm14, %ymm11, %ymm11
	vpsllw	$2, %ymm11, %ymm11
	vpsubw	%ymm14, %ymm11, %ymm11
	vpsubw	%ymm11, %ymm4, %ymm4
	vpunpcklwd	%ymm13, %ymm8, %ymm11
	vpunpckhwd	%ymm13, %ymm8, %ymm13
	vperm2i128	$32, %ymm13, %ymm11, %ymm14
	vperm2i128	$49, %ymm13, %ymm11, %ymm11
	vmovdqa	1024(%rsp), %ymm13
	vpunpcklwd	%ymm4, %ymm13, %ymm15
	vpunpckhwd	%ymm4, %ymm13, %ymm4
	vperm2i128	$32, %ymm4, %ymm15, %ymm13
	vperm2i128	$49, %ymm4, %ymm15, %ymm4
	vinserti128	$1, 800(%rsp), %ymm14, %ymm15
	vperm2i128	$49, 800(%rsp), %ymm14, %ymm14
	vpermd	%ymm15, %ymm12, %ymm15
	vpermd	%ymm14, %ymm12, %ymm14
	vmovdqa	%ymm15, 512(%rsp)
	vmovdqa	%ymm14, 800(%rsp)
	vinserti128	$1, %xmm1, %ymm11, %ymm14
	vperm2i128	$49, %ymm1, %ymm11, %ymm11
	vpermd	%ymm14, %ymm12, %ymm14
	vpermd	%ymm11, %ymm12, %ymm11
	vmovdqa	%ymm14, 480(%rsp)
	vmovdqa	%ymm11, 320(%rsp)
	vinserti128	$1, 384(%rsp), %ymm13, %ymm11
	vpaddw	864(%rsp), %ymm7, %ymm7
	vperm2i128	$49, 384(%rsp), %ymm13, %ymm13
	vmovdqa	576(%rsp), %ymm15
	vpaddw	928(%rsp), %ymm7, %ymm7
	vpermd	%ymm11, %ymm12, %ymm11
	vmovdqa	544(%rsp), %ymm1
	vmovdqa	%ymm11, 384(%rsp)
	vinserti128	$1, %xmm2, %ymm4, %ymm11
	vperm2i128	$49, %ymm2, %ymm4, %ymm4
	vpermd	%ymm13, %ymm12, %ymm13
	vpermd	%ymm4, %ymm12, %ymm2
	vpaddw	%ymm7, %ymm6, %ymm4
	vmovdqa	%ymm13, 288(%rsp)
	vpermd	%ymm11, %ymm12, %ymm13
	vmovdqa	%ymm2, 32(%rsp)
	vmovdqa	992(%rsp), %ymm2
	vmovdqa	%ymm7, 992(%rsp)
	vpmulhuw	%ymm0, %ymm4, %ymm7
	vpaddw	832(%rsp), %ymm2, %ymm2
	vmovdqa	%ymm13, 64(%rsp)
	vpaddw	896(%rsp), %ymm2, %ymm2
	vpsrlw	$4, %ymm7, %ymm7
	vpaddw	%ymm2, %ymm5, %ymm11
	vmovdqa	%ymm2, 928(%rsp)
	vpsllw	$2, %ymm7, %ymm2
	vpaddw	%ymm7, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm2
	vpsubw	%ymm7, %ymm2, %ymm2
	vpmulhuw	%ymm0, %ymm11, %ymm7
	vpsubw	%ymm2, %ymm4, %ymm4
	vpsrlw	$4, %ymm7, %ymm7
	vpsllw	$2, %ymm7, %ymm2
	vpaddw	%ymm7, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm2
	vpsubw	%ymm7, %ymm2, %ymm2
	vpunpcklwd	%ymm10, %ymm4, %ymm7
	vpunpckhwd	%ymm10, %ymm4, %ymm4
	vpsubw	%ymm2, %ymm11, %ymm2
	vperm2i128	$32, %ymm4, %ymm7, %ymm10
	vperm2i128	$49, %ymm4, %ymm7, %ymm4
	vpunpcklwd	%ymm9, %ymm2, %ymm7
	vpunpckhwd	%ymm9, %ymm2, %ymm2
	vperm2i128	$32, %ymm2, %ymm7, %ymm9
	vperm2i128	$49, %ymm2, %ymm7, %ymm14
	vinserti128	$1, %xmm10, %ymm15, %ymm2
	vperm2i128	$49, %ymm10, %ymm15, %ymm7
	vmovdqa	256(%rsp), %ymm15
	vinserti128	$1, %xmm4, %ymm1, %ymm10
	vperm2i128	$49, %ymm4, %ymm1, %ymm4
	vmovdqa	736(%rsp), %ymm1
	vpermd	%ymm2, %ymm12, %ymm2
	vpermd	%ymm7, %ymm12, %ymm7
	vpermd	%ymm10, %ymm12, %ymm10
	vinserti128	$1, %xmm9, %ymm15, %ymm11
	vperm2i128	$49, %ymm9, %ymm15, %ymm9
	vmovdqa	224(%rsp), %ymm15
	vpermd	%ymm4, %ymm12, %ymm4
	vpermd	%ymm11, %ymm12, %ymm11
	vpermd	%ymm9, %ymm12, %ymm9
	vinserti128	$1, %xmm14, %ymm15, %ymm13
	vperm2i128	$49, %ymm14, %ymm15, %ymm14
	vpermd	%ymm14, %ymm12, %ymm15
	vinserti128	$1, %xmm1, %ymm2, %ymm14
	vperm2i128	$49, %ymm1, %ymm2, %ymm2
	vpermq	$216, %ymm2, %ymm2
	vpermq	$216, %ymm14, %ymm14
	vpermd	%ymm13, %ymm12, %ymm13
	vmovdqa	%ymm2, 864(%rsp)
	vinserti128	$1, 768(%rsp), %ymm7, %ymm2
	vperm2i128	$49, 768(%rsp), %ymm7, %ymm7
	vmovdqa	%ymm14, 896(%rsp)
	vpermq	$216, %ymm2, %ymm2
	vpermq	$216, %ymm7, %ymm7
	vmovdqa	%ymm2, 832(%rsp)
	vinserti128	$1, 704(%rsp), %ymm10, %ymm2
	vperm2i128	$49, 704(%rsp), %ymm10, %ymm10
	vmovdqa	%ymm7, 768(%rsp)
	vpermq	$216, %ymm2, %ymm7
	vinserti128	$1, 672(%rsp), %ymm4, %ymm2
	vpermq	$216, %ymm10, %ymm10
	vperm2i128	$49, 672(%rsp), %ymm4, %ymm4
	vmovdqa	%ymm10, 704(%rsp)
	vpermq	$216, %ymm2, %ymm10
	vmovdqa	%ymm7, 736(%rsp)
	vmovdqa	%ymm10, 672(%rsp)
	vpermq	$216, %ymm4, %ymm10
	vmovdqa	%ymm10, 576(%rsp)
	vinserti128	$1, 640(%rsp), %ymm11, %ymm2
	vperm2i128	$49, 640(%rsp), %ymm11, %ymm11
	vpermq	$216, %ymm2, %ymm10
	vinserti128	$1, 608(%rsp), %ymm9, %ymm2
	vperm2i128	$49, 608(%rsp), %ymm9, %ymm9
	vpermq	$216, %ymm11, %ymm4
	vmovdqa	%ymm10, 640(%rsp)
	vpermq	$216, %ymm2, %ymm11
	vinserti128	$1, 448(%rsp), %ymm13, %ymm2
	vpermq	$216, %ymm9, %ymm9
	vmovdqa	%ymm4, 544(%rsp)
	vmovdqa	%ymm9, 256(%rsp)
	vperm2i128	$49, 448(%rsp), %ymm13, %ymm13
	vpermq	$216, %ymm2, %ymm9
	vinserti128	$1, 352(%rsp), %ymm15, %ymm2
	vperm2i128	$49, 352(%rsp), %ymm15, %ymm15
	vmovdqa	%ymm11, 608(%rsp)
	vmovdqa	%ymm9, 448(%rsp)
	vpermq	$216, %ymm13, %ymm4
	vpermq	$216, %ymm2, %ymm9
	vmovdqa	.LC63(%rip), %ymm2
	vmovdqa	%ymm4, 224(%rsp)
	vpermq	$216, %ymm15, %ymm15
	vmovdqa	%ymm15, (%rsp)
	vpmullw	%ymm2, %ymm6, %ymm6
	vpmullw	%ymm2, %ymm5, %ymm4
	vmovdqa	%ymm9, 352(%rsp)
	vpaddw	992(%rsp), %ymm6, %ymm6
	vpaddw	928(%rsp), %ymm4, %ymm4
	vpmulhuw	%ymm0, %ymm6, %ymm5
	vpmulhuw	%ymm0, %ymm4, %ymm0
	vpsrlw	$4, %ymm5, %ymm5
	vpsrlw	$4, %ymm0, %ymm0
	vpsllw	$2, %ymm5, %ymm2
	vpaddw	%ymm5, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm2
	vpsubw	%ymm5, %ymm2, %ymm2
	vpsllw	$2, %ymm0, %ymm5
	vpaddw	%ymm0, %ymm5, %ymm5
	vpsubw	%ymm2, %ymm6, %ymm2
	vpsllw	$2, %ymm5, %ymm5
	vpsubw	%ymm0, %ymm5, %ymm5
	vpunpcklwd	%ymm8, %ymm2, %ymm0
	vpunpckhwd	%ymm8, %ymm2, %ymm2
	vpsubw	%ymm5, %ymm4, %ymm6
	vperm2i128	$32, %ymm2, %ymm0, %ymm5
	vperm2i128	$49, %ymm2, %ymm0, %ymm0
	vpunpcklwd	1024(%rsp), %ymm6, %ymm4
	vpunpckhwd	1024(%rsp), %ymm6, %ymm6
	vperm2i128	$49, 192(%rsp), %ymm5, %ymm2
	vperm2i128	$32, %ymm6, %ymm4, %ymm7
	vperm2i128	$49, %ymm6, %ymm4, %ymm4
	vinserti128	$1, 192(%rsp), %ymm5, %ymm6
	vinserti128	$1, 128(%rsp), %ymm7, %ymm15
	vpermd	%ymm2, %ymm12, %ymm2
	vinserti128	$1, 160(%rsp), %ymm0, %ymm5
	vpermd	%ymm6, %ymm12, %ymm6
	vinserti128	$1, 96(%rsp), %ymm4, %ymm14
	vperm2i128	$49, 160(%rsp), %ymm0, %ymm0
	vpermd	%ymm15, %ymm12, %ymm15
	vinserti128	$1, 512(%rsp), %ymm6, %ymm13
	vperm2i128	$49, 128(%rsp), %ymm7, %ymm7
	vperm2i128	$49, 96(%rsp), %ymm4, %ymm4
	vperm2i128	$49, 512(%rsp), %ymm6, %ymm6
	vpermd	%ymm14, %ymm12, %ymm14
	vinserti128	$1, 800(%rsp), %ymm2, %ymm11
	vperm2i128	$49, 800(%rsp), %ymm2, %ymm2
	vpermd	%ymm7, %ymm12, %ymm7
	vpextrb	$0, %xmm3, -125(%rax)
	vinserti128	$1, 384(%rsp), %ymm15, %ymm8
	vperm2i128	$49, 384(%rsp), %ymm15, %ymm15
	vpermd	%ymm5, %ymm12, %ymm5
	vpextrb	$1, %xmm3, -121(%rax)
	vpermd	%ymm0, %ymm12, %ymm0
	vpermd	%ymm4, %ymm12, %ymm4
	vinserti128	$1, 480(%rsp), %ymm5, %ymm10
	vpextrb	$2, %xmm3, -117(%rax)
	vpermq	$216, %ymm15, %ymm15
	vinserti128	$1, 320(%rsp), %ymm0, %ymm9
	vperm2i128	$49, 480(%rsp), %ymm5, %ymm5
	vpextrb	$3, %xmm3, -113(%rax)
	vmovdqa	%ymm15, 1024(%rsp)
	vinserti128	$1, 288(%rsp), %ymm7, %ymm15
	vperm2i128	$49, 288(%rsp), %ymm7, %ymm7
	vpextrb	$4, %xmm3, -109(%rax)
	vperm2i128	$49, 320(%rsp), %ymm0, %ymm0
	vpextrb	$5, %xmm3, -105(%rax)
	vpextrb	$6, %xmm3, -101(%rax)
	vpextrb	$7, %xmm3, -97(%rax)
	vpermq	$216, %ymm7, %ymm7
	vpextrb	$8, %xmm3, -93(%rax)
	vpextrb	$9, %xmm3, -89(%rax)
	vpextrb	$10, %xmm3, -85(%rax)
	vmovdqa	%ymm7, 992(%rsp)
	vinserti128	$1, 64(%rsp), %ymm14, %ymm7
	vpextrb	$11, %xmm3, -81(%rax)
	vperm2i128	$49, 64(%rsp), %ymm14, %ymm14
	vpextrb	$12, %xmm3, -77(%rax)
	vpextrb	$13, %xmm3, -73(%rax)
	vpextrb	$14, %xmm3, -69(%rax)
	vpextrb	$15, %xmm3, -65(%rax)
	vpermq	$216, %ymm7, %ymm7
	vpermq	$216, %ymm13, %ymm13
	vpermq	$216, %ymm6, %ymm6
	vmovdqa	%ymm7, 928(%rsp)
	vinserti128	$1, 32(%rsp), %ymm4, %ymm7
	vperm2i128	$49, 32(%rsp), %ymm4, %ymm4
	vpermq	$216, %ymm11, %ymm11
	vmovdqa	960(%rsp), %xmm3
	vpermq	$216, %ymm2, %ymm2
	vpermq	$216, %ymm10, %ymm10
	vpermq	$216, %ymm5, %ymm5
	vpermq	$216, %ymm9, %ymm9
	vpermq	$216, %ymm0, %ymm0
	vpermq	$216, %ymm8, %ymm8
	vpextrb	$0, %xmm3, -61(%rax)
	vpextrb	$1, %xmm3, -57(%rax)
	vpextrb	$2, %xmm3, -53(%rax)
	vpextrb	$3, %xmm3, -49(%rax)
	vpextrb	$4, %xmm3, -45(%rax)
	vpextrb	$5, %xmm3, -41(%rax)
	vpextrb	$6, %xmm3, -37(%rax)
	vpextrb	$7, %xmm3, -33(%rax)
	vpextrb	$8, %xmm3, -29(%rax)
	vpextrb	$9, %xmm3, -25(%rax)
	vpextrb	$10, %xmm3, -21(%rax)
	vpextrb	$11, %xmm3, -17(%rax)
	vpextrb	$12, %xmm3, -13(%rax)
	vpextrb	$13, %xmm3, -9(%rax)
	vpextrb	$14, %xmm3, -5(%rax)
	vpextrb	$15, %xmm3, -1(%rax)
	vmovdqa	896(%rsp), %ymm3
	vpermq	$216, %ymm15, %ymm15
	vpermq	$216, %ymm14, %ymm14
	vpermq	$216, %ymm7, %ymm7
	vpermq	$216, %ymm4, %ymm4
	vperm2i128	$32, %ymm3, %ymm13, %ymm1
	vperm2i128	$49, %ymm3, %ymm13, %ymm13
	vmovdqa	864(%rsp), %ymm3
	vmovdqu	%ymm1, -1024(%rdx)
	vperm2i128	$32, %ymm3, %ymm6, %ymm1
	vperm2i128	$49, %ymm3, %ymm6, %ymm6
	vmovdqa	736(%rsp), %ymm3
	vmovdqu	%ymm13, -992(%rdx)
	vmovdqu	%ymm6, -928(%rdx)
	vmovdqa	832(%rsp), %ymm6
	vmovdqu	%ymm1, -960(%rdx)
	vperm2i128	$32, %ymm6, %ymm11, %ymm1
	vperm2i128	$49, %ymm6, %ymm11, %ymm11
	vmovdqa	768(%rsp), %ymm6
	vmovdqu	%ymm1, -896(%rdx)
	vperm2i128	$32, %ymm6, %ymm2, %ymm1
	vperm2i128	$49, %ymm6, %ymm2, %ymm2
	vmovdqu	%ymm11, -864(%rdx)
	vmovdqu	%ymm1, -832(%rdx)
	vperm2i128	$32, %ymm3, %ymm10, %ymm1
	vperm2i128	$49, %ymm3, %ymm10, %ymm10
	vmovdqu	%ymm2, -800(%rdx)
	vmovdqu	%ymm1, -768(%rdx)
	vmovdqu	%ymm10, -736(%rdx)
	vmovdqa	704(%rsp), %ymm6
	vmovdqa	640(%rsp), %ymm3
	vmovdqa	1024(%rsp), %ymm2
	vperm2i128	$32, %ymm6, %ymm5, %ymm1
	vperm2i128	$49, %ymm6, %ymm5, %ymm5
	vmovdqa	608(%rsp), %ymm6
	vmovdqu	%ymm5, -672(%rdx)
	vmovdqa	672(%rsp), %ymm5
	vmovdqu	%ymm1, -704(%rdx)
	vperm2i128	$32, %ymm5, %ymm9, %ymm1
	vperm2i128	$49, %ymm5, %ymm9, %ymm9
	vmovdqa	576(%rsp), %ymm5
	vmovdqu	%ymm1, -640(%rdx)
	vperm2i128	$32, %ymm5, %ymm0, %ymm1
	vperm2i128	$49, %ymm5, %ymm0, %ymm0
	vmovdqa	544(%rsp), %ymm5
	vmovdqu	%ymm9, -608(%rdx)
	vmovdqu	%ymm0, -544(%rdx)
	vperm2i128	$32, %ymm3, %ymm8, %ymm0
	vperm2i128	$49, %ymm3, %ymm8, %ymm8
	vmovdqa	256(%rsp), %ymm3
	vmovdqu	%ymm0, -512(%rdx)
	vperm2i128	$32, %ymm5, %ymm2, %ymm0
	vmovdqu	%ymm0, -448(%rdx)
	vperm2i128	$49, %ymm5, %ymm2, %ymm0
	vmovdqa	992(%rsp), %ymm2
	vmovdqa	448(%rsp), %ymm5
	vmovdqu	%ymm0, -416(%rdx)
	vperm2i128	$32, %ymm6, %ymm15, %ymm0
	vperm2i128	$49, %ymm6, %ymm15, %ymm15
	vmovdqa	224(%rsp), %ymm6
	vmovdqu	%ymm0, -384(%rdx)
	vperm2i128	$32, %ymm3, %ymm2, %ymm0
	vmovdqu	%ymm0, -320(%rdx)
	vperm2i128	$49, %ymm3, %ymm2, %ymm0
	vmovdqa	928(%rsp), %ymm2
	vmovdqa	352(%rsp), %ymm3
	vmovdqu	%ymm0, -288(%rdx)
	vperm2i128	$32, %ymm5, %ymm2, %ymm0
	vmovdqu	%ymm1, -576(%rdx)
	vmovdqu	%ymm0, -256(%rdx)
	vperm2i128	$49, %ymm5, %ymm2, %ymm0
	vmovdqu	%ymm0, -224(%rdx)
	vperm2i128	$32, %ymm6, %ymm14, %ymm0
	vperm2i128	$49, %ymm6, %ymm14, %ymm14
	vmovdqu	%ymm0, -192(%rdx)
	vperm2i128	$32, %ymm3, %ymm7, %ymm0
	vperm2i128	$49, %ymm3, %ymm7, %ymm7
	vmovdqu	%ymm0, -128(%rdx)
	vmovdqu	%ymm8, -480(%rdx)
	vmovdqu	%ymm15, -352(%rdx)
	vmovdqu	%ymm14, -160(%rdx)
	vmovdqu	%ymm7, -96(%rdx)
	vmovdqa	(%rsp), %ymm5
	vperm2i128	$32, %ymm5, %ymm4, %ymm0
	vperm2i128	$49, %ymm5, %ymm4, %ymm4
	vmovdqu	%ymm0, -64(%rdx)
	vmovdqu	%ymm4, -32(%rdx)
	cmpq	%rdx, %rsi
	jne	.L69
	vmovdqa	.LC23(%rip), %xmm2
	vmovq	2464(%rsp), %xmm6
	vmovq	2480(%rsp), %xmm7
	vmovhps	2472(%rsp), %xmm6, %xmm6
	vpshufb	%xmm2, %xmm6, %xmm0
	vmovhps	2488(%rsp), %xmm7, %xmm7
	vpshufb	%xmm2, %xmm7, %xmm1
	vpunpcklqdq	%xmm1, %xmm0, %xmm0
	vmovdqa	.LC24(%rip), %xmm1
	vpshufb	%xmm2, %xmm0, %xmm3
	vpshufb	%xmm1, %xmm0, %xmm0
	vpshufb	%xmm1, %xmm7, %xmm7
	vpmovzxbw	%xmm0, %xmm5
	vpsrlq	$32, %xmm0, %xmm4
	vpshufb	%xmm1, %xmm6, %xmm0
	vmovq	%xmm5, %rcx
	vpunpcklqdq	%xmm7, %xmm0, %xmm0
	vpmovzxbw	%xmm4, %xmm4
	vmovq	%rcx, %xmm6
	vmovq	%rcx, %xmm7
	vpshufb	%xmm2, %xmm0, %xmm2
	vpsllw	$4, %xmm6, %xmm6
	vpmovzxbw	%xmm2, %xmm12
	vpshufb	%xmm1, %xmm0, %xmm0
	vpsllw	$1, %xmm12, %xmm10
	vpsrlq	$32, %xmm2, %xmm2
	vpsubw	%xmm7, %xmm6, %xmm6
	vpsllw	$1, %xmm5, %xmm13
	vpsllw	$1, %xmm4, %xmm11
	vpmovzxbw	%xmm2, %xmm2
	vpsllw	$1, %xmm2, %xmm15
	vpsllw	$3, %xmm2, %xmm14
	vpaddw	%xmm5, %xmm13, %xmm9
	vpaddw	%xmm10, %xmm6, %xmm6
	vpaddw	%xmm12, %xmm10, %xmm10
	vpaddw	%xmm4, %xmm11, %xmm5
	vmovq	%xmm6, %r12
	vpsllw	$4, %xmm4, %xmm6
	vpsubw	%xmm4, %xmm6, %xmm6
	vpaddw	%xmm15, %xmm6, %xmm6
	vpaddw	%xmm2, %xmm15, %xmm15
	vmovq	%xmm6, %r13
	vpsllw	$2, %xmm10, %xmm6
	vpaddw	%xmm12, %xmm6, %xmm6
	vpsllw	$1, %xmm10, %xmm10
	vpaddw	%xmm9, %xmm10, %xmm10
	vpaddw	%xmm13, %xmm6, %xmm6
	vmovq	%xmm10, %r8
	vpaddw	%xmm14, %xmm11, %xmm10
	vmovq	%xmm6, %rdx
	vpsllw	$2, %xmm15, %xmm6
	vpaddw	%xmm2, %xmm6, %xmm6
	vpsllw	$1, %xmm15, %xmm15
	vmovq	%xmm10, %r14
	vpaddw	%xmm5, %xmm15, %xmm15
	vpaddw	%xmm11, %xmm6, %xmm6
	vmovq	%xmm15, 1024(%rsp)
	vmovq	%xmm6, 544(%rsp)
	vpsllw	$3, %xmm12, %xmm6
	vpaddw	%xmm12, %xmm6, %xmm8
	vpsubw	%xmm12, %xmm6, %xmm12
	vpaddw	%xmm6, %xmm13, %xmm13
	vpsllw	$1, %xmm8, %xmm8
	vpsllw	$1, %xmm12, %xmm15
	vpaddw	%xmm7, %xmm8, %xmm8
	vpaddw	%xmm2, %xmm14, %xmm7
	vmovq	%xmm13, 928(%rsp)
	vmovq	%xmm15, %r15
	vpsubw	%xmm2, %xmm14, %xmm2
	vpaddw	%xmm9, %xmm15, %xmm9
	vpsllw	$1, %xmm7, %xmm7
	vpsllw	$1, %xmm2, %xmm2
	vmovq	%xmm9, %r11
	vpxor	%xmm9, %xmm9, %xmm9
	vpaddw	%xmm5, %xmm2, %xmm5
	vpcmpeqb	%xmm9, %xmm0, %xmm1
	vpaddw	%xmm4, %xmm7, %xmm7
	vmovq	%xmm2, 512(%rsp)
	vmovq	%xmm5, %r9
	vmovq	.LC25(%rip), %xmm5
	vpcmpeqb	%xmm9, %xmm1, %xmm1
	vpsubb	%xmm0, %xmm5, %xmm5
	vpsubb	%xmm1, %xmm5, %xmm5
	vpcmpeqb	%xmm9, %xmm3, %xmm1
	vpcmpeqb	%xmm9, %xmm1, %xmm1
	vpandn	%xmm5, %xmm1, %xmm1
	vpor	%xmm3, %xmm1, %xmm3
	vmovq	.LC26(%rip), %xmm1
	vpmovzxbw	%xmm3, %xmm11
	vpsrlq	$32, %xmm3, %xmm3
	vpsllw	$4, %xmm11, %xmm5
	vpmovzxbw	%xmm3, %xmm3
	vpsubw	%xmm11, %xmm5, %xmm10
	vpsllw	$4, %xmm3, %xmm13
	vmovq	%xmm5, 960(%rsp)
	vpaddw	%xmm8, %xmm10, %xmm10
	vpsubw	%xmm3, %xmm13, %xmm8
	vpaddw	%xmm3, %xmm13, %xmm13
	vpmulhuw	%xmm1, %xmm10, %xmm9
	vpaddw	%xmm7, %xmm8, %xmm8
	vpsrlw	$4, %xmm9, %xmm9
	vpsllw	$2, %xmm9, %xmm7
	vpaddw	%xmm9, %xmm7, %xmm7
	vpsllw	$2, %xmm7, %xmm7
	vpsubw	%xmm9, %xmm7, %xmm7
	vpmulhuw	%xmm1, %xmm8, %xmm9
	vpsubw	%xmm7, %xmm10, %xmm10
	vpsrlw	$4, %xmm9, %xmm9
	vpsllw	$2, %xmm9, %xmm7
	vpaddw	%xmm9, %xmm7, %xmm7
	vpsllw	$2, %xmm7, %xmm7
	vpsubw	%xmm9, %xmm7, %xmm7
	vpsllw	$1, %xmm11, %xmm9
	vpaddw	%xmm11, %xmm9, %xmm9
	vpsubw	%xmm7, %xmm8, %xmm15
	vpsllw	$1, %xmm3, %xmm8
	vpsllw	$2, %xmm9, %xmm7
	vpaddw	%xmm3, %xmm8, %xmm8
	vpsubw	%xmm11, %xmm7, %xmm7
	vpsllw	$2, %xmm8, %xmm2
	vpaddw	%xmm6, %xmm7, %xmm12
	vpsubw	%xmm3, %xmm2, %xmm2
	vpmulhuw	%xmm1, %xmm12, %xmm5
	vpaddw	%xmm14, %xmm2, %xmm2
	vpsrlw	$4, %xmm5, %xmm5
	vmovq	%xmm5, %rdi
	vpsllw	$2, %xmm5, %xmm5
	vmovq	%rdi, %xmm7
	vpaddw	%xmm7, %xmm5, %xmm5
	vpsllw	$2, %xmm5, %xmm7
	vmovq	%rdi, %xmm5
	vpsubw	%xmm5, %xmm7, %xmm7
	vpmulhuw	%xmm1, %xmm2, %xmm5
	vpsubw	%xmm7, %xmm12, %xmm7
	vpsrlw	$4, %xmm5, %xmm5
	vmovdqa	%xmm5, %xmm12
	vpsllw	$2, %xmm5, %xmm5
	vpaddw	%xmm12, %xmm5, %xmm5
	vpsllw	$2, %xmm5, %xmm5
	vpsubw	%xmm12, %xmm5, %xmm5
	vpsllw	$3, %xmm11, %xmm12
	vpsubw	%xmm11, %xmm12, %xmm12
	vpsubw	%xmm5, %xmm2, %xmm2
	vpunpcklwd	%xmm10, %xmm7, %xmm5
	vmovq	%xmm12, %rax
	vpsllw	$3, %xmm3, %xmm12
	vmovq	%xmm5, 896(%rsp)
	vpunpcklwd	%xmm10, %xmm7, %xmm5
	vpsubw	%xmm3, %xmm12, %xmm12
	vpshufd	$78, %xmm5, %xmm5
	vmovq	%xmm5, 864(%rsp)
	vpunpcklwd	%xmm15, %xmm2, %xmm5
	vmovq	%xmm5, 832(%rsp)
	vpunpcklwd	%xmm15, %xmm2, %xmm5
	vmovq	%xmm12, %r10
	vmovq	%rax, %xmm12
	vpshufd	$78, %xmm5, %xmm5
	vpaddw	%xmm12, %xmm6, %xmm6
	vmovq	%r10, %xmm12
	vmovq	%xmm5, 800(%rsp)
	vpaddw	%xmm12, %xmm14, %xmm14
	vpmulhuw	%xmm1, %xmm6, %xmm12
	vpsrlw	$4, %xmm12, %xmm12
	vmovdqa	%xmm12, %xmm5
	vpsllw	$2, %xmm12, %xmm12
	vpaddw	%xmm5, %xmm12, %xmm12
	vpsllw	$2, %xmm12, %xmm12
	vpsubw	%xmm5, %xmm12, %xmm12
	vpsubw	%xmm12, %xmm6, %xmm6
	vpmulhuw	%xmm1, %xmm14, %xmm12
	vpsrlw	$4, %xmm12, %xmm12
	vmovdqa	%xmm12, %xmm5
	vpsllw	$2, %xmm12, %xmm12
	vpaddw	%xmm5, %xmm12, %xmm12
	vpsllw	$2, %xmm12, %xmm12
	vpsubw	%xmm5, %xmm12, %xmm12
	vpunpcklwd	%xmm10, %xmm6, %xmm5
	vpunpcklwd	%xmm10, %xmm6, %xmm10
	vpshufd	$78, %xmm10, %xmm10
	vmovq	%xmm5, 640(%rsp)
	vmovq	%xmm10, 608(%rsp)
	vpsubw	%xmm12, %xmm14, %xmm14
	vpunpcklwd	%xmm15, %xmm14, %xmm12
	vpunpcklwd	%xmm15, %xmm14, %xmm10
	vmovq	1024(%rsp), %xmm15
	vpshufd	$78, %xmm12, %xmm12
	vmovq	%xmm10, 576(%rsp)
	vmovq	%rax, %xmm10
	vmovq	%xmm12, %rdi
	vmovq	%r8, %xmm12
	vpaddw	%xmm10, %xmm12, %xmm10
	vmovq	%r10, %xmm12
	vpaddw	%xmm12, %xmm15, %xmm12
	vpmulhuw	%xmm1, %xmm10, %xmm15
	vmovq	%xmm12, %r10
	vpsrlw	$4, %xmm15, %xmm12
	vpsllw	$2, %xmm12, %xmm15
	vpaddw	%xmm12, %xmm15, %xmm15
	vpsllw	$2, %xmm15, %xmm15
	vpsubw	%xmm12, %xmm15, %xmm15
	vmovq	%r10, %xmm12
	vpsubw	%xmm15, %xmm10, %xmm10
	vpmulhuw	%xmm1, %xmm12, %xmm15
	vpunpcklwd	%xmm7, %xmm10, %xmm5
	vpunpcklwd	%xmm7, %xmm10, %xmm7
	vpshufd	$78, %xmm7, %xmm7
	vmovq	%xmm5, 768(%rsp)
	vmovq	960(%rsp), %xmm5
	vpsrlw	$4, %xmm15, %xmm15
	vmovq	%xmm7, 736(%rsp)
	vpsllw	$2, %xmm15, %xmm12
	vpaddw	%xmm11, %xmm5, %xmm5
	vpaddw	%xmm15, %xmm12, %xmm12
	vpsllw	$2, %xmm12, %xmm12
	vpsubw	%xmm15, %xmm12, %xmm15
	vmovq	%r10, %xmm12
	vpsubw	%xmm15, %xmm12, %xmm15
	vpunpcklwd	%xmm2, %xmm15, %xmm7
	vpunpcklwd	%xmm14, %xmm15, %xmm12
	vmovq	%xmm7, 704(%rsp)
	vpunpcklwd	%xmm2, %xmm15, %xmm7
	vmovq	%xmm12, %r8
	vmovq	%rdx, %xmm12
	vpshufd	$78, %xmm7, %xmm7
	vpunpcklwd	%xmm14, %xmm15, %xmm15
	vmovq	544(%rsp), %xmm14
	vmovq	%xmm7, 672(%rsp)
	vpunpcklwd	%xmm6, %xmm10, %xmm7
	vpunpcklwd	%xmm6, %xmm10, %xmm6
	vpaddw	%xmm12, %xmm9, %xmm10
	vpshufd	$78, %xmm15, %xmm15
	vmovq	%xmm7, 1024(%rsp)
	vpaddw	%xmm14, %xmm8, %xmm7
	vmovq	%r14, %xmm12
	vmovq	%xmm15, 992(%rsp)
	vpaddw	%xmm8, %xmm12, %xmm8
	vmovq	%r12, %xmm12
	vpshufd	$78, %xmm6, %xmm6
	vpmulhuw	%xmm1, %xmm10, %xmm15
	vpsrlw	$4, %xmm15, %xmm15
	vpsllw	$2, %xmm15, %xmm14
	vpaddw	%xmm15, %xmm14, %xmm14
	vpsllw	$2, %xmm14, %xmm14
	vpsubw	%xmm15, %xmm14, %xmm14
	vpmulhuw	%xmm1, %xmm7, %xmm15
	vpsubw	%xmm14, %xmm10, %xmm10
	vpsrlw	$4, %xmm15, %xmm15
	vpsllw	$2, %xmm15, %xmm14
	vpaddw	%xmm15, %xmm14, %xmm14
	vpsllw	$2, %xmm14, %xmm14
	vpsubw	%xmm15, %xmm14, %xmm14
	vpsubw	%xmm14, %xmm7, %xmm7
	vmovq	928(%rsp), %xmm14
	vpaddw	%xmm9, %xmm14, %xmm9
	vpmulhuw	%xmm1, %xmm9, %xmm15
	vpsrlw	$4, %xmm15, %xmm15
	vpsllw	$2, %xmm15, %xmm14
	vpaddw	%xmm15, %xmm14, %xmm14
	vpsllw	$2, %xmm14, %xmm14
	vpsubw	%xmm15, %xmm14, %xmm14
	vpmulhuw	%xmm1, %xmm8, %xmm15
	vpsubw	%xmm14, %xmm9, %xmm9
	vpsrlw	$4, %xmm15, %xmm15
	vpsllw	$2, %xmm15, %xmm14
	vpaddw	%xmm15, %xmm14, %xmm14
	vpsllw	$2, %xmm14, %xmm14
	vpsubw	%xmm15, %xmm14, %xmm14
	vpmovzxbw	%xmm0, %xmm15
	vpaddw	%xmm15, %xmm5, %xmm5
	vpsrlq	$32, %xmm0, %xmm0
	vpmovzxbw	%xmm0, %xmm0
	vpsubw	%xmm14, %xmm8, %xmm8
	vpaddw	%xmm0, %xmm13, %xmm13
	vpaddw	%xmm12, %xmm5, %xmm5
	vmovq	%r13, %xmm12
	vpaddw	%xmm12, %xmm13, %xmm13
	vpmulhuw	%xmm1, %xmm5, %xmm14
	vpsrlw	$4, %xmm14, %xmm12
	vpsllw	$2, %xmm12, %xmm14
	vpaddw	%xmm12, %xmm14, %xmm14
	vpsllw	$2, %xmm14, %xmm14
	vpsubw	%xmm12, %xmm14, %xmm14
	vpsubw	%xmm14, %xmm5, %xmm5
	vpmulhuw	%xmm1, %xmm13, %xmm14
	vpsrlw	$4, %xmm14, %xmm12
	vpsllw	$2, %xmm12, %xmm14
	vpaddw	%xmm12, %xmm14, %xmm14
	vpsllw	$2, %xmm14, %xmm14
	vpsubw	%xmm12, %xmm14, %xmm14
	vpunpcklwd	%xmm5, %xmm10, %xmm12
	vpunpcklwd	%xmm5, %xmm10, %xmm5
	vmovq	%xmm12, %r10
	vpshufd	$78, %xmm5, %xmm5
	vpsubw	%xmm14, %xmm13, %xmm13
	vpunpcklwd	%xmm13, %xmm7, %xmm14
	vpunpcklwd	%xmm13, %xmm7, %xmm13
	vpshufd	$78, %xmm13, %xmm13
	vmovq	%xmm14, 544(%rsp)
	vmovq	%xmm13, %r13
	vmovq	%r11, %xmm13
	vpaddw	%xmm13, %xmm15, %xmm13
	vmovq	%xmm13, %rsi
	vmovq	%r9, %xmm13
	vpaddw	%xmm13, %xmm0, %xmm13
	vpaddw	%xmm4, %xmm0, %xmm0
	vmovq	%xmm13, %rax
	vmovq	%rsi, %xmm13
	vpmulhuw	%xmm1, %xmm13, %xmm14
	vpsrlw	$4, %xmm14, %xmm14
	vpsllw	$2, %xmm14, %xmm13
	vpaddw	%xmm14, %xmm13, %xmm13
	vpsllw	$2, %xmm13, %xmm13
	vpsubw	%xmm14, %xmm13, %xmm14
	vmovq	%rsi, %xmm13
	vpsubw	%xmm14, %xmm13, %xmm14
	vmovq	%rax, %xmm13
	vpmulhuw	%xmm1, %xmm13, %xmm13
	vpsrlw	$4, %xmm13, %xmm13
	vmovdqa	%xmm13, %xmm12
	vpsllw	$2, %xmm13, %xmm13
	vpaddw	%xmm12, %xmm13, %xmm13
	vpsllw	$2, %xmm13, %xmm13
	vpsubw	%xmm12, %xmm13, %xmm13
	vmovq	%rax, %xmm12
	vpsubw	%xmm13, %xmm12, %xmm13
	vpunpcklwd	%xmm14, %xmm9, %xmm12
	vpunpcklwd	%xmm14, %xmm9, %xmm14
	vmovq	%xmm12, %rsi
	vmovq	%rcx, %xmm12
	vpshufd	$78, %xmm14, %xmm14
	vpaddw	%xmm12, %xmm15, %xmm15
	vpunpcklwd	%xmm13, %xmm8, %xmm2
	vpunpcklwd	%xmm13, %xmm8, %xmm13
	vpshufd	$78, %xmm13, %xmm13
	vmovq	%xmm2, 960(%rsp)
	vmovq	%xmm13, 928(%rsp)
	vmovq	%r15, %xmm13
	vmovq	512(%rsp), %xmm2
	vpaddw	%xmm13, %xmm15, %xmm15
	vpaddw	%xmm2, %xmm0, %xmm0
	vpaddw	%xmm11, %xmm15, %xmm2
	vpaddw	%xmm3, %xmm0, %xmm13
	vpmulhuw	%xmm1, %xmm2, %xmm12
	vpsrlw	$4, %xmm12, %xmm12
	vpsllw	$2, %xmm12, %xmm4
	vpaddw	%xmm12, %xmm4, %xmm4
	vpsllw	$2, %xmm4, %xmm4
	vpsubw	%xmm12, %xmm4, %xmm4
	vpmulhuw	%xmm1, %xmm13, %xmm12
	vpsubw	%xmm4, %xmm2, %xmm2
	vpsrlw	$4, %xmm12, %xmm12
	vpsllw	$2, %xmm12, %xmm4
	vpaddw	%xmm12, %xmm4, %xmm4
	vpsllw	$2, %xmm4, %xmm4
	vpsubw	%xmm12, %xmm4, %xmm4
	vpunpcklwd	%xmm10, %xmm2, %xmm12
	vpunpcklwd	%xmm10, %xmm2, %xmm2
	vpshufd	$78, %xmm2, %xmm2
	vpsubw	%xmm4, %xmm13, %xmm4
	vpunpcklwd	%xmm7, %xmm4, %xmm13
	vpunpcklwd	%xmm7, %xmm4, %xmm4
	vpshufd	$78, %xmm4, %xmm4
	vmovq	%xmm4, %rax
	vpsllw	$2, %xmm11, %xmm4
	vpaddw	%xmm11, %xmm4, %xmm4
	vpsllw	$2, %xmm3, %xmm11
	vpaddw	%xmm3, %xmm11, %xmm3
	vpsllw	$1, %xmm4, %xmm4
	vpaddw	%xmm15, %xmm4, %xmm4
	vpsllw	$1, %xmm3, %xmm3
	vpaddw	%xmm0, %xmm3, %xmm3
	vpmulhuw	%xmm1, %xmm4, %xmm11
	vpmulhuw	%xmm1, %xmm3, %xmm1
	vpsrlw	$4, %xmm11, %xmm11
	vpsllw	$2, %xmm11, %xmm0
	vpsrlw	$4, %xmm1, %xmm1
	vpaddw	%xmm11, %xmm0, %xmm0
	vpsllw	$2, %xmm0, %xmm0
	vpsubw	%xmm11, %xmm0, %xmm0
	vpsubw	%xmm0, %xmm4, %xmm0
	vpsllw	$2, %xmm1, %xmm4
	vpaddw	%xmm1, %xmm4, %xmm4
	vpsllw	$2, %xmm4, %xmm4
	vpsubw	%xmm1, %xmm4, %xmm4
	vpunpcklwd	%xmm9, %xmm0, %xmm1
	vpunpcklwd	%xmm9, %xmm0, %xmm0
	vmovq	%r10, %xmm9
	vpshufd	$78, %xmm0, %xmm0
	vpsubw	%xmm4, %xmm3, %xmm4
	vpunpcklwd	%xmm8, %xmm4, %xmm3
	vpunpcklwd	%xmm8, %xmm4, %xmm4
	vinsertps	$16, 1024(%rsp), %xmm1, %xmm8
	vpshufd	$78, %xmm4, %xmm4
	vmovq	%xmm8, 9216(%rbx)
	vmovq	%rsi, %xmm8
	vinsertps	$16, 896(%rsp), %xmm8, %xmm8
	vmovq	%xmm8, 9224(%rbx)
	vmovq	768(%rsp), %xmm8
	vinsertps	$16, %xmm12, %xmm8, %xmm8
	vinsertps	$0, 772(%rsp), %xmm12, %xmm12
	vmovq	%xmm8, 9232(%rbx)
	vmovq	640(%rsp), %xmm8
	vmovq	%xmm12, 9264(%rbx)
	vinsertps	$16, %xmm9, %xmm8, %xmm8
	vmovq	%xmm8, 9240(%rbx)
	vmovq	1024(%rsp), %xmm8
	vinsertps	$64, %xmm1, %xmm8, %xmm1
	vmovq	%rsi, %xmm8
	vmovq	%xmm1, 9248(%rbx)
	vmovq	896(%rsp), %xmm1
	vinsertps	$64, %xmm8, %xmm1, %xmm1
	vmovq	%xmm1, 9256(%rbx)
	vinsertps	$0, 644(%rsp), %xmm9, %xmm1
	vmovq	%xmm1, 9272(%rbx)
	vinsertps	$16, %xmm6, %xmm0, %xmm1
	vinsertps	$64, %xmm0, %xmm6, %xmm6
	vmovq	%xmm1, 9280(%rbx)
	vinsertps	$16, 864(%rsp), %xmm14, %xmm1
	vmovq	%xmm6, 9312(%rbx)
	vmovq	864(%rsp), %xmm6
	vmovq	%xmm1, 9288(%rbx)
	vmovq	736(%rsp), %xmm1
	vinsertps	$64, %xmm14, %xmm6, %xmm14
	vmovq	%r8, %xmm6
	vinsertps	$16, %xmm2, %xmm1, %xmm1
	vinsertps	$0, 740(%rsp), %xmm2, %xmm2
	vinsertps	$16, %xmm6, %xmm3, %xmm0
	vmovq	%xmm14, 9320(%rbx)
	vmovq	%xmm1, 9296(%rbx)
	vmovq	608(%rsp), %xmm1
	vmovq	%xmm0, 9344(%rbx)
	vinsertps	$16, %xmm5, %xmm1, %xmm1
	vinsertps	$0, 612(%rsp), %xmm5, %xmm5
	vmovq	%xmm2, 9328(%rbx)
	vmovq	%xmm1, 9304(%rbx)
	vmovq	%xmm5, 9336(%rbx)
	vmovq	960(%rsp), %xmm6
	vinsertps	$16, 832(%rsp), %xmm6, %xmm0
	vmovq	704(%rsp), %xmm6
	vmovq	%xmm0, 9352(%rbx)
	vinsertps	$16, %xmm13, %xmm6, %xmm0
	vmovq	576(%rsp), %xmm6
	vinsertps	$0, 708(%rsp), %xmm13, %xmm13
	vmovq	%xmm0, 9360(%rbx)
	vinsertps	$16, 544(%rsp), %xmm6, %xmm0
	vmovq	%r8, %xmm6
	vmovq	%xmm13, 9392(%rbx)
	vinsertps	$64, %xmm3, %xmm6, %xmm3
	vmovq	%rax, %xmm6
	vmovq	%xmm3, 9376(%rbx)
	vmovq	832(%rsp), %xmm3
	vmovq	%xmm0, 9368(%rbx)
	vinsertps	$0, 964(%rsp), %xmm3, %xmm0
	vmovq	544(%rsp), %xmm3
	vmovq	%xmm0, 9384(%rbx)
	vinsertps	$0, 580(%rsp), %xmm3, %xmm0
	vmovq	928(%rsp), %xmm3
	vmovq	%xmm0, 9400(%rbx)
	vinsertps	$16, 992(%rsp), %xmm4, %xmm0
	vmovq	%xmm0, 9408(%rbx)
	vinsertps	$16, 800(%rsp), %xmm3, %xmm0
	vmovq	672(%rsp), %xmm3
	vmovq	%xmm0, 9416(%rbx)
	vinsertps	$16, %xmm6, %xmm3, %xmm0
	vmovq	%rdi, %xmm3
	vmovq	%r13, %xmm6
	vmovq	%xmm0, 9424(%rbx)
	vinsertps	$16, %xmm6, %xmm3, %xmm0
	vmovq	992(%rsp), %xmm3
	vmovq	%rdi, %xmm6
	vmovq	%xmm0, 9432(%rbx)
	vinsertps	$64, %xmm4, %xmm3, %xmm4
	vmovq	800(%rsp), %xmm3
	vmovq	%xmm4, 9440(%rbx)
	vinsertps	$0, 932(%rsp), %xmm3, %xmm0
	vmovq	%rax, %xmm3
	vmovq	%xmm0, 9448(%rbx)
	vinsertps	$0, 676(%rsp), %xmm3, %xmm0
	vmovq	%r13, %xmm3
	vmovq	%xmm0, 9456(%rbx)
	vinsertps	$64, %xmm6, %xmm3, %xmm0
	vmovq	%xmm0, 9464(%rbx)
	movq	2520(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L76
	vzeroupper
	leaq	-40(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	.cfi_remember_state
	.cfi_def_cfa 7, 8
	ret
.L76:
	.cfi_restore_state
	vzeroupper
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE14:
	.size	expand_T12, .-expand_T12
	.p2align 4
	.globl	_snova_37_8_19_4_SNOVA_OPT_genkeys
	.type	_snova_37_8_19_4_SNOVA_OPT_genkeys, @function
_snova_37_8_19_4_SNOVA_OPT_genkeys:
.LFB16:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	.cfi_offset 15, -24
	.cfi_offset 14, -32
	.cfi_offset 13, -40
	.cfi_offset 12, -48
	.cfi_offset 3, -56
	movq	%rdi, %rbx
	andq	$-32, %rsp
	subq	$290944, %rsp
	movq	%rsi, 24(%rsp)
	leaq	2144(%rsp), %r13
	leaq	16(%rdx), %rsi
	movq	%r13, %rdi
	leaq	25312(%rsp), %r15
	leaq	208752(%rsp), %r14
	movq	%fs:40, %r12
	movq	%r12, 290936(%rsp)
	movq	%rdx, %r12
	call	expand_T12
	leaq	33520(%rsp), %rdi
	movq	%r12, %rsi
	call	expand_public
	movq	%r15, %rdi
	movl	$8192, %edx
	xorl	%esi, %esi
	movq	%r15, 56(%rsp)
	call	memset@PLT
	leaq	96(%rsp), %rax
	movq	$0, 80(%rsp)
	movq	%r12, %r10
	movq	%rax, 88(%rsp)
	leaq	21088(%rsp), %rax
	movq	%rbx, %r12
	leaq	33520(%rsp), %rbx
	movq	%rax, 48(%rsp)
	movq	%r15, 72(%rsp)
	leaq	11616(%rsp), %r15
.L94:
	movl	$9472, %edx
	xorl	%esi, %esi
	movq	%r15, %rdi
	movq	%r10, 40(%rsp)
	call	memset@PLT
	movq	88(%rsp), %rdi
	movl	$2048, %edx
	xorl	%esi, %esi
	call	memset@PLT
	movq	%rbx, 64(%rsp)
	vmovdqa	.LC64(%rip), %ymm15
	movq	%rbx, %rdx
	vmovdqa	.LC65(%rip), %ymm14
	vmovdqa	.LC66(%rip), %ymm13
	movq	%r13, %rsi
	xorl	%r11d, %r11d
	vmovdqa	.LC67(%rip), %ymm12
	vmovdqa	.LC8(%rip), %ymm11
	movq	%r13, %rcx
.L78:
	movl	%r11d, 36(%rsp)
	movq	%r15, %r8
	movq	%r15, %rbx
	movq	%rdx, %r10
	xorl	%eax, %eax
	leaq	256(%rsi), %r9
.L82:
	vpmovzxbw	(%r10), %ymm2
	movq	%rbx, %r11
	movq	%rsi, %rdi
	vpshufb	%ymm15, %ymm2, %ymm5
	vpshufb	%ymm14, %ymm2, %ymm4
	vpshufb	%ymm13, %ymm2, %ymm3
	vpshufb	%ymm12, %ymm2, %ymm2
	.p2align 4,,10
	.p2align 3
.L79:
	vmovdqa	(%rdi), %ymm1
	addq	$32, %rdi
	addq	$32, %r11
	vpermq	$0, %ymm1, %ymm0
	vpermq	$85, %ymm1, %ymm6
	vpmullw	%ymm0, %ymm5, %ymm0
	vpmullw	%ymm6, %ymm4, %ymm6
	vpaddw	-32(%r11), %ymm0, %ymm0
	vpaddw	%ymm6, %ymm0, %ymm0
	vpermq	$170, %ymm1, %ymm6
	vpermq	$255, %ymm1, %ymm1
	vpmullw	%ymm6, %ymm3, %ymm6
	vpmullw	%ymm2, %ymm1, %ymm1
	vpaddw	%ymm6, %ymm0, %ymm0
	vpaddw	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, -32(%r11)
	cmpq	%rdi, %r9
	jne	.L79
	addq	$8, %rax
	addq	$592, %r10
	addq	$256, %rbx
	cmpq	$296, %rax
	jne	.L82
	movl	36(%rsp), %r11d
	addq	$16, %rdx
	incl	%r11d
	cmpl	$37, %r11d
	je	.L81
	movq	%r9, %rsi
	jmp	.L78
.L81:
	movl	$1808407283, %esi
	movq	64(%rsp), %rbx
	movq	40(%rsp), %r10
	movq	%rcx, %rax
	vmovd	%esi, %xmm2
	movq	%r14, %rcx
	vpxor	%xmm3, %xmm3, %xmm3
	movq	%r15, %rdx
	vpbroadcastd	%xmm2, %ymm2
.L83:
	vmovdqu	(%rcx), %ymm0
	vmovdqa	(%rdx), %ymm5
	addq	$64, %rdx
	addq	$32, %rcx
	vmovdqa	-32(%rdx), %ymm4
	vpmovzxbw	%xmm0, %ymm1
	vpmovzxwd	%xmm5, %ymm7
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxwd	%xmm1, %ymm6
	vextracti128	$0x1, %ymm5, %xmm5
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm0, %ymm0
	vpmovzxwd	%xmm5, %ymm5
	vpmovzxwd	%xmm1, %ymm1
	vpaddd	%ymm5, %ymm1, %ymm1
	vpaddd	%ymm7, %ymm6, %ymm6
	vpmovzxwd	%xmm0, %ymm5
	vpmovzxwd	%xmm4, %ymm7
	vextracti128	$0x1, %ymm0, %xmm0
	vextracti128	$0x1, %ymm4, %xmm4
	vpmovzxwd	%xmm4, %ymm4
	vpmovzxwd	%xmm0, %ymm0
	vpaddd	%ymm7, %ymm5, %ymm5
	vpaddd	%ymm4, %ymm0, %ymm0
	vpmuldq	%ymm2, %ymm6, %ymm7
	vpsrlq	$32, %ymm6, %ymm4
	vpmuldq	%ymm2, %ymm4, %ymm4
	vpshufd	$245, %ymm7, %ymm7
	vpblendd	$85, %ymm7, %ymm4, %ymm4
	vpsrad	$3, %ymm4, %ymm4
	vpslld	$2, %ymm4, %ymm7
	vpaddd	%ymm4, %ymm7, %ymm7
	vpslld	$2, %ymm7, %ymm7
	vpsubd	%ymm4, %ymm7, %ymm4
	vpmuldq	%ymm2, %ymm1, %ymm7
	vpsubd	%ymm4, %ymm6, %ymm6
	vpsrlq	$32, %ymm1, %ymm4
	vpmuldq	%ymm2, %ymm4, %ymm4
	vpshufd	$245, %ymm7, %ymm7
	vpblendd	$85, %ymm7, %ymm4, %ymm4
	vpsrad	$3, %ymm4, %ymm4
	vpslld	$2, %ymm4, %ymm7
	vpaddd	%ymm4, %ymm7, %ymm7
	vpslld	$2, %ymm7, %ymm7
	vpsubd	%ymm4, %ymm7, %ymm4
	vpsubd	%ymm4, %ymm1, %ymm4
	vpblendw	$85, %ymm6, %ymm3, %ymm1
	vpblendw	$85, %ymm4, %ymm3, %ymm4
	vpackusdw	%ymm4, %ymm1, %ymm1
	vpmuldq	%ymm2, %ymm5, %ymm4
	vpermq	$216, %ymm1, %ymm1
	vmovdqa	%ymm1, -64(%rdx)
	vpsrlq	$32, %ymm5, %ymm1
	vpmuldq	%ymm2, %ymm1, %ymm1
	vpshufd	$245, %ymm4, %ymm4
	vpblendd	$85, %ymm4, %ymm1, %ymm1
	vpsrad	$3, %ymm1, %ymm1
	vpslld	$2, %ymm1, %ymm4
	vpaddd	%ymm1, %ymm4, %ymm4
	vpslld	$2, %ymm4, %ymm4
	vpsubd	%ymm1, %ymm4, %ymm4
	vpsrlq	$32, %ymm0, %ymm1
	vpsubd	%ymm4, %ymm5, %ymm4
	vpmuldq	%ymm2, %ymm0, %ymm5
	vpmuldq	%ymm2, %ymm1, %ymm1
	vpshufd	$245, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm1, %ymm1
	vpsrad	$3, %ymm1, %ymm1
	vpslld	$2, %ymm1, %ymm5
	vpaddd	%ymm1, %ymm5, %ymm5
	vpslld	$2, %ymm5, %ymm5
	vpsubd	%ymm1, %ymm5, %ymm1
	vpsubd	%ymm1, %ymm0, %ymm1
	vpblendw	$85, %ymm4, %ymm3, %ymm0
	vpblendw	$85, %ymm1, %ymm3, %ymm1
	vpackusdw	%ymm1, %ymm0, %ymm0
	vpermq	$216, %ymm0, %ymm0
	vmovdqa	%ymm0, -32(%rdx)
	cmpq	%rdx, 48(%rsp)
	jne	.L83
	movq	%r13, %rdi
	xorl	%edx, %edx
	movq	%rax, %rcx
.L84:
	movq	%rbx, 64(%rsp)
	movq	%r13, %r9
	movq	%r8, %r11
	xorl	%eax, %eax
.L88:
	vmovdqa	(%r11), %ymm2
	leaq	-2048(%r9), %rsi
	movq	%rdi, %rbx
	vpermq	$0, %ymm2, %ymm5
	vpermq	$85, %ymm2, %ymm4
	vpermq	$170, %ymm2, %ymm3
	vpermq	$255, %ymm2, %ymm2
.L85:
	vmovdqa	(%rbx), %ymm0
	addq	$256, %rsi
	addq	$32, %rbx
	vpshufb	%ymm15, %ymm0, %ymm0
	vpmullw	%ymm0, %ymm5, %ymm0
	vpaddw	-256(%rsi), %ymm0, %ymm0
	vmovdqa	%ymm0, -256(%rsi)
	vmovdqa	-32(%rbx), %ymm1
	vpshufb	%ymm14, %ymm1, %ymm1
	vpmullw	%ymm1, %ymm4, %ymm1
	vpaddw	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, -256(%rsi)
	vmovdqa	-32(%rbx), %ymm0
	vpshufb	%ymm13, %ymm0, %ymm0
	vpmullw	%ymm0, %ymm3, %ymm0
	vpaddw	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, -256(%rsi)
	vmovdqa	-32(%rbx), %ymm1
	vpshufb	%ymm12, %ymm1, %ymm1
	vpmullw	%ymm1, %ymm2, %ymm1
	vpaddw	%ymm0, %ymm1, %ymm0
	vmovdqa	%ymm0, -256(%rsi)
	cmpq	%rsi, %r9
	jne	.L85
	incq	%rax
	addq	$32, %r11
	addq	$32, %r9
	cmpq	$8, %rax
	jne	.L88
	subq	$256, %rdx
	movq	64(%rsp), %rbx
	addq	$256, %rdi
	addq	$256, %r8
	cmpq	$-9472, %rdx
	jne	.L84
	movq	%rcx, %rax
	movl	$-678045803, %ecx
	movq	88(%rsp), %rdx
	vmovd	%ecx, %xmm3
	vpbroadcastd	%xmm3, %ymm3
.L87:
	vmovdqa	(%rdx), %ymm2
	addq	$32, %rdx
	vpmulhuw	%ymm3, %ymm2, %ymm1
	vpsrlw	$4, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm0
	vpaddw	%ymm1, %ymm0, %ymm0
	vpsllw	$2, %ymm0, %ymm0
	vpsubw	%ymm1, %ymm0, %ymm0
	vpsubw	%ymm0, %ymm2, %ymm2
	vmovdqa	%ymm2, -32(%rdx)
	cmpq	%rdx, %r13
	jne	.L87
	leaq	37888(%r14), %rdi
	xorl	%edx, %edx
.L89:
	leaq	256(%rax), %rsi
	movq	88(%rsp), %r11
	movq	%rdi, %r8
	xorl	%r9d, %r9d
	movq	%rsi, 64(%rsp)
.L93:
	movq	%rax, 40(%rsp)
	movq	%r11, %rcx
	movq	%rax, %rsi
.L90:
	vmovdqa	(%r8), %xmm2
	vmovdqa	(%rsi), %xmm6
	addq	$32, %rsi
	addq	$32, %rcx
	vmovdqa	-16(%rsi), %xmm4
	vpshufb	.LC69(%rip), %xmm2, %xmm0
	vpshufb	.LC70(%rip), %xmm2, %xmm7
	vpunpcklqdq	%xmm6, %xmm6, %xmm8
	vpsrldq	$8, %xmm0, %xmm1
	vpsrldq	$8, %xmm7, %xmm9
	vpunpckhqdq	%xmm6, %xmm6, %xmm6
	vpmovzxbw	%xmm1, %xmm1
	vpmovzxbw	%xmm9, %xmm9
	vpshufb	.LC71(%rip), %xmm2, %xmm3
	vpmullw	%xmm6, %xmm9, %xmm9
	vpmullw	%xmm8, %xmm1, %xmm1
	vpshufb	.LC72(%rip), %xmm2, %xmm2
	vpmovzxbw	%xmm0, %xmm0
	vpmovzxbw	%xmm7, %xmm7
	vpunpcklqdq	%xmm4, %xmm4, %xmm5
	vpsrldq	$8, %xmm2, %xmm10
	vpmullw	%xmm8, %xmm0, %xmm0
	vpunpckhqdq	%xmm4, %xmm4, %xmm4
	vpmullw	%xmm6, %xmm7, %xmm6
	vpmovzxbw	%xmm10, %xmm10
	vpmovzxbw	%xmm2, %xmm2
	vpmullw	%xmm4, %xmm10, %xmm10
	vpmullw	%xmm4, %xmm2, %xmm2
	vpaddw	%xmm9, %xmm1, %xmm1
	vpsrldq	$8, %xmm3, %xmm9
	vpmovzxbw	%xmm3, %xmm3
	vpmovzxbw	%xmm9, %xmm9
	vpmullw	%xmm5, %xmm3, %xmm3
	vpaddw	-16(%rcx), %xmm1, %xmm1
	vpmullw	%xmm5, %xmm9, %xmm9
	vpaddw	%xmm6, %xmm0, %xmm0
	vpaddw	-32(%rcx), %xmm0, %xmm0
	vpaddw	%xmm2, %xmm3, %xmm2
	vpaddw	%xmm10, %xmm9, %xmm9
	vpaddw	%xmm2, %xmm0, %xmm0
	vpaddw	%xmm9, %xmm1, %xmm1
	vmovdqa	%xmm0, -32(%rcx)
	vmovdqa	%xmm1, -16(%rcx)
	cmpq	64(%rsp), %rsi
	jne	.L90
	addq	$8, %r9
	movq	40(%rsp), %rax
	addq	$256, %r11
	addq	$592, %r8
	cmpq	$64, %r9
	jne	.L93
	incq	%rdx
	addq	$16, %rdi
	cmpq	$37, %rdx
	je	.L123
	movq	%rsi, %rax
	jmp	.L89
.L123:
	movl	$-678045803, %ecx
	movq	72(%rsp), %rdx
	movq	88(%rsp), %rax
	vpxor	%xmm3, %xmm3, %xmm3
	vmovd	%ecx, %xmm5
	movl	$1245203, %ecx
	vmovd	%ecx, %xmm4
	movl	$1808407283, %ecx
	vpbroadcastd	%xmm5, %ymm5
	vmovd	%ecx, %xmm2
	vpbroadcastd	%xmm4, %ymm4
	vpbroadcastd	%xmm2, %ymm2
.L92:
	vmovdqa	(%rax), %ymm7
	vmovdqa	32(%rax), %ymm6
	addq	$64, %rax
	addq	$32, %rdx
	vpmulhuw	%ymm5, %ymm7, %ymm0
	vpsrlw	$4, %ymm0, %ymm0
	vpsllw	$2, %ymm0, %ymm1
	vpaddw	%ymm0, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm0, %ymm1, %ymm1
	vpsubw	%ymm7, %ymm1, %ymm1
	vpmulhuw	%ymm5, %ymm6, %ymm7
	vpaddw	%ymm4, %ymm1, %ymm1
	vpsrlw	$4, %ymm7, %ymm7
	vpsllw	$2, %ymm7, %ymm0
	vpaddw	%ymm7, %ymm0, %ymm0
	vpsllw	$2, %ymm0, %ymm0
	vpsubw	%ymm7, %ymm0, %ymm0
	vpsubw	%ymm6, %ymm0, %ymm0
	vpmovzxwd	%xmm1, %ymm6
	vextracti128	$0x1, %ymm1, %xmm1
	vpmuldq	%ymm2, %ymm6, %ymm9
	vpsrlq	$32, %ymm6, %ymm8
	vpmovzxwd	%xmm1, %ymm1
	vpmuldq	%ymm2, %ymm8, %ymm8
	vpaddw	%ymm4, %ymm0, %ymm0
	vpmovzxwd	%xmm0, %ymm7
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxwd	%xmm0, %ymm0
	vpshufd	$245, %ymm9, %ymm9
	vpblendd	$85, %ymm9, %ymm8, %ymm8
	vpsrad	$3, %ymm8, %ymm8
	vpslld	$2, %ymm8, %ymm9
	vpaddd	%ymm8, %ymm9, %ymm9
	vpslld	$2, %ymm9, %ymm9
	vpsubd	%ymm8, %ymm9, %ymm8
	vpmuldq	%ymm2, %ymm1, %ymm9
	vpsubd	%ymm8, %ymm6, %ymm6
	vpsrlq	$32, %ymm1, %ymm8
	vpmuldq	%ymm2, %ymm8, %ymm8
	vpblendw	$85, %ymm6, %ymm3, %ymm6
	vpshufd	$245, %ymm9, %ymm9
	vpblendd	$85, %ymm9, %ymm8, %ymm8
	vpsrad	$3, %ymm8, %ymm8
	vpslld	$2, %ymm8, %ymm9
	vpaddd	%ymm8, %ymm9, %ymm9
	vpslld	$2, %ymm9, %ymm9
	vpsubd	%ymm8, %ymm9, %ymm8
	vpsubd	%ymm8, %ymm1, %ymm1
	vpmuldq	%ymm2, %ymm7, %ymm8
	vpblendw	$85, %ymm1, %ymm3, %ymm1
	vpackusdw	%ymm1, %ymm6, %ymm1
	vpsrlq	$32, %ymm7, %ymm6
	vpmuldq	%ymm2, %ymm6, %ymm6
	vpermq	$216, %ymm1, %ymm1
	vpand	%ymm1, %ymm11, %ymm1
	vpshufd	$245, %ymm8, %ymm8
	vpblendd	$85, %ymm8, %ymm6, %ymm6
	vpsrad	$3, %ymm6, %ymm6
	vpslld	$2, %ymm6, %ymm8
	vpaddd	%ymm6, %ymm8, %ymm8
	vpslld	$2, %ymm8, %ymm8
	vpsubd	%ymm6, %ymm8, %ymm6
	vpmuldq	%ymm2, %ymm0, %ymm8
	vpsubd	%ymm6, %ymm7, %ymm6
	vpsrlq	$32, %ymm0, %ymm7
	vpmuldq	%ymm2, %ymm7, %ymm7
	vpshufd	$245, %ymm8, %ymm8
	vpblendd	$85, %ymm8, %ymm7, %ymm7
	vpsrad	$3, %ymm7, %ymm7
	vpslld	$2, %ymm7, %ymm8
	vpaddd	%ymm7, %ymm8, %ymm8
	vpslld	$2, %ymm8, %ymm8
	vpsubd	%ymm7, %ymm8, %ymm7
	vpsubd	%ymm7, %ymm0, %ymm7
	vpblendw	$85, %ymm6, %ymm3, %ymm0
	vpblendw	$85, %ymm7, %ymm3, %ymm6
	vpackusdw	%ymm6, %ymm0, %ymm0
	vpermq	$216, %ymm0, %ymm0
	vpand	%ymm0, %ymm11, %ymm0
	vpackuswb	%ymm0, %ymm1, %ymm0
	vpermq	$216, %ymm0, %ymm0
	vmovdqa	%ymm0, -32(%rdx)
	cmpq	%r13, %rax
	jne	.L92
	addq	$296, 80(%rsp)
	addq	$4736, %r14
	addq	$21904, %rbx
	addq	$1024, 72(%rsp)
	cmpq	$2368, 80(%rsp)
	je	.L244
	vzeroupper
	jmp	.L94
.L244:
	vmovdqu	(%r10), %xmm0
	movq	%r12, %rbx
	movl	$4224, %edx
	xorl	%esi, %esi
	leaq	21088(%rsp), %rdi
	movq	%r10, %r12
	vmovdqu	%xmm0, (%rbx)
	vzeroupper
	call	memset@PLT
	xorl	%edx, %edx
	movq	%rax, %r10
.L95:
	movq	56(%rsp), %rsi
	movq	%rdx, %rax
	leaq	0(,%rdx,8), %r13
	movl	$7, %r15d
	salq	$7, %rax
	xorl	%r11d, %r11d
	movq	%rdx, %r9
	leaq	(%rsi,%rax), %r14
	movq	%rdx, %rax
	salq	$5, %rax
	movq	%rax, 88(%rsp)
.L109:
	movq	%r11, %rcx
	leal	-1(%r15), %edi
	movl	88(%rsp), %eax
	movq	%r14, 16(%rsp)
	negq	%rcx
	movl	%edi, 80(%rsp)
	movq	%r14, %r8
	movq	%rcx, %rsi
	leaq	29(,%rcx,4), %rcx
	leal	0(,%rax,4), %edx
	movq	%rcx, 64(%rsp)
	leaq	4(,%rdi,4), %rcx
	salq	$4, %rsi
	leaq	16(%r14), %rax
	movq	%rcx, 48(%rsp)
	movl	%r15d, %ecx
	shrl	%ecx
	movq	%rsi, 72(%rsp)
	xorl	%esi, %esi
	movl	%ecx, 40(%rsp)
	movl	%r15d, %ecx
	andl	$1, %ecx
	movl	%ecx, 36(%rsp)
	movl	%r15d, %ecx
	andl	$-2, %ecx
	movl	%ecx, 32(%rsp)
.L108:
	movl	$4, %r14d
	subq	%rsi, %r14
	testl	%r14d, %r14d
	je	.L105
	movq	%rax, 8(%rsp)
	xorl	%ecx, %ecx
.L104:
	movl	%ecx, %edi
	incl	%ecx
	movzbl	(%r8,%rdi), %eax
	movb	%al, (%r10,%rdi)
	cmpl	%r14d, %ecx
	jb	.L104
	movq	8(%rsp), %rax
.L105:
	movl	$3, %edi
	subq	%rsi, %rdi
	addq	%r10, %rdi
	leaq	1(%rdi), %rcx
	movq	%rcx, %r10
	testl	%r15d, %r15d
	je	.L245
	movq	64(%rsp), %r14
	addq	%rdi, %r14
	cmpq	%r14, %rax
	jnb	.L126
	movq	72(%rsp), %r14
	leaq	100(%rax,%r14), %r14
	cmpq	%r14, %r10
	jb	.L96
.L126:
	cmpq	$6, %r11
	je	.L124
	vmovq	(%rax), %xmm0
	vmovd	16(%rax), %xmm1
	vinsertps	$16, %xmm1, %xmm0, %xmm0
	vmovq	%xmm0, 1(%rdi)
	movl	40(%rsp), %edi
	cmpl	$1, %edi
	je	.L99
	vmovq	32(%rax), %xmm0
	vmovd	48(%rax), %xmm1
	vinsertps	$16, %xmm1, %xmm0, %xmm0
	vmovq	%xmm0, 8(%rcx)
	cmpl	$2, %edi
	je	.L99
	vmovq	64(%rax), %xmm0
	vmovd	80(%rax), %xmm1
	vinsertps	$16, %xmm1, %xmm0, %xmm0
	vmovq	%xmm0, 16(%rcx)
.L99:
	movl	36(%rsp), %edi
	testl	%edi, %edi
	je	.L103
	movl	32(%rsp), %edi
.L98:
	leaq	1(%r13,%rdi), %r10
	leaq	(%rsi,%r10,4), %r10
	movl	25312(%rsp,%r10,4), %r10d
	movl	%r10d, (%rcx,%rdi,4)
.L103:
	movq	48(%rsp), %rdi
	incq	%rsi
	leaq	(%rdi,%rcx), %r10
	cmpq	$4, %rsi
	je	.L246
.L100:
	addq	$5, %r8
	addl	$4, %edx
	addq	$4, %rax
	jmp	.L108
.L124:
	xorl	%edi, %edi
	jmp	.L98
.L96:
	leal	16(%rdx), %r10d
	movslq	%r10d, %r10
	movl	25312(%rsp,%r10), %r10d
	movl	%r10d, 1(%rdi)
	cmpl	$1, %r15d
	je	.L103
	leal	32(%rdx), %edi
	movslq	%edi, %rdi
	movl	25312(%rsp,%rdi), %edi
	movl	%edi, 4(%rcx)
	cmpl	$2, %r15d
	je	.L103
	leal	48(%rdx), %edi
	movslq	%edi, %rdi
	movl	25312(%rsp,%rdi), %edi
	movl	%edi, 8(%rcx)
	cmpl	$3, %r15d
	je	.L103
	leal	64(%rdx), %edi
	movslq	%edi, %rdi
	movl	25312(%rsp,%rdi), %edi
	movl	%edi, 12(%rcx)
	cmpl	$4, %r15d
	je	.L103
	leal	80(%rdx), %edi
	movslq	%edi, %rdi
	movl	25312(%rsp,%rdi), %edi
	movl	%edi, 16(%rcx)
	cmpl	$5, %r15d
	je	.L103
	leal	96(%rdx), %edi
	movslq	%edi, %rdi
	movl	25312(%rsp,%rdi), %edi
	movl	%edi, 20(%rcx)
	cmpl	$6, %r15d
	je	.L103
	leal	112(%rdx), %edi
	movslq	%edi, %rdi
	movl	25312(%rsp,%rdi), %edi
	movl	%edi, 24(%rcx)
	jmp	.L103
.L245:
	incq	%rsi
	cmpq	$4, %rsi
	jne	.L100
	leaq	8(%r9), %rdx
	cmpq	$64, %rdx
	jne	.L95
	xorl	%esi, %esi
	xorl	%ecx, %ecx
	movl	$27, %edi
	movabsq	$16983563041, %r13
	movabsq	$322687697779, %r11
	movabsq	$6131066257801, %r10
	movabsq	$116490258898219, %r9
	movabsq	$2213314919066161, %r15
	jmp	.L118
.L114:
	movq	%rdx, %rax
	movb	%dh, 17(%rbx,%rsi)
	shrq	$16, %rax
	movb	%al, 18(%rbx,%rsi)
	movq	%rdx, %rax
	shrq	$24, %rax
	movb	%al, 19(%rbx,%rsi)
	cmpq	$2249, %rsi
	je	.L242
	movq	%rdx, %rax
	shrq	$32, %rax
	movb	%al, 20(%rbx,%rsi)
	cmpq	$2248, %rsi
	je	.L242
	movq	%rdx, %rax
	shrq	$40, %rax
	movb	%al, 21(%rbx,%rsi)
	movq	%rdx, %rax
	shrq	$56, %rdx
	shrq	$48, %rax
	movb	%dl, 23(%rbx,%rsi)
	movb	%al, 22(%rbx,%rsi)
	addq	$8, %rsi
	cmpq	$4224, %rcx
	je	.L112
.L118:
	movzbl	21088(%rsp,%rcx), %edx
	movl	%edx, %eax
	mulb	%dil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r8d
	leal	(%rax,%r8,2), %eax
	leaq	1(%rcx), %r8
	subl	%eax, %edx
	movzbl	%dl, %edx
	cmpq	$4223, %rcx
	je	.L247
.L110:
	movzbl	21088(%rsp,%r8), %r8d
	movl	%r8d, %eax
	mulb	%dil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r14d
	leal	(%rax,%r14,2), %r14d
	movl	%r8d, %eax
	subl	%r14d, %eax
	movzbl	%al, %eax
	leaq	(%rax,%rax,8), %r8
	leaq	(%rax,%r8,2), %rax
	addq	%rax, %rdx
	leaq	2(%rcx), %rax
	cmpq	$4222, %rcx
	je	.L113
	movzbl	21088(%rsp,%rax), %r8d
	movl	%r8d, %eax
	mulb	%dil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r14d
	leal	(%rax,%r14,2), %r14d
	movl	%r8d, %eax
	subl	%r14d, %eax
	movzbl	%al, %eax
	imulq	$361, %rax, %rax
	addq	%rax, %rdx
	leaq	3(%rcx), %rax
	cmpq	$4221, %rcx
	je	.L113
	movzbl	21088(%rsp,%rax), %r8d
	movl	%r8d, %eax
	mulb	%dil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r14d
	leal	(%rax,%r14,2), %r14d
	movl	%r8d, %eax
	subl	%r14d, %eax
	movzbl	%al, %eax
	imulq	$6859, %rax, %rax
	addq	%rax, %rdx
	leaq	4(%rcx), %rax
	cmpq	$4220, %rcx
	je	.L113
	movzbl	21088(%rsp,%rax), %r8d
	movl	%r8d, %eax
	mulb	%dil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r14d
	leal	(%rax,%r14,2), %r14d
	movl	%r8d, %eax
	subl	%r14d, %eax
	movzbl	%al, %eax
	imulq	$130321, %rax, %rax
	addq	%rax, %rdx
	leaq	5(%rcx), %rax
	cmpq	$4219, %rcx
	je	.L113
	movzbl	21088(%rsp,%rax), %r8d
	movl	%r8d, %eax
	mulb	%dil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r14d
	leal	(%rax,%r14,2), %r14d
	movl	%r8d, %eax
	subl	%r14d, %eax
	movzbl	%al, %eax
	imulq	$2476099, %rax, %rax
	addq	%rax, %rdx
	leaq	6(%rcx), %rax
	cmpq	$4218, %rcx
	je	.L113
	movzbl	21088(%rsp,%rax), %r8d
	movl	%r8d, %eax
	mulb	%dil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r14d
	leal	(%rax,%r14,2), %r14d
	movl	%r8d, %eax
	subl	%r14d, %eax
	movzbl	%al, %eax
	imulq	$47045881, %rax, %rax
	addq	%rax, %rdx
	leaq	7(%rcx), %rax
	cmpq	$4217, %rcx
	je	.L113
	movzbl	21088(%rsp,%rax), %r8d
	movl	%r8d, %eax
	mulb	%dil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r14d
	leal	(%rax,%r14,2), %r14d
	movl	%r8d, %eax
	subl	%r14d, %eax
	movzbl	%al, %eax
	imulq	$893871739, %rax, %rax
	addq	%rax, %rdx
	leaq	8(%rcx), %rax
	cmpq	$4216, %rcx
	je	.L113
	movzbl	21088(%rsp,%rax), %r8d
	movl	%r8d, %eax
	mulb	%dil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r14d
	leal	(%rax,%r14,2), %r14d
	movl	%r8d, %eax
	subl	%r14d, %eax
	movzbl	%al, %eax
	imulq	%r13, %rax
	addq	%rax, %rdx
	leaq	9(%rcx), %rax
	cmpq	$4215, %rcx
	je	.L113
	movzbl	21088(%rsp,%rax), %r8d
	movl	%r8d, %eax
	mulb	%dil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r14d
	leal	(%rax,%r14,2), %r14d
	movl	%r8d, %eax
	subl	%r14d, %eax
	movzbl	%al, %eax
	imulq	%r11, %rax
	addq	%rax, %rdx
	leaq	10(%rcx), %rax
	cmpq	$4214, %rcx
	je	.L113
	movzbl	21088(%rsp,%rax), %r8d
	movl	%r8d, %eax
	mulb	%dil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r14d
	leal	(%rax,%r14,2), %r14d
	movl	%r8d, %eax
	subl	%r14d, %eax
	movzbl	%al, %eax
	imulq	%r10, %rax
	addq	%rax, %rdx
	leaq	11(%rcx), %rax
	cmpq	$4213, %rcx
	je	.L113
	movzbl	21088(%rsp,%rax), %r8d
	movl	%r8d, %eax
	mulb	%dil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r14d
	leal	(%rax,%r14,2), %r14d
	movl	%r8d, %eax
	subl	%r14d, %eax
	movzbl	%al, %eax
	imulq	%r9, %rax
	addq	%rax, %rdx
	leaq	12(%rcx), %rax
	cmpq	$4212, %rcx
	je	.L113
	movzbl	21088(%rsp,%rax), %r8d
	movl	%r8d, %eax
	mulb	%dil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r14d
	leal	(%rax,%r14,2), %r14d
	movl	%r8d, %eax
	subl	%r14d, %eax
	movzbl	%al, %eax
	imulq	%r15, %rax
	addq	%rax, %rdx
	leaq	13(%rcx), %rax
	cmpq	$4211, %rcx
	je	.L113
	movzbl	21088(%rsp,%rax), %r8d
	movl	%r8d, %eax
	mulb	%dil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r14d
	leal	(%rax,%r14,2), %r14d
	movl	%r8d, %eax
	movabsq	$42052983462257059, %r8
	subl	%r14d, %eax
	movzbl	%al, %eax
	imulq	%r8, %rax
	addq	%rax, %rdx
	leaq	14(%rcx), %rax
	cmpq	$4210, %rcx
	je	.L113
	movzbl	21088(%rsp,%rax), %r8d
	movl	%r8d, %eax
	mulb	%dil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r14d
	leal	(%rax,%r14,2), %r14d
	movl	%r8d, %eax
	movabsq	$799006685782884121, %r8
	subl	%r14d, %eax
	movzbl	%al, %eax
	imulq	%r8, %rax
	addq	%rax, %rdx
	leaq	15(%rcx), %rax
.L113:
	cmpq	$2253, %rsi
	je	.L112
	movq	%rax, %rcx
.L111:
	movb	%dl, 16(%rbx,%rsi)
	cmpq	$2252, %rsi
	jne	.L114
.L242:
	cmpq	$4224, %rcx
	je	.L112
	leaq	1(%rcx), %r8
	cmpq	$4223, %rcx
	je	.L112
	movzbl	21088(%rsp,%rcx), %esi
	movl	$27, %eax
	mulb	%sil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %edx
	leal	(%rax,%rdx,2), %eax
	subl	%eax, %esi
	movzbl	%sil, %edx
	movl	$2253, %esi
	jmp	.L110
.L246:
	movq	16(%rsp), %r14
	addq	$36, 88(%rsp)
	incq	%r11
	addq	$9, %r13
	movl	80(%rsp), %r15d
	addq	$144, %r14
	jmp	.L109
.L112:
	vmovdqu	(%r12), %ymm0
	movq	24(%rsp), %rax
	vmovdqu	%ymm0, (%rax)
	vmovdqu	32(%r12), %xmm0
	vmovdqu	%xmm0, 32(%rax)
	movq	290936(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L248
	xorl	%eax, %eax
	vzeroupper
	leaq	-40(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	.cfi_remember_state
	.cfi_def_cfa 7, 8
	ret
.L247:
	.cfi_restore_state
	cmpq	$2253, %rsi
	je	.L112
	movl	$4224, %ecx
	jmp	.L111
.L248:
	vzeroupper
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE16:
	.size	_snova_37_8_19_4_SNOVA_OPT_genkeys, .-_snova_37_8_19_4_SNOVA_OPT_genkeys
	.p2align 4
	.globl	_snova_37_8_19_4_SNOVA_OPT_sk_expand
	.type	_snova_37_8_19_4_SNOVA_OPT_sk_expand, @function
_snova_37_8_19_4_SNOVA_OPT_sk_expand:
.LFB17:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	addq	$16, %rsi
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	pushq	%rbx
	.cfi_offset 15, -24
	.cfi_offset 14, -32
	.cfi_offset 13, -40
	.cfi_offset 12, -48
	.cfi_offset 3, -56
	leaq	518400(%rdi), %rbx
	andq	$-32, %rsp
	subq	$338720, %rsp
	movq	%fs:40, %r12
	movq	%r12, 338712(%rsp)
	leaq	626688(%rdi), %r12
	vmovdqu	-16(%rsi), %ymm0
	movq	%rdi, 352(%rsp)
	leaq	81280(%rsp), %r14
	vmovdqu	%ymm0, 626688(%rdi)
	vmovdqu	16(%rsi), %xmm0
	vmovdqu	%xmm0, 626720(%rdi)
	movq	%rbx, %rdi
	vzeroupper
	call	expand_T12
	movq	%r12, %rsi
	movq	%r14, %rdi
	movq	%r14, 16(%rsp)
	call	expand_public
	movq	352(%rsp), %r8
	movq	%r14, %rax
	leaq	256512(%rsp), %rcx
	movq	%r8, %rdx
.L250:
	vmovdqa	(%rax), %ymm0
	addq	$32, %rax
	addq	$64, %rdx
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, -64(%rdx)
	vmovdqu	%ymm0, -32(%rdx)
	cmpq	%rcx, %rax
	jne	.L250
	movq	%r8, 352(%rsp)
	xorl	%esi, %esi
	leaq	384(%rsp), %rdi
	movl	$75776, %edx
	vzeroupper
	call	memset@PLT
	movq	352(%rsp), %r8
	vmovdqa	.LC64(%rip), %ymm5
	movq	%rax, %rcx
	vmovdqa	.LC65(%rip), %ymm13
	vmovdqa	.LC66(%rip), %ymm12
	vmovdqa	.LC67(%rip), %ymm11
	leaq	43808(%r8), %rsi
	leaq	394272(%r8), %rax
	movq	%rcx, %rdi
.L251:
	leaq	-43808(%rsi), %r10
	movq	%rbx, %r9
.L255:
	vmovdqu	(%r9), %ymm1
	vmovdqu	32(%r9), %ymm0
	movq	%rdi, %rdx
	movq	%r10, %r12
	vmovdqu	64(%r9), %ymm4
	vmovdqu	96(%r9), %ymm10
	xorl	%r11d, %r11d
	vpshufb	%ymm5, %ymm1, %ymm3
	vpshufb	%ymm11, %ymm1, %ymm2
	vmovdqu	128(%r9), %ymm9
	vmovdqu	160(%r9), %ymm8
	vmovdqa	%ymm3, 352(%rsp)
	vpshufb	%ymm13, %ymm1, %ymm3
	vmovdqu	192(%r9), %ymm7
	vmovdqu	224(%r9), %ymm6
	vmovdqa	%ymm3, 320(%rsp)
	vpshufb	%ymm12, %ymm1, %ymm3
	vmovdqa	%ymm3, 288(%rsp)
	vpshufb	%ymm5, %ymm0, %ymm3
	vmovdqa	%ymm2, 256(%rsp)
	vpshufb	%ymm13, %ymm0, %ymm2
	vmovdqa	%ymm3, 224(%rsp)
	vpshufb	%ymm12, %ymm0, %ymm3
	vmovdqa	%ymm4, 32(%rsp)
	vmovdqa	%ymm2, 192(%rsp)
	vpshufb	%ymm11, %ymm0, %ymm2
	vmovdqa	%ymm3, 160(%rsp)
	vpshufb	%ymm5, %ymm4, %ymm3
	vpshufb	%ymm13, %ymm4, %ymm4
	vmovdqa	%ymm2, 128(%rsp)
	vmovdqa	%ymm3, 96(%rsp)
	vmovdqa	%ymm4, 64(%rsp)
.L252:
	vmovdqu	(%r12), %ymm0
	addq	$32, %r11
	addq	$32, %r12
	addq	$32, %rdx
	vpermq	$0, %ymm0, %ymm4
	vpermq	$85, %ymm0, %ymm3
	vpermq	$170, %ymm0, %ymm2
	vpmullw	320(%rsp), %ymm3, %ymm14
	vpmullw	352(%rsp), %ymm4, %ymm1
	vpaddw	%ymm14, %ymm1, %ymm1
	vpermq	$255, %ymm0, %ymm0
	vpaddw	-32(%rdx), %ymm1, %ymm1
	vpmullw	256(%rsp), %ymm0, %ymm15
	vpmullw	288(%rsp), %ymm2, %ymm14
	vpaddw	%ymm15, %ymm14, %ymm14
	vpmullw	128(%rsp), %ymm0, %ymm15
	vpaddw	%ymm14, %ymm1, %ymm1
	vpmullw	192(%rsp), %ymm3, %ymm14
	vmovdqa	%ymm1, -32(%rdx)
	vpmullw	224(%rsp), %ymm4, %ymm1
	vpaddw	%ymm14, %ymm1, %ymm1
	vpmullw	160(%rsp), %ymm2, %ymm14
	vpaddw	1152(%rdx), %ymm1, %ymm1
	vpaddw	%ymm15, %ymm14, %ymm14
	vmovdqa	32(%rsp), %ymm15
	vpaddw	%ymm14, %ymm1, %ymm1
	vpmullw	64(%rsp), %ymm3, %ymm14
	vmovdqa	%ymm1, 1152(%rdx)
	vpmullw	96(%rsp), %ymm4, %ymm1
	vpaddw	%ymm14, %ymm1, %ymm1
	vpshufb	%ymm11, %ymm15, %ymm14
	vpshufb	%ymm12, %ymm15, %ymm15
	vpmullw	%ymm0, %ymm14, %ymm14
	vpaddw	2336(%rdx), %ymm1, %ymm1
	vpmullw	%ymm2, %ymm15, %ymm15
	vpaddw	%ymm15, %ymm14, %ymm14
	vpshufb	%ymm12, %ymm10, %ymm15
	vpaddw	%ymm14, %ymm1, %ymm1
	vpmullw	%ymm2, %ymm15, %ymm15
	vpshufb	%ymm5, %ymm10, %ymm14
	vmovdqa	%ymm1, 2336(%rdx)
	vpshufb	%ymm13, %ymm10, %ymm1
	vpmullw	%ymm4, %ymm14, %ymm14
	vpmullw	%ymm3, %ymm1, %ymm1
	vpaddw	%ymm14, %ymm1, %ymm1
	vpshufb	%ymm11, %ymm10, %ymm14
	vpmullw	%ymm0, %ymm14, %ymm14
	vpaddw	3520(%rdx), %ymm1, %ymm1
	vpaddw	%ymm15, %ymm14, %ymm14
	vpshufb	%ymm12, %ymm9, %ymm15
	vpaddw	%ymm14, %ymm1, %ymm1
	vpmullw	%ymm2, %ymm15, %ymm15
	vpshufb	%ymm5, %ymm9, %ymm14
	vmovdqa	%ymm1, 3520(%rdx)
	vpshufb	%ymm13, %ymm9, %ymm1
	vpmullw	%ymm4, %ymm14, %ymm14
	vpmullw	%ymm3, %ymm1, %ymm1
	vpaddw	%ymm14, %ymm1, %ymm1
	vpshufb	%ymm11, %ymm9, %ymm14
	vpmullw	%ymm0, %ymm14, %ymm14
	vpaddw	4704(%rdx), %ymm1, %ymm1
	vpaddw	%ymm15, %ymm14, %ymm14
	vpshufb	%ymm12, %ymm8, %ymm15
	vpaddw	%ymm14, %ymm1, %ymm1
	vpmullw	%ymm2, %ymm15, %ymm15
	vpshufb	%ymm5, %ymm8, %ymm14
	vmovdqa	%ymm1, 4704(%rdx)
	vpshufb	%ymm13, %ymm8, %ymm1
	vpmullw	%ymm4, %ymm14, %ymm14
	vpmullw	%ymm3, %ymm1, %ymm1
	vpaddw	%ymm14, %ymm1, %ymm1
	vpshufb	%ymm11, %ymm8, %ymm14
	vpmullw	%ymm0, %ymm14, %ymm14
	vpaddw	5888(%rdx), %ymm1, %ymm1
	vpaddw	%ymm15, %ymm14, %ymm14
	vpshufb	%ymm12, %ymm7, %ymm15
	vpaddw	%ymm14, %ymm1, %ymm1
	vpmullw	%ymm2, %ymm15, %ymm15
	vpshufb	%ymm5, %ymm7, %ymm14
	vmovdqa	%ymm1, 5888(%rdx)
	vpshufb	%ymm13, %ymm7, %ymm1
	vpmullw	%ymm4, %ymm14, %ymm14
	vpmullw	%ymm3, %ymm1, %ymm1
	vpaddw	%ymm14, %ymm1, %ymm1
	vpshufb	%ymm11, %ymm7, %ymm14
	vpmullw	%ymm0, %ymm14, %ymm14
	vpaddw	7072(%rdx), %ymm1, %ymm1
	vpaddw	%ymm15, %ymm14, %ymm14
	vpaddw	%ymm14, %ymm1, %ymm1
	vmovdqa	%ymm1, 7072(%rdx)
	vpshufb	%ymm5, %ymm6, %ymm1
	vpmullw	%ymm4, %ymm1, %ymm1
	vpshufb	%ymm13, %ymm6, %ymm4
	vpmullw	%ymm3, %ymm4, %ymm3
	vpaddw	%ymm3, %ymm1, %ymm1
	vpaddw	8256(%rdx), %ymm1, %ymm3
	vpshufb	%ymm12, %ymm6, %ymm1
	vpmullw	%ymm2, %ymm1, %ymm1
	vpshufb	%ymm11, %ymm6, %ymm2
	vpmullw	%ymm0, %ymm2, %ymm0
	vpaddw	%ymm0, %ymm1, %ymm0
	vpaddw	%ymm0, %ymm3, %ymm0
	vmovdqa	%ymm0, 8256(%rdx)
	cmpq	$1184, %r11
	jne	.L252
	addq	$1184, %r10
	addq	$256, %r9
	cmpq	%rsi, %r10
	jne	.L255
	leaq	43808(%r10), %rsi
	addq	$9472, %rdi
	cmpq	%rax, %rsi
	jne	.L251
	leaq	527872(%r8), %rdx
	leaq	294400(%rsp), %rax
	vpxor	%xmm4, %xmm4, %xmm4
	movl	$1808407283, %esi
	vmovd	%esi, %xmm3
	leaq	332288(%rsp), %rdi
	vpbroadcastd	%xmm3, %ymm3
.L256:
	vmovdqa	(%rax), %ymm0
	vmovdqa	(%rcx), %ymm2
	addq	$32, %rax
	addq	$64, %rdx
	vmovdqa	32(%rcx), %ymm5
	addq	$64, %rcx
	vpmovzxbw	%xmm0, %ymm1
	vpmovzxwd	%xmm2, %ymm6
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxwd	%xmm1, %ymm7
	vextracti128	$0x1, %ymm2, %xmm2
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm0, %ymm0
	vpmovzxwd	%xmm2, %ymm2
	vpmovzxwd	%xmm1, %ymm1
	vpaddd	%ymm6, %ymm7, %ymm7
	vpaddd	%ymm2, %ymm1, %ymm1
	vpmovzxwd	%xmm5, %ymm6
	vpmovzxwd	%xmm0, %ymm2
	vextracti128	$0x1, %ymm5, %xmm5
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxwd	%xmm5, %ymm5
	vpmovzxwd	%xmm0, %ymm0
	vpaddd	%ymm6, %ymm2, %ymm2
	vpaddd	%ymm5, %ymm0, %ymm0
	vpmuldq	%ymm3, %ymm7, %ymm6
	vpsrlq	$32, %ymm7, %ymm5
	vpmuldq	%ymm3, %ymm5, %ymm5
	vpshufd	$245, %ymm6, %ymm6
	vpblendd	$85, %ymm6, %ymm5, %ymm5
	vpsrad	$3, %ymm5, %ymm5
	vpslld	$2, %ymm5, %ymm6
	vpaddd	%ymm5, %ymm6, %ymm6
	vpslld	$2, %ymm6, %ymm6
	vpsubd	%ymm5, %ymm6, %ymm6
	vpsrlq	$32, %ymm1, %ymm5
	vpsubd	%ymm6, %ymm7, %ymm6
	vpmuldq	%ymm3, %ymm1, %ymm7
	vpmuldq	%ymm3, %ymm5, %ymm5
	vpshufd	$245, %ymm7, %ymm7
	vpblendd	$85, %ymm7, %ymm5, %ymm5
	vpsrad	$3, %ymm5, %ymm5
	vpslld	$2, %ymm5, %ymm7
	vpaddd	%ymm5, %ymm7, %ymm7
	vpslld	$2, %ymm7, %ymm7
	vpsubd	%ymm5, %ymm7, %ymm5
	vpsubd	%ymm5, %ymm1, %ymm5
	vpblendw	$85, %ymm6, %ymm4, %ymm1
	vpblendw	$85, %ymm5, %ymm4, %ymm5
	vpackusdw	%ymm5, %ymm1, %ymm1
	vpmuldq	%ymm3, %ymm2, %ymm5
	vpermq	$216, %ymm1, %ymm1
	vmovdqu	%ymm1, -64(%rdx)
	vpsrlq	$32, %ymm2, %ymm1
	vpmuldq	%ymm3, %ymm1, %ymm1
	vpshufd	$245, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm1, %ymm1
	vpsrad	$3, %ymm1, %ymm1
	vpslld	$2, %ymm1, %ymm5
	vpaddd	%ymm1, %ymm5, %ymm5
	vpslld	$2, %ymm5, %ymm5
	vpsubd	%ymm1, %ymm5, %ymm1
	vpmuldq	%ymm3, %ymm0, %ymm5
	vpsubd	%ymm1, %ymm2, %ymm2
	vpsrlq	$32, %ymm0, %ymm1
	vpmuldq	%ymm3, %ymm1, %ymm1
	vpshufd	$245, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm1, %ymm1
	vpsrad	$3, %ymm1, %ymm1
	vpslld	$2, %ymm1, %ymm5
	vpaddd	%ymm1, %ymm5, %ymm5
	vpslld	$2, %ymm5, %ymm5
	vpsubd	%ymm1, %ymm5, %ymm1
	vpsubd	%ymm1, %ymm0, %ymm1
	vpblendw	$85, %ymm2, %ymm4, %ymm0
	vpblendw	$85, %ymm1, %ymm4, %ymm1
	vpackusdw	%ymm1, %ymm0, %ymm0
	vpermq	$216, %ymm0, %ymm0
	vmovdqu	%ymm0, -32(%rdx)
	cmpq	%rdi, %rax
	jne	.L256
	leaq	334848(%rsp), %rdi
	movq	%r8, (%rsp)
	leaq	76160(%rsp), %r14
	vmovdqa	.LC75(%rip), %ymm4
	movq	%rdi, 32(%rsp)
	vmovdqa	.LC76(%rip), %ymm3
	movq	%r14, %r15
	movq	%rax, %r13
	vmovdqa	.LC77(%rip), %xmm2
	vmovdqa	.LC78(%rip), %xmm1
	movq	%r14, 8(%rsp)
	leaq	613888(%r8), %rbx
	leaq	78720(%rsp), %r12
	leaq	337408(%rsp), %r14
.L262:
	movzbl	0(%r13), %eax
	movq	%r15, %rdi
	movb	%al, (%r15)
	movq	1(%r13), %rax
	movq	%rax, 1(%r15)
	movl	9(%r13), %eax
	movl	%eax, 9(%r15)
	movzwl	13(%r13), %eax
	movw	%ax, 13(%r15)
	movzbl	15(%r13), %eax
	movb	%al, 15(%r15)
	call	gf_mat_det
	testb	%al, %al
	jne	.L260
	movq	%r12, 352(%rsp)
	movq	%rbx, %r12
	movl	$1, %ebx
.L257:
	movzbl	(%r15), %ecx
	movzbl	2(%r15), %r9d
	addl	%ebx, %ecx
	movslq	%ecx, %rax
	movl	%ecx, %esi
	imulq	$1808407283, %rax, %rax
	sarl	$31, %esi
	sarq	$35, %rax
	subl	%esi, %eax
	leal	(%rax,%rax,8), %esi
	leal	(%rax,%rsi,2), %eax
	leal	(%rbx,%rbx), %esi
	subl	%eax, %ecx
	movzbl	1(%r15), %eax
	leal	(%rsi,%rbx), %edi
	movb	%cl, (%r15)
	addl	%edi, %r9d
	addl	%esi, %eax
	movslq	%eax, %rcx
	movl	%eax, %r8d
	imulq	$1808407283, %rcx, %rcx
	sarl	$31, %r8d
	sarq	$35, %rcx
	subl	%r8d, %ecx
	leal	(%rcx,%rcx,8), %r8d
	leal	(%rcx,%r8,2), %ecx
	movl	%r9d, %r8d
	subl	%ecx, %eax
	movslq	%r9d, %rcx
	sarl	$31, %r8d
	imulq	$1808407283, %rcx, %rcx
	vmovd	%eax, %xmm7
	movzbl	9(%r15), %eax
	sarq	$35, %rcx
	subl	%r8d, %ecx
	leal	(%rcx,%rcx,8), %r8d
	leal	(%rcx,%r8,2), %ecx
	subl	%ecx, %r9d
	movzbl	3(%r15), %ecx
	movq	%rcx, %r8
	imulq	$1808407283, %rcx, %rcx
	shrq	$35, %rcx
	leal	(%rcx,%rcx,8), %r10d
	leal	(%rcx,%r10,2), %ecx
	movzbl	4(%r15), %r10d
	subl	%ecx, %r8d
	addl	%esi, %r10d
	vmovd	%r8d, %xmm0
	movslq	%r10d, %rcx
	movl	%r10d, %r8d
	imulq	$1808407283, %rcx, %rcx
	sarl	$31, %r8d
	sarq	$35, %rcx
	subl	%r8d, %ecx
	leal	(%rcx,%rcx,8), %r8d
	leal	(%rcx,%r8,2), %ecx
	subl	%ecx, %r10d
	movzbl	5(%r15), %ecx
	addl	%edi, %ecx
	movslq	%ecx, %r8
	movl	%ecx, %r11d
	imulq	$1808407283, %r8, %r8
	sarl	$31, %r11d
	sarq	$35, %r8
	subl	%r11d, %r8d
	leal	(%r8,%r8,8), %r11d
	leal	(%r8,%r11,2), %r11d
	subl	%r11d, %ecx
	vmovd	%ecx, %xmm5
	movzbl	6(%r15), %ecx
	movq	%rcx, %r11
	imulq	$1808407283, %rcx, %rcx
	shrq	$35, %rcx
	leal	(%rcx,%rcx,8), %edx
	leal	(%rcx,%rdx,2), %r8d
	movzbl	7(%r15), %ecx
	subl	%r8d, %r11d
	addl	%ebx, %ecx
	vpinsrd	$1, %r11d, %xmm5, %xmm5
	movslq	%ecx, %r8
	movl	%ecx, %edx
	imulq	$1808407283, %r8, %r8
	sarl	$31, %edx
	sarq	$35, %r8
	subl	%edx, %r8d
	leal	(%r8,%r8,8), %edx
	leal	(%r8,%rdx,2), %r8d
	subl	%r8d, %ecx
	movzbl	8(%r15), %r8d
	vmovd	%ecx, %xmm6
	movq	%rax, %rcx
	addl	%edi, %r8d
	imulq	$1808407283, %rax, %rax
	movslq	%r8d, %rdi
	movl	%r8d, %edx
	imulq	$1808407283, %rdi, %rdi
	sarl	$31, %edx
	shrq	$35, %rax
	sarq	$35, %rdi
	subl	%edx, %edi
	leal	(%rdi,%rdi,8), %edx
	leal	(%rdi,%rdx,2), %edi
	subl	%edi, %r8d
	leal	(%rax,%rax,8), %edi
	vpinsrd	$1, %r8d, %xmm6, %xmm6
	leal	(%rax,%rdi,2), %eax
	movzbl	10(%r15), %edi
	vpunpcklqdq	%xmm6, %xmm5, %xmm5
	vpinsrd	$1, %r10d, %xmm0, %xmm6
	vpinsrd	$1, %r9d, %xmm7, %xmm0
	subl	%eax, %ecx
	vpunpcklqdq	%xmm6, %xmm0, %xmm0
	addl	%ebx, %edi
	vinserti128	$0x1, %xmm5, %ymm0, %ymm0
	movslq	%edi, %rax
	vpshufb	%ymm4, %ymm0, %ymm5
	imulq	$1808407283, %rax, %rax
	vpshufb	%ymm3, %ymm0, %ymm0
	vpermq	$78, %ymm5, %ymm5
	vpor	%ymm5, %ymm0, %ymm0
	vmovq	%xmm0, 1(%r15)
	vmovd	%ecx, %xmm0
	movl	%edi, %ecx
	sarq	$35, %rax
	sarl	$31, %ecx
	subl	%ecx, %eax
	leal	(%rax,%rax,8), %ecx
	leal	(%rax,%rcx,2), %eax
	subl	%eax, %edi
	movzbl	11(%r15), %eax
	vpinsrd	$1, %edi, %xmm0, %xmm0
	addl	%esi, %eax
	movslq	%eax, %rcx
	movl	%eax, %r8d
	imulq	$1808407283, %rcx, %rcx
	sarl	$31, %r8d
	sarq	$35, %rcx
	subl	%r8d, %ecx
	leal	(%rcx,%rcx,8), %r8d
	leal	(%rcx,%r8,2), %ecx
	subl	%ecx, %eax
	movzbl	12(%r15), %ecx
	vmovd	%eax, %xmm7
	movzbl	13(%r15), %eax
	movq	%rcx, %r8
	imulq	$1808407283, %rcx, %rcx
	shrq	$35, %rcx
	addl	%ebx, %eax
	leal	(%rcx,%rcx,8), %r9d
	movl	%eax, %edi
	leal	(%rcx,%r9,2), %ecx
	sarl	$31, %edi
	subl	%ecx, %r8d
	movslq	%eax, %rcx
	imulq	$1808407283, %rcx, %rcx
	vpinsrd	$1, %r8d, %xmm7, %xmm5
	vpunpcklqdq	%xmm5, %xmm0, %xmm0
	vpshufb	%xmm2, %xmm0, %xmm0
	sarq	$35, %rcx
	vmovd	%xmm0, 9(%r15)
	subl	%edi, %ecx
	leal	(%rcx,%rcx,8), %edi
	leal	(%rcx,%rdi,2), %ecx
	movq	%r15, %rdi
	subl	%ecx, %eax
	vmovd	%eax, %xmm0
	movzbl	14(%r15), %eax
	leal	(%rax,%rsi), %ecx
	movslq	%ecx, %rax
	movl	%ecx, %esi
	imulq	$1808407283, %rax, %rax
	sarl	$31, %esi
	sarq	$35, %rax
	subl	%esi, %eax
	leal	(%rax,%rax,8), %esi
	leal	(%rax,%rsi,2), %esi
	movl	%ecx, %eax
	movzbl	15(%r15), %ecx
	subl	%esi, %eax
	vpinsrd	$1, %eax, %xmm0, %xmm0
	movl	%ebx, %eax
	sall	$4, %eax
	vpshufb	%xmm1, %xmm0, %xmm0
	subl	%ebx, %eax
	vpextrw	$0, %xmm0, 13(%r15)
	addl	%eax, %ecx
	movslq	%ecx, %rax
	movl	%ecx, %esi
	imulq	$1808407283, %rax, %rax
	sarl	$31, %esi
	sarq	$35, %rax
	subl	%esi, %eax
	leal	(%rax,%rax,8), %esi
	leal	(%rax,%rsi,2), %eax
	subl	%eax, %ecx
	movb	%cl, 15(%r15)
	call	gf_mat_det
	testb	%al, %al
	jne	.L287
	incl	%ebx
	cmpl	$19, %ebx
	jne	.L257
.L287:
	movq	%r12, %rbx
	movq	352(%rsp), %r12
.L260:
	movzbl	2560(%r13), %eax
	movq	%r12, %rdi
	movb	%al, (%r12)
	movq	2561(%r13), %rax
	movq	%rax, 1(%r12)
	movl	2569(%r13), %eax
	movl	%eax, 9(%r12)
	movzwl	2573(%r13), %eax
	movw	%ax, 13(%r12)
	movzbl	2575(%r13), %eax
	movb	%al, 15(%r12)
	call	gf_mat_det
	testb	%al, %al
	jne	.L259
	movq	%rbx, 352(%rsp)
	movl	$1, %ebx
.L258:
	movzbl	(%r12), %ecx
	movzbl	2(%r12), %r9d
	addl	%ebx, %ecx
	movslq	%ecx, %rax
	movl	%ecx, %esi
	imulq	$1808407283, %rax, %rax
	sarl	$31, %esi
	sarq	$35, %rax
	subl	%esi, %eax
	leal	(%rax,%rax,8), %esi
	leal	(%rax,%rsi,2), %eax
	leal	(%rbx,%rbx), %esi
	subl	%eax, %ecx
	movzbl	1(%r12), %eax
	leal	(%rsi,%rbx), %edi
	movb	%cl, (%r12)
	addl	%edi, %r9d
	addl	%esi, %eax
	movslq	%eax, %rcx
	movl	%eax, %r8d
	imulq	$1808407283, %rcx, %rcx
	sarl	$31, %r8d
	sarq	$35, %rcx
	subl	%r8d, %ecx
	leal	(%rcx,%rcx,8), %r8d
	leal	(%rcx,%r8,2), %ecx
	movl	%r9d, %r8d
	subl	%ecx, %eax
	movslq	%r9d, %rcx
	sarl	$31, %r8d
	imulq	$1808407283, %rcx, %rcx
	vmovd	%eax, %xmm7
	movzbl	9(%r12), %eax
	sarq	$35, %rcx
	subl	%r8d, %ecx
	leal	(%rcx,%rcx,8), %r8d
	leal	(%rcx,%r8,2), %ecx
	subl	%ecx, %r9d
	movzbl	3(%r12), %ecx
	movq	%rcx, %r8
	imulq	$1808407283, %rcx, %rcx
	shrq	$35, %rcx
	leal	(%rcx,%rcx,8), %r10d
	leal	(%rcx,%r10,2), %ecx
	movzbl	4(%r12), %r10d
	subl	%ecx, %r8d
	addl	%esi, %r10d
	vmovd	%r8d, %xmm0
	movslq	%r10d, %rcx
	movl	%r10d, %r8d
	imulq	$1808407283, %rcx, %rcx
	sarl	$31, %r8d
	sarq	$35, %rcx
	subl	%r8d, %ecx
	leal	(%rcx,%rcx,8), %r8d
	leal	(%rcx,%r8,2), %ecx
	subl	%ecx, %r10d
	movzbl	5(%r12), %ecx
	addl	%edi, %ecx
	movslq	%ecx, %r8
	movl	%ecx, %r11d
	imulq	$1808407283, %r8, %r8
	sarl	$31, %r11d
	sarq	$35, %r8
	subl	%r11d, %r8d
	leal	(%r8,%r8,8), %r11d
	leal	(%r8,%r11,2), %r11d
	subl	%r11d, %ecx
	vmovd	%ecx, %xmm5
	movzbl	6(%r12), %ecx
	movq	%rcx, %r11
	imulq	$1808407283, %rcx, %rcx
	shrq	$35, %rcx
	leal	(%rcx,%rcx,8), %edx
	leal	(%rcx,%rdx,2), %r8d
	movzbl	7(%r12), %ecx
	subl	%r8d, %r11d
	addl	%ebx, %ecx
	vpinsrd	$1, %r11d, %xmm5, %xmm5
	movslq	%ecx, %r8
	movl	%ecx, %edx
	imulq	$1808407283, %r8, %r8
	sarl	$31, %edx
	sarq	$35, %r8
	subl	%edx, %r8d
	leal	(%r8,%r8,8), %edx
	leal	(%r8,%rdx,2), %r8d
	subl	%r8d, %ecx
	movzbl	8(%r12), %r8d
	vmovd	%ecx, %xmm6
	movq	%rax, %rcx
	addl	%edi, %r8d
	imulq	$1808407283, %rax, %rax
	movslq	%r8d, %rdi
	movl	%r8d, %edx
	imulq	$1808407283, %rdi, %rdi
	sarl	$31, %edx
	shrq	$35, %rax
	sarq	$35, %rdi
	subl	%edx, %edi
	leal	(%rdi,%rdi,8), %edx
	leal	(%rdi,%rdx,2), %edi
	subl	%edi, %r8d
	leal	(%rax,%rax,8), %edi
	vpinsrd	$1, %r8d, %xmm6, %xmm6
	leal	(%rax,%rdi,2), %eax
	movzbl	10(%r12), %edi
	vpunpcklqdq	%xmm6, %xmm5, %xmm5
	vpinsrd	$1, %r10d, %xmm0, %xmm6
	vpinsrd	$1, %r9d, %xmm7, %xmm0
	subl	%eax, %ecx
	vpunpcklqdq	%xmm6, %xmm0, %xmm0
	addl	%ebx, %edi
	vinserti128	$0x1, %xmm5, %ymm0, %ymm0
	movslq	%edi, %rax
	vpshufb	%ymm4, %ymm0, %ymm5
	imulq	$1808407283, %rax, %rax
	vpshufb	%ymm3, %ymm0, %ymm0
	vpermq	$78, %ymm5, %ymm5
	vpor	%ymm5, %ymm0, %ymm0
	vmovq	%xmm0, 1(%r12)
	vmovd	%ecx, %xmm0
	movl	%edi, %ecx
	sarq	$35, %rax
	sarl	$31, %ecx
	subl	%ecx, %eax
	leal	(%rax,%rax,8), %ecx
	leal	(%rax,%rcx,2), %eax
	subl	%eax, %edi
	movzbl	11(%r12), %eax
	vpinsrd	$1, %edi, %xmm0, %xmm0
	addl	%esi, %eax
	movslq	%eax, %rcx
	movl	%eax, %r8d
	imulq	$1808407283, %rcx, %rcx
	sarl	$31, %r8d
	sarq	$35, %rcx
	subl	%r8d, %ecx
	leal	(%rcx,%rcx,8), %r8d
	leal	(%rcx,%r8,2), %ecx
	subl	%ecx, %eax
	movzbl	12(%r12), %ecx
	vmovd	%eax, %xmm7
	movzbl	13(%r12), %eax
	movq	%rcx, %r8
	imulq	$1808407283, %rcx, %rcx
	shrq	$35, %rcx
	addl	%ebx, %eax
	leal	(%rcx,%rcx,8), %r9d
	movl	%eax, %edi
	leal	(%rcx,%r9,2), %ecx
	sarl	$31, %edi
	subl	%ecx, %r8d
	movslq	%eax, %rcx
	imulq	$1808407283, %rcx, %rcx
	vpinsrd	$1, %r8d, %xmm7, %xmm5
	vpunpcklqdq	%xmm5, %xmm0, %xmm0
	vpshufb	%xmm2, %xmm0, %xmm0
	sarq	$35, %rcx
	vmovd	%xmm0, 9(%r12)
	subl	%edi, %ecx
	leal	(%rcx,%rcx,8), %edi
	leal	(%rcx,%rdi,2), %ecx
	movq	%r12, %rdi
	subl	%ecx, %eax
	vmovd	%eax, %xmm0
	movzbl	14(%r12), %eax
	leal	(%rax,%rsi), %ecx
	movslq	%ecx, %rax
	movl	%ecx, %esi
	imulq	$1808407283, %rax, %rax
	sarl	$31, %esi
	sarq	$35, %rax
	subl	%esi, %eax
	leal	(%rax,%rax,8), %esi
	leal	(%rax,%rsi,2), %esi
	movl	%ecx, %eax
	movzbl	15(%r12), %ecx
	subl	%esi, %eax
	vpinsrd	$1, %eax, %xmm0, %xmm0
	movl	%ebx, %eax
	sall	$4, %eax
	vpshufb	%xmm1, %xmm0, %xmm0
	subl	%ebx, %eax
	vpextrw	$0, %xmm0, 13(%r12)
	addl	%eax, %ecx
	movslq	%ecx, %rax
	movl	%ecx, %esi
	imulq	$1808407283, %rax, %rax
	sarl	$31, %esi
	sarq	$35, %rax
	subl	%esi, %eax
	leal	(%rax,%rax,8), %esi
	leal	(%rax,%rsi,2), %eax
	subl	%eax, %ecx
	movb	%cl, 15(%r12)
	call	gf_mat_det
	testb	%al, %al
	jne	.L288
	incl	%ebx
	cmpl	$19, %ebx
	jne	.L258
.L288:
	movq	352(%rsp), %rbx
.L259:
	movzbl	(%r14), %r11d
	movzbl	3(%r14), %ecx
	movl	$18, %esi
	movzbl	2(%r14), %edi
	movzbl	1(%r14), %r9d
	testb	%r11b, %r11b
	movl	%r11d, %edx
	setne	%al
	leal	0(,%rdi,8), %r8d
	leal	(%r9,%r9), %r10d
	subl	%edx, %esi
	addl	%esi, %eax
	cmpb	$1, %cl
	leal	(%r11,%r9), %edx
	sbbl	%esi, %esi
	andl	%esi, %eax
	orl	%ecx, %eax
	movzbl	%al, %esi
	movb	%al, 3(%r14)
	movl	$14, %eax
	mulb	%dil
	leal	0(,%rsi,4), %ecx
	movw	%cx, 256(%rsp)
	addl	%eax, %edx
	movw	%ax, 352(%rsp)
	leal	(%rcx,%rsi), %eax
	movl	$19, %ecx
	leal	(%rdx,%rax,2), %eax
	movw	%dx, 320(%rsp)
	movl	%eax, %edx
	sarw	$15, %dx
	idivw	%cx
	leal	(%r10,%r8), %eax
	addl	%r9d, %r10d
	movw	%ax, 288(%rsp)
	movw	%r10w, 160(%rsp)
	movw	%dx, (%rbx)
	leal	(%rsi,%rsi,2), %edx
	addl	%edx, %eax
	movw	%dx, 224(%rsp)
	movl	%eax, %edx
	sarw	$15, %dx
	idivw	%cx
	movw	%dx, 192(%rsp)
	leal	(%rdi,%rdi), %edx
	leal	(%rdx,%rdi), %eax
	movw	%dx, 128(%rsp)
	leal	(%r10,%rax,2), %eax
	leal	0(,%rsi,8), %r10d
	subl	%esi, %r10d
	vmovd	192(%rsp), %xmm5
	addl	%r10d, %eax
	addl	%r8d, %r10d
	movl	%eax, %edx
	sarw	$15, %dx
	idivw	%cx
	movl	%r10d, %eax
	movw	%dx, 96(%rsp)
	movl	%r10d, %edx
	sarw	$15, %dx
	idivw	%cx
	vpinsrw	$1, 96(%rsp), %xmm5, %xmm0
	movw	%dx, 30(%rsp)
	movzwl	256(%rsp), %edx
	leal	(%rdx,%r10), %eax
	movl	%eax, %edx
	movzwl	30(%rsp), %r10d
	sarw	$15, %dx
	idivw	%cx
	leal	(%r8,%rdi), %eax
	leal	(%rdi,%rdi,4), %edi
	vmovd	%r10d, %xmm5
	movl	%esi, %r8d
	sall	$4, %r8d
	leal	(%r9,%rax,2), %eax
	vpinsrw	$1, 192(%rsp), %xmm5, %xmm7
	movw	%r8w, 64(%rsp)
	vpunpckldq	%xmm7, %xmm0, %xmm0
	movw	%dx, 256(%rsp)
	movl	%r8d, %edx
	subl	%esi, %edx
	addl	%edx, %eax
	movl	%eax, %edx
	sarw	$15, %dx
	idivw	%cx
	movzwl	352(%rsp), %eax
	addw	160(%rsp), %ax
	addl	%r11d, %eax
	movl	%edx, %r8d
	movl	%eax, %edx
	sarw	$15, %dx
	vmovd	%r8d, %xmm8
	idivw	%cx
	movzwl	288(%rsp), %eax
	addl	%edi, %eax
	addw	224(%rsp), %ax
	vmovd	%edx, %xmm6
	movl	%eax, %edx
	sarw	$15, %dx
	vpinsrw	$1, 256(%rsp), %xmm6, %xmm5
	vpinsrw	$1, 96(%rsp), %xmm8, %xmm6
	idivw	%cx
	movzwl	320(%rsp), %eax
	addl	%esi, %eax
	vpunpckldq	%xmm6, %xmm5, %xmm5
	vpunpcklqdq	%xmm5, %xmm0, %xmm0
	vmovdqu	%xmm0, 2(%rbx)
	movl	%edx, %edi
	movl	%eax, %edx
	sarw	$15, %dx
	idivw	%cx
	movzwl	%r10w, %eax
	movzwl	%di, %r10d
	salq	$16, %rax
	orq	%r10, %rax
	salq	$16, %rax
	movzwl	%dx, %edx
	orq	%rdx, %rax
	movzwl	256(%rsp), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movq	%rax, 18(%rbx)
	movl	%r9d, %eax
	sall	$4, %eax
	movw	%r8w, 26(%rbx)
	movzwl	64(%rsp), %r8d
	movl	%eax, %edx
	movw	%di, 28(%rbx)
	subl	%r9d, %edx
	leal	(%r8,%rsi), %eax
	movl	$18, %esi
	movzbl	641(%r14), %r9d
	addw	128(%rsp), %dx
	addl	%r11d, %edx
	movzbl	640(%r14), %r11d
	addl	%edx, %eax
	movl	%eax, %edx
	sarw	$15, %dx
	idivw	%cx
	movl	%r11d, %eax
	subl	%eax, %esi
	cmpb	$1, %r11b
	movl	$14, %eax
	sbbb	$-1, %sil
	movw	%dx, 30(%rbx)
	movzbl	643(%r14), %edx
	cmpb	$1, %dl
	sbbl	%edi, %edi
	andl	%edi, %esi
	movzbl	642(%r14), %edi
	orl	%edx, %esi
	leal	(%r11,%r9), %edx
	mulb	%dil
	movb	%sil, 643(%r14)
	movzbl	%sil, %esi
	leal	0(,%rdi,8), %r8d
	leal	0(,%rsi,4), %r10d
	movw	%r10w, 256(%rsp)
	addl	%eax, %edx
	movw	%ax, 352(%rsp)
	leal	(%r10,%rsi), %eax
	leal	(%r9,%r9), %r10d
	leal	(%rdx,%rax,2), %eax
	movw	%dx, 320(%rsp)
	movl	%eax, %edx
	sarw	$15, %dx
	idivw	%cx
	leal	(%r10,%r8), %eax
	addl	%r9d, %r10d
	movw	%ax, 288(%rsp)
	movw	%r10w, 160(%rsp)
	movw	%dx, 5120(%rbx)
	leal	(%rsi,%rsi,2), %edx
	addl	%edx, %eax
	movw	%dx, 224(%rsp)
	movl	%eax, %edx
	sarw	$15, %dx
	idivw	%cx
	movw	%dx, 192(%rsp)
	leal	(%rdi,%rdi), %edx
	leal	(%rdx,%rdi), %eax
	movw	%dx, 128(%rsp)
	leal	(%r10,%rax,2), %eax
	leal	0(,%rsi,8), %r10d
	subl	%esi, %r10d
	vmovd	192(%rsp), %xmm5
	addl	%r10d, %eax
	addl	%r8d, %r10d
	movl	%eax, %edx
	sarw	$15, %dx
	idivw	%cx
	movl	%r10d, %eax
	movw	%dx, 96(%rsp)
	movl	%r10d, %edx
	sarw	$15, %dx
	idivw	%cx
	vpinsrw	$1, 96(%rsp), %xmm5, %xmm0
	movw	%dx, 30(%rsp)
	movzwl	256(%rsp), %edx
	leal	(%rdx,%r10), %eax
	movl	%eax, %edx
	movzwl	30(%rsp), %r10d
	sarw	$15, %dx
	idivw	%cx
	leal	(%r8,%rdi), %eax
	vmovd	%r10d, %xmm5
	leal	(%rdi,%rdi,4), %edi
	movl	%esi, %r8d
	sall	$4, %r8d
	leal	(%r9,%rax,2), %eax
	vpinsrw	$1, 192(%rsp), %xmm5, %xmm7
	movw	%r8w, 64(%rsp)
	vpunpckldq	%xmm7, %xmm0, %xmm0
	movw	%dx, 256(%rsp)
	movl	%r8d, %edx
	subl	%esi, %edx
	addl	%edx, %eax
	movl	%eax, %edx
	sarw	$15, %dx
	idivw	%cx
	movzwl	352(%rsp), %eax
	addw	160(%rsp), %ax
	addl	%r11d, %eax
	movl	%edx, %r8d
	movl	%eax, %edx
	sarw	$15, %dx
	vmovd	%r8d, %xmm8
	idivw	%cx
	vmovd	%edx, %xmm6
	vpinsrw	$1, 256(%rsp), %xmm6, %xmm5
	vpinsrw	$1, 96(%rsp), %xmm8, %xmm6
	vpunpckldq	%xmm6, %xmm5, %xmm5
	vpunpcklqdq	%xmm5, %xmm0, %xmm0
	vmovdqu	%xmm0, 5122(%rbx)
	movzwl	288(%rsp), %eax
	movw	%r8w, 5146(%rbx)
	movzwl	64(%rsp), %r8d
	addl	%edi, %eax
	addw	224(%rsp), %ax
	movl	%eax, %edx
	sarw	$15, %dx
	idivw	%cx
	movzwl	320(%rsp), %eax
	addl	%esi, %eax
	addq	$16, %r13
	addq	$16, %r15
	addq	$4, %r14
	addq	$32, %rbx
	addq	$16, %r12
	movl	%edx, %edi
	movl	%eax, %edx
	sarw	$15, %dx
	movw	%di, 5116(%rbx)
	idivw	%cx
	movzwl	%r10w, %eax
	movzwl	%di, %r10d
	salq	$16, %rax
	orq	%r10, %rax
	salq	$16, %rax
	movzwl	%dx, %edx
	orq	%rdx, %rax
	movzwl	256(%rsp), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movq	%rax, 5106(%rbx)
	movl	%r9d, %eax
	sall	$4, %eax
	movl	%eax, %edx
	leal	(%r8,%rsi), %eax
	subl	%r9d, %edx
	addw	128(%rsp), %dx
	addl	%r11d, %edx
	addl	%edx, %eax
	movl	%eax, %edx
	sarw	$15, %dx
	idivw	%cx
	movw	%dx, 5118(%rbx)
	cmpq	32(%rsp), %r13
	jne	.L262
	movq	(%rsp), %r8
	movq	8(%rsp), %r14
	leaq	78720(%rsp), %rdx
	leaq	608768(%r8), %rax
.L265:
	vmovdqa	(%r14), %ymm0
	addq	$32, %rdx
	addq	$64, %rax
	addq	$32, %r14
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, -5184(%rax)
	vmovdqu	%ymm0, -5152(%rax)
	vmovdqa	-32(%rdx), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, -64(%rax)
	vmovdqu	%ymm0, -32(%rax)
	cmpq	16(%rsp), %rdx
	jne	.L265
	leaq	624128(%r8), %r13
	leaq	338048(%rsp), %rax
	leaq	338688(%rsp), %rdx
.L266:
	vmovdqa	-640(%rax), %ymm0
	addq	$32, %rax
	addq	$64, %r13
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, -64(%r13)
	vmovdqu	%ymm0, -32(%r13)
	vmovdqa	-32(%rax), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 1216(%r13)
	vmovdqu	%ymm0, 1248(%r13)
	cmpq	%rdx, %rax
	jne	.L266
	movq	338712(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L289
	xorl	%eax, %eax
	vzeroupper
	leaq	-40(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	.cfi_remember_state
	.cfi_def_cfa 7, 8
	ret
.L289:
	.cfi_restore_state
	vzeroupper
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE17:
	.size	_snova_37_8_19_4_SNOVA_OPT_sk_expand, .-_snova_37_8_19_4_SNOVA_OPT_sk_expand
	.p2align 4
	.globl	_snova_37_8_19_4_SNOVA_OPT_sign
	.type	_snova_37_8_19_4_SNOVA_OPT_sign, @function
_snova_37_8_19_4_SNOVA_OPT_sign:
.LFB18:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%r15
	.cfi_offset 15, -24
	movq	%rsi, %r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	.cfi_offset 14, -32
	.cfi_offset 13, -40
	.cfi_offset 12, -48
	movq	%rcx, %r12
	pushq	%rbx
	.cfi_offset 3, -56
	movq	%rdx, %rbx
	andq	$-32, %rsp
	subq	$125568, %rsp
	movq	%rdi, 264(%rsp)
	leaq	86080(%rsp), %r14
	movq	%r14, %rdi
	movq	%fs:40, %r13
	movq	%r13, 125560(%rsp)
	movq	%r8, %r13
	movq	%r14, 160(%rsp)
	call	shake256_init@PLT
	movq	264(%rsp), %rax
	movl	$16, %edx
	movq	%r14, %rdi
	leaq	626688(%rax), %rsi
	call	shake_absorb@PLT
	movq	%r12, %rdx
	movq	%rbx, %rsi
	movq	%r14, %rdi
	call	shake_absorb@PLT
	movl	$16, %edx
	movq	%r14, %rdi
	movq	%r13, %rsi
	call	shake_absorb@PLT
	movq	%r14, %rdi
	call	shake_finalize@PLT
	leaq	124112(%rsp), %rax
	movl	$128, %esi
	movq	%r14, %rdx
	movq	%rax, %rdi
	movq	%rax, 40(%rsp)
	call	shake_squeeze@PLT
	xorl	%edi, %edi
	xorl	%ecx, %ecx
	movabsq	$-2912643801112034465, %rsi
	cmpq	$68, %rdi
	ja	.L384
.L754:
	movzbl	124112(%rsp,%rdi), %r8d
	leaq	1(%rdi), %r9
	je	.L291
	movzbl	124112(%rsp,%r9), %edx
	movzbl	124114(%rsp,%rdi), %eax
	leaq	4(%rdi), %r9
	salq	$8, %rdx
	salq	$16, %rax
	xorq	%r8, %rdx
	movzbl	124115(%rsp,%rdi), %r8d
	xorq	%rdx, %rax
	salq	$24, %r8
	xorq	%rax, %r8
	cmpq	$65, %rdi
	je	.L291
	movzbl	124112(%rsp,%r9), %eax
	leaq	5(%rdi), %r9
	salq	$32, %rax
	xorq	%rax, %r8
	cmpq	$64, %rdi
	je	.L291
	movzbl	124112(%rsp,%r9), %edx
	movzbl	124118(%rsp,%rdi), %eax
	leaq	8(%rdi), %r9
	salq	$40, %rdx
	salq	$48, %rax
	xorq	%r8, %rdx
	movzbl	124119(%rsp,%rdi), %r8d
	xorq	%rdx, %rax
	salq	$56, %r8
	xorq	%rax, %r8
.L291:
	movq	%r8, %rax
	mulq	%rsi
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r11
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %r8
	movb	%r8b, 123984(%rsp,%rcx)
	cmpq	$127, %rcx
	je	.L292
	movq	%rdx, %rax
	mulq	%rsi
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r10
	leaq	(%rdx,%rax,2), %rdx
	movq	%r11, %rax
	subq	%rdx, %rax
	movb	%al, 123985(%rsp,%rcx)
	cmpq	$126, %rcx
	je	.L292
	movq	%r10, %rax
	mulq	%rsi
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r8
	leaq	(%rdx,%rax,2), %rdx
	movq	%r10, %rax
	subq	%rdx, %rax
	movb	%al, 123986(%rsp,%rcx)
	cmpq	$125, %rcx
	je	.L292
	movq	%r8, %rax
	mulq	%rsi
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r10
	leaq	(%rdx,%rax,2), %rdx
	movq	%r8, %rax
	subq	%rdx, %rax
	movb	%al, 123987(%rsp,%rcx)
	cmpq	$124, %rcx
	je	.L292
	movq	%r10, %rax
	mulq	%rsi
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r8
	leaq	(%rdx,%rax,2), %rdx
	movq	%r10, %rax
	subq	%rdx, %rax
	movb	%al, 123988(%rsp,%rcx)
	cmpq	$123, %rcx
	je	.L292
	movq	%r8, %rax
	mulq	%rsi
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r10
	leaq	(%rdx,%rax,2), %rdx
	movq	%r8, %rax
	subq	%rdx, %rax
	movb	%al, 123989(%rsp,%rcx)
	cmpq	$122, %rcx
	je	.L292
	movq	%r10, %rax
	mulq	%rsi
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r8
	leaq	(%rdx,%rax,2), %rdx
	movq	%r10, %rax
	subq	%rdx, %rax
	movb	%al, 123990(%rsp,%rcx)
	cmpq	$121, %rcx
	je	.L292
	movq	%r8, %rax
	mulq	%rsi
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r10
	leaq	(%rdx,%rax,2), %rdx
	movq	%r8, %rax
	subq	%rdx, %rax
	movb	%al, 123991(%rsp,%rcx)
	cmpq	$120, %rcx
	je	.L292
	movq	%r10, %rax
	mulq	%rsi
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r8
	leaq	(%rdx,%rax,2), %rdx
	movq	%r10, %rax
	subq	%rdx, %rax
	movb	%al, 123992(%rsp,%rcx)
	cmpq	$119, %rcx
	je	.L292
	movq	%r8, %rax
	mulq	%rsi
	movq	%rdx, %rax
	shrq	$4, %rax
	leaq	(%rax,%rax,8), %rdx
	leaq	(%rax,%rdx,2), %rdx
	movq	%r8, %rax
	subq	%rdx, %rax
	movb	%al, 123993(%rsp,%rcx)
	cmpq	$118, %rcx
	je	.L292
	movq	%r8, %rax
	mulq	%rsi
	movq	%rdx, %r8
	shrq	$4, %r8
	movq	%r8, %rax
	mulq	%rsi
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r10
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %r8
	movb	%r8b, 123994(%rsp,%rcx)
	cmpq	$117, %rcx
	je	.L292
	movq	%rdx, %rax
	mulq	%rsi
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r8
	leaq	(%rdx,%rax,2), %rdx
	movq	%r10, %rax
	subq	%rdx, %rax
	movb	%al, 123995(%rsp,%rcx)
	cmpq	$116, %rcx
	je	.L292
	movq	%r8, %rax
	mulq	%rsi
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r10
	leaq	(%rdx,%rax,2), %rdx
	movq	%r8, %rax
	subq	%rdx, %rax
	movb	%al, 123996(%rsp,%rcx)
	cmpq	$115, %rcx
	je	.L292
	movq	%r10, %rax
	mulq	%rsi
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r8
	leaq	(%rdx,%rax,2), %rdx
	movq	%r10, %rax
	subq	%rdx, %rax
	movb	%al, 123997(%rsp,%rcx)
	cmpq	$114, %rcx
	je	.L292
	movq	%r8, %rax
	mulq	%rsi
	movq	%rdx, %rax
	shrq	$4, %rax
	leaq	(%rax,%rax,8), %rdx
	leaq	(%rax,%rdx,2), %rdx
	movq	%r8, %rax
	subq	%rdx, %rax
	movb	%al, 123998(%rsp,%rcx)
	addq	$15, %rcx
	cmpq	$128, %rcx
	je	.L292
	cmpq	$68, %rdi
	ja	.L294
	movq	%r9, %rdi
	cmpq	$68, %rdi
	jbe	.L754
.L384:
	movq	%rdi, %r9
	xorl	%r8d, %r8d
	jmp	.L291
.L755:
	movb	$0, 123990(%rsp,%rcx)
	cmpq	$121, %rcx
	je	.L292
	movb	$0, 123991(%rsp,%rcx)
	cmpq	$120, %rcx
	je	.L292
	movb	$0, 123992(%rsp,%rcx)
	cmpq	$119, %rcx
	je	.L292
	movb	$0, 123993(%rsp,%rcx)
	cmpq	$118, %rcx
	je	.L292
	movb	$0, 123994(%rsp,%rcx)
	cmpq	$117, %rcx
	je	.L292
	movb	$0, 123995(%rsp,%rcx)
	cmpq	$116, %rcx
	je	.L292
	movb	$0, 123996(%rsp,%rcx)
	cmpq	$115, %rcx
	je	.L292
	movb	$0, 123997(%rsp,%rcx)
	cmpq	$114, %rcx
	je	.L292
	movb	$0, 123998(%rsp,%rcx)
	addq	$15, %rcx
	cmpq	$128, %rcx
	je	.L292
.L294:
	movb	$0, 123984(%rsp,%rcx)
	cmpq	$127, %rcx
	je	.L292
	movb	$0, 123985(%rsp,%rcx)
	cmpq	$126, %rcx
	je	.L292
	movb	$0, 123986(%rsp,%rcx)
	cmpq	$125, %rcx
	je	.L292
	movb	$0, 123987(%rsp,%rcx)
	cmpq	$124, %rcx
	je	.L292
	movb	$0, 123988(%rsp,%rcx)
	cmpq	$123, %rcx
	je	.L292
	movb	$0, 123989(%rsp,%rcx)
	cmpq	$122, %rcx
	jne	.L755
.L292:
	xorl	%ecx, %ecx
	leaq	124832(%rsp), %rax
	vpxor	%xmm0, %xmm0, %xmm0
	xorl	%esi, %esi
	movw	%cx, 1536(%rsp)
	movl	$720, %edx
	movq	%rax, %rdi
	movq	%rax, 232(%rsp)
	vmovdqa	%ymm0, 1280(%rsp)
	vmovdqa	%ymm0, 1312(%rsp)
	vmovdqa	%ymm0, 1344(%rsp)
	vmovdqa	%ymm0, 1376(%rsp)
	vmovdqa	%ymm0, 1408(%rsp)
	vmovdqa	%ymm0, 1440(%rsp)
	vmovdqa	%ymm0, 1472(%rsp)
	vmovdqa	%ymm0, 1504(%rsp)
	vzeroupper
	call	memset@PLT
	leaq	20032(%rsp), %rax
	movq	%r15, 152(%rsp)
	movq	%rax, 256(%rsp)
	leaq	53056(%rsp), %rax
	xorl	%ebx, %ebx
	movq	%rax, 176(%rsp)
	movq	%r13, 24(%rsp)
.L380:
	movq	256(%rsp), %rdi
	movl	$33024, %edx
	xorl	%esi, %esi
	call	memset@PLT
	movq	176(%rsp), %rdi
	movl	$33024, %edx
	xorl	%esi, %esi
	call	memset@PLT
	leal	1(%rbx), %eax
	movb	%al, 287(%rsp)
	cmpb	$-1, %al
	je	.L756
	leaq	288(%rsp), %rdi
	call	shake256_init@PLT
	movq	264(%rsp), %rax
	movl	$32, %edx
	leaq	288(%rsp), %rdi
	leaq	626704(%rax), %rsi
	call	shake_absorb@PLT
	movq	40(%rsp), %rsi
	movl	$128, %edx
	leaq	288(%rsp), %rdi
	call	shake_absorb@PLT
	leaq	287(%rsp), %rsi
	movl	$1, %edx
	leaq	288(%rsp), %rdi
	call	shake_absorb@PLT
	leaq	288(%rsp), %rdi
	call	shake_finalize@PLT
	leaq	124240(%rsp), %rdi
	leaq	288(%rsp), %rdx
	movl	$592, %esi
	call	shake_squeeze@PLT
	xorl	%r8d, %r8d
	xorl	%ecx, %ecx
	movabsq	$-2912643801112034465, %rdi
	cmpq	$315, %r8
	ja	.L386
.L757:
	movzbl	124241(%rsp,%r8), %edx
	movzbl	124240(%rsp,%r8), %eax
	leaq	4(%r8), %r10
	movzbl	124243(%rsp,%r8), %esi
	salq	$8, %rdx
	xorq	%rax, %rdx
	movzbl	124242(%rsp,%r8), %eax
	salq	$24, %rsi
	salq	$16, %rax
	xorq	%rdx, %rax
	xorq	%rax, %rsi
	cmpq	$312, %r8
	je	.L297
	movzbl	124240(%rsp,%r10), %eax
	movzbl	124245(%rsp,%r8), %edx
	leaq	8(%r8), %r10
	salq	$32, %rax
	salq	$40, %rdx
	xorq	%rsi, %rax
	movzbl	124247(%rsp,%r8), %esi
	xorq	%rax, %rdx
	movzbl	124246(%rsp,%r8), %eax
	salq	$56, %rsi
	salq	$48, %rax
	xorq	%rdx, %rax
	xorq	%rax, %rsi
.L297:
	movq	%rsi, %rax
	mulq	%rdi
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r11
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %rsi
	movb	%sil, 124832(%rsp,%rcx)
	cmpq	$591, %rcx
	je	.L298
	movq	%rdx, %rax
	mulq	%rdi
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r9
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %r11
	movb	%r11b, 124833(%rsp,%rcx)
	cmpq	$590, %rcx
	je	.L298
	movq	%rdx, %rax
	mulq	%rdi
	movq	%rdx, %rsi
	shrq	$4, %rsi
	leaq	(%rsi,%rsi,8), %rax
	leaq	(%rsi,%rax,2), %rax
	subq	%rax, %r9
	movb	%r9b, 124834(%rsp,%rcx)
	cmpq	$589, %rcx
	je	.L298
	movq	%rsi, %rax
	mulq	%rdi
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r9
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %rsi
	movb	%sil, 124835(%rsp,%rcx)
	cmpq	$588, %rcx
	je	.L298
	movq	%rdx, %rax
	mulq	%rdi
	movq	%rdx, %rsi
	shrq	$4, %rsi
	leaq	(%rsi,%rsi,8), %rax
	leaq	(%rsi,%rax,2), %rax
	subq	%rax, %r9
	movb	%r9b, 124836(%rsp,%rcx)
	cmpq	$587, %rcx
	je	.L298
	movq	%rsi, %rax
	mulq	%rdi
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r9
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %rsi
	movb	%sil, 124837(%rsp,%rcx)
	cmpq	$586, %rcx
	je	.L298
	movq	%rdx, %rax
	mulq	%rdi
	movq	%rdx, %rsi
	shrq	$4, %rsi
	leaq	(%rsi,%rsi,8), %rax
	leaq	(%rsi,%rax,2), %rax
	subq	%rax, %r9
	movb	%r9b, 124838(%rsp,%rcx)
	cmpq	$585, %rcx
	je	.L298
	movq	%rsi, %rax
	mulq	%rdi
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r9
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %rsi
	movb	%sil, 124839(%rsp,%rcx)
	cmpq	$584, %rcx
	je	.L298
	movq	%rdx, %rax
	mulq	%rdi
	movq	%rdx, %rsi
	shrq	$4, %rsi
	leaq	(%rsi,%rsi,8), %rax
	leaq	(%rsi,%rax,2), %rax
	subq	%rax, %r9
	movb	%r9b, 124840(%rsp,%rcx)
	cmpq	$583, %rcx
	je	.L298
	movq	%rsi, %rax
	mulq	%rdi
	movq	%rdx, %rax
	shrq	$4, %rax
	leaq	(%rax,%rax,8), %rdx
	leaq	(%rax,%rdx,2), %rdx
	movq	%rsi, %rax
	subq	%rdx, %rax
	movb	%al, 124841(%rsp,%rcx)
	cmpq	$582, %rcx
	je	.L298
	movq	%rsi, %rax
	mulq	%rdi
	movq	%rdx, %rsi
	shrq	$4, %rsi
	movq	%rsi, %rax
	mulq	%rdi
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r9
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %rsi
	movb	%sil, 124842(%rsp,%rcx)
	cmpq	$581, %rcx
	je	.L298
	movq	%rdx, %rax
	mulq	%rdi
	movq	%rdx, %rsi
	shrq	$4, %rsi
	leaq	(%rsi,%rsi,8), %rax
	leaq	(%rsi,%rax,2), %rax
	subq	%rax, %r9
	movb	%r9b, 124843(%rsp,%rcx)
	cmpq	$580, %rcx
	je	.L298
	movq	%rsi, %rax
	mulq	%rdi
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r9
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %rsi
	movb	%sil, 124844(%rsp,%rcx)
	cmpq	$579, %rcx
	je	.L298
	movq	%rdx, %rax
	mulq	%rdi
	movq	%rdx, %rsi
	shrq	$4, %rsi
	leaq	(%rsi,%rsi,8), %rax
	leaq	(%rsi,%rax,2), %rax
	subq	%rax, %r9
	movb	%r9b, 124845(%rsp,%rcx)
	cmpq	$578, %rcx
	je	.L298
	movq	%rsi, %rax
	mulq	%rdi
	movq	%rdx, %rax
	shrq	$4, %rax
	leaq	(%rax,%rax,8), %rdx
	leaq	(%rax,%rdx,2), %rax
	subq	%rax, %rsi
	movb	%sil, 124846(%rsp,%rcx)
	addq	$15, %rcx
	cmpq	$592, %rcx
	je	.L298
	cmpq	$315, %r8
	ja	.L300
	movq	%r10, %r8
	cmpq	$315, %r8
	jbe	.L757
.L386:
	movq	%r8, %r10
	xorl	%esi, %esi
	jmp	.L297
.L756:
	movq	152(%rsp), %r15
	movl	$-1, 248(%rsp)
	vpxor	%xmm0, %xmm0, %xmm0
	vmovdqu	%ymm0, (%r15)
	vmovdqu	%ymm0, 32(%r15)
	vmovdqu	%ymm0, 64(%r15)
	vmovdqu	%ymm0, 96(%r15)
	vmovdqu	%ymm0, 128(%r15)
	vmovdqu	%ymm0, 160(%r15)
	vmovdqu	%ymm0, 192(%r15)
	vmovdqu	%ymm0, 224(%r15)
	vmovdqu	%ymm0, 256(%r15)
	vmovdqu	%ymm0, 288(%r15)
	vmovdqu	%ymm0, 320(%r15)
	vmovdqu	%ymm0, 352(%r15)
	vmovdqu	%xmm0, 384(%r15)
.L290:
	movq	125560(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L758
	movl	248(%rsp), %eax
	vzeroupper
	leaq	-40(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	.cfi_remember_state
	.cfi_def_cfa 7, 8
	ret
.L300:
	.cfi_restore_state
	movb	$0, 124832(%rsp,%rcx)
	cmpq	$591, %rcx
	je	.L298
	movb	$0, 124833(%rsp,%rcx)
	cmpq	$590, %rcx
	je	.L298
	movb	$0, 124834(%rsp,%rcx)
	cmpq	$589, %rcx
	je	.L298
	movb	$0, 124835(%rsp,%rcx)
	cmpq	$588, %rcx
	je	.L298
	movb	$0, 124836(%rsp,%rcx)
	cmpq	$587, %rcx
	je	.L298
	movb	$0, 124837(%rsp,%rcx)
	cmpq	$586, %rcx
	je	.L298
	movb	$0, 124838(%rsp,%rcx)
	cmpq	$585, %rcx
	je	.L298
	movb	$0, 124839(%rsp,%rcx)
	cmpq	$584, %rcx
	je	.L298
	movb	$0, 124840(%rsp,%rcx)
	cmpq	$583, %rcx
	je	.L298
	movb	$0, 124841(%rsp,%rcx)
	cmpq	$582, %rcx
	je	.L298
	movb	$0, 124842(%rsp,%rcx)
	cmpq	$581, %rcx
	je	.L298
	movb	$0, 124843(%rsp,%rcx)
	cmpq	$580, %rcx
	je	.L298
	movb	$0, 124844(%rsp,%rcx)
	cmpq	$579, %rcx
	je	.L298
	movb	$0, 124845(%rsp,%rcx)
	cmpq	$578, %rcx
	je	.L298
	movb	$0, 124846(%rsp,%rcx)
	addq	$15, %rcx
	cmpq	$592, %rcx
	jne	.L300
.L298:
	vpxor	%xmm0, %xmm0, %xmm0
	leaq	7104(%rsp), %rbx
	xorl	%esi, %esi
	movl	$4736, %edx
	vmovdqa	%ymm0, 512(%rsp)
	movq	%rbx, %rdi
	vmovdqa	%ymm0, 544(%rsp)
	vmovdqa	%ymm0, 576(%rsp)
	vmovdqa	%ymm0, 608(%rsp)
	vmovdqa	%ymm0, 640(%rsp)
	vmovdqa	%ymm0, 672(%rsp)
	vmovdqa	%ymm0, 704(%rsp)
	vmovdqa	%ymm0, 736(%rsp)
	vzeroupper
	call	memset@PLT
	vmovdqa	.LC67(%rip), %ymm14
	leaq	_snova_37_8_19_4_SNOVA_OPT_Smat(%rip), %rdi
	movq	%rbx, %rsi
	xorl	%ecx, %ecx
	leaq	125424(%rsp), %r8
.L301:
	vmovdqa	(%rdi), %ymm2
	movq	232(%rsp), %rax
	movq	%rsi, %rdx
	vpshufb	.LC64(%rip), %ymm2, %ymm5
	vpshufb	.LC65(%rip), %ymm2, %ymm4
	vpshufb	.LC66(%rip), %ymm2, %ymm3
	vpshufb	%ymm14, %ymm2, %ymm2
.L302:
	vmovdqa	(%rax), %xmm1
	addq	$16, %rax
	addq	$32, %rdx
	vpshufd	$0, %xmm1, %xmm0
	vpshufd	$85, %xmm1, %xmm6
	vpmovzxbw	%xmm0, %ymm0
	vpmovzxbw	%xmm6, %ymm6
	vpmullw	%ymm4, %ymm6, %ymm6
	vpmullw	%ymm5, %ymm0, %ymm0
	vpaddw	%ymm6, %ymm0, %ymm0
	vpshufd	$170, %xmm1, %xmm6
	vpshufd	$255, %xmm1, %xmm1
	vpmovzxbw	%xmm6, %ymm6
	vpmovzxbw	%xmm1, %ymm1
	vpaddw	-32(%rdx), %ymm0, %ymm0
	vpmullw	%ymm3, %ymm6, %ymm6
	vpmullw	%ymm2, %ymm1, %ymm1
	vpaddw	%ymm1, %ymm6, %ymm1
	vpaddw	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, -32(%rdx)
	cmpq	%r8, %rax
	jne	.L302
	addq	$37, %rcx
	addq	$1184, %rsi
	addq	$32, %rdi
	cmpq	$148, %rcx
	jne	.L301
	movl	$-678045803, %edx
	leaq	4736(%rbx), %rcx
	movq	%rbx, %rax
	vmovd	%edx, %xmm3
	vpbroadcastd	%xmm3, %ymm3
.L304:
	vmovdqa	(%rax), %ymm2
	addq	$32, %rax
	vpmulhuw	%ymm3, %ymm2, %ymm1
	vpsrlw	$4, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm0
	vpaddw	%ymm1, %ymm0, %ymm0
	vpsllw	$2, %ymm0, %ymm0
	vpsubw	%ymm1, %ymm0, %ymm0
	vpsubw	%ymm0, %ymm2, %ymm2
	vmovdqa	%ymm2, -32(%rax)
	cmpq	%rcx, %rax
	jne	.L304
	movq	160(%rsp), %r14
	xorl	%esi, %esi
	movl	$37888, %edx
	vzeroupper
	movq	%r14, %rdi
	call	memset@PLT
	leaq	3008(%rsp), %rax
	movl	$4096, %edx
	xorl	%esi, %esi
	movq	%rax, %rdi
	movq	%rax, 192(%rsp)
	call	memset@PLT
	movq	264(%rsp), %r9
	vmovdqa	.LC67(%rip), %ymm14
	movq	%r14, %rcx
	movq	%r14, %rdx
	xorl	%edi, %edi
	movq	%r9, 56(%rsp)
.L305:
	movq	%rbx, %r8
	movq	%rdx, %r13
	xorl	%eax, %eax
.L311:
	movq	%r8, %r15
	xorl	%r14d, %r14d
	xorl	%r12d, %r12d
.L309:
	vmovdqa	(%r15), %ymm3
	leaq	(%r14,%r9), %r11
	movq	%r13, %rsi
	movl	$37, %r10d
	vpermq	$0, %ymm3, %ymm6
	vpermq	$85, %ymm3, %ymm5
	vpermq	$170, %ymm3, %ymm4
	vpermq	$255, %ymm3, %ymm3
.L306:
	vmovdqu	(%r11), %ymm1
	addq	$32, %rsi
	addq	$1184, %r11
	vpshufb	.LC64(%rip), %ymm1, %ymm0
	vpshufb	.LC65(%rip), %ymm1, %ymm2
	vpmullw	%ymm2, %ymm5, %ymm2
	vpmullw	%ymm0, %ymm6, %ymm0
	vpaddw	%ymm2, %ymm0, %ymm0
	vpshufb	.LC66(%rip), %ymm1, %ymm2
	vpshufb	%ymm14, %ymm1, %ymm1
	vpmullw	%ymm2, %ymm4, %ymm2
	vpmullw	%ymm1, %ymm3, %ymm1
	vpaddw	-32(%rsi), %ymm0, %ymm0
	vpaddw	%ymm1, %ymm2, %ymm1
	vpaddw	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, -32(%rsi)
	decl	%r10d
	jne	.L306
	incq	%r12
	addq	$32, %r15
	addq	$32, %r14
	cmpq	$37, %r12
	jne	.L309
	addl	$37, %eax
	addq	$1184, %r13
	addq	$1184, %r8
	cmpl	$148, %eax
	jne	.L311
	addq	$37, %rdi
	addq	$43808, %r9
	addq	$4736, %rdx
	cmpq	$296, %rdi
	jne	.L305
	movq	160(%rsp), %rax
	movl	$-678045803, %edx
	vmovd	%edx, %xmm3
	leaq	37888(%rax), %rsi
	vpbroadcastd	%xmm3, %ymm3
.L312:
	vmovdqa	(%rax), %ymm2
	addq	$32, %rax
	vpmulhuw	%ymm3, %ymm2, %ymm1
	vpsrlw	$4, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm0
	vpaddw	%ymm1, %ymm0, %ymm0
	vpsllw	$2, %ymm0, %ymm0
	vpsubw	%ymm1, %ymm0, %ymm0
	vpsubw	%ymm0, %ymm2, %ymm2
	vmovdqa	%ymm2, -32(%rax)
	cmpq	%rsi, %rax
	jne	.L312
	movq	192(%rsp), %r8
	vmovdqa	.LC79(%rip), %ymm0
	movl	$2368, %edi
.L313:
	leal	-2368(%rdi), %esi
	movq	%r8, %rdx
	movq	%rcx, %r9
.L317:
	movq	%rbx, %rax
	movq	%r9, %r11
	xorl	%r10d, %r10d
.L314:
	vmovdqa	(%r11), %ymm2
	vmovq	(%rax), %xmm1
	vmovq	8(%rax), %xmm8
	vmovq	16(%rax), %xmm6
	vperm2i128	$0, %ymm1, %ymm1, %ymm1
	vperm2i128	$0, %ymm8, %ymm8, %ymm8
	vmovq	24(%rax), %xmm7
	addq	$32, %r10
	vpermq	$0, %ymm2, %ymm5
	vpermq	$85, %ymm2, %ymm4
	vpshufb	%ymm0, %ymm1, %ymm1
	addq	$32, %r11
	vpshufb	%ymm0, %ymm8, %ymm8
	vpmullw	%ymm5, %ymm1, %ymm1
	vperm2i128	$0, %ymm6, %ymm6, %ymm6
	addq	$32, %rax
	vpmullw	%ymm4, %ymm8, %ymm8
	vperm2i128	$0, %ymm7, %ymm7, %ymm7
	vpermq	$170, %ymm2, %ymm3
	vpshufb	%ymm0, %ymm6, %ymm6
	vpermq	$255, %ymm2, %ymm2
	vpshufb	%ymm0, %ymm7, %ymm7
	vpmullw	%ymm2, %ymm7, %ymm7
	vpmullw	%ymm3, %ymm6, %ymm6
	vpaddw	%ymm8, %ymm1, %ymm1
	vpaddw	(%rdx), %ymm1, %ymm1
	vpaddw	%ymm7, %ymm6, %ymm6
	vpaddw	%ymm6, %ymm1, %ymm1
	vmovdqa	%ymm1, (%rdx)
	vmovq	1152(%rax), %xmm1
	vmovq	1160(%rax), %xmm8
	vmovq	1168(%rax), %xmm6
	vperm2i128	$0, %ymm1, %ymm1, %ymm1
	vperm2i128	$0, %ymm8, %ymm8, %ymm8
	vmovq	1176(%rax), %xmm7
	vpshufb	%ymm0, %ymm1, %ymm1
	vpshufb	%ymm0, %ymm8, %ymm8
	vperm2i128	$0, %ymm6, %ymm6, %ymm6
	vpmullw	%ymm4, %ymm8, %ymm8
	vpmullw	%ymm5, %ymm1, %ymm1
	vperm2i128	$0, %ymm7, %ymm7, %ymm7
	vpshufb	%ymm0, %ymm6, %ymm6
	vpshufb	%ymm0, %ymm7, %ymm7
	vpmullw	%ymm2, %ymm7, %ymm7
	vpmullw	%ymm3, %ymm6, %ymm6
	vpaddw	%ymm8, %ymm1, %ymm1
	vpaddw	128(%rdx), %ymm1, %ymm1
	vpaddw	%ymm7, %ymm6, %ymm6
	vpaddw	%ymm6, %ymm1, %ymm1
	vmovdqa	%ymm1, 128(%rdx)
	vmovq	2336(%rax), %xmm1
	vmovq	2344(%rax), %xmm8
	vmovq	2352(%rax), %xmm6
	vperm2i128	$0, %ymm1, %ymm1, %ymm1
	vperm2i128	$0, %ymm8, %ymm8, %ymm8
	vmovq	2360(%rax), %xmm7
	vpshufb	%ymm0, %ymm1, %ymm1
	vpshufb	%ymm0, %ymm8, %ymm8
	vperm2i128	$0, %ymm6, %ymm6, %ymm6
	vpmullw	%ymm4, %ymm8, %ymm8
	vpmullw	%ymm5, %ymm1, %ymm1
	vperm2i128	$0, %ymm7, %ymm7, %ymm7
	vpshufb	%ymm0, %ymm6, %ymm6
	vpshufb	%ymm0, %ymm7, %ymm7
	vpmullw	%ymm2, %ymm7, %ymm7
	vpmullw	%ymm3, %ymm6, %ymm6
	vpaddw	%ymm8, %ymm1, %ymm1
	vpaddw	256(%rdx), %ymm1, %ymm1
	vpaddw	%ymm7, %ymm6, %ymm6
	vpaddw	%ymm6, %ymm1, %ymm1
	vmovdqa	%ymm1, 256(%rdx)
	vmovq	3520(%rax), %xmm1
	vmovq	3528(%rax), %xmm8
	vmovq	3536(%rax), %xmm6
	vperm2i128	$0, %ymm1, %ymm1, %ymm1
	vperm2i128	$0, %ymm8, %ymm8, %ymm8
	vmovq	3544(%rax), %xmm7
	vpshufb	%ymm0, %ymm1, %ymm1
	vperm2i128	$0, %ymm6, %ymm6, %ymm6
	vperm2i128	$0, %ymm7, %ymm7, %ymm7
	vpmullw	%ymm5, %ymm1, %ymm1
	vpshufb	%ymm0, %ymm8, %ymm5
	vpmullw	%ymm4, %ymm5, %ymm4
	vpaddw	%ymm4, %ymm1, %ymm1
	vpshufb	%ymm0, %ymm6, %ymm4
	vpmullw	%ymm3, %ymm4, %ymm3
	vpshufb	%ymm0, %ymm7, %ymm4
	vpaddw	384(%rdx), %ymm1, %ymm1
	vpmullw	%ymm2, %ymm4, %ymm2
	vpaddw	%ymm2, %ymm3, %ymm2
	vpaddw	%ymm2, %ymm1, %ymm1
	vmovdqa	%ymm1, 384(%rdx)
	cmpq	$1184, %r10
	jne	.L314
	addl	$592, %esi
	addq	$1184, %r9
	addq	$32, %rdx
	cmpl	%edi, %esi
	jne	.L317
	leal	2368(%rsi), %edi
	addq	$4736, %rcx
	addq	$512, %r8
	cmpl	$18944, %esi
	jne	.L313
	movq	192(%rsp), %rax
	movl	$-678045803, %edx
	vmovd	%edx, %xmm3
	leaq	4096(%rax), %rcx
	vpbroadcastd	%xmm3, %ymm3
.L318:
	vmovdqa	(%rax), %ymm2
	addq	$32, %rax
	vpmulhuw	%ymm3, %ymm2, %ymm1
	vpsrlw	$4, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm0
	vpaddw	%ymm1, %ymm0, %ymm0
	vpsllw	$2, %ymm0, %ymm0
	vpsubw	%ymm1, %ymm0, %ymm0
	vpsubw	%ymm0, %ymm2, %ymm2
	vmovdqa	%ymm2, -32(%rax)
	cmpq	%rcx, %rax
	jne	.L318
	movq	264(%rsp), %rdi
	movq	192(%rsp), %rax
	movq	$0, 224(%rsp)
	leaq	512(%rsp), %r13
	movl	$0, 248(%rsp)
	movq	256(%rsp), %r14
	movl	$80, %r15d
	addq	$512, %rax
	leaq	625408(%rdi), %r12
	movq	%rdi, 240(%rsp)
	movq	%rax, 32(%rsp)
	movl	$-678045803, %eax
	movq	%r12, 184(%rsp)
	vmovd	%eax, %xmm2
	leaq	123984(%rsp), %rax
	vpbroadcastd	%xmm2, %ymm2
.L319:
	movzbl	2(%rax), %ecx
	movzbl	(%rax), %edx
	movl	248(%rsp), %r9d
	leal	19(%rcx), %r11d
	movzbl	3(%rax), %ecx
	leal	19(%rdx), %edi
	movzbl	1(%rax), %edx
	movl	%edi, 168(%rsp)
	leal	19(%rcx), %edi
	movzbl	4(%rax), %ecx
	addl	$19, %edx
	movl	%edi, 144(%rsp)
	leal	19(%rcx), %edi
	movzbl	5(%rax), %ecx
	movl	%edi, 136(%rsp)
	leal	19(%rcx), %edi
	movzbl	6(%rax), %ecx
	movl	%edi, 128(%rsp)
	leal	19(%rcx), %edi
	movzbl	7(%rax), %ecx
	movl	%edi, 120(%rsp)
	leal	19(%rcx), %edi
	movzbl	8(%rax), %ecx
	movl	%edi, 112(%rsp)
	leal	19(%rcx), %edi
	movzbl	9(%rax), %ecx
	movl	%edi, 104(%rsp)
	leal	19(%rcx), %edi
	movzbl	10(%rax), %ecx
	movl	%edi, 96(%rsp)
	leal	19(%rcx), %edi
	movzbl	11(%rax), %ecx
	movl	%edi, 88(%rsp)
	leal	19(%rcx), %edi
	movzbl	12(%rax), %ecx
	movl	%edi, 84(%rsp)
	leal	19(%rcx), %edi
	movzbl	13(%rax), %ecx
	movl	%edi, 80(%rsp)
	leal	19(%rcx), %edi
	movzbl	14(%rax), %ecx
	movl	%edi, 76(%rsp)
	leal	19(%rcx), %edi
	movzbl	15(%rax), %ecx
	movl	%edi, 72(%rsp)
	leal	19(%rcx), %edi
	movl	%edi, 68(%rsp)
	movl	224(%rsp), %edi
	leal	0(,%rdi,4), %ecx
	movq	240(%rsp), %rdi
	movq	184(%rsp), %rsi
	movl	%edx, 64(%rsp)
	leaq	603648(%rdi), %r8
.L321:
	movl	%r9d, %edi
	movq	192(%rsp), %rdx
	movslq	%ecx, %r10
	vpbroadcastw	(%rsi), %ymm7
	andl	$7, %edi
	vpbroadcastw	2(%rsi), %ymm6
	vpbroadcastw	4(%rsi), %ymm5
	vpxor	%xmm0, %xmm0, %xmm0
	salq	$9, %rdi
	vpbroadcastw	6(%rsi), %ymm4
	addq	%rdi, %rdx
	addq	32(%rsp), %rdi
	movq	%rdx, 48(%rsp)
	movq	264(%rsp), %rdx
	leaq	(%rdx,%r10,2), %r10
	movq	48(%rsp), %rdx
.L320:
	vpmullw	64(%rdx), %ymm5, %ymm3
	vpmullw	32(%rdx), %ymm6, %ymm8
	vpmullw	96(%rdx), %ymm4, %ymm1
	vpaddw	%ymm3, %ymm1, %ymm1
	vpmullw	(%rdx), %ymm7, %ymm3
	vpaddw	%ymm8, %ymm3, %ymm3
	subq	$-128, %rdx
	addq	$2, %r10
	vpaddw	%ymm3, %ymm1, %ymm1
	vpmulhuw	%ymm2, %ymm1, %ymm8
	vpsrlw	$4, %ymm8, %ymm8
	vpsllw	$2, %ymm8, %ymm3
	vpaddw	%ymm8, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm3
	vpsubw	%ymm8, %ymm3, %ymm3
	vpsubw	%ymm3, %ymm1, %ymm1
	vpbroadcastw	624126(%r10), %ymm3
	vpmullw	%ymm3, %ymm1, %ymm1
	vpaddw	%ymm1, %ymm0, %ymm0
	cmpq	%rdi, %rdx
	jne	.L320
	vpmulhuw	%ymm2, %ymm0, %ymm3
	addl	$4, %ecx
	incl	%r9d
	addq	$32, %r8
	addq	$8, %rsi
	vpsrlw	$4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm1
	vpaddw	%ymm3, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm3, %ymm1, %ymm1
	vmovdqu	5088(%r8), %ymm3
	vpsubw	%ymm1, %ymm0, %ymm0
	vpshufb	.LC66(%rip), %ymm0, %ymm4
	vpermq	$170, %ymm3, %ymm1
	vpshufb	%ymm14, %ymm0, %ymm5
	vpmullw	%ymm4, %ymm1, %ymm1
	vpermq	$255, %ymm3, %ymm4
	vpmullw	%ymm5, %ymm4, %ymm4
	vpshufb	.LC64(%rip), %ymm0, %ymm5
	vpshufb	.LC65(%rip), %ymm0, %ymm0
	vpaddw	%ymm4, %ymm1, %ymm1
	vpermq	$0, %ymm3, %ymm4
	vpermq	$85, %ymm3, %ymm3
	vpmullw	%ymm5, %ymm4, %ymm4
	vpmullw	%ymm0, %ymm3, %ymm0
	vmovdqu	-32(%r8), %ymm5
	vpaddw	%ymm0, %ymm4, %ymm0
	vpaddw	%ymm0, %ymm1, %ymm0
	vpermq	$0, %ymm0, %ymm3
	vpermq	$85, %ymm0, %ymm6
	vpermq	$170, %ymm0, %ymm1
	vpmulhuw	%ymm2, %ymm3, %ymm7
	vpermq	$255, %ymm0, %ymm0
	vpsrlw	$4, %ymm7, %ymm7
	vpsllw	$2, %ymm7, %ymm4
	vpaddw	%ymm7, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm4
	vpsubw	%ymm7, %ymm4, %ymm4
	vpmulhuw	%ymm2, %ymm6, %ymm7
	vpsubw	%ymm4, %ymm3, %ymm3
	vpshufb	.LC64(%rip), %ymm5, %ymm4
	vpmullw	%ymm4, %ymm3, %ymm3
	vpsrlw	$4, %ymm7, %ymm7
	vpsllw	$2, %ymm7, %ymm4
	vpaddw	%ymm7, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm4
	vpsubw	%ymm7, %ymm4, %ymm4
	vpsubw	%ymm4, %ymm6, %ymm4
	vpshufb	.LC65(%rip), %ymm5, %ymm6
	vpmullw	%ymm6, %ymm4, %ymm4
	vpmulhuw	%ymm2, %ymm1, %ymm6
	vpsrlw	$4, %ymm6, %ymm6
	vpaddw	%ymm4, %ymm3, %ymm3
	vpsllw	$2, %ymm6, %ymm4
	vpaddw	0(%r13), %ymm3, %ymm3
	vpaddw	%ymm6, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm4
	vpsubw	%ymm6, %ymm4, %ymm4
	vpmulhuw	%ymm2, %ymm0, %ymm6
	vpsubw	%ymm4, %ymm1, %ymm1
	vpshufb	.LC66(%rip), %ymm5, %ymm4
	vpshufb	%ymm14, %ymm5, %ymm5
	vpmullw	%ymm4, %ymm1, %ymm1
	vpsrlw	$4, %ymm6, %ymm6
	vpsllw	$2, %ymm6, %ymm4
	vpaddw	%ymm6, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm4
	vpsubw	%ymm6, %ymm4, %ymm4
	vpsubw	%ymm4, %ymm0, %ymm0
	vpmullw	%ymm5, %ymm0, %ymm0
	vpaddw	%ymm0, %ymm1, %ymm0
	vpaddw	%ymm0, %ymm3, %ymm3
	vmovdqa	%ymm3, 0(%r13)
	cmpl	%r15d, %ecx
	jne	.L321
	movzwl	2(%r13), %esi
	movl	64(%rsp), %edx
	movl	%r11d, %r9d
	movl	%esi, %r8d
	imull	$55189, %esi, %esi
	shrl	$20, %esi
	leal	(%rsi,%rsi,8), %edi
	leal	(%rsi,%rdi,2), %esi
	movl	%r8d, %edi
	movl	144(%rsp), %r8d
	subl	%esi, %edi
	movzwl	%di, %esi
	subl	%esi, %edx
	movl	%edx, %r10d
	movslq	%edx, %rdx
	imulq	$1808407283, %rdx, %rdx
	movl	%r10d, %esi
	sarl	$31, %esi
	sarq	$35, %rdx
	subl	%esi, %edx
	leal	(%rdx,%rdx,8), %esi
	leal	(%rdx,%rsi,2), %edx
	subl	%edx, %r10d
	movzwl	4(%r13), %edx
	movl	%edx, %edi
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %esi
	leal	(%rdx,%rsi,2), %edx
	subl	%edx, %edi
	movzwl	%di, %edx
	subl	%edx, %r9d
	movslq	%r9d, %rdx
	movl	%r9d, %esi
	imulq	$1808407283, %rdx, %rdx
	sarl	$31, %esi
	sarq	$35, %rdx
	subl	%esi, %edx
	leal	(%rdx,%rdx,8), %esi
	leal	(%rdx,%rsi,2), %edx
	subl	%edx, %r9d
	movzwl	6(%r13), %edx
	movl	%edx, %edi
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %esi
	leal	(%rdx,%rsi,2), %edx
	subl	%edx, %edi
	movzwl	%di, %edx
	subl	%edx, %r8d
	movslq	%r8d, %rdx
	movl	%r8d, %esi
	imulq	$1808407283, %rdx, %rdx
	sarl	$31, %esi
	sarq	$35, %rdx
	subl	%esi, %edx
	leal	(%rdx,%rdx,8), %esi
	leal	(%rdx,%rsi,2), %edx
	subl	%edx, %r8d
	movzwl	8(%r13), %edx
	movl	%edx, %edi
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %esi
	leal	(%rdx,%rsi,2), %edx
	subl	%edx, %edi
	movzwl	%di, %edx
	movl	136(%rsp), %edi
	subl	%edx, %edi
	movslq	%edi, %rdx
	movl	%edi, %esi
	imulq	$1808407283, %rdx, %rdx
	sarq	$35, %rdx
	sarl	$31, %esi
	subl	%esi, %edx
	leal	(%rdx,%rdx,8), %esi
	leal	(%rdx,%rsi,2), %edx
	subl	%edx, %edi
	movzwl	10(%r13), %edx
	movl	%edx, %r11d
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %esi
	leal	(%rdx,%rsi,2), %edx
	movl	%r11d, %esi
	subl	%edx, %esi
	movzwl	%si, %edx
	movl	128(%rsp), %esi
	subl	%edx, %esi
	movslq	%esi, %rdx
	movl	%esi, %r11d
	imulq	$1808407283, %rdx, %rdx
	sarl	$31, %r11d
	sarq	$35, %rdx
	subl	%r11d, %edx
	leal	(%rdx,%rdx,8), %r11d
	leal	(%rdx,%r11,2), %edx
	subl	%edx, %esi
	movzwl	12(%r13), %edx
	movl	%edx, %r15d
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %r11d
	leal	(%rdx,%r11,2), %edx
	movl	120(%rsp), %r11d
	subl	%edx, %r15d
	movzwl	%r15w, %edx
	subl	%edx, %r11d
	movslq	%r11d, %rdx
	movl	%r11d, %r15d
	imulq	$1808407283, %rdx, %rdx
	sarl	$31, %r15d
	sarq	$35, %rdx
	subl	%r15d, %edx
	leal	(%rdx,%rdx,8), %r15d
	leal	(%rdx,%r15,2), %edx
	subl	%edx, %r11d
	movzwl	14(%r13), %edx
	movl	%r11d, 144(%rsp)
	movl	%edx, %r15d
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %r11d
	leal	(%rdx,%r11,2), %edx
	subl	%edx, %r15d
	movzwl	%r15w, %edx
	movl	112(%rsp), %r15d
	subl	%edx, %r15d
	movslq	%r15d, %rdx
	sarl	$31, %r15d
	movq	%rdx, %r11
	imulq	$1808407283, %rdx, %rdx
	sarq	$35, %rdx
	subl	%r15d, %edx
	leal	(%rdx,%rdx,8), %r15d
	leal	(%rdx,%r15,2), %edx
	movl	%r11d, %r15d
	subl	%edx, %r15d
	movzwl	16(%r13), %edx
	movl	%r15d, 136(%rsp)
	movl	%edx, %r15d
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %r11d
	leal	(%rdx,%r11,2), %edx
	movl	104(%rsp), %r11d
	subl	%edx, %r15d
	movzwl	%r15w, %edx
	subl	%edx, %r11d
	movslq	%r11d, %rdx
	movl	%r11d, %r15d
	imulq	$1808407283, %rdx, %rdx
	sarl	$31, %r15d
	sarq	$35, %rdx
	subl	%r15d, %edx
	leal	(%rdx,%rdx,8), %r15d
	leal	(%rdx,%r15,2), %edx
	subl	%edx, %r11d
	movzwl	18(%r13), %edx
	movl	%r11d, 128(%rsp)
	movl	%edx, %r15d
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %r11d
	leal	(%rdx,%r11,2), %edx
	subl	%edx, %r15d
	movzwl	%r15w, %edx
	movl	96(%rsp), %r15d
	subl	%edx, %r15d
	movslq	%r15d, %rdx
	sarl	$31, %r15d
	movq	%rdx, %r11
	imulq	$1808407283, %rdx, %rdx
	sarq	$35, %rdx
	subl	%r15d, %edx
	leal	(%rdx,%rdx,8), %r15d
	leal	(%rdx,%r15,2), %edx
	subl	%edx, %r11d
	movzwl	20(%r13), %edx
	movl	%r11d, 120(%rsp)
	movl	%edx, %r15d
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %r11d
	leal	(%rdx,%r11,2), %edx
	subl	%edx, %r15d
	movzwl	%r15w, %edx
	movl	88(%rsp), %r15d
	subl	%edx, %r15d
	movslq	%r15d, %rdx
	sarl	$31, %r15d
	movq	%rdx, %r11
	imulq	$1808407283, %rdx, %rdx
	sarq	$35, %rdx
	subl	%r15d, %edx
	leal	(%rdx,%rdx,8), %r15d
	leal	(%rdx,%r15,2), %edx
	movl	%r11d, %r15d
	subl	%edx, %r15d
	movzwl	22(%r13), %edx
	movl	%r15d, 112(%rsp)
	movl	%edx, %r15d
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %r11d
	leal	(%rdx,%r11,2), %edx
	movl	84(%rsp), %r11d
	subl	%edx, %r15d
	movzwl	%r15w, %edx
	subl	%edx, %r11d
	movslq	%r11d, %rdx
	movl	%r11d, %r15d
	imulq	$1808407283, %rdx, %rdx
	sarq	$35, %rdx
	sarl	$31, %r15d
	subl	%r15d, %edx
	leal	(%rdx,%rdx,8), %r15d
	leal	(%rdx,%r15,2), %edx
	subl	%edx, %r11d
	movzwl	24(%r13), %edx
	movl	%r11d, 104(%rsp)
	movl	%edx, %r15d
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %r11d
	leal	(%rdx,%r11,2), %edx
	subl	%edx, %r15d
	movzwl	%r15w, %edx
	movl	80(%rsp), %r15d
	subl	%edx, %r15d
	movslq	%r15d, %rdx
	sarl	$31, %r15d
	movq	%rdx, %r11
	imulq	$1808407283, %rdx, %rdx
	sarq	$35, %rdx
	subl	%r15d, %edx
	leal	(%rdx,%rdx,8), %r15d
	leal	(%rdx,%r15,2), %edx
	movl	%r11d, %r15d
	subl	%edx, %r15d
	movzwl	26(%r13), %edx
	movl	%r15d, 96(%rsp)
	movl	%edx, %r15d
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %r11d
	leal	(%rdx,%r11,2), %edx
	movl	76(%rsp), %r11d
	subl	%edx, %r15d
	movzwl	%r15w, %edx
	subl	%edx, %r11d
	movslq	%r11d, %rdx
	movl	%r11d, %r15d
	imulq	$1808407283, %rdx, %rdx
	sarl	$31, %r15d
	sarq	$35, %rdx
	subl	%r15d, %edx
	leal	(%rdx,%rdx,8), %r15d
	leal	(%rdx,%r15,2), %edx
	subl	%edx, %r11d
	movl	%r11d, 88(%rsp)
	movzwl	28(%r13), %edx
	movl	%edx, %r15d
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %r11d
	leal	(%rdx,%r11,2), %edx
	subl	%edx, %r15d
	movzwl	%r15w, %edx
	movl	72(%rsp), %r15d
	subl	%edx, %r15d
	movslq	%r15d, %rdx
	sarl	$31, %r15d
	movq	%rdx, %r11
	imulq	$1808407283, %rdx, %rdx
	sarq	$35, %rdx
	subl	%r15d, %edx
	leal	(%rdx,%rdx,8), %r15d
	leal	(%rdx,%r15,2), %edx
	movl	%r11d, %r15d
	subl	%edx, %r15d
	movzwl	30(%r13), %edx
	movw	%di, 1288(%r14)
	movl	%r15d, 84(%rsp)
	movzwl	144(%rsp), %edi
	movl	%edx, %r15d
	imull	$55189, %edx, %edx
	movw	%r10w, 514(%r14)
	movw	%di, 1804(%r14)
	movzwl	136(%rsp), %edi
	movw	%r9w, 772(%r14)
	shrl	$20, %edx
	movw	%di, 2062(%r14)
	movzwl	128(%rsp), %edi
	leal	(%rdx,%rdx,8), %r11d
	movw	%r8w, 1030(%r14)
	leal	(%rdx,%r11,2), %edx
	movl	68(%rsp), %r11d
	movw	%di, 2320(%r14)
	subl	%edx, %r15d
	movzwl	120(%rsp), %edi
	movw	%si, 1546(%r14)
	addq	$16, %rax
	movzwl	%r15w, %edx
	addq	$32, %r13
	addq	$4128, %r14
	subl	%edx, %r11d
	movw	%di, -1550(%r14)
	movzwl	112(%rsp), %edi
	movslq	%r11d, %rdx
	movl	%r11d, %r15d
	imulq	$1808407283, %rdx, %rdx
	sarl	$31, %r15d
	movw	%di, -1292(%r14)
	movzwl	104(%rsp), %edi
	movw	%di, -1034(%r14)
	movzwl	96(%rsp), %edi
	sarq	$35, %rdx
	subl	%r15d, %edx
	movw	%di, -776(%r14)
	movzwl	88(%rsp), %edi
	leal	(%rdx,%rdx,8), %r15d
	leal	(%rdx,%r15,2), %edx
	movw	%di, -518(%r14)
	movzwl	84(%rsp), %edi
	subl	%edx, %r11d
	movl	%r11d, 80(%rsp)
	vpextrw	$0, %xmm3, %r11d
	imull	$55189, %r11d, %edx
	movw	%di, -260(%r14)
	movzwl	80(%rsp), %edi
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %r15d
	leal	(%rdx,%r15,2), %edx
	movl	168(%rsp), %r15d
	subl	%edx, %r11d
	movzwl	%r11w, %edx
	subl	%edx, %r15d
	movslq	%r15d, %rdx
	sarl	$31, %r15d
	movq	%rdx, %r11
	imulq	$1808407283, %rdx, %rdx
	sarq	$35, %rdx
	subl	%r15d, %edx
	leal	(%rdx,%rdx,8), %r15d
	leal	(%rdx,%r15,2), %edx
	leal	80(%rcx), %r15d
	subl	%edx, %r11d
	movw	%r11w, -3872(%r14)
	movw	%di, -2(%r14)
	incl	248(%rsp)
	addq	$640, 240(%rsp)
	addq	$20, 224(%rsp)
	addq	$160, 184(%rsp)
	movl	248(%rsp), %edi
	cmpl	$8, %edi
	jne	.L319
	leaq	11840(%rsp), %r14
	xorl	%esi, %esi
	movl	$8192, %edx
	movq	%r14, %rdi
	vzeroupper
	call	memset@PLT
	vmovdqa	.LC67(%rip), %ymm14
	movq	%r14, %rsi
	xorl	%eax, %eax
	xorl	%r9d, %r9d
.L323:
	movq	264(%rsp), %rdi
	movq	%rsi, %r10
	xorl	%r8d, %r8d
	movq	%rax, %r11
	leaq	(%rdi,%rax), %rcx
.L330:
	movq	%rsi, 248(%rsp)
	xorl	%eax, %eax
	movq	%r10, %rdx
	movq	%rbx, %rdi
.L324:
	movq	%rdi, %r15
	xorl	%r13d, %r13d
	xorl	%esi, %esi
.L326:
	vmovdqa	(%r15), %ymm0
	vmovdqu	527872(%rcx,%r13), %ymm3
	addl	$2, %esi
	addq	$64, %r15
	vmovdqa	-32(%r15), %ymm2
	vpshufb	.LC64(%rip), %ymm3, %ymm4
	vpermq	$0, %ymm0, %ymm1
	vpshufb	.LC65(%rip), %ymm3, %ymm5
	vpmullw	%ymm4, %ymm1, %ymm1
	vpermq	$85, %ymm0, %ymm4
	vpmullw	%ymm5, %ymm4, %ymm4
	vpshufb	.LC66(%rip), %ymm3, %ymm5
	vpshufb	%ymm14, %ymm3, %ymm3
	vpaddw	%ymm4, %ymm1, %ymm1
	vpermq	$170, %ymm0, %ymm4
	vpermq	$255, %ymm0, %ymm0
	vpmullw	%ymm5, %ymm4, %ymm4
	vpmullw	%ymm3, %ymm0, %ymm0
	vpaddw	(%rdx), %ymm1, %ymm1
	vpaddw	%ymm0, %ymm4, %ymm0
	vpaddw	%ymm0, %ymm1, %ymm1
	vpermq	$0, %ymm2, %ymm0
	vmovdqa	%ymm1, (%rdx)
	vmovdqu	527904(%rcx,%r13), %ymm3
	addq	$64, %r13
	vpshufb	.LC64(%rip), %ymm3, %ymm4
	vpshufb	.LC65(%rip), %ymm3, %ymm5
	vpmullw	%ymm4, %ymm0, %ymm0
	vpermq	$85, %ymm2, %ymm4
	vpmullw	%ymm5, %ymm4, %ymm4
	vpaddw	%ymm4, %ymm0, %ymm0
	vpshufb	.LC66(%rip), %ymm3, %ymm4
	vpshufb	%ymm14, %ymm3, %ymm3
	vpaddw	%ymm1, %ymm0, %ymm0
	vpermq	$170, %ymm2, %ymm1
	vpmullw	%ymm4, %ymm1, %ymm4
	vpermq	$255, %ymm2, %ymm1
	vpmullw	%ymm3, %ymm1, %ymm1
	vpaddw	%ymm1, %ymm4, %ymm1
	vpaddw	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, (%rdx)
	cmpl	$36, %esi
	jne	.L326
	vmovdqa	1152(%rdi), %ymm3
	vmovdqu	529024(%rcx), %ymm2
	addl	$37, %eax
	addq	$1184, %rdi
	addq	$256, %rdx
	vpermq	$0, %ymm3, %ymm4
	vpshufb	.LC64(%rip), %ymm2, %ymm1
	vpermq	$85, %ymm3, %ymm5
	vpmullw	%ymm4, %ymm1, %ymm1
	vpshufb	.LC65(%rip), %ymm2, %ymm4
	vpmullw	%ymm5, %ymm4, %ymm4
	vpaddw	%ymm4, %ymm1, %ymm1
	vpermq	$170, %ymm3, %ymm4
	vpermq	$255, %ymm3, %ymm3
	vpaddw	%ymm0, %ymm1, %ymm0
	vpshufb	.LC66(%rip), %ymm2, %ymm1
	vpmullw	%ymm4, %ymm1, %ymm4
	vpshufb	%ymm14, %ymm2, %ymm1
	vpmullw	%ymm3, %ymm1, %ymm1
	vpaddw	%ymm1, %ymm4, %ymm1
	vpaddw	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, -256(%rdx)
	cmpl	$148, %eax
	jne	.L324
	incq	%r8
	movq	248(%rsp), %rsi
	addq	$1184, %rcx
	addq	$32, %r10
	cmpq	$8, %r8
	jne	.L330
	addq	$4, %r9
	leaq	9472(%r11), %rax
	addq	$1024, %rsi
	cmpq	$32, %r9
	jne	.L323
	movl	$-678045803, %edx
	leaq	8192(%r14), %rcx
	movq	%r14, %rax
	vmovd	%edx, %xmm3
	vpbroadcastd	%xmm3, %ymm3
.L331:
	vmovdqa	(%rax), %ymm2
	addq	$32, %rax
	vpmulhuw	%ymm3, %ymm2, %ymm1
	vpsrlw	$4, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm0
	vpaddw	%ymm1, %ymm0, %ymm0
	vpsllw	$2, %ymm0, %ymm0
	vpsubw	%ymm1, %ymm0, %ymm0
	vpsubw	%ymm0, %ymm2, %ymm2
	vmovdqa	%ymm2, -32(%rax)
	cmpq	%rcx, %rax
	jne	.L331
	leaq	1024(%rsp), %rdx
	movq	176(%rsp), %rbx
	movq	264(%rsp), %rsi
	xorl	%r11d, %r11d
	movq	%rdx, 248(%rsp)
	leaq	1568(%rsp), %rdx
	xorl	%ecx, %ecx
	vpxor	%xmm0, %xmm0, %xmm0
	movq	%rdx, 184(%rsp)
	leaq	1280(%rsp), %rdx
	movq	%rbx, %r8
	xorl	%eax, %eax
	movq	%rdx, 224(%rsp)
	movl	$-678045803, %edx
	vmovd	%edx, %xmm11
	movq	%rbx, %rdx
	movq	%r14, %rbx
	vpbroadcastd	%xmm11, %ymm11
.L332:
	movl	%eax, %r13d
	leal	80(%rax), %eax
	movq	%rsi, 104(%rsp)
	movl	%ecx, %r14d
	movl	%eax, 120(%rsp)
	leaq	608768(%rsi), %r9
	movq	%r12, %r15
	movl	%r11d, %edi
	movl	%ecx, 112(%rsp)
	movq	%r8, %rcx
.L338:
	movl	%r14d, %esi
	vpbroadcastw	(%r15), %ymm6
	vpbroadcastw	6(%r15), %ymm5
	vmovdqa	%ymm0, 768(%rsp)
	andl	$7, %esi
	vpbroadcastw	2(%r15), %ymm4
	vpbroadcastw	4(%r15), %ymm3
	vmovdqa	%ymm0, 800(%rsp)
	salq	$10, %rsi
	vmovdqa	%ymm0, 832(%rsp)
	leaq	768(%rsp), %r8
	vmovdqa	%ymm0, 864(%rsp)
	addq	%rbx, %rsi
	vmovdqa	%ymm0, 896(%rsp)
	vmovdqa	%ymm0, 928(%rsp)
	vmovdqa	%ymm0, 960(%rsp)
	vmovdqa	%ymm0, 992(%rsp)
	vmovdqa	%ymm0, 1024(%rsp)
	vmovdqa	%ymm0, 1056(%rsp)
	vmovdqa	%ymm0, 1088(%rsp)
	vmovdqa	%ymm0, 1120(%rsp)
	vmovdqa	%ymm0, 1152(%rsp)
	vmovdqa	%ymm0, 1184(%rsp)
	vmovdqa	%ymm0, 1216(%rsp)
	vmovdqa	%ymm0, 1248(%rsp)
	vmovdqa	%ymm0, 1568(%rsp)
	vmovdqa	%ymm0, 1600(%rsp)
	vmovdqa	%ymm0, 1632(%rsp)
	vmovdqa	%ymm0, 1664(%rsp)
	vmovdqa	%ymm0, 1696(%rsp)
	vmovdqa	%ymm0, 1728(%rsp)
	vmovdqa	%ymm0, 1760(%rsp)
	vmovdqa	%ymm0, 1792(%rsp)
.L333:
	vmovdqa	(%rsi), %ymm2
	vmovdqa	256(%rsi), %ymm1
	addq	$32, %r8
	addq	$32, %rsi
	vmovdqa	480(%rsi), %ymm7
	vmovdqa	736(%rsi), %ymm8
	vperm2i128	$1, %ymm2, %ymm2, %ymm2
	vperm2i128	$1, %ymm1, %ymm1, %ymm1
	vmovdqa	-32(%r8), %ymm9
	movq	248(%rsp), %rax
	vpshufb	.LC80(%rip), %ymm2, %ymm2
	vperm2i128	$1, %ymm8, %ymm8, %ymm8
	vperm2i128	$1, %ymm7, %ymm7, %ymm7
	vpmullw	%ymm2, %ymm6, %ymm2
	vpshufb	.LC80(%rip), %ymm8, %ymm8
	vpshufb	.LC80(%rip), %ymm1, %ymm1
	vpshufb	.LC80(%rip), %ymm7, %ymm7
	vpmullw	%ymm8, %ymm5, %ymm8
	vperm2i128	$1, %ymm9, %ymm9, %ymm9
	vpmullw	%ymm1, %ymm4, %ymm1
	vpmullw	%ymm7, %ymm3, %ymm7
	vpshufb	.LC80(%rip), %ymm9, %ymm9
	vpaddw	%ymm9, %ymm2, %ymm2
	vpaddw	%ymm8, %ymm2, %ymm2
	vpaddw	%ymm7, %ymm1, %ymm1
	vpaddw	%ymm1, %ymm2, %ymm1
	vperm2i128	$1, %ymm1, %ymm1, %ymm1
	vpshufb	.LC80(%rip), %ymm1, %ymm1
	vmovdqa	%ymm1, -32(%r8)
	cmpq	%rax, %r8
	jne	.L333
	vmovdqa	768(%rsp), %ymm8
	vmovdqa	800(%rsp), %ymm7
	movq	%rax, %r10
	vmovdqa	832(%rsp), %ymm6
	vmovdqa	864(%rsp), %ymm5
	vpmulhuw	%ymm11, %ymm8, %ymm2
	vmovdqa	896(%rsp), %ymm4
	vmovdqa	928(%rsp), %ymm3
	vmovdqa	992(%rsp), %ymm10
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm2, %ymm1, %ymm1
	vpmulhuw	%ymm11, %ymm7, %ymm2
	vpsubw	%ymm1, %ymm8, %ymm8
	vpshufb	.LC64(%rip), %ymm8, %ymm15
	vpshufb	.LC65(%rip), %ymm8, %ymm13
	vmovdqa	%ymm8, 768(%rsp)
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm2, %ymm1, %ymm1
	vpmulhuw	%ymm11, %ymm6, %ymm2
	vpsubw	%ymm1, %ymm7, %ymm7
	vmovdqa	%ymm7, 800(%rsp)
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm2, %ymm1, %ymm1
	vpmulhuw	%ymm11, %ymm5, %ymm2
	vpsubw	%ymm1, %ymm6, %ymm6
	vmovdqa	%ymm6, 832(%rsp)
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm2, %ymm1, %ymm1
	vpmulhuw	%ymm11, %ymm4, %ymm2
	vpsubw	%ymm1, %ymm5, %ymm5
	vmovdqa	%ymm5, 864(%rsp)
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm2, %ymm1, %ymm1
	vpmulhuw	%ymm11, %ymm3, %ymm2
	vpsubw	%ymm1, %ymm4, %ymm4
	vmovdqa	%ymm4, 896(%rsp)
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm2, %ymm1, %ymm1
	vmovdqa	960(%rsp), %ymm2
	vpsubw	%ymm1, %ymm3, %ymm3
	vpmulhuw	%ymm11, %ymm2, %ymm9
	vmovdqa	%ymm3, 928(%rsp)
	vpsrlw	$4, %ymm9, %ymm9
	vpsllw	$2, %ymm9, %ymm1
	vpaddw	%ymm9, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm9, %ymm1, %ymm1
	vpmulhuw	%ymm11, %ymm10, %ymm9
	vpsubw	%ymm1, %ymm2, %ymm2
	vmovdqa	%ymm2, 960(%rsp)
	vpsrlw	$4, %ymm9, %ymm9
	vpsllw	$2, %ymm9, %ymm1
	vpaddw	%ymm9, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm9, %ymm1, %ymm1
	vpsubw	%ymm1, %ymm10, %ymm12
	vmovdqu	(%r9), %ymm1
	vmovdqa	%ymm12, 192(%rsp)
	vpermq	$0, %ymm1, %ymm10
	vpermq	$85, %ymm1, %ymm9
	vmovdqa	%ymm12, 992(%rsp)
	vpermq	$170, %ymm1, %ymm12
	vpmullw	%ymm9, %ymm13, %ymm13
	vpmullw	%ymm10, %ymm15, %ymm15
	vpermq	$255, %ymm1, %ymm1
	vpaddw	%ymm13, %ymm15, %ymm15
	vpshufb	.LC66(%rip), %ymm8, %ymm13
	vpshufb	%ymm14, %ymm8, %ymm8
	vpmullw	%ymm1, %ymm8, %ymm8
	vpmullw	%ymm12, %ymm13, %ymm13
	vpaddw	%ymm8, %ymm13, %ymm13
	vpshufb	.LC65(%rip), %ymm7, %ymm8
	vpaddw	%ymm13, %ymm15, %ymm15
	vpmullw	%ymm9, %ymm8, %ymm8
	vpshufb	.LC64(%rip), %ymm7, %ymm13
	vpmullw	%ymm10, %ymm13, %ymm13
	vpaddw	%ymm8, %ymm13, %ymm13
	vpshufb	.LC66(%rip), %ymm7, %ymm8
	vpshufb	%ymm14, %ymm7, %ymm7
	vpmullw	%ymm1, %ymm7, %ymm7
	vpmullw	%ymm12, %ymm8, %ymm8
	vpaddw	%ymm7, %ymm8, %ymm8
	vpshufb	%ymm14, %ymm6, %ymm7
	vpaddw	%ymm8, %ymm13, %ymm13
	vpmullw	%ymm1, %ymm7, %ymm7
	vpshufb	.LC66(%rip), %ymm6, %ymm8
	vpmullw	%ymm12, %ymm8, %ymm8
	vpaddw	%ymm7, %ymm8, %ymm8
	vpshufb	.LC64(%rip), %ymm6, %ymm7
	vpshufb	.LC65(%rip), %ymm6, %ymm6
	vpmullw	%ymm9, %ymm6, %ymm6
	vpmullw	%ymm10, %ymm7, %ymm7
	vpaddw	%ymm6, %ymm7, %ymm7
	vpshufb	%ymm14, %ymm5, %ymm6
	vpaddw	%ymm7, %ymm8, %ymm8
	vpmullw	%ymm1, %ymm6, %ymm6
	vpshufb	.LC66(%rip), %ymm5, %ymm7
	vpmullw	%ymm12, %ymm7, %ymm7
	vpaddw	%ymm6, %ymm7, %ymm7
	vpshufb	.LC64(%rip), %ymm5, %ymm6
	vpshufb	.LC65(%rip), %ymm5, %ymm5
	vpmullw	%ymm9, %ymm5, %ymm5
	vpmullw	%ymm10, %ymm6, %ymm6
	vpaddw	%ymm5, %ymm6, %ymm6
	vpshufb	%ymm14, %ymm4, %ymm5
	vpaddw	%ymm6, %ymm7, %ymm7
	vpmullw	%ymm1, %ymm5, %ymm5
	vpshufb	.LC66(%rip), %ymm4, %ymm6
	vpmullw	%ymm12, %ymm6, %ymm6
	vpaddw	%ymm5, %ymm6, %ymm6
	vpshufb	.LC64(%rip), %ymm4, %ymm5
	vpshufb	.LC65(%rip), %ymm4, %ymm4
	movq	184(%rsp), %rsi
	vpmullw	%ymm9, %ymm4, %ymm4
	vpmullw	%ymm10, %ymm5, %ymm5
	movq	%rsi, %r8
	vpaddw	%ymm4, %ymm5, %ymm5
	vpshufb	%ymm14, %ymm3, %ymm4
	vpaddw	%ymm5, %ymm6, %ymm6
	vpmullw	%ymm1, %ymm4, %ymm4
	vpshufb	.LC66(%rip), %ymm3, %ymm5
	vpmullw	%ymm12, %ymm5, %ymm5
	vpaddw	%ymm4, %ymm5, %ymm5
	vpshufb	.LC64(%rip), %ymm3, %ymm4
	vpshufb	.LC65(%rip), %ymm3, %ymm3
	vpmullw	%ymm9, %ymm3, %ymm3
	vpmullw	%ymm10, %ymm4, %ymm4
	vpaddw	%ymm3, %ymm4, %ymm4
	vpshufb	%ymm14, %ymm2, %ymm3
	vpaddw	%ymm4, %ymm5, %ymm5
	vpmullw	%ymm1, %ymm3, %ymm3
	vpshufb	.LC66(%rip), %ymm2, %ymm4
	vpmullw	%ymm12, %ymm4, %ymm4
	vpaddw	%ymm3, %ymm4, %ymm4
	vpshufb	.LC64(%rip), %ymm2, %ymm3
	vpshufb	.LC65(%rip), %ymm2, %ymm2
	vpmullw	%ymm10, %ymm3, %ymm3
	vpmullw	%ymm9, %ymm2, %ymm2
	vpaddw	%ymm2, %ymm3, %ymm2
	vpaddw	%ymm2, %ymm4, %ymm2
	vmovdqa	192(%rsp), %ymm4
	vpshufb	.LC66(%rip), %ymm4, %ymm3
	vpmullw	%ymm12, %ymm3, %ymm3
	vmovdqa	%ymm4, %ymm12
	vpshufb	%ymm14, %ymm4, %ymm4
	vpmullw	%ymm1, %ymm4, %ymm4
	vpshufb	.LC64(%rip), %ymm12, %ymm1
	vpaddw	%ymm4, %ymm3, %ymm3
	vpmullw	%ymm10, %ymm1, %ymm4
	vpshufb	.LC65(%rip), %ymm12, %ymm1
	vpmullw	%ymm9, %ymm1, %ymm1
	vpaddw	%ymm1, %ymm4, %ymm1
	vpmulhuw	%ymm11, %ymm15, %ymm4
	vpaddw	%ymm1, %ymm3, %ymm1
	vpsrlw	$4, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm3
	vpaddw	%ymm4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm3
	vpsubw	%ymm4, %ymm3, %ymm3
	vpmulhuw	%ymm11, %ymm13, %ymm4
	vpsubw	%ymm3, %ymm15, %ymm15
	vmovdqa	%ymm15, 1024(%rsp)
	vpsrlw	$4, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm3
	vpaddw	%ymm4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm3
	vpsubw	%ymm4, %ymm3, %ymm3
	vpmulhuw	%ymm11, %ymm8, %ymm4
	vpsubw	%ymm3, %ymm13, %ymm13
	vmovdqa	%ymm13, 1056(%rsp)
	vpsrlw	$4, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm3
	vpaddw	%ymm4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm3
	vpsubw	%ymm4, %ymm3, %ymm3
	vpmulhuw	%ymm11, %ymm7, %ymm4
	vpsubw	%ymm3, %ymm8, %ymm8
	vmovdqa	%ymm8, 1088(%rsp)
	vpsrlw	$4, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm3
	vpaddw	%ymm4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm3
	vpsubw	%ymm4, %ymm3, %ymm3
	vpmulhuw	%ymm11, %ymm6, %ymm4
	vpsubw	%ymm3, %ymm7, %ymm7
	vmovdqa	%ymm7, 1120(%rsp)
	vpsrlw	$4, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm3
	vpaddw	%ymm4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm3
	vpsubw	%ymm4, %ymm3, %ymm3
	vpmulhuw	%ymm11, %ymm5, %ymm4
	vpsubw	%ymm3, %ymm6, %ymm6
	vmovdqa	%ymm6, 1152(%rsp)
	vpsrlw	$4, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm3
	vpaddw	%ymm4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm3
	vpsubw	%ymm4, %ymm3, %ymm3
	vpmulhuw	%ymm11, %ymm2, %ymm4
	vpsubw	%ymm3, %ymm5, %ymm5
	vmovdqa	%ymm5, 1184(%rsp)
	vpsrlw	$4, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm3
	vpaddw	%ymm4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm3
	vpsubw	%ymm4, %ymm3, %ymm3
	vpsubw	%ymm3, %ymm2, %ymm2
	vpmulhuw	%ymm11, %ymm1, %ymm3
	vmovdqa	%ymm2, 1216(%rsp)
	vpsrlw	$4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm2
	vpaddw	%ymm3, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm2
	vpsubw	%ymm3, %ymm2, %ymm2
	vmovdqu	5120(%r9), %ymm3
	vpsubw	%ymm2, %ymm1, %ymm1
	vpshufb	.LC64(%rip), %ymm3, %ymm6
	vpshufb	.LC65(%rip), %ymm3, %ymm5
	vpshufb	.LC66(%rip), %ymm3, %ymm4
	vmovdqa	%ymm1, 1248(%rsp)
	vpshufb	%ymm14, %ymm3, %ymm3
.L334:
	vmovdqa	(%r10), %ymm2
	addq	$32, %r10
	addq	$32, %rsi
	vpermq	$0, %ymm2, %ymm1
	vpermq	$85, %ymm2, %ymm7
	vpmullw	%ymm5, %ymm7, %ymm7
	vpmullw	%ymm6, %ymm1, %ymm1
	vpaddw	%ymm7, %ymm1, %ymm1
	vpermq	$170, %ymm2, %ymm7
	vpermq	$255, %ymm2, %ymm2
	vpmullw	%ymm4, %ymm7, %ymm7
	vpmullw	%ymm3, %ymm2, %ymm2
	vpaddw	-32(%rsi), %ymm1, %ymm1
	vpaddw	%ymm2, %ymm7, %ymm2
	vpaddw	%ymm2, %ymm1, %ymm1
	vmovdqa	%ymm1, -32(%rsi)
	cmpq	%r10, 224(%rsp)
	jne	.L334
	vmovdqa	1568(%rsp), %ymm3
	movq	264(%rsp), %rax
	movslq	%edi, %rsi
	movq	%r15, 96(%rsp)
	movq	%rdx, %r10
	movl	%r14d, %r15d
	vpmulhuw	%ymm11, %ymm3, %ymm2
	leaq	(%rax,%rsi,2), %rsi
	movq	%rsi, 168(%rsp)
	leal	1(%rdi), %esi
	movslq	%esi, %rsi
	leaq	(%rax,%rsi,2), %rsi
	movq	%rsi, 240(%rsp)
	leal	2(%rdi), %esi
	vpsrlw	$4, %ymm2, %ymm2
	movslq	%esi, %rsi
	vpsllw	$2, %ymm2, %ymm1
	leaq	(%rax,%rsi,2), %rsi
	vpaddw	%ymm2, %ymm1, %ymm1
	movq	%rsi, 192(%rsp)
	leal	3(%rdi), %esi
	vpsllw	$2, %ymm1, %ymm1
	movslq	%esi, %rsi
	vpsubw	%ymm2, %ymm1, %ymm1
	leaq	(%rax,%rsi,2), %rax
	movl	%r13d, %esi
	vpsubw	%ymm1, %ymm3, %ymm3
	movq	%rax, 128(%rsp)
	xorl	%eax, %eax
	vmovdqa	%ymm3, 1568(%rsp)
	vmovdqa	1600(%rsp), %ymm3
	vpmulhuw	%ymm11, %ymm3, %ymm2
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm2, %ymm1, %ymm1
	vpsubw	%ymm1, %ymm3, %ymm3
	vmovdqa	%ymm3, 1600(%rsp)
	vmovdqa	1632(%rsp), %ymm3
	vpmulhuw	%ymm11, %ymm3, %ymm2
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm2, %ymm1, %ymm1
	vpsubw	%ymm1, %ymm3, %ymm3
	vmovdqa	%ymm3, 1632(%rsp)
	vmovdqa	1664(%rsp), %ymm3
	vpmulhuw	%ymm11, %ymm3, %ymm2
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm2, %ymm1, %ymm1
	vpsubw	%ymm1, %ymm3, %ymm3
	vmovdqa	%ymm3, 1664(%rsp)
	vmovdqa	1696(%rsp), %ymm3
	vpmulhuw	%ymm11, %ymm3, %ymm2
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm2, %ymm1, %ymm1
	vpsubw	%ymm1, %ymm3, %ymm3
	vmovdqa	%ymm3, 1696(%rsp)
	vmovdqa	1728(%rsp), %ymm3
	vpmulhuw	%ymm11, %ymm3, %ymm2
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm2, %ymm1, %ymm1
	vpsubw	%ymm1, %ymm3, %ymm3
	vmovdqa	%ymm3, 1728(%rsp)
	vmovdqa	1760(%rsp), %ymm3
	vpmulhuw	%ymm11, %ymm3, %ymm2
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm2, %ymm1, %ymm1
	vpsubw	%ymm1, %ymm3, %ymm3
	vmovdqa	%ymm3, 1760(%rsp)
	vmovdqa	1792(%rsp), %ymm3
	vpmulhuw	%ymm11, %ymm3, %ymm2
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm2, %ymm1, %ymm1
	vpsubw	%ymm1, %ymm3, %ymm3
	vmovdqa	%ymm3, 1792(%rsp)
.L335:
	movq	%rax, 88(%rsp)
	movq	%r10, %r13
	xorl	%r14d, %r14d
.L336:
	movq	168(%rsp), %rax
	addq	$1032, %r13
	movzwl	603648(%rax,%r14), %eax
	movw	%ax, 144(%rsp)
	movq	192(%rsp), %rax
	movzwl	603648(%rax,%r14), %eax
	vmovd	144(%rsp), %xmm1
	movw	%ax, 136(%rsp)
	movq	240(%rsp), %rax
	vpinsrw	$1, 603648(%rax,%r14), %xmm1, %xmm1
	movq	128(%rsp), %rax
	vmovd	136(%rsp), %xmm2
	vpinsrw	$1, 603648(%rax,%r14), %xmm2, %xmm2
	addq	$8, %r14
	vpunpckldq	%xmm2, %xmm1, %xmm1
	vmovdqa	(%r8), %ymm2
	vpunpcklqdq	%xmm1, %xmm1, %xmm1
	vinserti128	$1, %xmm1, %ymm1, %ymm1
	vpshufb	.LC64(%rip), %ymm2, %ymm2
	vpmullw	%ymm2, %ymm1, %ymm2
	vpaddw	-1032(%r13), %ymm2, %ymm2
	vmovdqu	%ymm2, -1032(%r13)
	vmovdqa	(%r8), %ymm2
	vpshufb	.LC65(%rip), %ymm2, %ymm2
	vpmullw	%ymm2, %ymm1, %ymm2
	vpaddw	-774(%r13), %ymm2, %ymm2
	vmovdqu	%ymm2, -774(%r13)
	vmovdqa	(%r8), %ymm2
	vpshufb	.LC66(%rip), %ymm2, %ymm2
	vpmullw	%ymm2, %ymm1, %ymm2
	vpaddw	-516(%r13), %ymm2, %ymm2
	vmovdqu	%ymm2, -516(%r13)
	vmovdqa	(%r8), %ymm2
	vpshufb	%ymm14, %ymm2, %ymm2
	vpmullw	%ymm2, %ymm1, %ymm1
	vpaddw	-258(%r13), %ymm1, %ymm1
	vmovdqu	%ymm1, -258(%r13)
	cmpq	$32, %r14
	jne	.L336
	movq	88(%rsp), %rax
	addq	$32, %r10
	addq	$32, %r8
	addq	$16, %rax
	cmpq	$128, %rax
	jne	.L335
	leal	1(%r15), %r14d
	movq	96(%rsp), %r15
	leal	4(%rsi), %r13d
	addl	$16, %edi
	addq	$32, %r9
	addq	$8, %r15
	cmpl	120(%rsp), %r13d
	jne	.L338
	movq	%rcx, %r8
	movl	112(%rsp), %ecx
	movq	104(%rsp), %rsi
	addq	$4128, %rdx
	addl	$320, %r11d
	addq	$160, %r12
	incl	%ecx
	addq	$640, %rsi
	cmpl	$8, %ecx
	je	.L388
	movl	%r13d, %eax
	jmp	.L332
.L388:
	movl	$-678045803, %edx
	movq	264(%rsp), %r11
	movq	176(%rsp), %r15
	movq	%rbx, %r14
	vmovd	%edx, %xmm11
	movq	264(%rsp), %rcx
	xorl	%ebx, %ebx
	vpxor	%xmm0, %xmm0, %xmm0
	vpbroadcastd	%xmm11, %ymm11
	leaq	1024(%rsp), %r13
	movq	%r8, %rdi
.L339:
	leaq	4(%r11), %rsi
	leaq	603648(%rcx), %rax
	xorl	%edx, %edx
	movq	%rsi, 240(%rsp)
	leaq	6(%r11), %rsi
	leaq	2(%r11), %r8
	movq	%rsi, 168(%rsp)
	movq	%rcx, %rsi
	movq	%rdi, %rcx
.L345:
	leal	(%rbx,%rdx), %edi
	movq	%rax, 192(%rsp)
	leaq	768(%rsp), %r9
	xorl	%r12d, %r12d
	andl	$7, %edi
	vmovdqa	%ymm0, 768(%rsp)
	movq	%r9, %r10
	salq	$10, %rdi
	vmovdqa	%ymm0, 800(%rsp)
	vmovdqa	%ymm0, 832(%rsp)
	addq	%r14, %rdi
	vmovdqa	%ymm0, 864(%rsp)
	vmovdqa	%ymm0, 896(%rsp)
	vmovdqa	%ymm0, 928(%rsp)
	vmovdqa	%ymm0, 960(%rsp)
	vmovdqa	%ymm0, 992(%rsp)
	vmovdqa	%ymm0, 1024(%rsp)
	vmovdqa	%ymm0, 1056(%rsp)
	vmovdqa	%ymm0, 1088(%rsp)
	vmovdqa	%ymm0, 1120(%rsp)
	vmovdqa	%ymm0, 1152(%rsp)
	vmovdqa	%ymm0, 1184(%rsp)
	vmovdqa	%ymm0, 1216(%rsp)
	vmovdqa	%ymm0, 1248(%rsp)
	vmovdqa	%ymm0, 1568(%rsp)
	vmovdqa	%ymm0, 1600(%rsp)
	vmovdqa	%ymm0, 1632(%rsp)
	vmovdqa	%ymm0, 1664(%rsp)
	vmovdqa	%ymm0, 1696(%rsp)
	vmovdqa	%ymm0, 1728(%rsp)
	vmovdqa	%ymm0, 1760(%rsp)
	vmovdqa	%ymm0, 1792(%rsp)
.L340:
	vpbroadcastw	624128(%r11,%rdx,8), %ymm1
	vpbroadcastw	624128(%r8,%rdx,8), %ymm2
	addq	$32, %r12
	addq	$32, %r10
	movq	168(%rsp), %rax
	addq	$32, %rdi
	vpmullw	224(%rdi), %ymm2, %ymm2
	vpmullw	-32(%rdi), %ymm1, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpbroadcastw	624128(%rax,%rdx,8), %ymm2
	movq	240(%rsp), %rax
	vpaddw	-32(%r10), %ymm1, %ymm1
	vpbroadcastw	624128(%rax,%rdx,8), %ymm3
	vpmullw	736(%rdi), %ymm2, %ymm2
	vpmullw	480(%rdi), %ymm3, %ymm3
	vpaddw	%ymm3, %ymm2, %ymm2
	vpaddw	%ymm2, %ymm1, %ymm1
	vmovdqa	%ymm1, -32(%r10)
	cmpq	$256, %r12
	jne	.L340
	vmovdqa	768(%rsp), %ymm3
	movq	192(%rsp), %rax
	movq	248(%rsp), %rdi
	vpmulhuw	%ymm11, %ymm3, %ymm2
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm2, %ymm1, %ymm1
	vpsubw	%ymm1, %ymm3, %ymm3
	vmovdqa	%ymm3, 768(%rsp)
	vmovdqa	800(%rsp), %ymm3
	vpmulhuw	%ymm11, %ymm3, %ymm2
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm2, %ymm1, %ymm1
	vpsubw	%ymm1, %ymm3, %ymm3
	vmovdqa	%ymm3, 800(%rsp)
	vmovdqa	832(%rsp), %ymm3
	vpmulhuw	%ymm11, %ymm3, %ymm2
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm2, %ymm1, %ymm1
	vpsubw	%ymm1, %ymm3, %ymm3
	vmovdqa	%ymm3, 832(%rsp)
	vmovdqa	864(%rsp), %ymm3
	vpmulhuw	%ymm11, %ymm3, %ymm2
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm2, %ymm1, %ymm1
	vpsubw	%ymm1, %ymm3, %ymm3
	vmovdqa	%ymm3, 864(%rsp)
	vmovdqa	896(%rsp), %ymm3
	vpmulhuw	%ymm11, %ymm3, %ymm2
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm2, %ymm1, %ymm1
	vpsubw	%ymm1, %ymm3, %ymm3
	vmovdqa	%ymm3, 896(%rsp)
	vmovdqa	928(%rsp), %ymm3
	vpmulhuw	%ymm11, %ymm3, %ymm2
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm2, %ymm1, %ymm1
	vpsubw	%ymm1, %ymm3, %ymm3
	vmovdqa	%ymm3, 928(%rsp)
	vmovdqa	960(%rsp), %ymm3
	vpmulhuw	%ymm11, %ymm3, %ymm2
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm2, %ymm1, %ymm1
	vpsubw	%ymm1, %ymm3, %ymm3
	vmovdqa	%ymm3, 960(%rsp)
	vmovdqa	992(%rsp), %ymm3
	vpmulhuw	%ymm11, %ymm3, %ymm2
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm2, %ymm1, %ymm1
	vpsubw	%ymm1, %ymm3, %ymm3
	vmovdqa	%ymm3, 992(%rsp)
	vmovdqu	(%rax), %ymm3
	vpshufb	.LC64(%rip), %ymm3, %ymm6
	vpshufb	.LC65(%rip), %ymm3, %ymm5
	vpshufb	.LC66(%rip), %ymm3, %ymm4
	vpshufb	%ymm14, %ymm3, %ymm3
.L341:
	vmovdqa	(%r9), %ymm1
	addq	$32, %r9
	addq	$32, %rdi
	vpshufb	.LC81(%rip), %ymm1, %ymm2
	vpermq	$78, %ymm2, %ymm7
	vpor	%ymm7, %ymm2, %ymm2
	vpshufb	.LC82(%rip), %ymm1, %ymm7
	vpermq	$78, %ymm7, %ymm8
	vpmullw	%ymm6, %ymm2, %ymm2
	vpor	%ymm8, %ymm7, %ymm7
	vpmullw	%ymm5, %ymm7, %ymm7
	vpaddw	%ymm7, %ymm2, %ymm2
	vpaddw	-32(%rdi), %ymm2, %ymm7
	vpshufb	.LC83(%rip), %ymm1, %ymm2
	vpshufb	.LC84(%rip), %ymm1, %ymm1
	vpermq	$78, %ymm2, %ymm8
	vpor	%ymm8, %ymm2, %ymm2
	vpermq	$78, %ymm1, %ymm8
	vpor	%ymm8, %ymm1, %ymm1
	vpmullw	%ymm4, %ymm2, %ymm2
	vpmullw	%ymm3, %ymm1, %ymm1
	vpaddw	%ymm1, %ymm2, %ymm1
	vpaddw	%ymm1, %ymm7, %ymm1
	vmovdqa	%ymm1, -32(%rdi)
	cmpq	%r9, %r13
	jne	.L341
	vmovdqa	1024(%rsp), %ymm8
	vmovdqa	1056(%rsp), %ymm7
	xorl	%r10d, %r10d
	movq	%r15, %r9
	vmovdqa	1088(%rsp), %ymm6
	vmovdqa	1120(%rsp), %ymm5
	vpmulhuw	%ymm11, %ymm8, %ymm2
	vmovdqa	1152(%rsp), %ymm4
	vmovdqa	1184(%rsp), %ymm3
	vmovdqa	1248(%rsp), %ymm10
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm2, %ymm1, %ymm1
	vpmulhuw	%ymm11, %ymm7, %ymm2
	vpsubw	%ymm1, %ymm8, %ymm8
	vpshufb	.LC64(%rip), %ymm8, %ymm13
	vpshufb	.LC65(%rip), %ymm8, %ymm15
	vmovdqa	%ymm8, 1024(%rsp)
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm2, %ymm1, %ymm1
	vpmulhuw	%ymm11, %ymm6, %ymm2
	vpsubw	%ymm1, %ymm7, %ymm7
	vmovdqa	%ymm7, 1056(%rsp)
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm2, %ymm1, %ymm1
	vpmulhuw	%ymm11, %ymm5, %ymm2
	vpsubw	%ymm1, %ymm6, %ymm6
	vmovdqa	%ymm6, 1088(%rsp)
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm2, %ymm1, %ymm1
	vpmulhuw	%ymm11, %ymm4, %ymm2
	vpsubw	%ymm1, %ymm5, %ymm5
	vmovdqa	%ymm5, 1120(%rsp)
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm2, %ymm1, %ymm1
	vpmulhuw	%ymm11, %ymm3, %ymm2
	vpsubw	%ymm1, %ymm4, %ymm4
	vmovdqa	%ymm4, 1152(%rsp)
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm2, %ymm1, %ymm1
	vmovdqa	1216(%rsp), %ymm2
	vpsubw	%ymm1, %ymm3, %ymm3
	vpmulhuw	%ymm11, %ymm2, %ymm9
	vmovdqa	%ymm3, 1184(%rsp)
	vpsrlw	$4, %ymm9, %ymm9
	vpsllw	$2, %ymm9, %ymm1
	vpaddw	%ymm9, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm9, %ymm1, %ymm1
	vpmulhuw	%ymm11, %ymm10, %ymm9
	vpsubw	%ymm1, %ymm2, %ymm2
	vmovdqa	%ymm2, 1216(%rsp)
	vpsrlw	$4, %ymm9, %ymm9
	vpsllw	$2, %ymm9, %ymm1
	vpaddw	%ymm9, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm9, %ymm1, %ymm1
	vpsubw	%ymm1, %ymm10, %ymm12
	vmovdqu	15360(%rax), %ymm1
	vmovdqa	%ymm12, 192(%rsp)
	vpermq	$85, %ymm1, %ymm10
	vmovdqa	%ymm12, 1248(%rsp)
	vpermq	$0, %ymm1, %ymm12
	vpermq	$170, %ymm1, %ymm9
	vpmullw	%ymm12, %ymm13, %ymm13
	vpmullw	%ymm10, %ymm15, %ymm15
	vpermq	$255, %ymm1, %ymm1
	vpaddw	%ymm15, %ymm13, %ymm13
	vpshufb	.LC66(%rip), %ymm8, %ymm15
	vpshufb	%ymm14, %ymm8, %ymm8
	vpmullw	%ymm1, %ymm8, %ymm8
	vpmullw	%ymm9, %ymm15, %ymm15
	vpaddw	1568(%rsp), %ymm13, %ymm13
	vpaddw	%ymm8, %ymm15, %ymm15
	vpshufb	.LC64(%rip), %ymm7, %ymm8
	vpaddw	%ymm15, %ymm13, %ymm15
	vpmullw	%ymm12, %ymm8, %ymm8
	vpshufb	.LC65(%rip), %ymm7, %ymm13
	vpmullw	%ymm10, %ymm13, %ymm13
	vpaddw	%ymm13, %ymm8, %ymm8
	vpshufb	.LC66(%rip), %ymm7, %ymm13
	vpshufb	%ymm14, %ymm7, %ymm7
	vpmullw	%ymm1, %ymm7, %ymm7
	vpmullw	%ymm9, %ymm13, %ymm13
	vpaddw	1600(%rsp), %ymm8, %ymm8
	vpaddw	%ymm7, %ymm13, %ymm13
	vpshufb	.LC64(%rip), %ymm6, %ymm7
	vpaddw	%ymm13, %ymm8, %ymm13
	vpmullw	%ymm12, %ymm7, %ymm7
	vpshufb	.LC65(%rip), %ymm6, %ymm8
	vpmullw	%ymm10, %ymm8, %ymm8
	vpaddw	%ymm8, %ymm7, %ymm7
	vpshufb	.LC66(%rip), %ymm6, %ymm8
	vpshufb	%ymm14, %ymm6, %ymm6
	vpmullw	%ymm1, %ymm6, %ymm6
	vpmullw	%ymm9, %ymm8, %ymm8
	vpaddw	1632(%rsp), %ymm7, %ymm7
	vpaddw	%ymm6, %ymm8, %ymm8
	vpshufb	.LC64(%rip), %ymm5, %ymm6
	vpaddw	%ymm8, %ymm7, %ymm8
	vpmullw	%ymm12, %ymm6, %ymm6
	vpshufb	.LC65(%rip), %ymm5, %ymm7
	vpmullw	%ymm10, %ymm7, %ymm7
	vpaddw	%ymm7, %ymm6, %ymm6
	vpaddw	1664(%rsp), %ymm6, %ymm6
	vpshufb	.LC66(%rip), %ymm5, %ymm7
	vpshufb	%ymm14, %ymm5, %ymm5
	movq	184(%rsp), %rdi
	vpmullw	%ymm1, %ymm5, %ymm5
	vpmullw	%ymm9, %ymm7, %ymm7
	vpaddw	%ymm5, %ymm7, %ymm7
	vpshufb	.LC64(%rip), %ymm4, %ymm5
	vpaddw	%ymm7, %ymm6, %ymm7
	vpmullw	%ymm12, %ymm5, %ymm5
	vpshufb	.LC65(%rip), %ymm4, %ymm6
	vpmullw	%ymm10, %ymm6, %ymm6
	vpaddw	%ymm6, %ymm5, %ymm5
	vpshufb	.LC66(%rip), %ymm4, %ymm6
	vpshufb	%ymm14, %ymm4, %ymm4
	vpmullw	%ymm1, %ymm4, %ymm4
	vpmullw	%ymm9, %ymm6, %ymm6
	vpaddw	1696(%rsp), %ymm5, %ymm5
	vpaddw	%ymm4, %ymm6, %ymm6
	vpshufb	.LC64(%rip), %ymm3, %ymm4
	vpaddw	%ymm6, %ymm5, %ymm6
	vpmullw	%ymm12, %ymm4, %ymm4
	vpshufb	.LC65(%rip), %ymm3, %ymm5
	vpmullw	%ymm10, %ymm5, %ymm5
	vpaddw	%ymm5, %ymm4, %ymm4
	vpshufb	.LC66(%rip), %ymm3, %ymm5
	vpshufb	%ymm14, %ymm3, %ymm3
	vpmullw	%ymm1, %ymm3, %ymm3
	vpmullw	%ymm9, %ymm5, %ymm5
	vpaddw	1728(%rsp), %ymm4, %ymm4
	vpaddw	%ymm3, %ymm5, %ymm5
	vpshufb	.LC64(%rip), %ymm2, %ymm3
	vpaddw	%ymm5, %ymm4, %ymm5
	vpmullw	%ymm12, %ymm3, %ymm3
	vpshufb	.LC65(%rip), %ymm2, %ymm4
	vpmullw	%ymm10, %ymm4, %ymm4
	vpaddw	%ymm4, %ymm3, %ymm3
	vpaddw	1760(%rsp), %ymm3, %ymm4
	vpshufb	.LC66(%rip), %ymm2, %ymm3
	vpshufb	%ymm14, %ymm2, %ymm2
	vpmullw	%ymm9, %ymm3, %ymm3
	vpmullw	%ymm1, %ymm2, %ymm2
	vpaddw	%ymm2, %ymm3, %ymm2
	vmovdqa	192(%rsp), %ymm3
	vpaddw	%ymm2, %ymm4, %ymm2
	vpshufb	.LC64(%rip), %ymm3, %ymm4
	vpmullw	%ymm12, %ymm4, %ymm4
	vmovdqa	%ymm3, %ymm12
	vpshufb	.LC65(%rip), %ymm3, %ymm3
	vpmullw	%ymm10, %ymm3, %ymm3
	vpaddw	%ymm3, %ymm4, %ymm4
	vpshufb	.LC66(%rip), %ymm12, %ymm3
	vpmullw	%ymm9, %ymm3, %ymm9
	vpshufb	%ymm14, %ymm12, %ymm3
	vpaddw	1792(%rsp), %ymm4, %ymm4
	vpmullw	%ymm1, %ymm3, %ymm3
	vpaddw	%ymm3, %ymm9, %ymm1
	vpaddw	%ymm1, %ymm4, %ymm1
	vpmulhuw	%ymm11, %ymm15, %ymm4
	vpsrlw	$4, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm3
	vpaddw	%ymm4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm3
	vpsubw	%ymm4, %ymm3, %ymm3
	vpmulhuw	%ymm11, %ymm13, %ymm4
	vpsubw	%ymm3, %ymm15, %ymm15
	vmovdqa	%ymm15, 1568(%rsp)
	vpsrlw	$4, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm3
	vpaddw	%ymm4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm3
	vpsubw	%ymm4, %ymm3, %ymm3
	vpmulhuw	%ymm11, %ymm8, %ymm4
	vpsubw	%ymm3, %ymm13, %ymm13
	vmovdqa	%ymm13, 1600(%rsp)
	vpsrlw	$4, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm3
	vpaddw	%ymm4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm3
	vpsubw	%ymm4, %ymm3, %ymm3
	vpmulhuw	%ymm11, %ymm7, %ymm4
	vpsubw	%ymm3, %ymm8, %ymm8
	vmovdqa	%ymm8, 1632(%rsp)
	vpsrlw	$4, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm3
	vpaddw	%ymm4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm3
	vpsubw	%ymm4, %ymm3, %ymm3
	vpmulhuw	%ymm11, %ymm6, %ymm4
	vpsubw	%ymm3, %ymm7, %ymm7
	vmovdqa	%ymm7, 1664(%rsp)
	vpsrlw	$4, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm3
	vpaddw	%ymm4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm3
	vpsubw	%ymm4, %ymm3, %ymm3
	vpmulhuw	%ymm11, %ymm5, %ymm4
	vpsubw	%ymm3, %ymm6, %ymm6
	vmovdqa	%ymm6, 1696(%rsp)
	vpsrlw	$4, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm3
	vpaddw	%ymm4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm3
	vpsubw	%ymm4, %ymm3, %ymm3
	vpmulhuw	%ymm11, %ymm2, %ymm4
	vpsubw	%ymm3, %ymm5, %ymm5
	vmovdqa	%ymm5, 1728(%rsp)
	vpsrlw	$4, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm3
	vpaddw	%ymm4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm3
	vpsubw	%ymm4, %ymm3, %ymm3
	vpsubw	%ymm3, %ymm2, %ymm2
	vpmulhuw	%ymm11, %ymm1, %ymm3
	vmovdqa	%ymm2, 1760(%rsp)
	vpsrlw	$4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm2
	vpaddw	%ymm3, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm2
	vpsubw	%ymm3, %ymm2, %ymm2
	vpsubw	%ymm2, %ymm1, %ymm1
	vmovdqa	%ymm1, 1792(%rsp)
	vmovdqu	5120(%rax), %ymm1
	vpshufb	.LC81(%rip), %ymm1, %ymm6
	vpshufb	.LC82(%rip), %ymm1, %ymm5
	vpshufb	.LC83(%rip), %ymm1, %ymm4
	vpermq	$78, %ymm6, %ymm2
	vpshufb	.LC84(%rip), %ymm1, %ymm1
	movq	%r11, 120(%rsp)
	movq	%rax, %r11
	vpor	%ymm2, %ymm6, %ymm6
	vpermq	$78, %ymm5, %ymm2
	movq	%rsi, 112(%rsp)
	movq	%rcx, %rsi
	vpor	%ymm2, %ymm5, %ymm5
	vpermq	$78, %ymm4, %ymm2
	movq	%r13, %rcx
	movl	%ebx, %r13d
	vpor	%ymm2, %ymm4, %ymm4
	vpermq	$78, %ymm1, %ymm2
	movq	%rdx, %rbx
	vpor	%ymm2, %ymm1, %ymm2
.L342:
	leaq	2(%rdi), %r12
	movq	%r9, 104(%rsp)
	movq	%r9, %rax
	xorl	%edx, %edx
	movq	%r12, 144(%rsp)
	leaq	4(%rdi), %r12
	movq	%r12, 136(%rsp)
	leaq	6(%rdi), %r12
	movq	%r12, 128(%rsp)
	movq	%rcx, 96(%rsp)
.L343:
	movq	136(%rsp), %rcx
	movq	144(%rsp), %r9
	addq	$1032, %rax
	movzwl	(%rdi,%rdx), %r12d
	movzwl	(%rcx,%rdx), %ecx
	movzwl	(%r9,%rdx), %r9d
	vmovd	%r12d, %xmm3
	movw	%cx, 192(%rsp)
	movq	128(%rsp), %rcx
	vmovd	%r9d, %xmm7
	vpinsrw	$1, %r12d, %xmm3, %xmm1
	vpinsrw	$1, %r9d, %xmm7, %xmm3
	vpunpckldq	%xmm1, %xmm1, %xmm1
	movzwl	(%rcx,%rdx), %ecx
	vpunpckldq	%xmm3, %xmm3, %xmm3
	addq	$8, %rdx
	vpunpcklqdq	%xmm3, %xmm1, %xmm1
	vmovd	192(%rsp), %xmm7
	vpinsrw	$1, 192(%rsp), %xmm7, %xmm3
	vmovd	%ecx, %xmm8
	vpinsrw	$1, %ecx, %xmm8, %xmm7
	vpunpckldq	%xmm3, %xmm3, %xmm3
	vpunpckldq	%xmm7, %xmm7, %xmm7
	vpunpcklqdq	%xmm7, %xmm3, %xmm3
	vinserti128	$0x1, %xmm3, %ymm1, %ymm1
	vpmullw	%ymm6, %ymm1, %ymm3
	vpaddw	-1032(%rax), %ymm3, %ymm3
	vmovdqu	%ymm3, -1032(%rax)
	vpmullw	%ymm5, %ymm1, %ymm3
	vpaddw	-774(%rax), %ymm3, %ymm3
	vmovdqu	%ymm3, -774(%rax)
	vpmullw	%ymm4, %ymm1, %ymm3
	vpmullw	%ymm2, %ymm1, %ymm1
	vpaddw	-516(%rax), %ymm3, %ymm3
	vpaddw	-258(%rax), %ymm1, %ymm1
	vmovdqu	%ymm3, -516(%rax)
	vmovdqu	%ymm1, -258(%rax)
	cmpq	$32, %rdx
	jne	.L343
	movq	104(%rsp), %r9
	addl	$4, %r10d
	movq	96(%rsp), %rcx
	addq	$32, %rdi
	addq	$32, %r9
	cmpl	$32, %r10d
	jne	.L342
	leaq	1(%rbx), %rdx
	leaq	32(%r11), %rax
	movl	%r13d, %ebx
	movq	120(%rsp), %r11
	movq	%rcx, %r13
	movq	%rsi, %rcx
	movq	112(%rsp), %rsi
	cmpq	$20, %rdx
	jne	.L345
	incl	%ebx
	movq	%rcx, %rdi
	addq	$4128, %r15
	addq	$160, %r11
	leaq	640(%rsi), %rcx
	cmpl	$8, %ebx
	jne	.L339
	movq	256(%rsp), %rdx
	movl	$1808407283, %ecx
	movq	%rdi, %rax
	vpxor	%xmm2, %xmm2, %xmm2
	vmovd	%ecx, %xmm0
	leaq	33024(%rdx), %rsi
	vpbroadcastd	%xmm0, %ymm0
.L346:
	vmovdqu	(%rax), %ymm4
	vmovdqu	(%rdx), %ymm3
	addq	$258, %rdx
	addq	$258, %rax
	vpmovzxwd	%xmm4, %ymm5
	vpmovzxwd	%xmm3, %ymm1
	vextracti128	$0x1, %ymm4, %xmm4
	vextracti128	$0x1, %ymm3, %xmm3
	vpaddd	%ymm5, %ymm1, %ymm1
	vpmovzxwd	%xmm4, %ymm4
	vpmovzxwd	%xmm3, %ymm3
	vpmuldq	%ymm0, %ymm1, %ymm5
	vpaddd	%ymm4, %ymm3, %ymm3
	vpsrlq	$32, %ymm1, %ymm4
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpshufd	$245, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm4, %ymm4
	vpsrad	$3, %ymm4, %ymm4
	vpslld	$2, %ymm4, %ymm5
	vpaddd	%ymm4, %ymm5, %ymm5
	vpslld	$2, %ymm5, %ymm5
	vpsubd	%ymm4, %ymm5, %ymm4
	vpmuldq	%ymm0, %ymm3, %ymm5
	vpsubd	%ymm4, %ymm1, %ymm1
	vpsrlq	$32, %ymm3, %ymm4
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpblendw	$85, %ymm1, %ymm2, %ymm1
	vpshufd	$245, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm4, %ymm4
	vpsrad	$3, %ymm4, %ymm4
	vpslld	$2, %ymm4, %ymm5
	vpaddd	%ymm4, %ymm5, %ymm5
	vpslld	$2, %ymm5, %ymm5
	vpsubd	%ymm4, %ymm5, %ymm4
	vpsubd	%ymm4, %ymm3, %ymm3
	vpblendw	$85, %ymm3, %ymm2, %ymm3
	vpackusdw	%ymm3, %ymm1, %ymm1
	vmovdqu	-226(%rdx), %ymm3
	vpermq	$216, %ymm1, %ymm1
	vmovdqu	%ymm1, -258(%rdx)
	vpmovzxwd	%xmm3, %ymm1
	vextracti128	$0x1, %ymm3, %xmm3
	vmovdqu	-226(%rax), %ymm4
	vpmovzxwd	%xmm3, %ymm3
	vpmovzxwd	%xmm4, %ymm5
	vextracti128	$0x1, %ymm4, %xmm4
	vpaddd	%ymm5, %ymm1, %ymm1
	vpmovzxwd	%xmm4, %ymm4
	vpaddd	%ymm4, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm1, %ymm5
	vpsrlq	$32, %ymm1, %ymm4
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpshufd	$245, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm4, %ymm4
	vpsrad	$3, %ymm4, %ymm4
	vpslld	$2, %ymm4, %ymm5
	vpaddd	%ymm4, %ymm5, %ymm5
	vpslld	$2, %ymm5, %ymm5
	vpsubd	%ymm4, %ymm5, %ymm4
	vpmuldq	%ymm0, %ymm3, %ymm5
	vpsubd	%ymm4, %ymm1, %ymm1
	vpsrlq	$32, %ymm3, %ymm4
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpblendw	$85, %ymm1, %ymm2, %ymm1
	vpshufd	$245, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm4, %ymm4
	vpsrad	$3, %ymm4, %ymm4
	vpslld	$2, %ymm4, %ymm5
	vpaddd	%ymm4, %ymm5, %ymm5
	vpslld	$2, %ymm5, %ymm5
	vpsubd	%ymm4, %ymm5, %ymm4
	vpsubd	%ymm4, %ymm3, %ymm3
	vmovdqu	-194(%rdx), %ymm4
	vpblendw	$85, %ymm3, %ymm2, %ymm3
	vpackusdw	%ymm3, %ymm1, %ymm1
	vpmovzxwd	%xmm4, %ymm5
	vextracti128	$0x1, %ymm4, %xmm4
	vpermq	$216, %ymm1, %ymm1
	vpmovzxwd	%xmm4, %ymm4
	vmovdqu	%ymm1, -226(%rdx)
	vmovdqu	-194(%rax), %ymm3
	vpmovzxwd	%xmm3, %ymm1
	vextracti128	$0x1, %ymm3, %xmm3
	vpaddd	%ymm5, %ymm1, %ymm1
	vpmovzxwd	%xmm3, %ymm3
	vpaddd	%ymm4, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm1, %ymm5
	vpsrlq	$32, %ymm1, %ymm4
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpshufd	$245, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm4, %ymm4
	vpsrad	$3, %ymm4, %ymm4
	vpslld	$2, %ymm4, %ymm5
	vpaddd	%ymm4, %ymm5, %ymm5
	vpslld	$2, %ymm5, %ymm5
	vpsubd	%ymm4, %ymm5, %ymm4
	vpmuldq	%ymm0, %ymm3, %ymm5
	vpsubd	%ymm4, %ymm1, %ymm1
	vpsrlq	$32, %ymm3, %ymm4
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpblendw	$85, %ymm1, %ymm2, %ymm1
	vpshufd	$245, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm4, %ymm4
	vpsrad	$3, %ymm4, %ymm4
	vpslld	$2, %ymm4, %ymm5
	vpaddd	%ymm4, %ymm5, %ymm5
	vpslld	$2, %ymm5, %ymm5
	vpsubd	%ymm4, %ymm5, %ymm4
	vpsubd	%ymm4, %ymm3, %ymm3
	vmovdqu	-162(%rdx), %ymm4
	vpblendw	$85, %ymm3, %ymm2, %ymm3
	vpackusdw	%ymm3, %ymm1, %ymm1
	vpmovzxwd	%xmm4, %ymm5
	vextracti128	$0x1, %ymm4, %xmm4
	vpermq	$216, %ymm1, %ymm1
	vpmovzxwd	%xmm4, %ymm4
	vmovdqu	%ymm1, -194(%rdx)
	vmovdqu	-162(%rax), %ymm3
	vpmovzxwd	%xmm3, %ymm1
	vextracti128	$0x1, %ymm3, %xmm3
	vpaddd	%ymm5, %ymm1, %ymm1
	vpmovzxwd	%xmm3, %ymm3
	vpaddd	%ymm4, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm1, %ymm5
	vpsrlq	$32, %ymm1, %ymm4
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpshufd	$245, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm4, %ymm4
	vpsrad	$3, %ymm4, %ymm4
	vpslld	$2, %ymm4, %ymm5
	vpaddd	%ymm4, %ymm5, %ymm5
	vpslld	$2, %ymm5, %ymm5
	vpsubd	%ymm4, %ymm5, %ymm4
	vpmuldq	%ymm0, %ymm3, %ymm5
	vpsubd	%ymm4, %ymm1, %ymm1
	vpsrlq	$32, %ymm3, %ymm4
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpblendw	$85, %ymm1, %ymm2, %ymm1
	vpshufd	$245, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm4, %ymm4
	vpsrad	$3, %ymm4, %ymm4
	vpslld	$2, %ymm4, %ymm5
	vpaddd	%ymm4, %ymm5, %ymm5
	vpslld	$2, %ymm5, %ymm5
	vpsubd	%ymm4, %ymm5, %ymm4
	vpsubd	%ymm4, %ymm3, %ymm3
	vpblendw	$85, %ymm3, %ymm2, %ymm3
	vpackusdw	%ymm3, %ymm1, %ymm1
	vmovdqu	-130(%rdx), %ymm3
	vpermq	$216, %ymm1, %ymm1
	vmovdqu	%ymm1, -162(%rdx)
	vpmovzxwd	%xmm3, %ymm1
	vextracti128	$0x1, %ymm3, %xmm3
	vmovdqu	-130(%rax), %ymm4
	vpmovzxwd	%xmm3, %ymm3
	vpmovzxwd	%xmm4, %ymm5
	vextracti128	$0x1, %ymm4, %xmm4
	vpaddd	%ymm5, %ymm1, %ymm1
	vpmovzxwd	%xmm4, %ymm4
	vpaddd	%ymm4, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm1, %ymm5
	vpsrlq	$32, %ymm1, %ymm4
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpshufd	$245, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm4, %ymm4
	vpsrad	$3, %ymm4, %ymm4
	vpslld	$2, %ymm4, %ymm5
	vpaddd	%ymm4, %ymm5, %ymm5
	vpslld	$2, %ymm5, %ymm5
	vpsubd	%ymm4, %ymm5, %ymm4
	vpmuldq	%ymm0, %ymm3, %ymm5
	vpsubd	%ymm4, %ymm1, %ymm1
	vpsrlq	$32, %ymm3, %ymm4
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpblendw	$85, %ymm1, %ymm2, %ymm1
	vpshufd	$245, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm4, %ymm4
	vpsrad	$3, %ymm4, %ymm4
	vpslld	$2, %ymm4, %ymm5
	vpaddd	%ymm4, %ymm5, %ymm5
	vpslld	$2, %ymm5, %ymm5
	vpsubd	%ymm4, %ymm5, %ymm4
	vpsubd	%ymm4, %ymm3, %ymm3
	vpblendw	$85, %ymm3, %ymm2, %ymm3
	vpackusdw	%ymm3, %ymm1, %ymm1
	vmovdqu	-98(%rdx), %ymm3
	vpermq	$216, %ymm1, %ymm1
	vmovdqu	%ymm1, -130(%rdx)
	vpmovzxwd	%xmm3, %ymm1
	vextracti128	$0x1, %ymm3, %xmm3
	vmovdqu	-98(%rax), %ymm4
	vpmovzxwd	%xmm3, %ymm3
	vpmovzxwd	%xmm4, %ymm5
	vextracti128	$0x1, %ymm4, %xmm4
	vpaddd	%ymm5, %ymm1, %ymm1
	vpmovzxwd	%xmm4, %ymm4
	vpaddd	%ymm4, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm1, %ymm5
	vpsrlq	$32, %ymm1, %ymm4
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpshufd	$245, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm4, %ymm4
	vpsrad	$3, %ymm4, %ymm4
	vpslld	$2, %ymm4, %ymm5
	vpaddd	%ymm4, %ymm5, %ymm5
	vpslld	$2, %ymm5, %ymm5
	vpsubd	%ymm4, %ymm5, %ymm4
	vpmuldq	%ymm0, %ymm3, %ymm5
	vpsubd	%ymm4, %ymm1, %ymm1
	vpsrlq	$32, %ymm3, %ymm4
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpblendw	$85, %ymm1, %ymm2, %ymm1
	vpshufd	$245, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm4, %ymm4
	vpsrad	$3, %ymm4, %ymm4
	vpslld	$2, %ymm4, %ymm5
	vpaddd	%ymm4, %ymm5, %ymm5
	vpslld	$2, %ymm5, %ymm5
	vpsubd	%ymm4, %ymm5, %ymm4
	vpsubd	%ymm4, %ymm3, %ymm3
	vpblendw	$85, %ymm3, %ymm2, %ymm3
	vpackusdw	%ymm3, %ymm1, %ymm1
	vmovdqu	-66(%rdx), %ymm3
	vpermq	$216, %ymm1, %ymm1
	vmovdqu	%ymm1, -98(%rdx)
	vpmovzxwd	%xmm3, %ymm1
	vextracti128	$0x1, %ymm3, %xmm3
	vmovdqu	-66(%rax), %ymm4
	vpmovzxwd	%xmm3, %ymm3
	vpmovzxwd	%xmm4, %ymm5
	vextracti128	$0x1, %ymm4, %xmm4
	vpaddd	%ymm5, %ymm1, %ymm1
	vpmovzxwd	%xmm4, %ymm4
	vpaddd	%ymm4, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm1, %ymm5
	vpsrlq	$32, %ymm1, %ymm4
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpshufd	$245, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm4, %ymm4
	vpsrad	$3, %ymm4, %ymm4
	vpslld	$2, %ymm4, %ymm5
	vpaddd	%ymm4, %ymm5, %ymm5
	vpslld	$2, %ymm5, %ymm5
	vpsubd	%ymm4, %ymm5, %ymm4
	vpmuldq	%ymm0, %ymm3, %ymm5
	vpsubd	%ymm4, %ymm1, %ymm1
	vpsrlq	$32, %ymm3, %ymm4
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpblendw	$85, %ymm1, %ymm2, %ymm1
	vpshufd	$245, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm4, %ymm4
	vpsrad	$3, %ymm4, %ymm4
	vpslld	$2, %ymm4, %ymm5
	vpaddd	%ymm4, %ymm5, %ymm5
	vpslld	$2, %ymm5, %ymm5
	vpsubd	%ymm4, %ymm5, %ymm4
	vpsubd	%ymm4, %ymm3, %ymm3
	vmovdqu	-34(%rdx), %ymm4
	vpblendw	$85, %ymm3, %ymm2, %ymm3
	vpackusdw	%ymm3, %ymm1, %ymm1
	vpmovzxwd	%xmm4, %ymm5
	vextracti128	$0x1, %ymm4, %xmm4
	vpermq	$216, %ymm1, %ymm1
	vpmovzxwd	%xmm4, %ymm4
	vmovdqu	%ymm1, -66(%rdx)
	vmovdqu	-34(%rax), %ymm3
	vpmovzxwd	%xmm3, %ymm1
	vextracti128	$0x1, %ymm3, %xmm3
	vpaddd	%ymm5, %ymm1, %ymm1
	vpmovzxwd	%xmm3, %ymm3
	vpaddd	%ymm4, %ymm3, %ymm3
	vpmuldq	%ymm0, %ymm1, %ymm5
	vpsrlq	$32, %ymm1, %ymm4
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpshufd	$245, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm4, %ymm4
	vpsrad	$3, %ymm4, %ymm4
	vpslld	$2, %ymm4, %ymm5
	vpaddd	%ymm4, %ymm5, %ymm5
	vpslld	$2, %ymm5, %ymm5
	vpsubd	%ymm4, %ymm5, %ymm4
	vpmuldq	%ymm0, %ymm3, %ymm5
	vpsubd	%ymm4, %ymm1, %ymm1
	vpsrlq	$32, %ymm3, %ymm4
	vpmuldq	%ymm0, %ymm4, %ymm4
	vpblendw	$85, %ymm1, %ymm2, %ymm1
	vpshufd	$245, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm4, %ymm4
	vpsrad	$3, %ymm4, %ymm4
	vpslld	$2, %ymm4, %ymm5
	vpaddd	%ymm4, %ymm5, %ymm5
	vpslld	$2, %ymm5, %ymm5
	vpsubd	%ymm4, %ymm5, %ymm4
	vpsubd	%ymm4, %ymm3, %ymm3
	vpblendw	$85, %ymm3, %ymm2, %ymm3
	vpackusdw	%ymm3, %ymm1, %ymm1
	vpermq	$216, %ymm1, %ymm1
	vmovdqu	%ymm1, -34(%rdx)
	cmpq	%rsi, %rdx
	jne	.L346
	movq	256(%rsp), %rax
	movl	$0, 240(%rsp)
	xorl	%r10d, %r10d
	movl	$258, %r15d
	movq	$0, 168(%rsp)
	xorl	%esi, %esi
	movl	$128, %r14d
	leaq	260(%rax), %r11
	leaq	258(%rax), %rcx
	movq	$0, 192(%rsp)
	movl	$-678045803, %eax
	movl	$0, 248(%rsp)
	vmovd	%eax, %xmm2
	movl	240(%rsp), %eax
	vpbroadcastd	%xmm2, %ymm1
	vpbroadcastd	%xmm2, %xmm2
.L364:
	leal	1(%rax), %ebx
	cmpl	$127, %eax
	je	.L354
	movl	$127, %r9d
	movq	%r15, %rdi
	leaq	-2(%r10), %r13
	movq	%rcx, %rdx
	subl	%ebx, %r9d
	addq	192(%rsp), %r9
	imulq	$258, %r9, %r9
	addq	$516, %r9
	jmp	.L353
.L759:
	vmovd	%r8d, %xmm0
	leaq	(%rsi,%rdx), %rax
	vpbroadcastw	%xmm0, %ymm0
	vpand	(%rdx), %ymm0, %ymm3
	vpaddw	-258(%rcx), %ymm3, %ymm3
	vmovdqu	%ymm3, -258(%rcx)
	vpand	32(%rdx), %ymm0, %ymm3
	vpaddw	-226(%rcx), %ymm3, %ymm3
	vmovdqu	%ymm3, -226(%rcx)
	vpand	64(%rdx), %ymm0, %ymm3
	vpaddw	-194(%rcx), %ymm3, %ymm3
	vmovdqu	%ymm3, -194(%rcx)
	vpand	96(%rdx), %ymm0, %ymm3
	vpaddw	-162(%rcx), %ymm3, %ymm3
	vmovdqu	%ymm3, -162(%rcx)
	vpand	128(%rdx), %ymm0, %ymm3
	vpaddw	-130(%rcx), %ymm3, %ymm3
	vmovdqu	%ymm3, -130(%rcx)
	vpand	160(%rdx), %ymm0, %ymm3
	vpaddw	-98(%rcx), %ymm3, %ymm3
	vmovdqu	%ymm3, -98(%rcx)
	vpand	192(%rdx), %ymm0, %ymm3
	vpaddw	-66(%rcx), %ymm3, %ymm3
	vmovdqu	%ymm3, -66(%rcx)
	vpand	224(%rdx), %ymm0, %ymm0
	vpaddw	-34(%rcx), %ymm0, %ymm0
	vmovdqu	%ymm0, -34(%rcx)
	andw	-2(%rax,%r15), %r8w
	addw	%r8w, -2(%rcx)
.L351:
	addq	$258, %rdi
	addq	$258, %rdx
	cmpq	%rdi, %r9
	je	.L354
.L353:
	cmpw	$1, -260(%r11)
	movq	%r13, %rax
	sbbl	%r8d, %r8d
	subq	%rdi, %rax
	cmpq	$28, %rax
	ja	.L759
	movq	%rdx, 144(%rsp)
	leaq	-258(%rcx), %rax
.L352:
	leaq	(%rax,%rsi), %r12
	movzwl	(%r12,%rdi), %edx
	andl	%r8d, %edx
	addw	%dx, (%rax)
	addq	$2, %rax
	cmpq	%rcx, %rax
	jne	.L352
	movq	144(%rsp), %rdx
	jmp	.L351
.L354:
	vmovdqu	-258(%rcx), %ymm9
	vmovdqu	-226(%rcx), %ymm8
	movq	%rcx, %rdi
	vmovdqu	-194(%rcx), %ymm7
	vmovdqu	-162(%rcx), %ymm6
	vpmulhuw	%ymm1, %ymm9, %ymm3
	vmovdqu	-130(%rcx), %ymm5
	vmovdqu	-98(%rcx), %ymm4
	vmovdqu	-34(%rcx), %ymm11
	movzwl	-2(%rcx), %edx
	movl	%edx, %r8d
	imull	$55189, %edx, %edx
	vpsrlw	$4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm0
	shrl	$20, %edx
	vpaddw	%ymm3, %ymm0, %ymm0
	leal	(%rdx,%rdx,8), %eax
	vpsllw	$2, %ymm0, %ymm0
	leal	(%rdx,%rax,2), %eax
	movl	%r8d, %edx
	vpsubw	%ymm3, %ymm0, %ymm0
	vpmulhuw	%ymm1, %ymm8, %ymm3
	subl	%eax, %edx
	xorl	%eax, %eax
	vpsubw	%ymm0, %ymm9, %ymm9
	movw	%dx, -2(%rcx)
	vmovdqu	%ymm9, -258(%rcx)
	vpsrlw	$4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm0
	vpaddw	%ymm3, %ymm0, %ymm0
	vpsllw	$2, %ymm0, %ymm0
	vpsubw	%ymm3, %ymm0, %ymm0
	vpmulhuw	%ymm1, %ymm7, %ymm3
	vpsubw	%ymm0, %ymm8, %ymm8
	vmovdqu	%ymm8, -226(%rcx)
	vpsrlw	$4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm0
	vpaddw	%ymm3, %ymm0, %ymm0
	vpsllw	$2, %ymm0, %ymm0
	vpsubw	%ymm3, %ymm0, %ymm0
	vpmulhuw	%ymm1, %ymm6, %ymm3
	vpsubw	%ymm0, %ymm7, %ymm7
	vmovdqu	%ymm7, -194(%rcx)
	vpsrlw	$4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm0
	vpaddw	%ymm3, %ymm0, %ymm0
	vpsllw	$2, %ymm0, %ymm0
	vpsubw	%ymm3, %ymm0, %ymm0
	vpmulhuw	%ymm1, %ymm5, %ymm3
	vpsubw	%ymm0, %ymm6, %ymm6
	vmovdqu	%ymm6, -162(%rcx)
	vpsrlw	$4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm0
	vpaddw	%ymm3, %ymm0, %ymm0
	vpsllw	$2, %ymm0, %ymm0
	vpsubw	%ymm3, %ymm0, %ymm0
	vpmulhuw	%ymm1, %ymm4, %ymm3
	vpsubw	%ymm0, %ymm5, %ymm5
	vmovdqu	%ymm5, -130(%rcx)
	vpsrlw	$4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm0
	vpaddw	%ymm3, %ymm0, %ymm0
	vpsllw	$2, %ymm0, %ymm0
	vpsubw	%ymm3, %ymm0, %ymm0
	vmovdqu	-66(%rcx), %ymm3
	vpsubw	%ymm0, %ymm4, %ymm4
	vpmulhuw	%ymm1, %ymm3, %ymm10
	vmovdqu	%ymm4, -98(%rcx)
	vpsrlw	$4, %ymm10, %ymm10
	vpsllw	$2, %ymm10, %ymm0
	vpaddw	%ymm10, %ymm0, %ymm0
	vpsllw	$2, %ymm0, %ymm0
	vpsubw	%ymm10, %ymm0, %ymm0
	vpmulhuw	%ymm1, %ymm11, %ymm10
	vpsubw	%ymm0, %ymm3, %ymm3
	vmovdqu	%ymm3, -66(%rcx)
	vpsrlw	$4, %ymm10, %ymm10
	vpsllw	$2, %ymm10, %ymm0
	vpaddw	%ymm10, %ymm0, %ymm0
	vpsllw	$2, %ymm0, %ymm0
	vpsubw	%ymm10, %ymm0, %ymm0
	vpsubw	%ymm0, %ymm11, %ymm0
	vmovdqu	%ymm0, -34(%rcx)
	movzwl	-260(%r11), %r8d
	testw	%r8w, %r8w
	movl	%r8d, %r9d
	sete	%al
	imull	%r8d, %r9d
	orl	%eax, 248(%rsp)
	movl	$2938661835, %eax
	imull	%r9d, %r9d
	movl	%r9d, %r12d
	imulq	%rax, %r12
	movl	%r9d, %eax
	shrq	$32, %r12
	subl	%r12d, %eax
	shrl	%eax
	addl	%r12d, %eax
	shrl	$4, %eax
	leal	(%rax,%rax,8), %r12d
	leal	(%rax,%r12,2), %r12d
	movl	%r9d, %eax
	subl	%r12d, %eax
	imull	%eax, %eax
	movl	%eax, %r9d
	cltq
	imulq	$1808407283, %rax, %rax
	movl	%r9d, %r12d
	sarl	$31, %r12d
	sarq	$35, %rax
	subl	%r12d, %eax
	leal	(%rax,%rax,8), %r12d
	leal	(%rax,%r12,2), %r12d
	movl	%r9d, %eax
	subl	%r12d, %eax
	imull	%eax, %eax
	movslq	%eax, %r9
	movl	%eax, %r12d
	imulq	$1808407283, %r9, %r9
	sarl	$31, %r12d
	sarq	$35, %r9
	subl	%r12d, %r9d
	leal	(%r9,%r9,8), %r12d
	leal	(%r9,%r12,2), %r9d
	subl	%r9d, %eax
	imull	%r8d, %eax
	movslq	%eax, %r8
	movl	%eax, %r9d
	imulq	$1808407283, %r8, %r8
	sarl	$31, %r9d
	sarq	$35, %r8
	subl	%r9d, %r8d
	leal	(%r8,%r8,8), %r9d
	leal	(%r8,%r9,2), %r8d
	movl	$19, %r9d
	subl	%r8d, %eax
	vmovd	%eax, %xmm10
	mulb	%dl
	vpbroadcastw	%xmm10, %ymm10
	vpmullw	%ymm9, %ymm10, %ymm9
	vpmullw	%ymm8, %ymm10, %ymm8
	vpmullw	%ymm10, %ymm7, %ymm7
	vpmullw	%ymm6, %ymm10, %ymm6
	movl	%eax, %edx
	vpmullw	%ymm5, %ymm10, %ymm5
	vpmullw	%ymm4, %ymm10, %ymm4
	sarw	$15, %dx
	vpmullw	%ymm3, %ymm10, %ymm3
	vpmullw	%ymm10, %ymm0, %ymm0
	idivw	%r9w
	vpmulhuw	%ymm1, %ymm9, %ymm11
	vpsrlw	$4, %ymm11, %ymm11
	vpsllw	$2, %ymm11, %ymm10
	vpaddw	%ymm11, %ymm10, %ymm10
	vpsllw	$2, %ymm10, %ymm10
	vpsubw	%ymm11, %ymm10, %ymm10
	vpsubw	%ymm10, %ymm9, %ymm9
	vpmulhuw	%ymm1, %ymm8, %ymm10
	vmovdqu	%ymm9, -258(%rcx)
	movw	%dx, -2(%rcx)
	vpsrlw	$4, %ymm10, %ymm10
	vpsllw	$2, %ymm10, %ymm9
	vpaddw	%ymm10, %ymm9, %ymm9
	vpsllw	$2, %ymm9, %ymm9
	vpsubw	%ymm10, %ymm9, %ymm9
	vpsubw	%ymm9, %ymm8, %ymm8
	vpmulhuw	%ymm1, %ymm7, %ymm9
	vmovdqu	%ymm8, -226(%rcx)
	vpsrlw	$4, %ymm9, %ymm9
	vpsllw	$2, %ymm9, %ymm8
	vpaddw	%ymm9, %ymm8, %ymm8
	vpsllw	$2, %ymm8, %ymm8
	vpsubw	%ymm9, %ymm8, %ymm8
	vpsubw	%ymm8, %ymm7, %ymm7
	vpmulhuw	%ymm1, %ymm6, %ymm8
	vmovdqu	%ymm7, -194(%rcx)
	vpsrlw	$4, %ymm8, %ymm8
	vpsllw	$2, %ymm8, %ymm7
	vpaddw	%ymm8, %ymm7, %ymm7
	vpsllw	$2, %ymm7, %ymm7
	vpsubw	%ymm8, %ymm7, %ymm7
	vpsubw	%ymm7, %ymm6, %ymm6
	vpmulhuw	%ymm1, %ymm5, %ymm7
	vmovdqu	%ymm6, -162(%rcx)
	vpsrlw	$4, %ymm7, %ymm7
	vpsllw	$2, %ymm7, %ymm6
	vpaddw	%ymm7, %ymm6, %ymm6
	vpsllw	$2, %ymm6, %ymm6
	vpsubw	%ymm7, %ymm6, %ymm6
	vpsubw	%ymm6, %ymm5, %ymm5
	vpmulhuw	%ymm1, %ymm4, %ymm6
	vmovdqu	%ymm5, -130(%rcx)
	vpsrlw	$4, %ymm6, %ymm6
	vpsllw	$2, %ymm6, %ymm5
	vpaddw	%ymm6, %ymm5, %ymm5
	vpsllw	$2, %ymm5, %ymm5
	vpsubw	%ymm6, %ymm5, %ymm5
	vpsubw	%ymm5, %ymm4, %ymm4
	vpmulhuw	%ymm1, %ymm3, %ymm5
	vmovdqu	%ymm4, -98(%rcx)
	vpsrlw	$4, %ymm5, %ymm5
	vpsllw	$2, %ymm5, %ymm4
	vpaddw	%ymm5, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm4
	vpsubw	%ymm5, %ymm4, %ymm4
	vpsubw	%ymm4, %ymm3, %ymm3
	vpmulhuw	%ymm1, %ymm0, %ymm4
	vmovdqu	%ymm3, -66(%rcx)
	vpsrlw	$4, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm3
	vpaddw	%ymm4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm3
	vpsubw	%ymm4, %ymm3, %ymm3
	vpsubw	%ymm3, %ymm0, %ymm0
	vmovdqu	%ymm0, -34(%rcx)
	decl	%r14d
	je	.L760
	movl	$127, %eax
	leaq	-516(%rsi), %rdx
	leaq	-258(%rsi), %r12
	addq	$258, %rcx
	subl	%ebx, %eax
	movq	%rcx, 136(%rsp)
	movq	%r12, %r8
	leaq	-2(%rsi), %r13
	imulq	$258, %rax, %rax
	subq	%rax, %rdx
	movq	%rcx, %rax
	movq	%rdx, 144(%rsp)
	jmp	.L358
.L762:
	vmovd	%r9d, %xmm0
	leaq	(%rsi,%rax), %rdx
	vpbroadcastw	%xmm0, %ymm0
	vpmullw	-258(%rdi), %ymm0, %ymm3
	vpaddw	-258(%rax), %ymm3, %ymm3
	vmovdqu	%ymm3, -258(%rax)
	vpmullw	-226(%rdi), %ymm0, %ymm3
	vpaddw	-226(%rax), %ymm3, %ymm3
	vmovdqu	%ymm3, -226(%rax)
	vpmullw	-194(%rdi), %ymm0, %ymm3
	vpaddw	-194(%rax), %ymm3, %ymm3
	vmovdqu	%ymm3, -194(%rax)
	vpmullw	-162(%rdi), %ymm0, %ymm3
	vpaddw	-162(%rax), %ymm3, %ymm3
	vmovdqu	%ymm3, -162(%rax)
	vpmullw	-130(%rdi), %ymm0, %ymm3
	vpaddw	-130(%rax), %ymm3, %ymm3
	vmovdqu	%ymm3, -130(%rax)
	vpmullw	-98(%rdi), %ymm0, %ymm3
	vpaddw	-98(%rax), %ymm3, %ymm3
	vmovdqu	%ymm3, -98(%rax)
	vpmullw	-66(%rdi), %ymm0, %ymm3
	vpaddw	-66(%rax), %ymm3, %ymm3
	vmovdqu	%ymm3, -66(%rax)
	vpmullw	-34(%rdi), %ymm0, %ymm0
	vpaddw	-34(%rax), %ymm0, %ymm0
	vmovdqu	%ymm0, -34(%rax)
	imulw	-2(%rdi), %r9w
	addw	%r9w, -260(%rdx,%r15)
.L356:
	subq	$258, %r8
	addq	$258, %rax
	cmpq	%r8, 144(%rsp)
	je	.L761
.L358:
	movq	168(%rsp), %rcx
	leaq	(%r15,%rax), %rdx
	movl	$19, %r9d
	subw	-516(%rdx,%rcx), %r9w
	movq	%r13, %rdx
	subq	%r8, %rdx
	cmpq	$28, %rdx
	ja	.L762
	movl	%ebx, 128(%rsp)
	leaq	-258(%rax), %rdx
.L357:
	leaq	(%r8,%rdx), %rbx
	movzwl	(%rbx,%r10), %ecx
	imull	%r9d, %ecx
	addw	%cx, (%rdx)
	addq	$2, %rdx
	cmpq	%rdx, %rax
	jne	.L357
	movl	128(%rsp), %ebx
	jmp	.L356
.L761:
	movl	240(%rsp), %eax
	movq	136(%rsp), %rcx
	subl	$112, %eax
	cmpl	$14, %eax
	jbe	.L389
	movl	%r14d, %esi
	movq	%r11, %rax
	shrl	$4, %esi
	imulq	$4128, %rsi, %rsi
	addq	%r11, %rsi
.L360:
	movzwl	(%rax), %edx
	addq	$4128, %rax
	vmovd	%edx, %xmm0
	movzwl	-3612(%rax), %edx
	vpinsrw	$1, -3870(%rax), %xmm0, %xmm0
	vmovd	%edx, %xmm5
	movzwl	-3096(%rax), %edx
	vpinsrw	$1, -3354(%rax), %xmm5, %xmm5
	vmovd	%edx, %xmm3
	movzwl	-2580(%rax), %edx
	vpinsrw	$1, -2838(%rax), %xmm3, %xmm3
	vpunpckldq	%xmm5, %xmm0, %xmm0
	vmovd	%edx, %xmm4
	movzwl	-2064(%rax), %edx
	vpinsrw	$1, -2322(%rax), %xmm4, %xmm4
	vpunpckldq	%xmm4, %xmm3, %xmm3
	vpunpcklqdq	%xmm3, %xmm0, %xmm0
	vmovd	%edx, %xmm3
	movzwl	-1548(%rax), %edx
	vpinsrw	$1, -1806(%rax), %xmm3, %xmm3
	vmovd	%edx, %xmm6
	movzwl	-1032(%rax), %edx
	vpinsrw	$1, -1290(%rax), %xmm6, %xmm6
	vmovd	%edx, %xmm4
	movzwl	-516(%rax), %edx
	vpinsrw	$1, -774(%rax), %xmm4, %xmm4
	vpunpckldq	%xmm6, %xmm3, %xmm3
	vmovd	%edx, %xmm5
	vpinsrw	$1, -258(%rax), %xmm5, %xmm5
	vpunpckldq	%xmm5, %xmm4, %xmm4
	vpunpcklqdq	%xmm4, %xmm3, %xmm3
	vinserti128	$0x1, %xmm3, %ymm0, %ymm0
	vpmulhuw	%ymm1, %ymm0, %ymm4
	vpsrlw	$4, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm3
	vpaddw	%ymm4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm3
	vpsubw	%ymm4, %ymm3, %ymm3
	vpsubw	%ymm3, %ymm0, %ymm0
	vpextrw	$0, %xmm0, -4128(%rax)
	vpextrw	$1, %xmm0, -3870(%rax)
	vpextrw	$2, %xmm0, -3612(%rax)
	vpextrw	$3, %xmm0, -3354(%rax)
	vpextrw	$4, %xmm0, -3096(%rax)
	vpextrw	$5, %xmm0, -2838(%rax)
	vpextrw	$6, %xmm0, -2580(%rax)
	vpextrw	$7, %xmm0, -2322(%rax)
	vextracti128	$0x1, %ymm0, %xmm0
	vpextrw	$0, %xmm0, -2064(%rax)
	vpextrw	$1, %xmm0, -1806(%rax)
	vpextrw	$2, %xmm0, -1548(%rax)
	vpextrw	$3, %xmm0, -1290(%rax)
	vpextrw	$4, %xmm0, -1032(%rax)
	vpextrw	$5, %xmm0, -774(%rax)
	vpextrw	$6, %xmm0, -516(%rax)
	vpextrw	$7, %xmm0, -258(%rax)
	cmpq	%rax, %rsi
	jne	.L360
	testb	$15, %r14b
	je	.L361
	movl	%r14d, %edx
	andl	$-16, %edx
	leal	(%rdx,%rbx), %eax
.L359:
	movl	192(%rsp), %edi
	leal	(%rdx,%rdi), %esi
	leal	-120(%rsi), %edi
	cmpl	$6, %edi
	jbe	.L362
	imulq	$258, %rdx, %rdx
	movl	$127, %edi
	subl	%esi, %edi
	addq	%r11, %rdx
	movzwl	(%rdx), %esi
	vmovd	%esi, %xmm0
	movzwl	516(%rdx), %esi
	vpinsrw	$1, 258(%rdx), %xmm0, %xmm0
	vmovd	%esi, %xmm5
	movzwl	1032(%rdx), %esi
	vpinsrw	$1, 774(%rdx), %xmm5, %xmm5
	vmovd	%esi, %xmm3
	movzwl	1548(%rdx), %esi
	vpinsrw	$1, 1290(%rdx), %xmm3, %xmm3
	vpunpckldq	%xmm5, %xmm0, %xmm0
	vmovd	%esi, %xmm4
	vpinsrw	$1, 1806(%rdx), %xmm4, %xmm4
	vpunpckldq	%xmm4, %xmm3, %xmm3
	vpunpcklqdq	%xmm3, %xmm0, %xmm0
	vpmulhuw	%xmm2, %xmm0, %xmm4
	vpsrlw	$4, %xmm4, %xmm4
	vpsllw	$2, %xmm4, %xmm3
	vpaddw	%xmm4, %xmm3, %xmm3
	vpsllw	$2, %xmm3, %xmm3
	vpsubw	%xmm4, %xmm3, %xmm3
	vpsubw	%xmm3, %xmm0, %xmm0
	vpextrw	$0, %xmm0, (%rdx)
	vpextrw	$1, %xmm0, 258(%rdx)
	vpextrw	$2, %xmm0, 516(%rdx)
	vpextrw	$3, %xmm0, 774(%rdx)
	vpextrw	$4, %xmm0, 1032(%rdx)
	vpextrw	$5, %xmm0, 1290(%rdx)
	vpextrw	$6, %xmm0, 1548(%rdx)
	vpextrw	$7, %xmm0, 1806(%rdx)
	testb	$7, %dil
	je	.L361
	andl	$-8, %edi
	addl	%edi, %eax
.L362:
	movslq	%eax, %rdx
	movslq	%ebx, %rsi
	movq	%rdx, %rdi
	salq	$7, %rdi
	addq	%rdx, %rdi
	addq	%rsi, %rdi
	movzwl	20032(%rsp,%rdi,2), %edx
	movl	%edx, %r8d
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %r9d
	leal	(%rdx,%r9,2), %edx
	subl	%edx, %r8d
	leal	1(%rax), %edx
	movw	%r8w, 20032(%rsp,%rdi,2)
	cmpl	$127, %eax
	je	.L361
	movslq	%edx, %rdx
	movq	%rdx, %rdi
	salq	$7, %rdi
	addq	%rdx, %rdi
	addq	%rsi, %rdi
	movzwl	20032(%rsp,%rdi,2), %edx
	movl	%edx, %r8d
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %r9d
	leal	(%rdx,%r9,2), %edx
	subl	%edx, %r8d
	leal	2(%rax), %edx
	movw	%r8w, 20032(%rsp,%rdi,2)
	cmpl	$126, %eax
	je	.L361
	movslq	%edx, %rdx
	movq	%rdx, %rdi
	salq	$7, %rdi
	addq	%rdx, %rdi
	addq	%rsi, %rdi
	movzwl	20032(%rsp,%rdi,2), %edx
	movl	%edx, %r8d
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %r9d
	leal	(%rdx,%r9,2), %edx
	subl	%edx, %r8d
	leal	3(%rax), %edx
	movw	%r8w, 20032(%rsp,%rdi,2)
	cmpl	$125, %eax
	je	.L361
	movslq	%edx, %rdx
	movq	%rdx, %rdi
	salq	$7, %rdi
	addq	%rdx, %rdi
	addq	%rsi, %rdi
	movzwl	20032(%rsp,%rdi,2), %edx
	movl	%edx, %r8d
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %r9d
	leal	(%rdx,%r9,2), %edx
	subl	%edx, %r8d
	leal	4(%rax), %edx
	movw	%r8w, 20032(%rsp,%rdi,2)
	cmpl	$124, %eax
	je	.L361
	movslq	%edx, %rdx
	movq	%rdx, %rdi
	salq	$7, %rdi
	addq	%rdx, %rdi
	addq	%rsi, %rdi
	movzwl	20032(%rsp,%rdi,2), %edx
	movl	%edx, %r8d
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %r9d
	leal	(%rdx,%r9,2), %edx
	subl	%edx, %r8d
	leal	5(%rax), %edx
	movw	%r8w, 20032(%rsp,%rdi,2)
	cmpl	$123, %eax
	je	.L361
	movslq	%edx, %rdx
	movq	%rdx, %rdi
	salq	$7, %rdi
	addq	%rdx, %rdi
	addq	%rsi, %rdi
	movzwl	20032(%rsp,%rdi,2), %edx
	movl	%edx, %r8d
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %r9d
	leal	(%rdx,%r9,2), %edx
	subl	%edx, %r8d
	leal	6(%rax), %edx
	movw	%r8w, 20032(%rsp,%rdi,2)
	cmpl	$122, %eax
	je	.L361
	movslq	%edx, %rax
	movq	%rax, %rdx
	salq	$7, %rdx
	addq	%rax, %rdx
	addq	%rsi, %rdx
	movzwl	20032(%rsp,%rdx,2), %eax
	movl	%eax, %esi
	imull	$55189, %eax, %eax
	shrl	$20, %eax
	leal	(%rax,%rax,8), %edi
	leal	(%rax,%rdi,2), %eax
	subl	%eax, %esi
	movw	%si, 20032(%rsp,%rdx,2)
.L361:
	incq	192(%rsp)
	addq	$260, %r11
	addq	$258, %r15
	addq	$258, %r10
	subq	$256, 168(%rsp)
	movq	%r12, %rsi
	movl	%ebx, %eax
	movl	%ebx, 240(%rsp)
	jmp	.L364
.L389:
	xorl	%edx, %edx
	movl	%ebx, %eax
	jmp	.L359
.L760:
	movl	248(%rsp), %edx
	testl	%edx, %edx
	je	.L763
.L366:
	movzbl	287(%rsp), %ebx
	vzeroupper
	jmp	.L380
.L763:
	xorl	%eax, %eax
	vpxor	%xmm0, %xmm0, %xmm0
	leaq	1534(%rsp), %rsi
	movl	$16510, %r15d
	movw	%ax, 1536(%rsp)
	movq	256(%rsp), %rax
	movl	$127, %r10d
	xorl	%r9d, %r9d
	vmovdqa	%ymm0, 1280(%rsp)
	movl	$128, %r8d
	leaq	33022(%rax), %r11
	vmovdqa	%ymm0, 1312(%rsp)
	vmovdqa	%ymm0, 1344(%rsp)
	movq	%r11, %rdi
	vmovdqa	%ymm0, 1376(%rsp)
	vmovdqa	%ymm0, 1408(%rsp)
	vmovdqa	%ymm0, 1440(%rsp)
	vmovdqa	%ymm0, 1472(%rsp)
	vmovdqa	%ymm0, 1504(%rsp)
	jmp	.L373
.L765:
	leal	-1(%r9), %eax
	movl	%r8d, %edx
	movl	%r9d, %ecx
	cmpl	$14, %eax
	jbe	.L391
	vmovdqu	(%rdi), %ymm0
	movl	%r9d, %eax
	shrl	$4, %eax
	vpmullw	2(%rsi), %ymm0, %ymm0
	cmpl	$1, %eax
	je	.L369
	vmovdqu	32(%rdi), %ymm1
	vpmullw	34(%rsi), %ymm1, %ymm1
	vpaddw	%ymm1, %ymm0, %ymm0
	cmpl	$2, %eax
	je	.L369
	vmovdqu	64(%rdi), %ymm1
	vpmullw	66(%rsi), %ymm1, %ymm1
	vpaddw	%ymm1, %ymm0, %ymm0
	cmpl	$3, %eax
	je	.L369
	vmovdqu	96(%rdi), %ymm1
	vpmullw	98(%rsi), %ymm1, %ymm1
	vpaddw	%ymm1, %ymm0, %ymm0
	cmpl	$4, %eax
	je	.L369
	vmovdqu	128(%rdi), %ymm1
	vpmullw	130(%rsi), %ymm1, %ymm1
	vpaddw	%ymm1, %ymm0, %ymm0
	cmpl	$5, %eax
	je	.L369
	vmovdqu	160(%rdi), %ymm1
	vpmullw	162(%rsi), %ymm1, %ymm1
	vpaddw	%ymm1, %ymm0, %ymm0
	cmpl	$7, %eax
	jne	.L369
	vmovdqu	192(%rdi), %ymm1
	vpmullw	194(%rsi), %ymm1, %ymm1
	vpaddw	%ymm1, %ymm0, %ymm0
.L369:
	vextracti128	$0x1, %ymm0, %xmm1
	vpaddw	%xmm0, %xmm1, %xmm1
	vpsrldq	$8, %xmm1, %xmm0
	vpaddw	%xmm0, %xmm1, %xmm0
	vpsrldq	$4, %xmm0, %xmm2
	vpaddw	%xmm2, %xmm0, %xmm0
	vpsrldq	$2, %xmm0, %xmm2
	vpaddw	%xmm2, %xmm0, %xmm0
	vpextrw	$0, %xmm0, %eax
	testb	$15, %cl
	je	.L370
	andl	$-16, %ecx
	leal	(%r8,%rcx), %edx
.L368:
	leal	(%rcx,%r10), %r12d
	leal	-120(%r12), %ebx
	cmpl	$6, %ebx
	jbe	.L371
	leaq	1(%rcx,%r10), %rax
	leaq	1(%rcx,%r15), %rcx
	movl	$127, %ebx
	vmovdqu	20032(%rsp,%rcx,2), %xmm0
	subl	%r12d, %ebx
	vpmullw	1280(%rsp,%rax,2), %xmm0, %xmm0
	vpaddw	%xmm1, %xmm0, %xmm0
	vpsrldq	$8, %xmm0, %xmm1
	vpaddw	%xmm1, %xmm0, %xmm0
	vpsrldq	$4, %xmm0, %xmm1
	vpaddw	%xmm1, %xmm0, %xmm0
	vpsrldq	$2, %xmm0, %xmm1
	vpaddw	%xmm1, %xmm0, %xmm0
	vpextrw	$0, %xmm0, %eax
	testb	$7, %bl
	je	.L370
	andl	$-8, %ebx
	addl	%ebx, %edx
.L371:
	movslq	%r10d, %r12
	movslq	%edx, %rbx
	movq	%r12, %rcx
	salq	$7, %rcx
	addq	%r12, %rcx
	leaq	(%rcx,%rbx), %r12
	movzwl	20032(%rsp,%r12,2), %r12d
	imulw	1280(%rsp,%rbx,2), %r12w
	leal	1(%rdx), %ebx
	addl	%r12d, %eax
	cmpl	$127, %edx
	je	.L370
	movslq	%ebx, %rbx
	leaq	(%rcx,%rbx), %r12
	movzwl	20032(%rsp,%r12,2), %r12d
	imulw	1280(%rsp,%rbx,2), %r12w
	leal	2(%rdx), %ebx
	addl	%r12d, %eax
	cmpl	$126, %edx
	je	.L370
	movslq	%ebx, %rbx
	leaq	(%rcx,%rbx), %r12
	movzwl	20032(%rsp,%r12,2), %r12d
	imulw	1280(%rsp,%rbx,2), %r12w
	leal	3(%rdx), %ebx
	addl	%r12d, %eax
	cmpl	$125, %edx
	je	.L370
	movslq	%ebx, %rbx
	leaq	(%rcx,%rbx), %r12
	movzwl	20032(%rsp,%r12,2), %r12d
	imulw	1280(%rsp,%rbx,2), %r12w
	leal	4(%rdx), %ebx
	addl	%r12d, %eax
	cmpl	$124, %edx
	je	.L370
	movslq	%ebx, %rbx
	leaq	(%rcx,%rbx), %r12
	movzwl	1280(%rsp,%rbx,2), %ebx
	imulw	20032(%rsp,%r12,2), %bx
	addl	%ebx, %eax
	leal	5(%rdx), %ebx
	cmpl	$123, %edx
	je	.L370
	movslq	%ebx, %rbx
	leaq	(%rcx,%rbx), %r12
	movzwl	1280(%rsp,%rbx,2), %ebx
	imulw	20032(%rsp,%r12,2), %bx
	addl	%ebx, %eax
	leal	6(%rdx), %ebx
	cmpl	$122, %edx
	je	.L370
	movslq	%ebx, %rdx
	addq	%rdx, %rcx
	movzwl	1280(%rsp,%rdx,2), %edx
	imulw	20032(%rsp,%rcx,2), %dx
	addl	%edx, %eax
.L370:
	movzwl	%ax, %edx
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %ecx
	leal	(%rdx,%rcx,2), %edx
	subl	%edx, %eax
	movzwl	%ax, %eax
.L367:
	movzwl	(%r11), %edx
	incq	%r9
	decq	%r10
	subq	$258, %r11
	subq	$2, %rsi
	subq	$260, %rdi
	subq	$130, %r15
	addl	$19, %edx
	subl	%eax, %edx
	movslq	%edx, %rax
	movl	%edx, %ecx
	imulq	$1808407283, %rax, %rax
	sarl	$31, %ecx
	sarq	$35, %rax
	subl	%ecx, %eax
	leal	(%rax,%rax,8), %ecx
	leal	(%rax,%rcx,2), %eax
	subl	%eax, %edx
	movw	%dx, 2(%rsi)
	decl	%r8d
	je	.L764
.L373:
	cmpl	$128, %r8d
	jne	.L765
	xorl	%eax, %eax
	jmp	.L367
.L391:
	xorl	%ecx, %ecx
	vpxor	%xmm1, %xmm1, %xmm1
	xorl	%eax, %eax
	jmp	.L368
.L764:
	vpcmpeqd	%ymm0, %ymm0, %ymm0
	movq	184(%rsp), %rbx
	xorl	%esi, %esi
	movl	$1440, %edx
	vpsrlw	$8, %ymm0, %ymm0
	vpand	1312(%rsp), %ymm0, %ymm2
	vpand	1280(%rsp), %ymm0, %ymm1
	movq	%rbx, %rdi
	vpackuswb	%ymm2, %ymm1, %ymm1
	vpand	1376(%rsp), %ymm0, %ymm2
	vpermq	$216, %ymm1, %ymm1
	vmovdqu	%ymm1, 125424(%rsp)
	vpand	1344(%rsp), %ymm0, %ymm1
	vpackuswb	%ymm2, %ymm1, %ymm1
	vpand	1440(%rsp), %ymm0, %ymm2
	vpermq	$216, %ymm1, %ymm1
	vmovdqu	%ymm1, 125456(%rsp)
	vpand	1408(%rsp), %ymm0, %ymm1
	vpackuswb	%ymm2, %ymm1, %ymm1
	vpermq	$216, %ymm1, %ymm1
	vmovdqu	%ymm1, 125488(%rsp)
	vpand	1472(%rsp), %ymm0, %ymm1
	vpand	1504(%rsp), %ymm0, %ymm0
	vpackuswb	%ymm0, %ymm1, %ymm0
	vpermq	$216, %ymm0, %ymm0
	vmovdqu	%ymm0, 125520(%rsp)
	vzeroupper
	call	memset@PLT
	movq	224(%rsp), %rax
	movq	56(%rsp), %r9
	vmovdqa	.LC67(%rip), %ymm14
	movq	%rbx, %rcx
	movq	%rbx, %rdx
	xorl	%esi, %esi
	leaq	256(%rax), %rdi
.L374:
	movq	224(%rsp), %rax
	movq	%r9, %r8
.L375:
	vmovdqa	(%rax), %ymm0
	vmovdqu	518400(%r8), %ymm3
	addq	$64, %rax
	addq	$64, %r8
	vmovdqa	-32(%rax), %ymm2
	vpshufb	.LC64(%rip), %ymm3, %ymm4
	vpermq	$0, %ymm0, %ymm1
	vpshufb	.LC65(%rip), %ymm3, %ymm5
	vpmullw	%ymm4, %ymm1, %ymm1
	vpermq	$85, %ymm0, %ymm4
	vpmullw	%ymm5, %ymm4, %ymm4
	vpshufb	.LC66(%rip), %ymm3, %ymm5
	vpshufb	%ymm14, %ymm3, %ymm3
	vpaddw	%ymm4, %ymm1, %ymm1
	vpermq	$170, %ymm0, %ymm4
	vpermq	$255, %ymm0, %ymm0
	vpmullw	%ymm5, %ymm4, %ymm4
	vpmullw	%ymm3, %ymm0, %ymm0
	vpaddw	(%rdx), %ymm1, %ymm1
	vmovdqu	518368(%r8), %ymm3
	vpermq	$85, %ymm2, %ymm5
	vpaddw	%ymm0, %ymm4, %ymm0
	vpshufb	.LC64(%rip), %ymm3, %ymm4
	vpaddw	%ymm0, %ymm1, %ymm1
	vpermq	$0, %ymm2, %ymm0
	vpmullw	%ymm4, %ymm0, %ymm0
	vpshufb	.LC65(%rip), %ymm3, %ymm4
	vpmullw	%ymm5, %ymm4, %ymm4
	vpaddw	%ymm4, %ymm0, %ymm0
	vpshufb	.LC66(%rip), %ymm3, %ymm4
	vpshufb	%ymm14, %ymm3, %ymm3
	vpaddw	%ymm1, %ymm0, %ymm0
	vpermq	$170, %ymm2, %ymm1
	vpmullw	%ymm4, %ymm1, %ymm4
	vpermq	$255, %ymm2, %ymm1
	vpmullw	%ymm3, %ymm1, %ymm1
	vpaddw	%ymm1, %ymm4, %ymm1
	vpaddw	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, (%rdx)
	cmpq	%rax, %rdi
	jne	.L375
	addq	$8, %rsi
	addq	$256, %r9
	addq	$32, %rdx
	cmpq	$296, %rsi
	jne	.L374
	movl	$-678045803, %edx
	movq	232(%rsp), %rax
	vpcmpeqd	%ymm4, %ymm4, %ymm4
	vpxor	%xmm5, %xmm5, %xmm5
	vmovd	%edx, %xmm7
	vpsrlw	$8, %ymm4, %ymm4
	movl	$1245203, %edx
	vmovd	%edx, %xmm6
	leaq	576(%rax), %rsi
	vpbroadcastd	%xmm7, %ymm7
	movl	$1808407283, %edx
	vmovd	%edx, %xmm3
	vpbroadcastd	%xmm6, %ymm6
	vpbroadcastd	%xmm3, %ymm3
.L377:
	vmovdqa	(%rcx), %ymm9
	vmovdqa	(%rax), %ymm0
	addq	$32, %rax
	addq	$64, %rcx
	vmovdqa	-32(%rcx), %ymm8
	vpmulhuw	%ymm7, %ymm9, %ymm10
	vpmovzxbw	%xmm0, %ymm2
	vpaddw	%ymm6, %ymm9, %ymm9
	vpsrlw	$4, %ymm10, %ymm10
	vpsllw	$2, %ymm10, %ymm1
	vpaddw	%ymm10, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm10, %ymm1, %ymm1
	vpsubw	%ymm1, %ymm2, %ymm2
	vextracti128	$0x1, %ymm0, %xmm1
	vpaddw	%ymm9, %ymm2, %ymm2
	vpmulhuw	%ymm7, %ymm8, %ymm9
	vpmovzxbw	%xmm1, %ymm1
	vpaddw	%ymm6, %ymm8, %ymm8
	vpsrlw	$4, %ymm9, %ymm9
	vpsllw	$2, %ymm9, %ymm0
	vpaddw	%ymm9, %ymm0, %ymm0
	vpsllw	$2, %ymm0, %ymm0
	vpsubw	%ymm9, %ymm0, %ymm0
	vpmovzxwd	%xmm2, %ymm9
	vpmuldq	%ymm3, %ymm9, %ymm10
	vpsubw	%ymm0, %ymm1, %ymm1
	vextracti128	$0x1, %ymm2, %xmm0
	vpsrlq	$32, %ymm9, %ymm2
	vpmovzxwd	%xmm0, %ymm0
	vpaddw	%ymm8, %ymm1, %ymm1
	vpmuldq	%ymm3, %ymm2, %ymm2
	vpmovzxwd	%xmm1, %ymm8
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxwd	%xmm1, %ymm1
	vpshufd	$245, %ymm10, %ymm10
	vpblendd	$85, %ymm10, %ymm2, %ymm2
	vpsrad	$3, %ymm2, %ymm2
	vpslld	$2, %ymm2, %ymm10
	vpaddd	%ymm2, %ymm10, %ymm10
	vpslld	$2, %ymm10, %ymm10
	vpsubd	%ymm2, %ymm10, %ymm2
	vpmuldq	%ymm3, %ymm0, %ymm10
	vpsubd	%ymm2, %ymm9, %ymm2
	vpsrlq	$32, %ymm0, %ymm9
	vpmuldq	%ymm3, %ymm9, %ymm9
	vpblendw	$85, %ymm2, %ymm5, %ymm2
	vpshufd	$245, %ymm10, %ymm10
	vpblendd	$85, %ymm10, %ymm9, %ymm9
	vpsrad	$3, %ymm9, %ymm9
	vpslld	$2, %ymm9, %ymm10
	vpaddd	%ymm9, %ymm10, %ymm10
	vpslld	$2, %ymm10, %ymm10
	vpsubd	%ymm9, %ymm10, %ymm9
	vpsubd	%ymm9, %ymm0, %ymm0
	vpmuldq	%ymm3, %ymm8, %ymm9
	vpblendw	$85, %ymm0, %ymm5, %ymm0
	vpackusdw	%ymm0, %ymm2, %ymm0
	vpsrlq	$32, %ymm8, %ymm2
	vpmuldq	%ymm3, %ymm2, %ymm2
	vpermq	$216, %ymm0, %ymm0
	vpand	%ymm0, %ymm4, %ymm0
	vpshufd	$245, %ymm9, %ymm9
	vpblendd	$85, %ymm9, %ymm2, %ymm2
	vpsrad	$3, %ymm2, %ymm2
	vpslld	$2, %ymm2, %ymm9
	vpaddd	%ymm2, %ymm9, %ymm9
	vpslld	$2, %ymm9, %ymm9
	vpsubd	%ymm2, %ymm9, %ymm2
	vpmuldq	%ymm3, %ymm1, %ymm9
	vpsubd	%ymm2, %ymm8, %ymm2
	vpsrlq	$32, %ymm1, %ymm8
	vpmuldq	%ymm3, %ymm8, %ymm8
	vpshufd	$245, %ymm9, %ymm9
	vpblendd	$85, %ymm9, %ymm8, %ymm8
	vpsrad	$3, %ymm8, %ymm8
	vpslld	$2, %ymm8, %ymm9
	vpaddd	%ymm8, %ymm9, %ymm9
	vpslld	$2, %ymm9, %ymm9
	vpsubd	%ymm8, %ymm9, %ymm8
	vpsubd	%ymm8, %ymm1, %ymm8
	vpblendw	$85, %ymm2, %ymm5, %ymm1
	vpblendw	$85, %ymm8, %ymm5, %ymm2
	vpackusdw	%ymm2, %ymm1, %ymm1
	vpermq	$216, %ymm1, %ymm1
	vpand	%ymm1, %ymm4, %ymm1
	vpackuswb	%ymm1, %ymm0, %ymm0
	vpermq	$216, %ymm0, %ymm0
	vmovdqa	%ymm0, -32(%rax)
	cmpq	%rsi, %rax
	jne	.L377
	movzwl	2720(%rsp), %eax
	movzbl	125408(%rsp), %edx
	imull	$55189, %eax, %eax
	shrl	$20, %eax
	leal	(%rax,%rax,8), %ecx
	leal	(%rax,%rcx,2), %ecx
	movzwl	2720(%rsp), %eax
	subl	%ecx, %eax
	movzwl	%ax, %eax
	leal	19(%rax,%rdx), %eax
	movslq	%eax, %rdx
	imulq	$1808407283, %rdx, %rdx
	shrq	$35, %rdx
	leal	(%rdx,%rdx,8), %ecx
	leal	(%rdx,%rcx,2), %edx
	subl	%edx, %eax
	movzwl	2722(%rsp), %edx
	vmovd	%eax, %xmm0
	movl	%edx, %ecx
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %esi
	leal	(%rdx,%rsi,2), %esi
	subl	%esi, %ecx
	movzwl	%cx, %edx
	movzbl	125409(%rsp), %ecx
	leal	19(%rdx,%rcx), %ebx
	movslq	%ebx, %rdx
	imulq	$1808407283, %rdx, %rdx
	shrq	$35, %rdx
	leal	(%rdx,%rdx,8), %ecx
	leal	(%rdx,%rcx,2), %edx
	subl	%edx, %ebx
	movzwl	2724(%rsp), %edx
	vpinsrb	$1, %ebx, %xmm0, %xmm0
	movl	%edx, %ecx
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %esi
	leal	(%rdx,%rsi,2), %esi
	subl	%esi, %ecx
	movzwl	%cx, %edx
	movzbl	125410(%rsp), %ecx
	leal	19(%rdx,%rcx), %ecx
	movslq	%ecx, %rdx
	imulq	$1808407283, %rdx, %rdx
	shrq	$35, %rdx
	leal	(%rdx,%rdx,8), %esi
	leal	(%rdx,%rsi,2), %edx
	subl	%edx, %ecx
	movzwl	2726(%rsp), %edx
	vmovd	%ecx, %xmm7
	movl	%edx, %ecx
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %esi
	leal	(%rdx,%rsi,2), %esi
	subl	%esi, %ecx
	movzwl	%cx, %edx
	movzbl	125411(%rsp), %ecx
	leal	19(%rdx,%rcx), %r11d
	movslq	%r11d, %rdx
	imulq	$1808407283, %rdx, %rdx
	shrq	$35, %rdx
	leal	(%rdx,%rdx,8), %ecx
	leal	(%rdx,%rcx,2), %edx
	subl	%edx, %r11d
	movzwl	2728(%rsp), %edx
	vpinsrb	$1, %r11d, %xmm7, %xmm7
	movl	%edx, %ecx
	imull	$55189, %edx, %edx
	vpunpcklwd	%xmm7, %xmm0, %xmm0
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %esi
	leal	(%rdx,%rsi,2), %esi
	subl	%esi, %ecx
	movzwl	%cx, %edx
	movzbl	125412(%rsp), %ecx
	leal	19(%rdx,%rcx), %ecx
	movslq	%ecx, %rdx
	imulq	$1808407283, %rdx, %rdx
	shrq	$35, %rdx
	leal	(%rdx,%rdx,8), %esi
	leal	(%rdx,%rsi,2), %edx
	subl	%edx, %ecx
	movzwl	2730(%rsp), %edx
	vmovd	%ecx, %xmm3
	movl	%edx, %ecx
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %esi
	leal	(%rdx,%rsi,2), %esi
	subl	%esi, %ecx
	movzwl	%cx, %edx
	movzbl	125413(%rsp), %ecx
	leal	19(%rdx,%rcx), %r10d
	movslq	%r10d, %rdx
	imulq	$1808407283, %rdx, %rdx
	shrq	$35, %rdx
	leal	(%rdx,%rdx,8), %ecx
	leal	(%rdx,%rcx,2), %edx
	subl	%edx, %r10d
	movzwl	2732(%rsp), %edx
	vpinsrb	$1, %r10d, %xmm3, %xmm3
	movl	%edx, %ecx
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %esi
	leal	(%rdx,%rsi,2), %esi
	subl	%esi, %ecx
	movzwl	%cx, %edx
	movzbl	125414(%rsp), %ecx
	leal	19(%rdx,%rcx), %ecx
	movslq	%ecx, %rdx
	imulq	$1808407283, %rdx, %rdx
	shrq	$35, %rdx
	leal	(%rdx,%rdx,8), %esi
	leal	(%rdx,%rsi,2), %edx
	subl	%edx, %ecx
	movzwl	2734(%rsp), %edx
	vmovd	%ecx, %xmm6
	movl	%edx, %ecx
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %esi
	leal	(%rdx,%rsi,2), %edx
	subl	%edx, %ecx
	movzwl	%cx, %edx
	movzbl	125415(%rsp), %ecx
	leal	19(%rdx,%rcx), %r9d
	movslq	%r9d, %rdx
	imulq	$1808407283, %rdx, %rdx
	shrq	$35, %rdx
	leal	(%rdx,%rdx,8), %ecx
	leal	(%rdx,%rcx,2), %edx
	subl	%edx, %r9d
	movzwl	2736(%rsp), %edx
	vpinsrb	$1, %r9d, %xmm6, %xmm6
	movl	%edx, %esi
	imull	$55189, %edx, %edx
	vpunpcklwd	%xmm6, %xmm3, %xmm3
	vpunpckldq	%xmm3, %xmm0, %xmm0
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %ecx
	leal	(%rdx,%rcx,2), %edx
	movzbl	125416(%rsp), %ecx
	subl	%edx, %esi
	movzwl	%si, %edx
	leal	19(%rdx,%rcx), %ecx
	movslq	%ecx, %rdx
	imulq	$1808407283, %rdx, %rdx
	shrq	$35, %rdx
	leal	(%rdx,%rdx,8), %esi
	leal	(%rdx,%rsi,2), %edx
	subl	%edx, %ecx
	movzwl	2738(%rsp), %edx
	movl	%ecx, 192(%rsp)
	movl	%edx, %esi
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %ecx
	leal	(%rdx,%rcx,2), %edx
	movzbl	125417(%rsp), %ecx
	subl	%edx, %esi
	movzwl	%si, %edx
	leal	19(%rdx,%rcx), %r8d
	movslq	%r8d, %rdx
	imulq	$1808407283, %rdx, %rdx
	shrq	$35, %rdx
	leal	(%rdx,%rdx,8), %ecx
	leal	(%rdx,%rcx,2), %edx
	subl	%edx, %r8d
	movzwl	2740(%rsp), %edx
	movl	%edx, %esi
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %ecx
	leal	(%rdx,%rcx,2), %edx
	movzbl	125418(%rsp), %ecx
	subl	%edx, %esi
	movzwl	%si, %edx
	leal	19(%rdx,%rcx), %ecx
	movslq	%ecx, %rdx
	imulq	$1808407283, %rdx, %rdx
	shrq	$35, %rdx
	leal	(%rdx,%rdx,8), %esi
	leal	(%rdx,%rsi,2), %edx
	subl	%edx, %ecx
	movzwl	2742(%rsp), %edx
	movl	%ecx, 240(%rsp)
	movl	%edx, %esi
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %ecx
	leal	(%rdx,%rcx,2), %edx
	movzbl	125419(%rsp), %ecx
	subl	%edx, %esi
	movzwl	%si, %edx
	leal	19(%rdx,%rcx), %edi
	movslq	%edi, %rdx
	imulq	$1808407283, %rdx, %rdx
	shrq	$35, %rdx
	leal	(%rdx,%rdx,8), %ecx
	leal	(%rdx,%rcx,2), %edx
	subl	%edx, %edi
	movzwl	2744(%rsp), %edx
	movl	%edx, %esi
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %ecx
	leal	(%rdx,%rcx,2), %edx
	movzbl	125420(%rsp), %ecx
	subl	%edx, %esi
	movzwl	%si, %edx
	leal	19(%rdx,%rcx), %ecx
	movslq	%ecx, %rdx
	imulq	$1808407283, %rdx, %rdx
	shrq	$35, %rdx
	leal	(%rdx,%rdx,8), %esi
	leal	(%rdx,%rsi,2), %edx
	subl	%edx, %ecx
	movzwl	2746(%rsp), %edx
	movl	%ecx, 224(%rsp)
	movl	%edx, %esi
	imull	$55189, %edx, %edx
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %ecx
	leal	(%rdx,%rcx,2), %edx
	movzbl	125421(%rsp), %ecx
	subl	%edx, %esi
	movzwl	%si, %edx
	leal	19(%rdx,%rcx), %esi
	movslq	%esi, %rdx
	imulq	$1808407283, %rdx, %rdx
	shrq	$35, %rdx
	leal	(%rdx,%rdx,8), %ecx
	leal	(%rdx,%rcx,2), %edx
	subl	%edx, %esi
	movzwl	2748(%rsp), %edx
	vmovd	192(%rsp), %xmm1
	vmovd	240(%rsp), %xmm5
	vpinsrb	$1, %r8d, %xmm1, %xmm1
	vpinsrb	$1, %edi, %xmm5, %xmm5
	vmovd	224(%rsp), %xmm2
	vpinsrb	$1, %esi, %xmm2, %xmm2
	imull	$55189, %edx, %edx
	vpunpcklwd	%xmm5, %xmm1, %xmm1
	movq	232(%rsp), %rbx
	leaq	1(%rbx), %rax
	leaq	721(%rbx), %rsi
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %ecx
	leal	(%rdx,%rcx,2), %edx
	movzwl	2748(%rsp), %ecx
	subl	%edx, %ecx
	movzwl	%cx, %edx
	movzbl	125422(%rsp), %ecx
	leal	19(%rdx,%rcx), %ecx
	movslq	%ecx, %rdx
	imulq	$1808407283, %rdx, %rdx
	shrq	$35, %rdx
	leal	(%rdx,%rdx,8), %r12d
	leal	(%rdx,%r12,2), %edx
	subl	%edx, %ecx
	movzwl	2750(%rsp), %edx
	movl	%ecx, 184(%rsp)
	imull	$55189, %edx, %edx
	vmovd	184(%rsp), %xmm4
	shrl	$20, %edx
	leal	(%rdx,%rdx,8), %ecx
	leal	(%rdx,%rcx,2), %edx
	movzwl	2750(%rsp), %ecx
	subl	%edx, %ecx
	movzwl	%cx, %edx
	movzbl	125423(%rsp), %ecx
	leal	19(%rdx,%rcx), %ecx
	movslq	%ecx, %rdx
	imulq	$1808407283, %rdx, %rdx
	shrq	$35, %rdx
	leal	(%rdx,%rdx,8), %r12d
	leal	(%rdx,%r12,2), %edx
	subl	%edx, %ecx
	vpinsrb	$1, %ecx, %xmm4, %xmm4
	xorl	%ecx, %ecx
	vpunpcklwd	%xmm4, %xmm2, %xmm2
	vpunpckldq	%xmm2, %xmm1, %xmm1
	vpunpcklqdq	%xmm1, %xmm0, %xmm0
	vmovdqa	%xmm0, 125408(%rsp)
.L378:
	movzbl	11(%rax), %ebx
	cmpb	%bl, 2(%rax)
	movzbl	8(%rax), %ebx
	sete	%dl
	cmpb	%bl, 5(%rax)
	movzbl	12(%rax), %ebx
	sete	%dil
	andl	%edi, %edx
	cmpb	%bl, 6(%rax)
	movzbl	13(%rax), %ebx
	sete	%dil
	andl	%edi, %edx
	cmpb	%bl, 10(%rax)
	movzbl	3(%rax), %ebx
	sete	%dil
	andl	%edi, %edx
	cmpb	%bl, (%rax)
	movzbl	7(%rax), %ebx
	sete	%dil
	cmpb	%bl, 1(%rax)
	sete	%r8b
	addq	$16, %rax
	andl	%r8d, %edi
	andl	%edi, %edx
	movzbl	%dl, %edx
	addl	%edx, %ecx
	cmpq	%rsi, %rax
	jne	.L378
	testl	%ecx, %ecx
	jg	.L366
	movq	152(%rsp), %r15
	movq	24(%rsp), %r13
	xorl	%edi, %edi
	xorl	%ecx, %ecx
	movl	$27, %esi
	movabsq	$16983563041, %rbx
	movabsq	$322687697779, %r11
	movabsq	$6131066257801, %r10
	movabsq	$116490258898219, %r9
	movabsq	$2213314919066161, %r14
	jmp	.L379
.L766:
	movq	%r15, %rcx
	movb	%dl, (%r15,%rdi)
	movb	%dh, 1(%rcx,%rdi)
	movq	%rdx, %rcx
	shrq	$16, %rcx
	movb	%cl, 2(%r15,%rdi)
	movq	%rdx, %rcx
	shrq	$24, %rcx
	movb	%cl, 3(%r15,%rdi)
	movq	%rdx, %rcx
	shrq	$32, %rcx
	movb	%cl, 4(%r15,%rdi)
	movq	%rdx, %rcx
	shrq	$40, %rcx
	movb	%cl, 5(%r15,%rdi)
	movq	%rdx, %rcx
	shrq	$56, %rdx
	shrq	$48, %rcx
	movb	%dl, 7(%r15,%rdi)
	movb	%cl, 6(%r15,%rdi)
	addq	$8, %rdi
	cmpq	$720, %rax
	je	.L382
	movq	%rax, %rcx
.L379:
	movzbl	124832(%rsp,%rcx), %edx
	movl	%edx, %eax
	mulb	%sil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r8d
	leal	(%rax,%r8,2), %eax
	subl	%eax, %edx
	leaq	1(%rcx), %rax
	movzbl	%dl, %edx
	cmpq	$719, %rcx
	je	.L381
	movzbl	124832(%rsp,%rax), %r8d
	movl	%r8d, %eax
	mulb	%sil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r12d
	leal	(%rax,%r12,2), %r12d
	movl	%r8d, %eax
	subl	%r12d, %eax
	movzbl	%al, %eax
	leaq	(%rax,%rax,8), %r8
	leaq	(%rax,%r8,2), %rax
	addq	%rax, %rdx
	leaq	2(%rcx), %rax
	cmpq	$718, %rcx
	je	.L381
	movzbl	124832(%rsp,%rax), %r8d
	movl	%r8d, %eax
	mulb	%sil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r12d
	leal	(%rax,%r12,2), %r12d
	movl	%r8d, %eax
	subl	%r12d, %eax
	movzbl	%al, %eax
	imulq	$361, %rax, %rax
	addq	%rax, %rdx
	leaq	3(%rcx), %rax
	cmpq	$717, %rcx
	je	.L381
	movzbl	124832(%rsp,%rax), %r8d
	movl	%r8d, %eax
	mulb	%sil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r12d
	leal	(%rax,%r12,2), %r12d
	movl	%r8d, %eax
	subl	%r12d, %eax
	movzbl	%al, %eax
	imulq	$6859, %rax, %rax
	addq	%rax, %rdx
	leaq	4(%rcx), %rax
	cmpq	$716, %rcx
	je	.L381
	movzbl	124832(%rsp,%rax), %r8d
	movl	%r8d, %eax
	mulb	%sil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r12d
	leal	(%rax,%r12,2), %r12d
	movl	%r8d, %eax
	subl	%r12d, %eax
	movzbl	%al, %eax
	imulq	$130321, %rax, %rax
	addq	%rax, %rdx
	leaq	5(%rcx), %rax
	cmpq	$715, %rcx
	je	.L381
	movzbl	124832(%rsp,%rax), %r8d
	movl	%r8d, %eax
	mulb	%sil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r12d
	leal	(%rax,%r12,2), %r12d
	movl	%r8d, %eax
	subl	%r12d, %eax
	movzbl	%al, %eax
	imulq	$2476099, %rax, %rax
	addq	%rax, %rdx
	leaq	6(%rcx), %rax
	cmpq	$714, %rcx
	je	.L381
	movzbl	124832(%rsp,%rax), %r8d
	movl	%r8d, %eax
	mulb	%sil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r12d
	leal	(%rax,%r12,2), %r12d
	movl	%r8d, %eax
	subl	%r12d, %eax
	movzbl	%al, %eax
	imulq	$47045881, %rax, %rax
	addq	%rax, %rdx
	leaq	7(%rcx), %rax
	cmpq	$713, %rcx
	je	.L381
	movzbl	124832(%rsp,%rax), %r8d
	movl	%r8d, %eax
	mulb	%sil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r12d
	leal	(%rax,%r12,2), %r12d
	movl	%r8d, %eax
	subl	%r12d, %eax
	movzbl	%al, %eax
	imulq	$893871739, %rax, %rax
	addq	%rax, %rdx
	leaq	8(%rcx), %rax
	cmpq	$712, %rcx
	je	.L381
	movzbl	124832(%rsp,%rax), %r8d
	movl	%r8d, %eax
	mulb	%sil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r12d
	leal	(%rax,%r12,2), %r12d
	movl	%r8d, %eax
	subl	%r12d, %eax
	movzbl	%al, %eax
	imulq	%rbx, %rax
	addq	%rax, %rdx
	leaq	9(%rcx), %rax
	cmpq	$711, %rcx
	je	.L381
	movzbl	124832(%rsp,%rax), %r8d
	movl	%r8d, %eax
	mulb	%sil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r12d
	leal	(%rax,%r12,2), %r12d
	movl	%r8d, %eax
	subl	%r12d, %eax
	movzbl	%al, %eax
	imulq	%r11, %rax
	addq	%rax, %rdx
	leaq	10(%rcx), %rax
	cmpq	$710, %rcx
	je	.L381
	movzbl	124832(%rsp,%rax), %r8d
	movl	%r8d, %eax
	mulb	%sil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r12d
	leal	(%rax,%r12,2), %r12d
	movl	%r8d, %eax
	subl	%r12d, %eax
	movzbl	%al, %eax
	imulq	%r10, %rax
	addq	%rax, %rdx
	leaq	11(%rcx), %rax
	cmpq	$709, %rcx
	je	.L381
	movzbl	124832(%rsp,%rax), %r8d
	movl	%r8d, %eax
	mulb	%sil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r12d
	leal	(%rax,%r12,2), %r12d
	movl	%r8d, %eax
	subl	%r12d, %eax
	movzbl	%al, %eax
	imulq	%r9, %rax
	addq	%rax, %rdx
	leaq	12(%rcx), %rax
	cmpq	$708, %rcx
	je	.L381
	movzbl	124832(%rsp,%rax), %r8d
	movl	%r8d, %eax
	mulb	%sil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r12d
	leal	(%rax,%r12,2), %r12d
	movl	%r8d, %eax
	subl	%r12d, %eax
	movzbl	%al, %eax
	imulq	%r14, %rax
	addq	%rax, %rdx
	leaq	13(%rcx), %rax
	cmpq	$707, %rcx
	je	.L381
	movzbl	124832(%rsp,%rax), %r8d
	movl	%r8d, %eax
	mulb	%sil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r12d
	leal	(%rax,%r12,2), %r12d
	movl	%r8d, %eax
	movabsq	$42052983462257059, %r8
	subl	%r12d, %eax
	movzbl	%al, %eax
	imulq	%r8, %rax
	addq	%rax, %rdx
	leaq	14(%rcx), %rax
	cmpq	$706, %rcx
	je	.L381
	movzbl	124832(%rsp,%rax), %r8d
	movl	%r8d, %eax
	mulb	%sil
	shrw	$9, %ax
	leal	(%rax,%rax,8), %r12d
	leal	(%rax,%r12,2), %r12d
	movl	%r8d, %eax
	movabsq	$799006685782884121, %r8
	subl	%r12d, %eax
	movzbl	%al, %eax
	imulq	%r8, %rax
	addq	%rax, %rdx
	leaq	15(%rcx), %rax
.L381:
	cmpq	$384, %rdi
	jne	.L766
.L382:
	vmovdqu	0(%r13), %xmm0
	vmovdqu	%xmm0, 384(%r15)
	jmp	.L290
.L758:
	vzeroupper
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE18:
	.size	_snova_37_8_19_4_SNOVA_OPT_sign, .-_snova_37_8_19_4_SNOVA_OPT_sign
	.p2align 4
	.globl	_snova_37_8_19_4_SNOVA_OPT_pk_expand
	.type	_snova_37_8_19_4_SNOVA_OPT_pk_expand, @function
_snova_37_8_19_4_SNOVA_OPT_pk_expand:
.LFB19:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movl	$16, %edx
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%r15
	pushq	%r14
	pushq	%r13
	.cfi_offset 15, -24
	.cfi_offset 14, -32
	.cfi_offset 13, -40
	movq	%rdi, %r13
	pushq	%r12
	pushq	%rbx
	andq	$-32, %rsp
	subq	$357024, %rsp
	.cfi_offset 12, -48
	.cfi_offset 3, -56
	movq	%fs:40, %r14
	movq	%r14, 357016(%rsp)
	movq	%rsi, %r14
	vmovdqu	(%r14), %xmm0
	movq	%r14, %rsi
	vmovdqu	%xmm0, 524800(%rdi)
	leaq	400(%rsp), %rdi
	call	snova_pk_expander_init@PLT
	leaq	400(%rsp), %rdx
	movl	$172160, %esi
	leaq	12672(%rsp), %rdi
	call	snova_pk_expander@PLT
	movl	$2139062143, %ecx
	leaq	184832(%rsp), %rdx
	vmovdqa	.LC5(%rip), %xmm4
	vmovd	%ecx, %xmm3
	leaq	12672(%rsp), %rax
	movq	%rdx, %rsi
	movq	%rdx, %rdi
	vpbroadcastd	%xmm3, %ymm3
.L768:
	vmovdqa	(%rax), %ymm2
	vpmovzxbw	%xmm4, %ymm5
	addq	$32, %rax
	addq	$32, %rdx
	vextracti128	$0x1, %ymm2, %xmm1
	vpmovzxbw	%xmm2, %ymm0
	vpmovzxbw	%xmm1, %ymm1
	vpmullw	%ymm5, %ymm0, %ymm0
	vpmullw	%ymm5, %ymm1, %ymm1
	vpsrlw	$8, %ymm0, %ymm0
	vpsrlw	$8, %ymm1, %ymm1
	vpackuswb	%ymm1, %ymm0, %ymm0
	vpermq	$216, %ymm0, %ymm0
	vpsrlw	$1, %ymm0, %ymm0
	vpand	%ymm0, %ymm3, %ymm0
	vpaddb	%ymm0, %ymm0, %ymm1
	vpaddb	%ymm1, %ymm1, %ymm1
	vpaddb	%ymm0, %ymm1, %ymm1
	vpaddb	%ymm1, %ymm1, %ymm1
	vpaddb	%ymm1, %ymm1, %ymm1
	vpsubb	%ymm0, %ymm1, %ymm0
	vpsubb	%ymm0, %ymm2, %ymm2
	vmovdqa	%ymm2, -32(%rdx)
	cmpq	%rdi, %rax
	jne	.L768
	leaq	1184(%r13), %r9
	leaq	32(%r13), %rbx
	movq	$5, 384(%rsp)
	movl	$15, %r12d
	movq	$10, 392(%rsp)
	xorl	%r15d, %r15d
	xorl	%eax, %eax
	xorl	%edx, %edx
	movq	%r9, 344(%rsp)
	movq	%rbx, 336(%rsp)
.L769:
	imulq	$-1440, %rax, %rbx
	leaq	-9(%r12), %r10
	movq	344(%rsp), %rdi
	movq	336(%rsp), %rcx
	imulq	$720, %rax, %r9
	movq	%r10, 360(%rsp)
	leaq	-4(%r12), %r10
	xorl	%r11d, %r11d
	movq	%r10, 352(%rsp)
	subq	%r15, %rdi
	subq	%r15, %rcx
	movq	%rax, 328(%rsp)
	movq	%rdx, 320(%rsp)
	movq	%rbx, 376(%rsp)
	leaq	7(%r9), %rbx
	movq	%rbx, 368(%rsp)
	movq	%rdx, %rbx
.L770:
	vmovd	(%rsi), %xmm0
	movzbl	4(%rsi), %edx
	leaq	(%rcx,%r15), %rax
	movl	%r11d, %r10d
	movq	384(%rsp), %r9
	movzbl	6(%rsi), %r8d
	vpmovzxbw	%xmm0, %xmm1
	vpsrld	$16, %xmm0, %xmm0
	vpmovzxbw	%xmm0, %xmm0
	vmovd	%xmm1, -32(%rcx)
	vmovd	%xmm0, -28(%rcx)
	movw	%dx, -32(%rax,%r9,2)
	movzbl	5(%rsi), %edx
	movq	360(%rsp), %r9
	movw	%dx, -32(%rax,%r9,2)
	movq	376(%rsp), %rdx
	movq	368(%rsp), %r9
	addq	%rcx, %rdx
	movw	%r8w, -32(%rdx,%r9,2)
	movzbl	7(%rsi), %edx
	leaq	10(%rsi), %r8
	movq	392(%rsp), %r9
	movw	%dx, -32(%rax,%r9,2)
	movzbl	8(%rsi), %edx
	movq	352(%rsp), %r9
	movw	%dx, -32(%rax,%r9,2)
	movzbl	9(%rsi), %edx
	movw	%dx, -32(%rax,%r12,2)
	cmpl	$36, %r11d
	je	.L775
	cmpq	$35, %r11
	je	.L839
	movl	$36, %r9d
	xorl	%eax, %eax
	subl	%r11d, %r9d
	movl	%r9d, %edx
	shrl	%edx
	salq	$5, %rdx
	.p2align 6
	.p2align 4,,10
	.p2align 3
.L773:
	vmovdqu	10(%rsi,%rax), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, (%rcx,%rax,2)
	vmovdqu	%ymm0, 32(%rcx,%rax,2)
	addq	$32, %rax
	cmpq	%rdx, %rax
	jne	.L773
	testb	$1, %r9b
	je	.L776
	andl	$-2, %r9d
.L772:
	movl	%r9d, %eax
	leaq	1(%rax,%rbx), %rdx
	salq	$4, %rax
	vmovdqu	(%r8,%rax), %xmm0
	salq	$5, %rdx
	vpmovzxbw	%xmm0, %xmm1
	vpsrldq	$8, %xmm0, %xmm0
	vpmovzxbw	%xmm0, %xmm0
	vmovdqu	%xmm1, 0(%r13,%rdx)
	vmovdqu	%xmm0, 16(%r13,%rdx)
.L776:
	movl	$35, %eax
	subl	%r10d, %eax
	salq	$4, %rax
	leaq	26(%rsi,%rax), %r8
.L775:
	vmovdqu	(%r8), %ymm0
	incq	%r11
	leaq	128(%r8), %rsi
	addq	$1440, %rdi
	addq	$46, %rbx
	addq	$1472, %rcx
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, -1440(%rdi)
	vmovdqu	%ymm0, -1408(%rdi)
	vmovdqu	32(%r8), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, -1376(%rdi)
	vmovdqu	%ymm0, -1344(%rdi)
	vmovdqu	64(%r8), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, -1312(%rdi)
	vmovdqu	%ymm0, -1280(%rdi)
	vmovdqu	96(%r8), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, -1248(%rdi)
	vmovdqu	%ymm0, -1216(%rdi)
	cmpq	$37, %r11
	jne	.L770
	movq	328(%rsp), %rax
	movq	320(%rsp), %rdx
	subq	$64800, %r15
	addq	$32400, %r12
	addq	$32400, 392(%rsp)
	addq	$45, %rax
	addq	$32400, 384(%rsp)
	addq	$2025, %rdx
	cmpq	$360, %rax
	jne	.L769
	movl	$6400, %edx
	leaq	6272(%rsp), %rdi
	vzeroupper
	call	memcpy@PLT
	leaq	2048(%rsp), %rdi
	movl	$4224, %edx
	xorl	%esi, %esi
	call	memset@PLT
	xorl	%r9d, %r9d
	movl	$0, 392(%rsp)
	xorl	%ecx, %ecx
	movq	%rax, %rdi
	movabsq	$-2912643801112034465, %r8
	cmpq	$2252, %r9
	ja	.L840
.L984:
	movzbl	16(%r14,%r9), %esi
	je	.L843
	movzbl	17(%r14,%r9), %edx
	movzbl	18(%r14,%r9), %eax
	salq	$8, %rdx
	salq	$16, %rax
	xorq	%rsi, %rdx
	movzbl	19(%r14,%r9), %esi
	xorq	%rdx, %rax
	salq	$24, %rsi
	xorq	%rax, %rsi
	cmpq	$2249, %r9
	je	.L843
	movzbl	20(%r14,%r9), %eax
	salq	$32, %rax
	xorq	%rax, %rsi
	cmpq	$2248, %r9
	je	.L843
	movzbl	21(%r14,%r9), %edx
	movzbl	22(%r14,%r9), %eax
	leaq	8(%r9), %r10
	salq	$40, %rdx
	salq	$48, %rax
	xorq	%rsi, %rdx
	movzbl	23(%r14,%r9), %esi
	xorq	%rdx, %rax
	salq	$56, %rsi
	xorq	%rax, %rsi
.L778:
	movq	%rsi, %rax
	mulq	%r8
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r11
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %rsi
	movb	%sil, 2048(%rsp,%rcx)
	cmpq	$4223, %rcx
	je	.L983
	movq	%rdx, %rax
	mulq	%r8
	movq	%rdx, %rsi
	shrq	$4, %rsi
	leaq	(%rsi,%rsi,8), %rax
	leaq	(%rsi,%rax,2), %rax
	subq	%rax, %r11
	movb	%r11b, 2049(%rsp,%rcx)
	cmpq	$4222, %rcx
	je	.L978
	movq	%rsi, %rax
	mulq	%r8
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r11
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %rsi
	movb	%sil, 2050(%rsp,%rcx)
	cmpq	$4221, %rcx
	je	.L983
	movq	%rdx, %rax
	mulq	%r8
	movq	%rdx, %rsi
	shrq	$4, %rsi
	leaq	(%rsi,%rsi,8), %rax
	leaq	(%rsi,%rax,2), %rax
	subq	%rax, %r11
	movb	%r11b, 2051(%rsp,%rcx)
	cmpq	$4220, %rcx
	je	.L978
	movq	%rsi, %rax
	mulq	%r8
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r11
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %rsi
	movb	%sil, 2052(%rsp,%rcx)
	cmpq	$4219, %rcx
	je	.L983
	movq	%rdx, %rax
	mulq	%r8
	movq	%rdx, %rsi
	shrq	$4, %rsi
	leaq	(%rsi,%rsi,8), %rax
	leaq	(%rsi,%rax,2), %rax
	subq	%rax, %r11
	movb	%r11b, 2053(%rsp,%rcx)
	cmpq	$4218, %rcx
	je	.L978
	movq	%rsi, %rax
	mulq	%r8
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r11
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %rsi
	movb	%sil, 2054(%rsp,%rcx)
	cmpq	$4217, %rcx
	je	.L983
	movq	%rdx, %rax
	mulq	%r8
	movq	%rdx, %rsi
	shrq	$4, %rsi
	leaq	(%rsi,%rsi,8), %rax
	leaq	(%rsi,%rax,2), %rax
	subq	%rax, %r11
	movb	%r11b, 2055(%rsp,%rcx)
	cmpq	$4216, %rcx
	je	.L978
	movq	%rsi, %rax
	mulq	%r8
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r11
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %rsi
	movb	%sil, 2056(%rsp,%rcx)
	cmpq	$4215, %rcx
	je	.L983
	movq	%rdx, %rax
	mulq	%r8
	movq	%rdx, %rsi
	shrq	$4, %rsi
	leaq	(%rsi,%rsi,8), %rax
	leaq	(%rsi,%rax,2), %rax
	subq	%rax, %r11
	movb	%r11b, 2057(%rsp,%rcx)
	cmpq	$4214, %rcx
	je	.L978
	movq	%rsi, %rax
	mulq	%r8
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r11
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %rsi
	movb	%sil, 2058(%rsp,%rcx)
	cmpq	$4213, %rcx
	je	.L983
	movq	%rdx, %rax
	mulq	%r8
	movq	%rdx, %rsi
	shrq	$4, %rsi
	leaq	(%rsi,%rsi,8), %rax
	leaq	(%rsi,%rax,2), %rax
	subq	%rax, %r11
	movb	%r11b, 2059(%rsp,%rcx)
	cmpq	$4212, %rcx
	je	.L978
	movq	%rsi, %rax
	mulq	%r8
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r11
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %rsi
	movb	%sil, 2060(%rsp,%rcx)
	cmpq	$4211, %rcx
	je	.L983
	movq	%rdx, %rax
	mulq	%r8
	movq	%rdx, %rsi
	shrq	$4, %rsi
	leaq	(%rsi,%rsi,8), %rax
	leaq	(%rsi,%rax,2), %rax
	subq	%rax, %r11
	movb	%r11b, 2061(%rsp,%rcx)
	cmpq	$4210, %rcx
	je	.L978
	movq	%rsi, %rax
	mulq	%r8
	movq	%rdx, %rax
	shrq	$4, %rax
	leaq	(%rax,%rax,8), %rdx
	orl	%eax, 392(%rsp)
	leaq	(%rax,%rdx,2), %rdx
	subq	%rdx, %rsi
	movb	%sil, 2062(%rsp,%rcx)
	addq	$15, %rcx
	cmpq	$4224, %rcx
	je	.L781
	cmpq	$2252, %r9
	ja	.L797
	movq	%r10, %r9
	cmpq	$2252, %r9
	jbe	.L984
.L840:
	movq	%r9, %r10
	xorl	%esi, %esi
	jmp	.L778
.L839:
	xorl	%r9d, %r9d
	jmp	.L772
.L983:
	orl	%r11d, 392(%rsp)
.L781:
	movl	392(%rsp), %r10d
	testl	%r10d, %r10d
	jne	.L845
	xorl	%esi, %esi
	movl	$1702, %ecx
	xorl	%r8d, %r8d
	xorl	%r9d, %r9d
	movq	%rdi, %r15
	leaq	6272(%rsp), %rax
	movq	%r13, %r14
.L799:
	leal	0(,%r8,4), %r11d
	leal	-37(%rcx), %edi
	movq	%rcx, 360(%rsp)
	movl	$224, %r13d
	movl	%edi, 320(%rsp)
	leaq	(%r14,%rsi), %rbx
	movl	$37, %r10d
	movq	%rax, %r12
	movq	$28, 328(%rsp)
	movl	$37, 384(%rsp)
	movl	$7, 272(%rsp)
	movl	%r11d, 264(%rsp)
	movq	%r9, 240(%rsp)
	movq	%r8, 232(%rsp)
	movq	%rcx, 224(%rsp)
	movq	%rsi, 216(%rsp)
.L817:
	movl	264(%rsp), %eax
	movl	%r10d, %edx
	movl	%r10d, 256(%rsp)
	movl	$44, %r9d
	incl	%r10d
	leaq	54464(%rbx), %rdi
	leaq	54496(%rbx), %rcx
	subl	%r10d, %r9d
	leal	27232(%rax), %r8d
	leal	27248(%rax), %esi
	leal	-41(%rdx), %eax
	xorl	%edx, %edx
	movl	%eax, 352(%rsp)
	leaq	4(,%r9,4), %rax
	movq	%rax, 344(%rsp)
	leaq	-24(%r13), %rax
	movq	%rax, 336(%rsp)
	movl	272(%rsp), %eax
	movl	%eax, %r9d
	andl	$-4, %eax
	andl	$3, %r9d
	movl	%eax, 304(%rsp)
	movl	%r9d, 312(%rsp)
	movl	%eax, %r9d
	addl	384(%rsp), %eax
	movq	%r9, 296(%rsp)
	salq	$2, %r9
	movq	%r9, 288(%rsp)
	movl	$44, %r9d
	subl	%eax, %r9d
	movl	%eax, 280(%rsp)
	movl	%r9d, 248(%rsp)
.L815:
	leal	-1(%rdx), %eax
	movl	%edx, 376(%rsp)
	cmpl	$2, %eax
	jbe	.L811
.L985:
	vmovd	(%r15), %xmm0
	leaq	4(%r15), %rax
	movq	%r15, %r9
	movq	%rax, %r15
	vpmovzxbw	%xmm0, %xmm1
	vpsrld	$16, %xmm0, %xmm0
	vpmovzxbw	%xmm0, %xmm0
	vmovd	%xmm1, (%rdi)
	vmovd	%xmm0, 4(%rdi)
	cmpl	$45, %r10d
	je	.L812
	addq	$3, %r9
	cmpl	$43, 384(%rsp)
	je	.L802
.L987:
	movq	336(%rsp), %r11
	addq	%rcx, %r11
	cmpq	%r11, %rax
	jnb	.L848
	movq	328(%rsp), %r11
	leaq	1(%r9,%r11), %r9
	cmpq	%r9, %rcx
	jb	.L802
.L848:
	cmpl	$2, 352(%rsp)
	jbe	.L804
	vmovdqu	(%rax), %xmm0
	movl	312(%rsp), %r9d
	vpmovzxbw	%xmm0, %xmm1
	vpsrldq	$8, %xmm0, %xmm0
	vpmovzxbw	%xmm0, %xmm0
	vmovq	%xmm1, (%rcx)
	vpextrq	$1, %xmm1, 32(%rcx)
	vmovq	%xmm0, 64(%rcx)
	vpextrq	$1, %xmm0, 96(%rcx)
	testl	%r9d, %r9d
	je	.L809
	movl	304(%rsp), %r15d
	movq	296(%rsp), %r9
	addl	%r10d, %r15d
	movl	%r15d, 376(%rsp)
	movq	288(%rsp), %r15
	addq	%rax, %r15
	cmpl	$43, 280(%rsp)
	je	.L807
	movl	248(%rsp), %r11d
	movl	%r11d, 368(%rsp)
.L836:
	vmovq	(%rax,%r9,4), %xmm0
	movq	360(%rsp), %r11
	vpmovzxbw	%xmm0, %xmm1
	vpsrlq	$32, %xmm0, %xmm0
	addq	%r9, %r11
	movl	368(%rsp), %r9d
	leaq	4(%rdx,%r11,4), %r11
	vpmovzxbw	%xmm0, %xmm0
	vmovq	%xmm1, (%r14,%r11,8)
	vmovq	%xmm0, 32(%r14,%r11,8)
	testb	$1, %r9b
	je	.L809
	andl	$-2, %r9d
	addl	%r9d, 376(%rsp)
	leaq	(%r15,%r9,4), %r15
.L807:
	movl	376(%rsp), %r9d
	movzbl	(%r15), %r11d
	addl	320(%rsp), %r9d
	leal	(%rdx,%r9,4), %r9d
	sall	$2, %r9d
	movslq	%r9d, %r9
	movw	%r11w, (%r14,%r9,2)
	movzbl	1(%r15), %r11d
	movw	%r11w, 2(%r14,%r9,2)
	movzbl	2(%r15), %r11d
	movw	%r11w, 4(%r14,%r9,2)
	movzbl	3(%r15), %r11d
	movw	%r11w, 6(%r14,%r9,2)
.L809:
	movq	344(%rsp), %r15
	addq	%rax, %r15
.L801:
	incq	%rdx
	cmpq	$4, %rdx
	je	.L810
	leal	-1(%rdx), %eax
	movl	%edx, 376(%rsp)
	addl	$4, %r8d
	addq	$10, %rdi
	addl	$4, %esi
	addq	$8, %rcx
	cmpl	$2, %eax
	ja	.L985
.L811:
	movzbl	(%r15), %r9d
	leal	(%r8,%rdx), %eax
	cltq
	movw	%r9w, (%r14,%rax,2)
	cmpl	$3, %edx
	jne	.L986
.L800:
	movl	$3, %r9d
	subq	%rdx, %r9
	addq	%r15, %r9
	leaq	1(%r9), %rax
	movq	%rax, %r15
	cmpl	$45, %r10d
	je	.L801
	cmpl	$43, 384(%rsp)
	jne	.L987
.L802:
	vmovd	(%rax), %xmm0
	movl	256(%rsp), %r15d
	movslq	%esi, %r9
	vpmovzxbw	%xmm0, %xmm0
	vmovq	%xmm0, (%r14,%r9,2)
	cmpl	$43, %r15d
	je	.L809
	vmovd	4(%rax), %xmm0
	leal	16(%rsi), %r9d
	movslq	%r9d, %r9
	vpmovzxbw	%xmm0, %xmm0
	vmovq	%xmm0, (%r14,%r9,2)
	cmpl	$42, %r15d
	je	.L809
	vmovd	8(%rax), %xmm0
	leal	32(%rsi), %r9d
	movslq	%r9d, %r9
	vpmovzxbw	%xmm0, %xmm0
	vmovq	%xmm0, (%r14,%r9,2)
	cmpl	$41, %r15d
	je	.L809
	vmovd	12(%rax), %xmm0
	leal	48(%rsi), %r9d
	movslq	%r9d, %r9
	vpmovzxbw	%xmm0, %xmm0
	vmovq	%xmm0, (%r14,%r9,2)
	cmpl	$40, %r15d
	je	.L809
	vmovd	16(%rax), %xmm0
	leal	64(%rsi), %r9d
	movslq	%r9d, %r9
	vpmovzxbw	%xmm0, %xmm0
	vmovq	%xmm0, (%r14,%r9,2)
	cmpl	$39, %r15d
	je	.L809
	vmovd	20(%rax), %xmm0
	leal	80(%rsi), %r9d
	movslq	%r9d, %r9
	vpmovzxbw	%xmm0, %xmm0
	vmovq	%xmm0, (%r14,%r9,2)
	cmpl	$38, %r15d
	je	.L809
	vmovd	24(%rax), %xmm0
	leal	96(%rsi), %r9d
	movslq	%r9d, %r9
	vpmovzxbw	%xmm0, %xmm0
	vmovq	%xmm0, (%r14,%r9,2)
	jmp	.L809
.L810:
	incl	384(%rsp)
	addq	$1472, %rbx
	subq	$32, %r13
	decl	272(%rsp)
	addl	$736, 264(%rsp)
	subq	$4, 328(%rsp)
	addl	$45, 320(%rsp)
	addq	$46, 360(%rsp)
	cmpl	$45, %r10d
	jne	.L817
	movq	240(%rsp), %r9
	movq	232(%rsp), %r8
	movq	%r12, %rax
	movq	224(%rsp), %rcx
	movq	216(%rsp), %rsi
	addq	$45, %r9
	addq	$8100, %r8
	addq	$2025, %rcx
	addq	$64800, %rsi
	cmpq	$360, %r9
	jne	.L799
	leaq	8(%r14), %rax
	vmovdqa	.LC89(%rip), %ymm3
	vmovdqa	.LC90(%rip), %ymm2
	movq	%r12, %rbx
	movq	%rax, 160(%rsp)
	leaq	4(%r14), %rax
	xorl	%r8d, %r8d
	movl	$1440, %edx
	movq	%rax, 152(%rsp)
	leaq	16(%r14), %rax
	xorl	%r9d, %r9d
	leaq	2(%r14), %rsi
	movq	%rax, 144(%rsp)
	leaq	6(%r14), %rax
	movq	%r14, %rdi
	movq	%rax, 136(%rsp)
	leaq	24(%r14), %rax
	movq	%rax, 128(%rsp)
.L825:
	leaq	61952(%rdx), %rax
	movq	%rdx, 296(%rsp)
	movl	%r9d, %r12d
	xorl	%r11d, %r11d
	movq	%rax, 288(%rsp)
	leaq	30(%rsi), %rax
	movl	$45, %r10d
	movq	%rax, 176(%rsp)
	leaq	1438(%rsi), %rax
	movq	%rax, 184(%rsp)
	leaq	10(%rsi), %rax
	movq	%rax, 112(%rsp)
	leaq	16(%rsi), %rax
	movq	%rax, 96(%rsp)
	leaq	12(%rsi), %rax
	movq	%rax, 104(%rsp)
	leaq	24(%rsi), %rax
	movq	%rax, 80(%rsp)
	leaq	20(%rsi), %rax
	movq	%rax, 88(%rsp)
	leaq	26(%rsi), %rax
	movq	%rdx, 168(%rsp)
	movq	%rax, 72(%rsp)
	movl	%r9d, 52(%rsp)
	movq	%rdx, 40(%rsp)
	movq	%rsi, 120(%rsp)
	movq	%r8, 32(%rsp)
	movq	%rbx, 24(%rsp)
.L823:
	movq	120(%rsp), %rax
	movq	160(%rsp), %rbx
	movzwl	(%rax,%r11), %eax
	movw	%ax, (%rbx,%r11)
	movq	152(%rsp), %rax
	movq	144(%rsp), %rbx
	movzwl	(%rax,%r11), %eax
	movw	%ax, (%rbx,%r11)
	movq	136(%rsp), %rax
	movq	128(%rsp), %rbx
	movzwl	(%rax,%r11), %eax
	movw	%ax, (%rbx,%r11)
	movq	112(%rsp), %rax
	movq	96(%rsp), %rbx
	movzwl	(%rax,%r11), %eax
	movw	%ax, (%rbx,%r11)
	movq	104(%rsp), %rax
	movq	80(%rsp), %rbx
	movzwl	(%rax,%r11), %eax
	movw	%ax, (%rbx,%r11)
	movq	88(%rsp), %rax
	movq	72(%rsp), %rbx
	movzwl	(%rax,%r11), %eax
	movw	%ax, (%rbx,%r11)
	decl	%r10d
	je	.L988
	movq	296(%rsp), %rbx
	leaq	-1408(%rbx), %rax
	cmpq	288(%rsp), %rax
	jge	.L849
	cmpq	%rbx, 168(%rsp)
	jg	.L818
.L849:
	movq	176(%rsp), %rcx
	movq	184(%rsp), %rdx
	xorl	%eax, %eax
	.p2align 6
	.p2align 4,,10
	.p2align 3
.L820:
	vmovdqu	(%rcx), %ymm0
	incl	%eax
	addq	$1440, %rdx
	addq	$32, %rcx
	vpshufb	%ymm3, %ymm0, %ymm1
	vpshufb	%ymm2, %ymm0, %ymm0
	vpermq	$78, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vmovdqu	%ymm0, -1440(%rdx)
	cmpl	%r10d, %eax
	jb	.L820
.L821:
	addq	$1440, 168(%rsp)
	addl	$736, %r12d
	addq	$1472, %r11
	addq	$1472, 296(%rsp)
	addq	$32, 288(%rsp)
	addq	$1472, 176(%rsp)
	addq	$1472, 184(%rsp)
	jmp	.L823
.L986:
	movzbl	1(%r15), %r9d
	leal	1(%rdx,%r8), %eax
	cmpl	$2, 376(%rsp)
	cltq
	movw	%r9w, (%r14,%rax,2)
	je	.L800
	movzbl	2(%r15), %r9d
	leal	3(%r8), %eax
	cltq
	movw	%r9w, (%r14,%rax,2)
	jmp	.L800
.L804:
	movl	$44, %r9d
	movl	%r10d, 376(%rsp)
	subl	384(%rsp), %r9d
	movl	%r9d, 368(%rsp)
	xorl	%r9d, %r9d
	jmp	.L836
.L812:
	addl	$4, %r8d
	addq	$10, %rdi
	addl	$4, %esi
	addq	$8, %rcx
	movl	$1, %edx
	jmp	.L815
.L978:
	orl	%esi, 392(%rsp)
	jmp	.L781
.L843:
	movl	$2253, %r10d
	jmp	.L778
.L818:
	movl	%r10d, %eax
	movl	%r12d, 48(%rsp)
	salq	$5, %rax
	movq	%r11, 16(%rsp)
	movq	%rax, 312(%rsp)
	leal	16(%r12), %eax
	cltq
	movl	%r10d, 12(%rsp)
	leaq	(%rdi,%rax,2), %r15
	leal	720(%r12), %eax
	cltq
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 280(%rsp)
	leal	17(%r12), %eax
	cltq
	leaq	(%rdi,%rax,2), %r14
	leal	724(%r12), %eax
	cltq
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 320(%rsp)
	leal	18(%r12), %eax
	cltq
	leaq	(%rdi,%rax,2), %r13
	leal	728(%r12), %eax
	cltq
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 240(%rsp)
	leal	19(%r12), %eax
	cltq
	leaq	(%rdi,%rax,2), %rbx
	leal	732(%r12), %eax
	cltq
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 224(%rsp)
	leal	20(%r12), %eax
	cltq
	leaq	(%rdi,%rax,2), %r9
	leal	721(%r12), %eax
	cltq
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 216(%rsp)
	leal	21(%r12), %eax
	cltq
	leaq	(%rdi,%rax,2), %r8
	leal	725(%r12), %eax
	cltq
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 208(%rsp)
	leal	22(%r12), %eax
	cltq
	leaq	(%rdi,%rax,2), %rsi
	leal	729(%r12), %eax
	cltq
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 232(%rsp)
	leal	23(%r12), %eax
	cltq
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 56(%rsp)
	leal	733(%r12), %eax
	cltq
	leaq	(%rdi,%rax,2), %rcx
	leal	24(%r12), %eax
	cltq
	movq	%rcx, 256(%rsp)
	leaq	(%rdi,%rax,2), %rcx
	leal	722(%r12), %eax
	cltq
	movq	%rcx, 360(%rsp)
	leaq	(%rdi,%rax,2), %rcx
	leal	25(%r12), %eax
	cltq
	movq	%rcx, 336(%rsp)
	leaq	(%rdi,%rax,2), %rcx
	leal	726(%r12), %eax
	cltq
	movq	%rcx, 344(%rsp)
	leaq	(%rdi,%rax,2), %rcx
	leal	26(%r12), %eax
	cltq
	movq	%rcx, 304(%rsp)
	leaq	(%rdi,%rax,2), %rcx
	leal	730(%r12), %eax
	cltq
	movq	%rcx, 64(%rsp)
	leaq	(%rdi,%rax,2), %rdx
	leal	27(%r12), %eax
	cltq
	movq	%rdx, 352(%rsp)
	leaq	(%rdi,%rax,2), %rdx
	leal	734(%r12), %eax
	cltq
	movq	%rdx, 192(%rsp)
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 264(%rsp)
	leal	28(%r12), %eax
	cltq
	movq	192(%rsp), %r11
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 328(%rsp)
	leal	723(%r12), %eax
	cltq
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 376(%rsp)
	leal	29(%r12), %eax
	cltq
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 368(%rsp)
	leal	727(%r12), %eax
	cltq
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 384(%rsp)
	leal	30(%r12), %eax
	cltq
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 200(%rsp)
	leal	731(%r12), %eax
	cltq
	leaq	(%rdi,%rax,2), %rcx
	leal	31(%r12), %eax
	cltq
	movq	%rcx, 248(%rsp)
	movq	200(%rsp), %r10
	leaq	(%rdi,%rax,2), %rcx
	leal	735(%r12), %eax
	movq	56(%rsp), %r12
	cltq
	movq	%rcx, 200(%rsp)
	leaq	(%rdi,%rax,2), %rdx
	xorl	%eax, %eax
	movq	%rdx, 272(%rsp)
	xorl	%edx, %edx
	movq	%rsi, 192(%rsp)
	movq	%rdi, 56(%rsp)
	movq	64(%rsp), %rdi
.L822:
	movzwl	(%r15,%rax), %esi
	movq	280(%rsp), %rcx
	movw	%si, (%rcx,%rdx)
	movq	320(%rsp), %rcx
	movzwl	(%r14,%rax), %esi
	movw	%si, (%rcx,%rdx)
	movq	240(%rsp), %rcx
	movzwl	0(%r13,%rax), %esi
	movw	%si, (%rcx,%rdx)
	movq	224(%rsp), %rcx
	movzwl	(%rbx,%rax), %esi
	movw	%si, (%rcx,%rdx)
	movq	216(%rsp), %rcx
	movzwl	(%r9,%rax), %esi
	movw	%si, (%rcx,%rdx)
	movq	208(%rsp), %rcx
	movzwl	(%r8,%rax), %esi
	movw	%si, (%rcx,%rdx)
	movq	192(%rsp), %rsi
	movq	232(%rsp), %rcx
	movzwl	(%rsi,%rax), %esi
	movw	%si, (%rcx,%rdx)
	movq	256(%rsp), %rcx
	movzwl	(%r12,%rax), %esi
	movw	%si, (%rcx,%rdx)
	movq	360(%rsp), %rcx
	movq	336(%rsp), %rsi
	movzwl	(%rcx,%rax), %ecx
	movw	%cx, (%rsi,%rdx)
	movq	344(%rsp), %rcx
	movq	304(%rsp), %rsi
	movzwl	(%rcx,%rax), %ecx
	movw	%cx, (%rsi,%rdx)
	movzwl	(%rdi,%rax), %ecx
	movq	352(%rsp), %rsi
	movw	%cx, (%rsi,%rdx)
	movq	264(%rsp), %rsi
	movzwl	(%r11,%rax), %ecx
	movw	%cx, (%rsi,%rdx)
	movq	328(%rsp), %rsi
	movzwl	(%rsi,%rax), %ecx
	movq	376(%rsp), %rsi
	movw	%cx, (%rsi,%rdx)
	movq	368(%rsp), %rsi
	movq	384(%rsp), %rcx
	movzwl	(%rsi,%rax), %esi
	movw	%si, (%rcx,%rdx)
	movq	248(%rsp), %rcx
	movzwl	(%r10,%rax), %esi
	movw	%si, (%rcx,%rdx)
	movq	200(%rsp), %rsi
	movq	272(%rsp), %rcx
	movzwl	(%rsi,%rax), %esi
	addq	$32, %rax
	movw	%si, (%rcx,%rdx)
	addq	$1440, %rdx
	cmpq	%rax, 312(%rsp)
	jne	.L822
	movl	48(%rsp), %r12d
	movq	16(%rsp), %r11
	movl	12(%rsp), %r10d
	movq	56(%rsp), %rdi
	jmp	.L821
.L988:
	movq	32(%rsp), %r8
	movl	52(%rsp), %r9d
	movq	40(%rsp), %rdx
	movq	120(%rsp), %rsi
	addq	$45, %r8
	addq	$64800, 160(%rsp)
	movq	24(%rsp), %rbx
	addl	$32400, %r9d
	addq	$64800, 152(%rsp)
	addq	$64800, %rdx
	addq	$64800, %rsi
	addq	$64800, 144(%rsp)
	addq	$64800, 136(%rsp)
	addq	$64800, 128(%rsp)
	cmpq	$360, %r8
	jne	.L825
	leaq	11392(%rsp), %r14
	leaq	8832(%rsp), %rax
	movq	%rdi, 368(%rsp)
	vmovdqa	.LC75(%rip), %ymm4
	movq	%rax, 384(%rsp)
	vmovdqa	.LC76(%rip), %ymm3
	movq	%rbx, %r15
	leaq	518400(%rdi), %r12
	vmovdqa	.LC77(%rip), %xmm2
	vmovdqa	.LC78(%rip), %xmm1
	movq	%r14, 376(%rsp)
	movq	%r14, %r13
.L835:
	movzbl	(%r15), %eax
	movq	%r12, %rdi
	movb	%al, (%r12)
	movq	1(%r15), %rax
	movq	%rax, 1(%r12)
	movl	9(%r15), %eax
	movl	%eax, 9(%r12)
	movzwl	13(%r15), %eax
	movw	%ax, 13(%r12)
	movzbl	15(%r15), %eax
	movb	%al, 15(%r12)
	call	gf_mat_det
	testb	%al, %al
	jne	.L829
	movl	$1, %ebx
.L826:
	movzbl	(%r12), %edx
	addl	%ebx, %edx
	movslq	%edx, %rax
	movl	%edx, %ecx
	imulq	$1808407283, %rax, %rax
	sarl	$31, %ecx
	sarq	$35, %rax
	subl	%ecx, %eax
	leal	(%rax,%rax,8), %ecx
	leal	(%rax,%rcx,2), %eax
	leal	(%rbx,%rbx), %ecx
	subl	%eax, %edx
	movzbl	1(%r12), %eax
	leal	(%rcx,%rbx), %esi
	movb	%dl, (%r12)
	addl	%ecx, %eax
	movslq	%eax, %rdx
	movl	%eax, %edi
	imulq	$1808407283, %rdx, %rdx
	sarl	$31, %edi
	sarq	$35, %rdx
	subl	%edi, %edx
	leal	(%rdx,%rdx,8), %edi
	leal	(%rdx,%rdi,2), %edx
	movzbl	2(%r12), %edi
	subl	%edx, %eax
	addl	%esi, %edi
	movslq	%edi, %rdx
	movl	%edi, %r8d
	imulq	$1808407283, %rdx, %rdx
	sarl	$31, %r8d
	sarq	$35, %rdx
	subl	%r8d, %edx
	leal	(%rdx,%rdx,8), %r8d
	leal	(%rdx,%r8,2), %edx
	subl	%edx, %edi
	movzbl	3(%r12), %edx
	movq	%rdx, %r8
	imulq	$1808407283, %rdx, %rdx
	shrq	$35, %rdx
	leal	(%rdx,%rdx,8), %r9d
	leal	(%rdx,%r9,2), %edx
	subl	%edx, %r8d
	vmovd	%r8d, %xmm0
	movzbl	4(%r12), %r8d
	addl	%ecx, %r8d
	movslq	%r8d, %rdx
	movl	%r8d, %r9d
	imulq	$1808407283, %rdx, %rdx
	sarl	$31, %r9d
	sarq	$35, %rdx
	subl	%r9d, %edx
	leal	(%rdx,%rdx,8), %r9d
	leal	(%rdx,%r9,2), %edx
	movzbl	5(%r12), %r9d
	subl	%edx, %r8d
	addl	%esi, %r9d
	movslq	%r9d, %rdx
	movl	%r9d, %r10d
	imulq	$1808407283, %rdx, %rdx
	sarl	$31, %r10d
	sarq	$35, %rdx
	subl	%r10d, %edx
	leal	(%rdx,%rdx,8), %r10d
	leal	(%rdx,%r10,2), %edx
	subl	%edx, %r9d
	movzbl	6(%r12), %edx
	movq	%rdx, %r10
	imulq	$1808407283, %rdx, %rdx
	shrq	$35, %rdx
	leal	(%rdx,%rdx,8), %r11d
	leal	(%rdx,%r11,2), %edx
	subl	%edx, %r10d
	movzbl	7(%r12), %edx
	addl	%ebx, %edx
	movslq	%edx, %r11
	movl	%edx, %r14d
	imulq	$1808407283, %r11, %r11
	sarl	$31, %r14d
	sarq	$35, %r11
	subl	%r14d, %r11d
	leal	(%r11,%r11,8), %r14d
	leal	(%r11,%r14,2), %r11d
	subl	%r11d, %edx
	movzbl	8(%r12), %r11d
	vmovd	%edx, %xmm7
	addl	%esi, %r11d
	movslq	%r11d, %rsi
	movl	%r11d, %r14d
	imulq	$1808407283, %rsi, %rsi
	sarl	$31, %r14d
	sarq	$35, %rsi
	subl	%r14d, %esi
	leal	(%rsi,%rsi,8), %r14d
	leal	(%rsi,%r14,2), %esi
	subl	%esi, %r11d
	vpinsrd	$1, %r11d, %xmm7, %xmm6
	vmovd	%r9d, %xmm7
	vpinsrd	$1, %r10d, %xmm7, %xmm5
	vmovd	%eax, %xmm7
	movzbl	9(%r12), %eax
	vpunpcklqdq	%xmm6, %xmm5, %xmm5
	vpinsrd	$1, %r8d, %xmm0, %xmm6
	vpinsrd	$1, %edi, %xmm7, %xmm0
	movq	%rax, %rdx
	imulq	$1808407283, %rax, %rax
	vpunpcklqdq	%xmm6, %xmm0, %xmm0
	vinserti128	$0x1, %xmm5, %ymm0, %ymm0
	vpshufb	%ymm4, %ymm0, %ymm5
	vpshufb	%ymm3, %ymm0, %ymm0
	shrq	$35, %rax
	vpermq	$78, %ymm5, %ymm5
	leal	(%rax,%rax,8), %esi
	vpor	%ymm5, %ymm0, %ymm0
	leal	(%rax,%rsi,2), %eax
	movzbl	10(%r12), %esi
	vmovq	%xmm0, 1(%r12)
	subl	%eax, %edx
	addl	%ebx, %esi
	vmovd	%edx, %xmm0
	movslq	%esi, %rax
	movl	%esi, %edx
	imulq	$1808407283, %rax, %rax
	sarl	$31, %edx
	sarq	$35, %rax
	subl	%edx, %eax
	leal	(%rax,%rax,8), %edx
	leal	(%rax,%rdx,2), %eax
	subl	%eax, %esi
	movzbl	11(%r12), %eax
	vpinsrd	$1, %esi, %xmm0, %xmm0
	addl	%ecx, %eax
	movslq	%eax, %rdx
	movl	%eax, %edi
	imulq	$1808407283, %rdx, %rdx
	sarl	$31, %edi
	sarq	$35, %rdx
	subl	%edi, %edx
	leal	(%rdx,%rdx,8), %edi
	leal	(%rdx,%rdi,2), %edx
	subl	%edx, %eax
	movzbl	12(%r12), %edx
	vmovd	%eax, %xmm7
	movzbl	13(%r12), %eax
	movq	%rdx, %rdi
	imulq	$1808407283, %rdx, %rdx
	shrq	$35, %rdx
	addl	%ebx, %eax
	leal	(%rdx,%rdx,8), %r8d
	movl	%eax, %esi
	leal	(%rdx,%r8,2), %edx
	sarl	$31, %esi
	subl	%edx, %edi
	movslq	%eax, %rdx
	imulq	$1808407283, %rdx, %rdx
	vpinsrd	$1, %edi, %xmm7, %xmm5
	movq	%r12, %rdi
	vpunpcklqdq	%xmm5, %xmm0, %xmm0
	vpshufb	%xmm2, %xmm0, %xmm0
	sarq	$35, %rdx
	vmovd	%xmm0, 9(%r12)
	subl	%esi, %edx
	leal	(%rdx,%rdx,8), %esi
	leal	(%rdx,%rsi,2), %edx
	subl	%edx, %eax
	movzbl	14(%r12), %edx
	vmovd	%eax, %xmm7
	movl	%ebx, %eax
	addl	%edx, %ecx
	sall	$4, %eax
	movslq	%ecx, %rdx
	movl	%ecx, %esi
	subl	%ebx, %eax
	imulq	$1808407283, %rdx, %rdx
	sarl	$31, %esi
	sarq	$35, %rdx
	subl	%esi, %edx
	leal	(%rdx,%rdx,8), %esi
	leal	(%rdx,%rsi,2), %edx
	subl	%edx, %ecx
	movzbl	15(%r12), %edx
	vpinsrd	$1, %ecx, %xmm7, %xmm0
	addl	%eax, %edx
	vpshufb	%xmm1, %xmm0, %xmm0
	movslq	%edx, %rax
	movl	%edx, %ecx
	vpextrw	$0, %xmm0, 13(%r12)
	imulq	$1808407283, %rax, %rax
	sarl	$31, %ecx
	sarq	$35, %rax
	subl	%ecx, %eax
	leal	(%rax,%rax,8), %ecx
	leal	(%rax,%rcx,2), %eax
	subl	%eax, %edx
	movb	%dl, 15(%r12)
	call	gf_mat_det
	testb	%al, %al
	jne	.L829
	incl	%ebx
	cmpl	$19, %ebx
	jne	.L826
.L829:
	movzbl	2560(%r15), %eax
	leaq	2560(%r12), %r14
	movq	%r14, %rdi
	movb	%al, 2560(%r12)
	movq	2561(%r15), %rax
	movq	%rax, 2561(%r12)
	movl	2569(%r15), %eax
	movl	%eax, 2569(%r12)
	movzwl	2573(%r15), %eax
	movw	%ax, 2573(%r12)
	movzbl	2575(%r15), %eax
	movb	%al, 2575(%r12)
	call	gf_mat_det
	testb	%al, %al
	jne	.L828
	movl	$1, %ebx
.L827:
	movzbl	2560(%r12), %edx
	addl	%ebx, %edx
	movslq	%edx, %rax
	movl	%edx, %ecx
	imulq	$1808407283, %rax, %rax
	sarl	$31, %ecx
	sarq	$35, %rax
	subl	%ecx, %eax
	leal	(%rax,%rax,8), %ecx
	leal	(%rax,%rcx,2), %eax
	leal	(%rbx,%rbx), %ecx
	subl	%eax, %edx
	movzbl	2561(%r12), %eax
	leal	(%rcx,%rbx), %esi
	movb	%dl, 2560(%r12)
	addl	%ecx, %eax
	movslq	%eax, %rdx
	movl	%eax, %edi
	imulq	$1808407283, %rdx, %rdx
	sarl	$31, %edi
	sarq	$35, %rdx
	subl	%edi, %edx
	leal	(%rdx,%rdx,8), %edi
	leal	(%rdx,%rdi,2), %edx
	movzbl	2562(%r12), %edi
	subl	%edx, %eax
	addl	%esi, %edi
	vmovd	%eax, %xmm7
	movzbl	2569(%r12), %eax
	movslq	%edi, %rdx
	movl	%edi, %r8d
	imulq	$1808407283, %rdx, %rdx
	sarl	$31, %r8d
	sarq	$35, %rdx
	subl	%r8d, %edx
	leal	(%rdx,%rdx,8), %r8d
	leal	(%rdx,%r8,2), %edx
	subl	%edx, %edi
	movzbl	2563(%r12), %edx
	movq	%rdx, %r8
	imulq	$1808407283, %rdx, %rdx
	shrq	$35, %rdx
	leal	(%rdx,%rdx,8), %r9d
	leal	(%rdx,%r9,2), %edx
	movzbl	2564(%r12), %r9d
	subl	%edx, %r8d
	addl	%ecx, %r9d
	vmovd	%r8d, %xmm0
	movslq	%r9d, %rdx
	movl	%r9d, %r8d
	imulq	$1808407283, %rdx, %rdx
	sarl	$31, %r8d
	sarq	$35, %rdx
	subl	%r8d, %edx
	leal	(%rdx,%rdx,8), %r8d
	leal	(%rdx,%r8,2), %edx
	subl	%edx, %r9d
	movzbl	2565(%r12), %edx
	addl	%esi, %edx
	movslq	%edx, %r8
	movl	%edx, %r10d
	imulq	$1808407283, %r8, %r8
	sarl	$31, %r10d
	sarq	$35, %r8
	subl	%r10d, %r8d
	leal	(%r8,%r8,8), %r10d
	leal	(%r8,%r10,2), %r8d
	subl	%r8d, %edx
	vmovd	%edx, %xmm5
	movzbl	2566(%r12), %edx
	movq	%rdx, %r10
	imulq	$1808407283, %rdx, %rdx
	shrq	$35, %rdx
	leal	(%rdx,%rdx,8), %r11d
	leal	(%rdx,%r11,2), %edx
	subl	%edx, %r10d
	movzbl	2567(%r12), %edx
	vpinsrd	$1, %r10d, %xmm5, %xmm5
	addl	%ebx, %edx
	movslq	%edx, %r10
	movl	%edx, %r11d
	imulq	$1808407283, %r10, %r10
	sarl	$31, %r11d
	sarq	$35, %r10
	subl	%r11d, %r10d
	leal	(%r10,%r10,8), %r11d
	leal	(%r10,%r11,2), %r10d
	subl	%r10d, %edx
	movzbl	2568(%r12), %r10d
	vmovd	%edx, %xmm6
	addl	%esi, %r10d
	movslq	%r10d, %rsi
	movl	%r10d, %r11d
	imulq	$1808407283, %rsi, %rsi
	sarl	$31, %r11d
	sarq	$35, %rsi
	subl	%r11d, %esi
	leal	(%rsi,%rsi,8), %r11d
	leal	(%rsi,%r11,2), %edx
	subl	%edx, %r10d
	movq	%rax, %rdx
	imulq	$1808407283, %rax, %rax
	vpinsrd	$1, %r10d, %xmm6, %xmm6
	vpunpcklqdq	%xmm6, %xmm5, %xmm5
	vpinsrd	$1, %r9d, %xmm0, %xmm6
	vpinsrd	$1, %edi, %xmm7, %xmm0
	vpunpcklqdq	%xmm6, %xmm0, %xmm0
	shrq	$35, %rax
	vinserti128	$0x1, %xmm5, %ymm0, %ymm0
	leal	(%rax,%rax,8), %esi
	vpshufb	%ymm4, %ymm0, %ymm5
	vpshufb	%ymm3, %ymm0, %ymm0
	leal	(%rax,%rsi,2), %eax
	movzbl	2570(%r12), %esi
	vpermq	$78, %ymm5, %ymm5
	subl	%eax, %edx
	vpor	%ymm5, %ymm0, %ymm0
	addl	%ebx, %esi
	vmovq	%xmm0, 2561(%r12)
	vmovd	%edx, %xmm0
	movslq	%esi, %rax
	movl	%esi, %edx
	imulq	$1808407283, %rax, %rax
	sarl	$31, %edx
	sarq	$35, %rax
	subl	%edx, %eax
	leal	(%rax,%rax,8), %edx
	leal	(%rax,%rdx,2), %eax
	subl	%eax, %esi
	movzbl	2571(%r12), %eax
	vpinsrd	$1, %esi, %xmm0, %xmm0
	addl	%ecx, %eax
	movslq	%eax, %rdx
	movl	%eax, %edi
	imulq	$1808407283, %rdx, %rdx
	sarl	$31, %edi
	sarq	$35, %rdx
	subl	%edi, %edx
	leal	(%rdx,%rdx,8), %edi
	leal	(%rdx,%rdi,2), %edx
	subl	%edx, %eax
	movzbl	2572(%r12), %edx
	vmovd	%eax, %xmm6
	movzbl	2573(%r12), %eax
	movq	%rdx, %rdi
	imulq	$1808407283, %rdx, %rdx
	shrq	$35, %rdx
	addl	%ebx, %eax
	leal	(%rdx,%rdx,8), %r8d
	movl	%eax, %esi
	leal	(%rdx,%r8,2), %edx
	sarl	$31, %esi
	subl	%edx, %edi
	movslq	%eax, %rdx
	imulq	$1808407283, %rdx, %rdx
	vpinsrd	$1, %edi, %xmm6, %xmm5
	movq	%r14, %rdi
	vpunpcklqdq	%xmm5, %xmm0, %xmm0
	vpshufb	%xmm2, %xmm0, %xmm0
	sarq	$35, %rdx
	vmovd	%xmm0, 2569(%r12)
	subl	%esi, %edx
	leal	(%rdx,%rdx,8), %esi
	leal	(%rdx,%rsi,2), %edx
	subl	%edx, %eax
	movzbl	2574(%r12), %edx
	vmovd	%eax, %xmm6
	movl	%ebx, %eax
	addl	%edx, %ecx
	sall	$4, %eax
	movslq	%ecx, %rdx
	movl	%ecx, %esi
	subl	%ebx, %eax
	imulq	$1808407283, %rdx, %rdx
	sarl	$31, %esi
	sarq	$35, %rdx
	subl	%esi, %edx
	leal	(%rdx,%rdx,8), %esi
	leal	(%rdx,%rsi,2), %edx
	subl	%edx, %ecx
	movzbl	2575(%r12), %edx
	vpinsrd	$1, %ecx, %xmm6, %xmm0
	addl	%eax, %edx
	vpshufb	%xmm1, %xmm0, %xmm0
	movslq	%edx, %rax
	movl	%edx, %ecx
	vpextrw	$0, %xmm0, 2573(%r12)
	imulq	$1808407283, %rax, %rax
	sarl	$31, %ecx
	sarq	$35, %rax
	subl	%ecx, %eax
	leal	(%rax,%rax,8), %ecx
	leal	(%rax,%rcx,2), %eax
	subl	%eax, %edx
	movb	%dl, 2575(%r12)
	call	gf_mat_det
	testb	%al, %al
	jne	.L828
	incl	%ebx
	cmpl	$19, %ebx
	jne	.L827
.L828:
	cmpb	$0, 3(%r13)
	jne	.L832
	movzbl	0(%r13), %edx
	movl	$19, %eax
	subl	%edx, %eax
	cmpb	$1, %dl
	sbbb	$0, %al
	movb	%al, 3(%r13)
.L832:
	cmpb	$0, 643(%r13)
	jne	.L834
	movzbl	640(%r13), %edx
	movl	$19, %eax
	subl	%edx, %eax
	cmpb	$1, %dl
	sbbb	$0, %al
	movb	%al, 643(%r13)
.L834:
	addq	$16, %r15
	addq	$16, %r12
	addq	$4, %r13
	cmpq	384(%rsp), %r15
	jne	.L835
	movq	368(%rsp), %r13
	movq	376(%rsp), %rsi
	movl	$640, %edx
	vzeroupper
	leaq	523520(%r13), %rdi
	call	memcpy@PLT
	leaq	524160(%r13), %rdi
	leaq	12032(%rsp), %rsi
	movl	$640, %edx
	call	memcpy@PLT
.L767:
	movq	357016(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L989
	movl	392(%rsp), %eax
	leaq	-40(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	.cfi_remember_state
	.cfi_def_cfa 7, 8
	ret
.L990:
	.cfi_restore_state
	movb	$0, 2054(%rsp,%rcx)
	cmpq	$4217, %rcx
	je	.L781
	movb	$0, 2055(%rsp,%rcx)
	cmpq	$4216, %rcx
	je	.L781
	movb	$0, 2056(%rsp,%rcx)
	cmpq	$4215, %rcx
	je	.L781
	movb	$0, 2057(%rsp,%rcx)
	cmpq	$4214, %rcx
	je	.L781
	movb	$0, 2058(%rsp,%rcx)
	cmpq	$4213, %rcx
	je	.L781
	movb	$0, 2059(%rsp,%rcx)
	cmpq	$4212, %rcx
	je	.L781
	movb	$0, 2060(%rsp,%rcx)
	cmpq	$4211, %rcx
	je	.L781
	movb	$0, 2061(%rsp,%rcx)
	cmpq	$4210, %rcx
	je	.L781
	movb	$0, 2062(%rsp,%rcx)
	addq	$15, %rcx
	cmpq	$4224, %rcx
	je	.L781
.L797:
	movb	$0, 2048(%rsp,%rcx)
	cmpq	$4223, %rcx
	je	.L781
	movb	$0, 2049(%rsp,%rcx)
	cmpq	$4222, %rcx
	je	.L781
	movb	$0, 2050(%rsp,%rcx)
	cmpq	$4221, %rcx
	je	.L781
	movb	$0, 2051(%rsp,%rcx)
	cmpq	$4220, %rcx
	je	.L781
	movb	$0, 2052(%rsp,%rcx)
	cmpq	$4219, %rcx
	je	.L781
	movb	$0, 2053(%rsp,%rcx)
	cmpq	$4218, %rcx
	jne	.L990
	jmp	.L781
.L845:
	movl	$-1, 392(%rsp)
	jmp	.L767
.L989:
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE19:
	.size	_snova_37_8_19_4_SNOVA_OPT_pk_expand, .-_snova_37_8_19_4_SNOVA_OPT_pk_expand
	.p2align 4
	.globl	_snova_37_8_19_4_SNOVA_OPT_verify
	.type	_snova_37_8_19_4_SNOVA_OPT_verify, @function
_snova_37_8_19_4_SNOVA_OPT_verify:
.LFB20:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%r15
	pushq	%r14
	pushq	%r13
	pushq	%r12
	.cfi_offset 15, -24
	.cfi_offset 14, -32
	.cfi_offset 13, -40
	.cfi_offset 12, -48
	movq	%rdi, %r12
	xorl	%edi, %edi
	pushq	%rbx
	.cfi_offset 3, -56
	movq	%rsi, %rbx
	movabsq	$-2912643801112034465, %rsi
	andq	$-64, %rsp
	subq	$16832, %rsp
	movq	%rcx, 24(%rsp)
	xorl	%ecx, %ecx
	movq	%rdx, 32(%rsp)
	movq	%fs:40, %r13
	movq	%r13, 16824(%rsp)
	xorl	%r13d, %r13d
	cmpq	$383, %rdi
	ja	.L1021
.L1200:
	movzbl	1(%rbx,%rdi), %edx
	movzbl	(%rbx,%rdi), %eax
	leaq	8(%rdi), %r10
	movzbl	7(%rbx,%rdi), %r8d
	salq	$8, %rdx
	xorq	%rax, %rdx
	movzbl	2(%rbx,%rdi), %eax
	salq	$56, %r8
	salq	$16, %rax
	xorq	%rdx, %rax
	movzbl	3(%rbx,%rdi), %edx
	salq	$24, %rdx
	xorq	%rax, %rdx
	movzbl	4(%rbx,%rdi), %eax
	salq	$32, %rax
	xorq	%rdx, %rax
	movzbl	5(%rbx,%rdi), %edx
	salq	$40, %rdx
	xorq	%rax, %rdx
	movzbl	6(%rbx,%rdi), %eax
	salq	$48, %rax
	xorq	%rdx, %rax
	xorq	%rax, %r8
.L992:
	movq	%r8, %rax
	mulq	%rsi
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r9
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %r8
	movq	%rdx, %rax
	mulq	%rsi
	movb	%r8b, 10976(%rsp,%rcx)
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r8
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %r9
	movq	%rdx, %rax
	mulq	%rsi
	movb	%r9b, 10977(%rsp,%rcx)
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r9
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %r8
	movq	%rdx, %rax
	mulq	%rsi
	movb	%r8b, 10978(%rsp,%rcx)
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r8
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %r9
	movq	%rdx, %rax
	mulq	%rsi
	movb	%r9b, 10979(%rsp,%rcx)
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r9
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %r8
	movq	%rdx, %rax
	mulq	%rsi
	movb	%r8b, 10980(%rsp,%rcx)
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r8
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %r9
	movq	%rdx, %rax
	mulq	%rsi
	movb	%r9b, 10981(%rsp,%rcx)
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r9
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %r8
	movq	%rdx, %rax
	mulq	%rsi
	movb	%r8b, 10982(%rsp,%rcx)
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r8
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %r9
	movq	%rdx, %rax
	mulq	%rsi
	movb	%r9b, 10983(%rsp,%rcx)
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r9
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %r8
	movq	%rdx, %rax
	mulq	%rsi
	movb	%r8b, 10984(%rsp,%rcx)
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r8
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %r9
	movq	%rdx, %rax
	mulq	%rsi
	movb	%r9b, 10985(%rsp,%rcx)
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r9
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %r8
	movq	%rdx, %rax
	mulq	%rsi
	movb	%r8b, 10986(%rsp,%rcx)
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r8
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %r9
	movq	%rdx, %rax
	mulq	%rsi
	movb	%r9b, 10987(%rsp,%rcx)
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r9
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %r8
	movq	%rdx, %rax
	mulq	%rsi
	movb	%r8b, 10988(%rsp,%rcx)
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r8
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %r9
	movq	%rdx, %rax
	mulq	%rsi
	movb	%r9b, 10989(%rsp,%rcx)
	movq	%rdx, %rax
	shrq	$4, %rax
	leaq	(%rax,%rax,8), %rdx
	orl	%eax, %r13d
	leaq	(%rax,%rdx,2), %rdx
	subq	%rdx, %r8
	movb	%r8b, 10990(%rsp,%rcx)
	addq	$15, %rcx
	cmpq	$720, %rcx
	je	.L993
	cmpq	$383, %rdi
	ja	.L995
	movq	%r10, %rdi
	cmpq	$383, %rdi
	jbe	.L1200
.L1021:
	movq	%rdi, %r10
	xorl	%r8d, %r8d
	jmp	.L992
.L1201:
	movb	$0, 10982(%rsp,%rcx)
	cmpq	$713, %rcx
	je	.L993
	movb	$0, 10983(%rsp,%rcx)
	cmpq	$712, %rcx
	je	.L993
	movb	$0, 10984(%rsp,%rcx)
	cmpq	$711, %rcx
	je	.L993
	movb	$0, 10985(%rsp,%rcx)
	cmpq	$710, %rcx
	je	.L993
	movb	$0, 10986(%rsp,%rcx)
	cmpq	$709, %rcx
	je	.L993
	movb	$0, 10987(%rsp,%rcx)
	cmpq	$708, %rcx
	je	.L993
	movb	$0, 10988(%rsp,%rcx)
	cmpq	$707, %rcx
	je	.L993
	movb	$0, 10989(%rsp,%rcx)
	cmpq	$706, %rcx
	je	.L993
	movb	$0, 10990(%rsp,%rcx)
	addq	$15, %rcx
	cmpq	$720, %rcx
	je	.L993
.L995:
	movb	$0, 10976(%rsp,%rcx)
	cmpq	$719, %rcx
	je	.L993
	movb	$0, 10977(%rsp,%rcx)
	cmpq	$718, %rcx
	je	.L993
	movb	$0, 10978(%rsp,%rcx)
	cmpq	$717, %rcx
	je	.L993
	movb	$0, 10979(%rsp,%rcx)
	cmpq	$716, %rcx
	je	.L993
	movb	$0, 10980(%rsp,%rcx)
	cmpq	$715, %rcx
	je	.L993
	movb	$0, 10981(%rsp,%rcx)
	cmpq	$714, %rcx
	jne	.L1201
.L993:
	testl	%r13d, %r13d
	jne	.L999
	leaq	518400(%r12), %rax
	leaq	11696(%rsp), %rdi
	movl	$2560, %edx
	movq	%rax, %rsi
	movq	%rdi, 56(%rsp)
	movq	%rax, 48(%rsp)
	call	memcpy@PLT
	leaq	14256(%rsp), %rax
	leaq	520960(%r12), %rsi
	movl	$2560, %edx
	movq	%rax, %rdi
	movq	%rax, 40(%rsp)
	call	memcpy@PLT
	leaq	10977(%rsp), %rax
	leaq	11697(%rsp), %rsi
	xorl	%ecx, %ecx
.L998:
	movzbl	5(%rax), %edi
	movzbl	1(%rax), %r11d
	cmpb	%dil, 8(%rax)
	movzbl	2(%rax), %edi
	sete	%dl
	cmpb	%dil, 11(%rax)
	sete	%dil
	andl	%edi, %edx
	movzbl	12(%rax), %edi
	cmpb	%dil, 6(%rax)
	sete	%dil
	andl	%edi, %edx
	movzbl	10(%rax), %edi
	cmpb	%dil, 13(%rax)
	sete	%dil
	andl	%edi, %edx
	movzbl	(%rax), %edi
	cmpb	%dil, 3(%rax)
	sete	%dil
	cmpb	%r11b, 7(%rax)
	sete	%r8b
	addq	$16, %rax
	andl	%r8d, %edi
	andl	%edi, %edx
	movzbl	%dl, %edx
	addl	%edx, %ecx
	cmpq	%rax, %rsi
	jne	.L998
	testl	%ecx, %ecx
	jg	.L999
	leaq	4960(%rsp), %r14
	xorl	%esi, %esi
	movl	$5760, %edx
	movq	%r14, %rdi
	call	memset@PLT
	leaq	_snova_37_8_19_4_SNOVA_OPT_Smat(%rip), %rdi
	movq	%r14, %rsi
	xorl	%ecx, %ecx
	leaq	11696(%rsp), %r8
.L1000:
	vmovdqa	(%rdi), %ymm3
	movq	%rsi, %rdx
	leaq	10976(%rsp), %rax
	vpshufb	.LC64(%rip), %ymm3, %ymm6
	vpshufb	.LC65(%rip), %ymm3, %ymm5
	vpshufb	.LC66(%rip), %ymm3, %ymm4
	vpshufb	.LC67(%rip), %ymm3, %ymm3
.L1001:
	vmovdqa	(%rax), %xmm1
	addq	$16, %rax
	subq	$-128, %rdx
	vpshufd	$0, %xmm1, %xmm0
	vpshufd	$85, %xmm1, %xmm2
	vpmovzxbw	%xmm0, %ymm0
	vpmovzxbw	%xmm2, %ymm2
	vpmullw	%ymm5, %ymm2, %ymm2
	vpmullw	%ymm6, %ymm0, %ymm0
	vpaddw	%ymm2, %ymm0, %ymm0
	vpshufd	$170, %xmm1, %xmm2
	vpshufd	$255, %xmm1, %xmm1
	vpmovzxbw	%xmm2, %ymm2
	vpmovzxbw	%xmm1, %ymm1
	vpaddw	-128(%rdx), %ymm0, %ymm0
	vpmullw	%ymm4, %ymm2, %ymm2
	vpmullw	%ymm3, %ymm1, %ymm1
	vpaddw	%ymm1, %ymm2, %ymm1
	vpaddw	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, -128(%rdx)
	cmpq	%rax, %r8
	jne	.L1001
	incq	%rcx
	addq	$32, %rsi
	addq	$32, %rdi
	cmpq	$4, %rcx
	jne	.L1000
	movl	$-678045803, %edx
	leaq	5760(%r14), %r15
	movq	%r14, %rax
	vmovd	%edx, %xmm3
	vpbroadcastd	%xmm3, %ymm3
.L1003:
	vmovdqa	(%rax), %ymm2
	addq	$32, %rax
	vpmulhuw	%ymm3, %ymm2, %ymm1
	vpsrlw	$4, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm0
	vpaddw	%ymm1, %ymm0, %ymm0
	vpsllw	$2, %ymm0, %ymm0
	vpsubw	%ymm1, %ymm0, %ymm0
	vpsubw	%ymm0, %ymm2, %ymm2
	vmovdqa	%ymm2, -32(%rax)
	cmpq	%rax, %r15
	jne	.L1003
	vpxor	%xmm0, %xmm0, %xmm0
	movl	$4096, %edx
	leaq	864(%rsp), %rdi
	xorl	%esi, %esi
	vmovdqa	%ymm0, 576(%rsp)
	vmovdqa	%ymm0, 608(%rsp)
	vmovdqa	%ymm0, 640(%rsp)
	vmovdqa	%ymm0, 672(%rsp)
	vmovdqa	%ymm0, 704(%rsp)
	vmovdqa	%ymm0, 736(%rsp)
	vmovdqa	%ymm0, 768(%rsp)
	vmovdqa	%ymm0, 800(%rsp)
	vzeroupper
	call	memset@PLT
	movl	$-678045803, %edx
	vmovdqa	.LC79(%rip), %ymm13
	movq	%rax, %rcx
	vmovd	%edx, %xmm11
	vmovdqa	.LC99(%rip), %ymm12
	movq	%r12, %r8
	movq	%r12, %rax
	movq	%rcx, %rdi
	vpbroadcastd	%xmm11, %ymm11
.L1004:
	movq	%rax, %r10
	movq	%r14, %r9
.L1007:
	vpxor	%xmm0, %xmm0, %xmm0
	movq	%r14, %rdx
	movq	%r10, %rsi
	vmovdqa	%ymm0, %ymm1
	vmovdqa	%ymm0, %ymm5
	vmovdqa	%ymm0, %ymm6
.L1005:
	vmovdqu	(%rsi), %ymm2
	vpbroadcastq	(%rdx), %ymm8
	subq	$-128, %rdx
	addq	$32, %rsi
	vpbroadcastq	-120(%rdx), %ymm10
	vpshufb	.LC64(%rip), %ymm2, %ymm3
	vpshufb	.LC65(%rip), %ymm2, %ymm7
	vpshufb	.LC66(%rip), %ymm2, %ymm4
	vpmullw	%ymm8, %ymm3, %ymm8
	vpmullw	%ymm10, %ymm7, %ymm10
	vpshufb	.LC67(%rip), %ymm2, %ymm2
	vpaddw	%ymm10, %ymm8, %ymm9
	vpbroadcastq	-104(%rdx), %ymm8
	vpbroadcastq	-112(%rdx), %ymm10
	vpmullw	%ymm8, %ymm2, %ymm8
	vpmullw	%ymm10, %ymm4, %ymm10
	vpaddw	%ymm10, %ymm8, %ymm8
	vpbroadcastq	-80(%rdx), %ymm10
	vpaddw	%ymm8, %ymm9, %ymm8
	vpaddw	%ymm8, %ymm6, %ymm6
	vpbroadcastq	-72(%rdx), %ymm8
	vpmullw	%ymm10, %ymm4, %ymm10
	vpmullw	%ymm8, %ymm2, %ymm8
	vpaddw	%ymm10, %ymm8, %ymm9
	vpbroadcastq	-96(%rdx), %ymm8
	vpbroadcastq	-88(%rdx), %ymm10
	vpmullw	%ymm8, %ymm3, %ymm8
	vpmullw	%ymm10, %ymm7, %ymm10
	vpaddw	%ymm10, %ymm8, %ymm8
	vpbroadcastq	-56(%rdx), %ymm10
	vpaddw	%ymm8, %ymm9, %ymm8
	vpaddw	%ymm8, %ymm5, %ymm5
	vpbroadcastq	-64(%rdx), %ymm8
	vpmullw	%ymm10, %ymm7, %ymm10
	vpmullw	%ymm8, %ymm3, %ymm8
	vpaddw	%ymm10, %ymm8, %ymm9
	vpbroadcastq	-48(%rdx), %ymm8
	vpbroadcastq	-40(%rdx), %ymm10
	vpmullw	%ymm8, %ymm4, %ymm8
	vpmullw	%ymm10, %ymm2, %ymm10
	vpaddw	%ymm10, %ymm8, %ymm8
	vpaddw	%ymm8, %ymm9, %ymm8
	vpaddw	%ymm8, %ymm1, %ymm1
	vpbroadcastq	-32(%rdx), %ymm8
	vpmullw	%ymm8, %ymm3, %ymm3
	vpbroadcastq	-24(%rdx), %ymm8
	vpmullw	%ymm8, %ymm7, %ymm7
	vpaddw	%ymm7, %ymm3, %ymm3
	vpbroadcastq	-8(%rdx), %ymm7
	vpmullw	%ymm7, %ymm2, %ymm2
	vpbroadcastq	-16(%rdx), %ymm7
	vpmullw	%ymm7, %ymm4, %ymm4
	vpaddw	%ymm4, %ymm2, %ymm2
	vpaddw	%ymm2, %ymm3, %ymm2
	vpaddw	%ymm2, %ymm0, %ymm0
	cmpq	%rdx, %r15
	jne	.L1005
	vpmulhuw	%ymm11, %ymm6, %ymm3
	movq	%rdi, %rdx
	movq	%r9, %rsi
	xorl	%r11d, %r11d
	vpsrlw	$4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm2
	vpaddw	%ymm3, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm2
	vpsubw	%ymm3, %ymm2, %ymm2
	vpmulhuw	%ymm11, %ymm5, %ymm3
	vpsubw	%ymm2, %ymm6, %ymm6
	vpsrldq	$8, %xmm6, %xmm4
	vpbroadcastq	%xmm6, %ymm10
	vextracti128	$0x1, %ymm6, %xmm6
	vpbroadcastq	%xmm4, %ymm4
	vpsrlw	$4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm2
	vpaddw	%ymm3, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm2
	vpsubw	%ymm3, %ymm2, %ymm2
	vpmulhuw	%ymm11, %ymm1, %ymm3
	vpsubw	%ymm2, %ymm5, %ymm5
	vpbroadcastq	%xmm5, %ymm9
	vpsrlw	$4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm2
	vpaddw	%ymm3, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm2
	vpsubw	%ymm3, %ymm2, %ymm2
	vpmulhuw	%ymm11, %ymm0, %ymm3
	vpsubw	%ymm2, %ymm1, %ymm1
	vpbroadcastq	%xmm1, %ymm8
	vpsrlw	$4, %ymm3, %ymm3
	vpsllw	$2, %ymm3, %ymm2
	vpaddw	%ymm3, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm2
	vpsubw	%ymm3, %ymm2, %ymm2
	vpsrldq	$8, %xmm5, %xmm3
	vextracti128	$0x1, %ymm5, %xmm5
	vpsubw	%ymm2, %ymm0, %ymm0
	vpsrldq	$8, %xmm1, %xmm2
	vextracti128	$0x1, %ymm1, %xmm1
	vpbroadcastq	%xmm0, %ymm7
	vpbroadcastq	%xmm3, %ymm3
	vpbroadcastq	%xmm2, %ymm2
	vpsrldq	$8, %xmm0, %xmm14
	vpbroadcastq	%xmm14, %ymm15
	vextracti128	$0x1, %ymm0, %xmm0
	vpbroadcastq	%xmm5, %ymm14
	vpsrldq	$8, %xmm5, %xmm5
	vmovdqa	%ymm15, 192(%rsp)
	vpbroadcastq	%xmm6, %ymm15
	vpsrldq	$8, %xmm6, %xmm6
	vpbroadcastq	%xmm5, %ymm5
	vpbroadcastq	%xmm6, %ymm6
	vmovdqa	%ymm15, 224(%rsp)
	vpbroadcastq	%xmm1, %ymm15
	vpsrldq	$8, %xmm1, %xmm1
	vmovdqa	%ymm14, 256(%rsp)
	vpbroadcastq	%xmm0, %ymm14
	vpsrldq	$8, %xmm0, %xmm0
	vmovdqa	%ymm6, 128(%rsp)
	vpbroadcastq	%xmm0, %ymm6
	vmovdqa	%ymm5, 96(%rsp)
	vpbroadcastq	%xmm1, %ymm5
	vmovdqa	%ymm15, 288(%rsp)
	vmovdqa	%ymm14, 320(%rsp)
	vmovdqa	%ymm5, 64(%rsp)
	vmovdqa	%ymm6, 160(%rsp)
.L1006:
	vmovdqa	(%rsi), %ymm0
	addq	$32, %r11
	addq	$32, %rsi
	subq	$-128, %rdx
	vperm2i128	$0, %ymm0, %ymm0, %ymm0
	vpshufb	%ymm13, %ymm0, %ymm0
	vpmullw	%ymm0, %ymm10, %ymm6
	vpmullw	%ymm0, %ymm9, %ymm5
	vpmullw	%ymm0, %ymm8, %ymm15
	vpmullw	%ymm0, %ymm7, %ymm0
	vpaddw	-128(%rdx), %ymm6, %ymm6
	vpaddw	-96(%rdx), %ymm5, %ymm5
	vpaddw	-64(%rdx), %ymm15, %ymm15
	vpaddw	-32(%rdx), %ymm0, %ymm0
	vmovdqa	%ymm6, -128(%rdx)
	vmovdqa	%ymm5, -96(%rdx)
	vmovdqa	%ymm15, -64(%rdx)
	vmovdqa	%ymm0, -32(%rdx)
	vmovdqa	-32(%rsi), %ymm1
	vperm2i128	$0, %ymm1, %ymm1, %ymm1
	vpshufb	%ymm12, %ymm1, %ymm1
	vpmullw	%ymm1, %ymm4, %ymm14
	vpaddw	%ymm6, %ymm14, %ymm14
	vpmullw	%ymm1, %ymm3, %ymm6
	vmovdqa	%ymm14, -128(%rdx)
	vpaddw	%ymm5, %ymm6, %ymm6
	vpmullw	%ymm1, %ymm2, %ymm5
	vpmullw	192(%rsp), %ymm1, %ymm1
	vpaddw	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm6, -96(%rdx)
	vmovdqa	%ymm1, -32(%rdx)
	vpaddw	%ymm15, %ymm5, %ymm5
	vmovdqa	%ymm5, -64(%rdx)
	vmovdqa	-32(%rsi), %ymm0
	vperm2i128	$17, %ymm0, %ymm0, %ymm0
	vpshufb	%ymm13, %ymm0, %ymm0
	vpmullw	224(%rsp), %ymm0, %ymm15
	vpaddw	%ymm14, %ymm15, %ymm14
	vpmullw	256(%rsp), %ymm0, %ymm15
	vpaddw	%ymm6, %ymm15, %ymm6
	vpmullw	288(%rsp), %ymm0, %ymm15
	vpmullw	320(%rsp), %ymm0, %ymm0
	vpaddw	%ymm5, %ymm15, %ymm5
	vpaddw	%ymm1, %ymm0, %ymm1
	vmovdqa	%ymm14, -128(%rdx)
	vmovdqa	%ymm6, -96(%rdx)
	vmovdqa	%ymm5, -64(%rdx)
	vmovdqa	%ymm1, -32(%rdx)
	vmovdqa	-32(%rsi), %ymm0
	vperm2i128	$17, %ymm0, %ymm0, %ymm0
	vpshufb	%ymm12, %ymm0, %ymm0
	vpmullw	128(%rsp), %ymm0, %ymm15
	vpaddw	%ymm14, %ymm15, %ymm14
	vmovdqa	%ymm14, -128(%rdx)
	vpmullw	96(%rsp), %ymm0, %ymm14
	vpaddw	%ymm6, %ymm14, %ymm6
	vmovdqa	%ymm6, -96(%rdx)
	vpmullw	64(%rsp), %ymm0, %ymm6
	vpmullw	160(%rsp), %ymm0, %ymm0
	vpaddw	%ymm5, %ymm6, %ymm5
	vpaddw	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm5, -64(%rdx)
	vmovdqa	%ymm0, -32(%rdx)
	cmpq	$128, %r11
	jne	.L1006
	subq	$-128, %r9
	addq	$1440, %r10
	cmpq	%r15, %r9
	jne	.L1007
	addq	$64800, %rax
	addq	$512, %rdi
	cmpq	%rax, 48(%rsp)
	jne	.L1004
	movl	$-678045803, %edx
	leaq	4096(%rcx), %rsi
	movq	%rcx, %rax
	vmovd	%edx, %xmm3
	vpbroadcastd	%xmm3, %ymm3
.L1009:
	vmovdqa	(%rax), %ymm2
	addq	$32, %rax
	vpmulhuw	%ymm3, %ymm2, %ymm1
	vpsrlw	$4, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm0
	vpaddw	%ymm1, %ymm0, %ymm0
	vpsllw	$2, %ymm0, %ymm0
	vpsubw	%ymm1, %ymm0, %ymm0
	vpsubw	%ymm0, %ymm2, %ymm2
	vmovdqa	%ymm2, -32(%rax)
	cmpq	%rax, %rsi
	jne	.L1009
	leaq	512(%rcx), %rax
	movq	40(%rsp), %r15
	movq	56(%rsp), %rdi
	leaq	576(%rsp), %rsi
	movq	%rax, 224(%rsp)
	movl	$-678045803, %eax
	vmovdqa	.LC100(%rip), %ymm12
	xorl	%edx, %edx
	vmovd	%eax, %xmm1
	vmovd	%eax, %xmm5
	vmovdqa	.LC69(%rip), %xmm14
	vmovdqa	.LC70(%rip), %xmm15
	vpbroadcastd	%xmm1, %ymm1
	vpbroadcastd	%xmm5, %xmm13
	movl	%r13d, %r14d
	movq	%rbx, %r9
.L1010:
	movq	%r8, %rax
	leaq	80(%r8), %r8
	movl	%edx, %ebx
	movq	%rdi, %r11
	movq	%r8, 320(%rsp)
	movq	%r15, %r10
.L1012:
	vpxor	%xmm7, %xmm7, %xmm7
	movl	%ebx, %r13d
	vpxor	%xmm6, %xmm6, %xmm6
	vpinsrw	$0, 524160(%rax), %xmm7, %xmm0
	andl	$7, %r13d
	salq	$9, %r13
	vinserti128	$0x1, %xmm7, %ymm0, %ymm0
	leaq	(%rcx,%r13), %r8
	vperm2i128	$0, %ymm0, %ymm0, %ymm0
	movq	%r8, 256(%rsp)
	movq	224(%rsp), %r8
	vpshufb	%ymm12, %ymm0, %ymm0
	vpmovzxbw	%xmm0, %ymm5
	vextracti128	$0x1, %ymm0, %xmm0
	addq	%r8, %r13
	vpmovzxbw	%xmm0, %ymm3
	vpinsrw	$0, 524162(%rax), %xmm7, %xmm0
	movq	256(%rsp), %r8
	movq	%rax, 256(%rsp)
	movq	%r13, 288(%rsp)
	movq	%rax, %r13
	vinserti128	$0x1, %xmm7, %ymm0, %ymm0
	vperm2i128	$0, %ymm0, %ymm0, %ymm0
	vpshufb	%ymm12, %ymm0, %ymm0
	vpmovzxbw	%xmm0, %ymm7
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
.L1011:
	vpmullw	64(%r8), %ymm7, %ymm4
	vpmullw	(%r8), %ymm5, %ymm8
	vpmullw	96(%r8), %ymm0, %ymm2
	vpaddw	%ymm4, %ymm2, %ymm2
	vpmullw	32(%r8), %ymm3, %ymm4
	vpaddw	%ymm8, %ymm4, %ymm4
	movzbl	523520(%r13), %eax
	subq	$-128, %r8
	vpaddw	%ymm4, %ymm2, %ymm2
	incq	%r13
	vpmulhuw	%ymm1, %ymm2, %ymm8
	vpsrlw	$4, %ymm8, %ymm8
	vpsllw	$2, %ymm8, %ymm4
	vpaddw	%ymm8, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm4
	vpsubw	%ymm8, %ymm4, %ymm4
	vpsubw	%ymm4, %ymm2, %ymm2
	vmovd	%eax, %xmm4
	vpbroadcastw	%xmm4, %ymm4
	vpmullw	%ymm4, %ymm2, %ymm2
	vpaddw	%ymm2, %ymm6, %ymm6
	cmpq	%r8, 288(%rsp)
	jne	.L1011
	vpmulhuw	%ymm1, %ymm6, %ymm0
	vmovdqa	(%r10), %xmm3
	movq	256(%rsp), %rax
	incl	%ebx
	addq	$16, %r10
	addq	$16, %r11
	addq	$4, %rax
	vpsrlw	$4, %ymm0, %ymm0
	vpsllw	$2, %ymm0, %ymm2
	vpaddw	%ymm0, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm2
	vpsubw	%ymm0, %ymm2, %ymm2
	vpshufd	$170, %xmm3, %xmm0
	vpsubw	%ymm2, %ymm6, %ymm2
	vpmovzxbw	%xmm0, %ymm0
	vpshufb	.LC66(%rip), %ymm2, %ymm4
	vpshufb	.LC67(%rip), %ymm2, %ymm5
	vpmullw	%ymm4, %ymm0, %ymm0
	vpshufd	$255, %xmm3, %xmm4
	vpmovzxbw	%xmm4, %ymm4
	vpmullw	%ymm5, %ymm4, %ymm4
	vpshufb	.LC64(%rip), %ymm2, %ymm5
	vpshufb	.LC65(%rip), %ymm2, %ymm2
	vpaddw	%ymm4, %ymm0, %ymm0
	vpshufd	$0, %xmm3, %xmm4
	vpshufd	$85, %xmm3, %xmm3
	vpmovzxbw	%xmm3, %ymm3
	vpmovzxbw	%xmm4, %ymm4
	vpmullw	%ymm5, %ymm4, %ymm4
	vpmullw	%ymm2, %ymm3, %ymm2
	vpaddw	%ymm2, %ymm4, %ymm2
	vmovdqa	-16(%r11), %xmm4
	vpaddw	%ymm2, %ymm0, %ymm0
	vpermq	$224, %ymm0, %ymm8
	vpermq	$229, %ymm0, %ymm7
	vpermq	$234, %ymm0, %ymm6
	vpmulhuw	%xmm13, %xmm8, %xmm3
	vpermq	$239, %ymm0, %ymm0
	vpshufb	%xmm15, %xmm4, %xmm9
	vpsrldq	$8, %xmm9, %xmm10
	vpshufb	.LC71(%rip), %xmm4, %xmm5
	vpmovzxbw	%xmm10, %xmm10
	vpsrlw	$4, %xmm3, %xmm3
	vpsllw	$2, %xmm3, %xmm2
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsllw	$2, %xmm2, %xmm2
	vpsubw	%xmm3, %xmm2, %xmm2
	vpmulhuw	%xmm13, %xmm7, %xmm3
	vpsubw	%xmm2, %xmm8, %xmm8
	vpsrlw	$4, %xmm3, %xmm3
	vpsllw	$2, %xmm3, %xmm2
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsllw	$2, %xmm2, %xmm2
	vpsubw	%xmm3, %xmm2, %xmm2
	vpmulhuw	%xmm13, %xmm6, %xmm3
	vpsubw	%xmm2, %xmm7, %xmm7
	vpmullw	%xmm7, %xmm10, %xmm10
	vpsrlw	$4, %xmm3, %xmm3
	vpsllw	$2, %xmm3, %xmm2
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsllw	$2, %xmm2, %xmm2
	vpsubw	%xmm3, %xmm2, %xmm2
	vpmulhuw	%xmm13, %xmm0, %xmm3
	vpsubw	%xmm2, %xmm6, %xmm6
	vpsrlw	$4, %xmm3, %xmm3
	vpsllw	$2, %xmm3, %xmm2
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsllw	$2, %xmm2, %xmm2
	vpsubw	%xmm3, %xmm2, %xmm2
	vpsubw	%xmm2, %xmm0, %xmm0
	vpshufb	%xmm14, %xmm4, %xmm2
	vpshufb	.LC72(%rip), %xmm4, %xmm4
	vpsrldq	$8, %xmm2, %xmm3
	vpsrldq	$8, %xmm4, %xmm11
	vpmovzxbw	%xmm2, %xmm2
	vpmovzxbw	%xmm3, %xmm3
	vpmullw	%xmm8, %xmm2, %xmm2
	vpmovzxbw	%xmm11, %xmm11
	vpmullw	%xmm8, %xmm3, %xmm3
	vpmovzxbw	%xmm9, %xmm8
	vpmovzxbw	%xmm4, %xmm4
	vpmullw	%xmm7, %xmm8, %xmm7
	vpmullw	%xmm0, %xmm11, %xmm11
	vpmullw	%xmm0, %xmm4, %xmm0
	vpaddw	%xmm10, %xmm3, %xmm3
	vpsrldq	$8, %xmm5, %xmm10
	vpmovzxbw	%xmm5, %xmm5
	vpmovzxbw	%xmm10, %xmm10
	vpmullw	%xmm6, %xmm5, %xmm5
	vpaddw	%xmm7, %xmm2, %xmm2
	vpmullw	%xmm6, %xmm10, %xmm10
	vpaddw	16(%rsi), %xmm3, %xmm3
	vpaddw	(%rsi), %xmm2, %xmm2
	vpaddw	%xmm0, %xmm5, %xmm0
	vpaddw	%xmm11, %xmm10, %xmm10
	vpaddw	%xmm0, %xmm2, %xmm0
	vpaddw	%xmm10, %xmm3, %xmm3
	vmovdqa	%xmm0, (%rsi)
	vmovdqa	%xmm3, 16(%rsi)
	cmpq	%rax, 320(%rsp)
	jne	.L1012
	incl	%edx
	addq	$32, %rsi
	addq	$320, %r15
	addq	$320, %rdi
	cmpl	$8, %edx
	je	.L1013
	movq	320(%rsp), %r8
	jmp	.L1010
.L1025:
	vmovdqa	.LC93(%rip), %ymm1
	vmovdqa	.LC94(%rip), %ymm0
.L1018:
	vmovd	%xmm1, %eax
	xorl	%edx, %edx
	leal	-1(%rax), %esi
	vmovd	%xmm0, %eax
	cltq
	leaq	576(%rsp,%rax,2), %rcx
	leaq	10720(%rsp,%rax), %rax
	jmp	.L1019
.L1202:
	cmpq	%rsi, %rdx
	je	.L1197
	incq	%rdx
.L1019:
	movzbl	(%rax,%rdx), %edi
	cmpw	(%rcx,%rdx,2), %di
	je	.L1202
	vzeroupper
.L999:
	movl	$-1, %r13d
.L991:
	movq	16824(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L1203
	leaq	-40(%rbp), %rsp
	movl	%r13d, %eax
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	.cfi_remember_state
	.cfi_def_cfa 7, 8
	ret
.L1013:
	.cfi_restore_state
	vmovdqa	576(%rsp), %ymm3
	vmovdqa	608(%rsp), %ymm9
	leaq	352(%rsp), %rdi
	movq	%r9, %rbx
	vmovdqa	640(%rsp), %ymm8
	vmovdqa	672(%rsp), %ymm7
	movl	%r14d, %r13d
	vpmulhuw	%ymm1, %ymm3, %ymm2
	vmovdqa	704(%rsp), %ymm6
	vmovdqa	736(%rsp), %ymm5
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm0
	vpaddw	%ymm2, %ymm0, %ymm0
	vpsllw	$2, %ymm0, %ymm0
	vpsubw	%ymm2, %ymm0, %ymm0
	vpmulhuw	%ymm1, %ymm9, %ymm2
	vpsubw	%ymm0, %ymm3, %ymm3
	vmovdqa	%ymm3, 576(%rsp)
	vmovdqa	%ymm3, 96(%rsp)
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm0
	vpaddw	%ymm2, %ymm0, %ymm0
	vpsllw	$2, %ymm0, %ymm0
	vpsubw	%ymm2, %ymm0, %ymm0
	vpmulhuw	%ymm1, %ymm8, %ymm2
	vpsubw	%ymm0, %ymm9, %ymm9
	vmovdqa	%ymm9, 608(%rsp)
	vmovdqa	%ymm9, 128(%rsp)
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm0
	vpaddw	%ymm2, %ymm0, %ymm0
	vpsllw	$2, %ymm0, %ymm0
	vpsubw	%ymm2, %ymm0, %ymm0
	vpmulhuw	%ymm1, %ymm7, %ymm2
	vpsubw	%ymm0, %ymm8, %ymm8
	vmovdqa	%ymm8, 640(%rsp)
	vmovdqa	%ymm8, 160(%rsp)
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm0
	vpaddw	%ymm2, %ymm0, %ymm0
	vpsllw	$2, %ymm0, %ymm0
	vpsubw	%ymm2, %ymm0, %ymm0
	vpmulhuw	%ymm1, %ymm6, %ymm2
	vpsubw	%ymm0, %ymm7, %ymm7
	vmovdqa	%ymm7, 672(%rsp)
	vmovdqa	%ymm7, 192(%rsp)
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm0
	vpaddw	%ymm2, %ymm0, %ymm0
	vpsllw	$2, %ymm0, %ymm0
	vpsubw	%ymm2, %ymm0, %ymm0
	vpmulhuw	%ymm1, %ymm5, %ymm2
	vpsubw	%ymm0, %ymm6, %ymm6
	vmovdqa	%ymm6, 704(%rsp)
	vmovdqa	%ymm6, 224(%rsp)
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$2, %ymm2, %ymm0
	vpaddw	%ymm2, %ymm0, %ymm0
	vpsllw	$2, %ymm0, %ymm0
	vpsubw	%ymm2, %ymm0, %ymm0
	vmovdqa	768(%rsp), %ymm2
	vpsubw	%ymm0, %ymm5, %ymm5
	vpmulhuw	%ymm1, %ymm2, %ymm4
	vmovdqa	%ymm5, 736(%rsp)
	vmovdqa	%ymm5, 256(%rsp)
	vpsrlw	$4, %ymm4, %ymm4
	vpsllw	$2, %ymm4, %ymm0
	vpaddw	%ymm4, %ymm0, %ymm0
	vpsllw	$2, %ymm0, %ymm0
	vpsubw	%ymm4, %ymm0, %ymm0
	vmovdqa	800(%rsp), %ymm4
	vpsubw	%ymm0, %ymm2, %ymm2
	vpmulhuw	%ymm1, %ymm4, %ymm0
	vmovdqa	%ymm2, 768(%rsp)
	vmovdqa	%ymm2, 288(%rsp)
	vpsrlw	$4, %ymm0, %ymm0
	vpsllw	$2, %ymm0, %ymm1
	vpaddw	%ymm0, %ymm1, %ymm1
	vpsllw	$2, %ymm1, %ymm1
	vpsubw	%ymm0, %ymm1, %ymm0
	vpsubw	%ymm0, %ymm4, %ymm4
	vpxor	%xmm0, %xmm0, %xmm0
	vmovdqa	%ymm4, 800(%rsp)
	vmovdqa	%ymm4, 320(%rsp)
	vmovdqa	%ymm0, 10720(%rsp)
	vmovdqa	%ymm0, 10752(%rsp)
	vmovdqa	%ymm0, 10784(%rsp)
	vmovdqa	%ymm0, 10816(%rsp)
	vzeroupper
	call	shake256_init@PLT
	leaq	524800(%r12), %rsi
	movl	$16, %edx
	leaq	352(%rsp), %rdi
	call	shake_absorb@PLT
	movq	24(%rsp), %rdx
	movq	32(%rsp), %rsi
	leaq	352(%rsp), %rdi
	call	shake_absorb@PLT
	leaq	384(%rbx), %rsi
	movl	$16, %edx
	leaq	352(%rsp), %rdi
	call	shake_absorb@PLT
	leaq	352(%rsp), %rdi
	call	shake_finalize@PLT
	leaq	10848(%rsp), %rdi
	leaq	352(%rsp), %rdx
	movl	$128, %esi
	call	shake_squeeze@PLT
	xorl	%edi, %edi
	vmovdqa	256(%rsp), %ymm5
	vmovdqa	128(%rsp), %ymm9
	vmovdqa	96(%rsp), %ymm3
	vmovdqa	192(%rsp), %ymm7
	xorl	%ecx, %ecx
	movabsq	$-2912643801112034465, %r8
	vmovdqa	160(%rsp), %ymm8
	vmovdqa	320(%rsp), %ymm4
	vmovdqa	224(%rsp), %ymm6
	vmovdqa	288(%rsp), %ymm2
	cmpq	$68, %rdi
	ja	.L1023
.L1204:
	movzbl	10848(%rsp,%rdi), %esi
	leaq	1(%rdi), %r10
	je	.L1014
	movzbl	10848(%rsp,%r10), %edx
	movzbl	10850(%rsp,%rdi), %eax
	leaq	4(%rdi), %r10
	salq	$8, %rdx
	salq	$16, %rax
	xorq	%rsi, %rdx
	movzbl	10851(%rsp,%rdi), %esi
	xorq	%rdx, %rax
	salq	$24, %rsi
	xorq	%rax, %rsi
	cmpq	$65, %rdi
	je	.L1014
	movzbl	10848(%rsp,%r10), %eax
	leaq	5(%rdi), %r10
	salq	$32, %rax
	xorq	%rax, %rsi
	cmpq	$64, %rdi
	je	.L1014
	movzbl	10848(%rsp,%r10), %edx
	movzbl	10854(%rsp,%rdi), %eax
	leaq	8(%rdi), %r10
	salq	$40, %rdx
	salq	$48, %rax
	xorq	%rsi, %rdx
	movzbl	10855(%rsp,%rdi), %esi
	xorq	%rdx, %rax
	salq	$56, %rsi
	xorq	%rax, %rsi
.L1014:
	movq	%rsi, %rax
	mulq	%r8
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r9
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %rsi
	movq	%rdx, %rax
	mulq	%r8
	movb	%sil, 10720(%rsp,%rcx)
	movq	%rdx, %rsi
	shrq	$4, %rsi
	leaq	(%rsi,%rsi,8), %rax
	leaq	(%rsi,%rax,2), %rax
	subq	%rax, %r9
	movq	%rsi, %rax
	mulq	%r8
	movb	%r9b, 10721(%rsp,%rcx)
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r9
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %rsi
	movq	%rdx, %rax
	mulq	%r8
	movb	%sil, 10722(%rsp,%rcx)
	movq	%rdx, %rsi
	shrq	$4, %rsi
	leaq	(%rsi,%rsi,8), %rax
	leaq	(%rsi,%rax,2), %rax
	subq	%rax, %r9
	movq	%rsi, %rax
	mulq	%r8
	movb	%r9b, 10723(%rsp,%rcx)
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r9
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %rsi
	movq	%rdx, %rax
	mulq	%r8
	movb	%sil, 10724(%rsp,%rcx)
	movq	%rdx, %rsi
	shrq	$4, %rsi
	leaq	(%rsi,%rsi,8), %rax
	leaq	(%rsi,%rax,2), %rax
	subq	%rax, %r9
	movq	%rsi, %rax
	mulq	%r8
	movb	%r9b, 10725(%rsp,%rcx)
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r9
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %rsi
	movq	%rdx, %rax
	mulq	%r8
	movb	%sil, 10726(%rsp,%rcx)
	movq	%rdx, %rsi
	shrq	$4, %rsi
	leaq	(%rsi,%rsi,8), %rax
	leaq	(%rsi,%rax,2), %rax
	subq	%rax, %r9
	movb	%r9b, 10727(%rsp,%rcx)
	cmpq	$120, %rcx
	je	.L1015
	movq	%rsi, %rax
	mulq	%r8
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r9
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %rsi
	movb	%sil, 10728(%rsp,%rcx)
	cmpq	$119, %rcx
	je	.L1015
	movq	%rdx, %rax
	mulq	%r8
	movq	%rdx, %rsi
	shrq	$4, %rsi
	leaq	(%rsi,%rsi,8), %rax
	leaq	(%rsi,%rax,2), %rax
	subq	%rax, %r9
	movb	%r9b, 10729(%rsp,%rcx)
	cmpq	$118, %rcx
	je	.L1015
	movq	%rsi, %rax
	mulq	%r8
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r9
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %rsi
	movb	%sil, 10730(%rsp,%rcx)
	cmpq	$117, %rcx
	je	.L1015
	movq	%rdx, %rax
	mulq	%r8
	movq	%rdx, %rsi
	shrq	$4, %rsi
	leaq	(%rsi,%rsi,8), %rax
	leaq	(%rsi,%rax,2), %rax
	subq	%rax, %r9
	movb	%r9b, 10731(%rsp,%rcx)
	cmpq	$116, %rcx
	je	.L1015
	movq	%rsi, %rax
	mulq	%r8
	shrq	$4, %rdx
	leaq	(%rdx,%rdx,8), %rax
	movq	%rdx, %r9
	leaq	(%rdx,%rax,2), %rax
	subq	%rax, %rsi
	movb	%sil, 10732(%rsp,%rcx)
	cmpq	$115, %rcx
	je	.L1015
	movq	%rdx, %rax
	mulq	%r8
	movq	%rdx, %rsi
	shrq	$4, %rsi
	leaq	(%rsi,%rsi,8), %rax
	leaq	(%rsi,%rax,2), %rax
	subq	%rax, %r9
	movb	%r9b, 10733(%rsp,%rcx)
	cmpq	$114, %rcx
	je	.L1015
	movq	%rsi, %rax
	mulq	%r8
	movq	%rdx, %rax
	shrq	$4, %rax
	leaq	(%rax,%rax,8), %rdx
	leaq	(%rax,%rdx,2), %rax
	subq	%rax, %rsi
	movb	%sil, 10734(%rsp,%rcx)
	addq	$15, %rcx
	cmpq	$128, %rcx
	je	.L1015
	cmpq	$68, %rdi
	ja	.L1017
	movq	%r10, %rdi
	cmpq	$68, %rdi
	jbe	.L1204
.L1023:
	movq	%rdi, %r10
	xorl	%esi, %esi
	jmp	.L1014
.L1205:
	movb	$0, 10726(%rsp,%rcx)
	cmpq	$121, %rcx
	je	.L1015
	movb	$0, 10727(%rsp,%rcx)
	cmpq	$120, %rcx
	je	.L1015
	movb	$0, 10728(%rsp,%rcx)
	cmpq	$119, %rcx
	je	.L1015
	movb	$0, 10729(%rsp,%rcx)
	cmpq	$118, %rcx
	je	.L1015
	movb	$0, 10730(%rsp,%rcx)
	cmpq	$117, %rcx
	je	.L1015
	movb	$0, 10731(%rsp,%rcx)
	cmpq	$116, %rcx
	je	.L1015
	movb	$0, 10732(%rsp,%rcx)
	cmpq	$115, %rcx
	je	.L1015
	movb	$0, 10733(%rsp,%rcx)
	cmpq	$114, %rcx
	je	.L1015
	movb	$0, 10734(%rsp,%rcx)
	addq	$15, %rcx
	cmpq	$128, %rcx
	je	.L1015
.L1017:
	movb	$0, 10720(%rsp,%rcx)
	cmpq	$127, %rcx
	je	.L1015
	movb	$0, 10721(%rsp,%rcx)
	cmpq	$126, %rcx
	je	.L1015
	movb	$0, 10722(%rsp,%rcx)
	cmpq	$125, %rcx
	je	.L1015
	movb	$0, 10723(%rsp,%rcx)
	cmpq	$124, %rcx
	je	.L1015
	movb	$0, 10724(%rsp,%rcx)
	cmpq	$123, %rcx
	je	.L1015
	movb	$0, 10725(%rsp,%rcx)
	cmpq	$122, %rcx
	jne	.L1205
.L1015:
	vmovdqa	10720(%rsp), %ymm1
	vpmovzxbw	%xmm1, %ymm0
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm1, %ymm1
	vpcmpeqw	%ymm3, %ymm0, %ymm0
	vpxor	%xmm3, %xmm3, %xmm3
	vpcmpeqw	%ymm9, %ymm1, %ymm1
	vpcmpeqw	%ymm3, %ymm0, %ymm0
	vpcmpeqw	%ymm3, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vptest	%ymm0, %ymm0
	jne	.L1025
	vmovdqa	10752(%rsp), %ymm1
	vpmovzxbw	%xmm1, %ymm0
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm1, %ymm1
	vpcmpeqw	%ymm8, %ymm0, %ymm0
	vpcmpeqw	%ymm7, %ymm1, %ymm1
	vpcmpeqw	%ymm3, %ymm0, %ymm0
	vpcmpeqw	%ymm3, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vptest	%ymm0, %ymm0
	jne	.L1026
	vmovdqa	10784(%rsp), %ymm1
	vpmovzxbw	%xmm1, %ymm0
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm1, %ymm1
	vpcmpeqw	%ymm6, %ymm0, %ymm0
	vpcmpeqw	%ymm5, %ymm1, %ymm1
	vpcmpeqw	%ymm3, %ymm0, %ymm0
	vpcmpeqw	%ymm3, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vptest	%ymm0, %ymm0
	jne	.L1027
	vmovdqa	10816(%rsp), %ymm1
	vextracti128	$0x1, %ymm1, %xmm0
	vpmovzxbw	%xmm1, %ymm1
	vpmovzxbw	%xmm0, %ymm0
	vpcmpeqw	%ymm2, %ymm1, %ymm1
	vpcmpeqw	%ymm4, %ymm0, %ymm0
	vpcmpeqw	%ymm3, %ymm1, %ymm1
	vpcmpeqw	%ymm3, %ymm0, %ymm0
	vpor	%ymm1, %ymm0, %ymm0
	vptest	%ymm0, %ymm0
	jne	.L1206
.L1197:
	vzeroupper
	jmp	.L991
.L1026:
	vmovdqa	.LC95(%rip), %ymm1
	vmovdqa	.LC96(%rip), %ymm0
	jmp	.L1018
.L1203:
	call	__stack_chk_fail@PLT
	.p2align 4,,10
	.p2align 3
.L1206:
	vmovdqa	.LC91(%rip), %ymm1
	vmovdqa	.LC92(%rip), %ymm0
	jmp	.L1018
.L1027:
	vmovdqa	.LC97(%rip), %ymm1
	vmovdqa	.LC98(%rip), %ymm0
	jmp	.L1018
	.cfi_endproc
.LFE20:
	.size	_snova_37_8_19_4_SNOVA_OPT_verify, .-_snova_37_8_19_4_SNOVA_OPT_verify
	.section	.rodata
	.align 32
	.type	_snova_37_8_19_4_SNOVA_OPT_Smat, @object
	.size	_snova_37_8_19_4_SNOVA_OPT_Smat, 128
_snova_37_8_19_4_SNOVA_OPT_Smat:
	.value	1
	.value	0
	.value	0
	.value	0
	.value	0
	.value	1
	.value	0
	.value	0
	.value	0
	.value	0
	.value	1
	.value	0
	.value	0
	.value	0
	.value	0
	.value	1
	.value	1
	.value	2
	.value	3
	.value	0
	.value	2
	.value	3
	.value	0
	.value	1
	.value	3
	.value	0
	.value	1
	.value	2
	.value	0
	.value	1
	.value	2
	.value	15
	.value	14
	.value	8
	.value	6
	.value	8
	.value	8
	.value	14
	.value	8
	.value	18
	.value	6
	.value	8
	.value	14
	.value	13
	.value	8
	.value	18
	.value	13
	.value	2
	.value	10
	.value	3
	.value	7
	.value	7
	.value	3
	.value	0
	.value	11
	.value	15
	.value	7
	.value	11
	.value	1
	.value	3
	.value	7
	.value	15
	.value	3
	.value	17
	.section	.rodata.cst32,"aM",@progbits,32
	.align 32
.LC2:
	.byte	0
	.byte	4
	.byte	8
	.byte	12
	.byte	1
	.byte	5
	.byte	9
	.byte	13
	.byte	2
	.byte	6
	.byte	10
	.byte	14
	.byte	3
	.byte	7
	.byte	11
	.byte	15
	.byte	0
	.byte	4
	.byte	8
	.byte	12
	.byte	1
	.byte	5
	.byte	9
	.byte	13
	.byte	2
	.byte	6
	.byte	10
	.byte	14
	.byte	3
	.byte	7
	.byte	11
	.byte	15
	.set	.LC3,.LC2
	.section	.rodata.cst16,"aM",@progbits,16
	.align 16
.LC5:
	.byte	27
	.byte	27
	.byte	27
	.byte	27
	.byte	27
	.byte	27
	.byte	27
	.byte	27
	.byte	27
	.byte	27
	.byte	27
	.byte	27
	.byte	27
	.byte	27
	.byte	27
	.byte	27
	.section	.rodata.cst32
	.align 32
.LC8:
	.value	255
	.value	255
	.value	255
	.value	255
	.value	255
	.value	255
	.value	255
	.value	255
	.value	255
	.value	255
	.value	255
	.value	255
	.value	255
	.value	255
	.value	255
	.value	255
	.align 32
.LC21:
	.long	0
	.long	4
	.long	1
	.long	5
	.long	2
	.long	6
	.long	3
	.long	7
	.section	.rodata.cst16
	.align 16
.LC23:
	.byte	1
	.byte	3
	.byte	5
	.byte	7
	.byte	9
	.byte	11
	.byte	13
	.byte	15
	.byte	1
	.byte	3
	.byte	5
	.byte	7
	.byte	9
	.byte	11
	.byte	13
	.byte	15
	.align 16
.LC24:
	.byte	0
	.byte	2
	.byte	4
	.byte	6
	.byte	8
	.byte	10
	.byte	12
	.byte	14
	.byte	0
	.byte	2
	.byte	4
	.byte	6
	.byte	8
	.byte	10
	.byte	12
	.byte	14
	.set	.LC25,.LC36
	.section	.rodata.cst8,"aM",@progbits,8
	.align 8
.LC26:
	.value	-10347
	.value	-10347
	.value	-10347
	.value	-10347
	.section	.rodata.cst16
	.align 16
.LC30:
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.align 16
.LC32:
	.byte	15
	.byte	15
	.byte	15
	.byte	15
	.byte	15
	.byte	15
	.byte	15
	.byte	15
	.byte	15
	.byte	15
	.byte	15
	.byte	15
	.byte	15
	.byte	15
	.byte	15
	.byte	15
	.align 16
.LC34:
	.byte	13
	.byte	13
	.byte	13
	.byte	13
	.byte	13
	.byte	13
	.byte	13
	.byte	13
	.byte	13
	.byte	13
	.byte	13
	.byte	13
	.byte	13
	.byte	13
	.byte	13
	.byte	13
	.align 16
.LC36:
	.byte	18
	.byte	18
	.byte	18
	.byte	18
	.byte	18
	.byte	18
	.byte	18
	.byte	18
	.byte	18
	.byte	18
	.byte	18
	.byte	18
	.byte	18
	.byte	18
	.byte	18
	.byte	18
	.align 16
.LC38:
	.byte	6
	.byte	6
	.byte	6
	.byte	6
	.byte	6
	.byte	6
	.byte	6
	.byte	6
	.byte	6
	.byte	6
	.byte	6
	.byte	6
	.byte	6
	.byte	6
	.byte	6
	.byte	6
	.align 16
.LC40:
	.byte	8
	.byte	8
	.byte	8
	.byte	8
	.byte	8
	.byte	8
	.byte	8
	.byte	8
	.byte	8
	.byte	8
	.byte	8
	.byte	8
	.byte	8
	.byte	8
	.byte	8
	.byte	8
	.align 16
.LC42:
	.byte	14
	.byte	14
	.byte	14
	.byte	14
	.byte	14
	.byte	14
	.byte	14
	.byte	14
	.byte	14
	.byte	14
	.byte	14
	.byte	14
	.byte	14
	.byte	14
	.byte	14
	.byte	14
	.align 16
.LC44:
	.byte	11
	.byte	11
	.byte	11
	.byte	11
	.byte	11
	.byte	11
	.byte	11
	.byte	11
	.byte	11
	.byte	11
	.byte	11
	.byte	11
	.byte	11
	.byte	11
	.byte	11
	.byte	11
	.section	.rodata.cst32
	.align 32
.LC45:
	.value	3
	.value	3
	.value	3
	.value	3
	.value	3
	.value	3
	.value	3
	.value	3
	.value	3
	.value	3
	.value	3
	.value	3
	.value	3
	.value	3
	.value	3
	.value	3
	.align 32
.LC57:
	.value	7
	.value	7
	.value	7
	.value	7
	.value	7
	.value	7
	.value	7
	.value	7
	.value	7
	.value	7
	.value	7
	.value	7
	.value	7
	.value	7
	.value	7
	.value	7
	.align 32
.LC60:
	.value	17
	.value	17
	.value	17
	.value	17
	.value	17
	.value	17
	.value	17
	.value	17
	.value	17
	.value	17
	.value	17
	.value	17
	.value	17
	.value	17
	.value	17
	.value	17
	.align 32
.LC63:
	.value	10
	.value	10
	.value	10
	.value	10
	.value	10
	.value	10
	.value	10
	.value	10
	.value	10
	.value	10
	.value	10
	.value	10
	.value	10
	.value	10
	.value	10
	.value	10
	.align 32
.LC64:
	.byte	0
	.byte	1
	.byte	0
	.byte	1
	.byte	0
	.byte	1
	.byte	0
	.byte	1
	.byte	8
	.byte	9
	.byte	8
	.byte	9
	.byte	8
	.byte	9
	.byte	8
	.byte	9
	.byte	0
	.byte	1
	.byte	0
	.byte	1
	.byte	0
	.byte	1
	.byte	0
	.byte	1
	.byte	8
	.byte	9
	.byte	8
	.byte	9
	.byte	8
	.byte	9
	.byte	8
	.byte	9
	.align 32
.LC65:
	.byte	2
	.byte	3
	.byte	2
	.byte	3
	.byte	2
	.byte	3
	.byte	2
	.byte	3
	.byte	10
	.byte	11
	.byte	10
	.byte	11
	.byte	10
	.byte	11
	.byte	10
	.byte	11
	.byte	2
	.byte	3
	.byte	2
	.byte	3
	.byte	2
	.byte	3
	.byte	2
	.byte	3
	.byte	10
	.byte	11
	.byte	10
	.byte	11
	.byte	10
	.byte	11
	.byte	10
	.byte	11
	.align 32
.LC66:
	.byte	4
	.byte	5
	.byte	4
	.byte	5
	.byte	4
	.byte	5
	.byte	4
	.byte	5
	.byte	12
	.byte	13
	.byte	12
	.byte	13
	.byte	12
	.byte	13
	.byte	12
	.byte	13
	.byte	4
	.byte	5
	.byte	4
	.byte	5
	.byte	4
	.byte	5
	.byte	4
	.byte	5
	.byte	12
	.byte	13
	.byte	12
	.byte	13
	.byte	12
	.byte	13
	.byte	12
	.byte	13
	.align 32
.LC67:
	.byte	6
	.byte	7
	.byte	6
	.byte	7
	.byte	6
	.byte	7
	.byte	6
	.byte	7
	.byte	14
	.byte	15
	.byte	14
	.byte	15
	.byte	14
	.byte	15
	.byte	14
	.byte	15
	.byte	6
	.byte	7
	.byte	6
	.byte	7
	.byte	6
	.byte	7
	.byte	6
	.byte	7
	.byte	14
	.byte	15
	.byte	14
	.byte	15
	.byte	14
	.byte	15
	.byte	14
	.byte	15
	.section	.rodata.cst16
	.align 16
.LC69:
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	4
	.byte	4
	.byte	4
	.byte	4
	.byte	8
	.byte	8
	.byte	8
	.byte	8
	.byte	12
	.byte	12
	.byte	12
	.byte	12
	.align 16
.LC70:
	.byte	1
	.byte	1
	.byte	1
	.byte	1
	.byte	5
	.byte	5
	.byte	5
	.byte	5
	.byte	9
	.byte	9
	.byte	9
	.byte	9
	.byte	13
	.byte	13
	.byte	13
	.byte	13
	.align 16
.LC71:
	.byte	2
	.byte	2
	.byte	2
	.byte	2
	.byte	6
	.byte	6
	.byte	6
	.byte	6
	.byte	10
	.byte	10
	.byte	10
	.byte	10
	.byte	14
	.byte	14
	.byte	14
	.byte	14
	.align 16
.LC72:
	.byte	3
	.byte	3
	.byte	3
	.byte	3
	.byte	7
	.byte	7
	.byte	7
	.byte	7
	.byte	11
	.byte	11
	.byte	11
	.byte	11
	.byte	15
	.byte	15
	.byte	15
	.byte	15
	.section	.rodata.cst32
	.align 32
.LC75:
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	0
	.byte	4
	.byte	8
	.byte	12
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.align 32
.LC76:
	.byte	0
	.byte	4
	.byte	8
	.byte	12
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	8
	.byte	9
	.byte	10
	.byte	11
	.byte	12
	.byte	13
	.byte	14
	.byte	15
	.byte	0
	.byte	1
	.byte	2
	.byte	3
	.byte	4
	.byte	5
	.byte	6
	.byte	7
	.byte	8
	.byte	9
	.byte	10
	.byte	11
	.byte	12
	.byte	13
	.byte	14
	.byte	15
	.section	.rodata.cst16
	.align 16
.LC77:
	.byte	0
	.byte	4
	.byte	8
	.byte	12
	.byte	4
	.byte	5
	.byte	6
	.byte	7
	.byte	8
	.byte	9
	.byte	10
	.byte	11
	.byte	12
	.byte	13
	.byte	14
	.byte	15
	.align 16
.LC78:
	.byte	0
	.byte	4
	.byte	2
	.byte	3
	.byte	4
	.byte	5
	.byte	6
	.byte	7
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.section	.rodata.cst32
	.align 32
.LC79:
	.byte	0
	.byte	1
	.byte	0
	.byte	1
	.byte	0
	.byte	1
	.byte	0
	.byte	1
	.byte	2
	.byte	3
	.byte	2
	.byte	3
	.byte	2
	.byte	3
	.byte	2
	.byte	3
	.byte	4
	.byte	5
	.byte	4
	.byte	5
	.byte	4
	.byte	5
	.byte	4
	.byte	5
	.byte	6
	.byte	7
	.byte	6
	.byte	7
	.byte	6
	.byte	7
	.byte	6
	.byte	7
	.align 32
.LC80:
	.byte	14
	.byte	15
	.byte	12
	.byte	13
	.byte	10
	.byte	11
	.byte	8
	.byte	9
	.byte	6
	.byte	7
	.byte	4
	.byte	5
	.byte	2
	.byte	3
	.byte	0
	.byte	1
	.byte	14
	.byte	15
	.byte	12
	.byte	13
	.byte	10
	.byte	11
	.byte	8
	.byte	9
	.byte	6
	.byte	7
	.byte	4
	.byte	5
	.byte	2
	.byte	3
	.byte	0
	.byte	1
	.align 32
.LC81:
	.byte	0
	.byte	1
	.byte	8
	.byte	9
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	0
	.byte	1
	.byte	8
	.byte	9
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	0
	.byte	1
	.byte	8
	.byte	9
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	0
	.byte	1
	.byte	8
	.byte	9
	.align 32
.LC82:
	.byte	2
	.byte	3
	.byte	10
	.byte	11
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	2
	.byte	3
	.byte	10
	.byte	11
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	2
	.byte	3
	.byte	10
	.byte	11
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	2
	.byte	3
	.byte	10
	.byte	11
	.align 32
.LC83:
	.byte	4
	.byte	5
	.byte	12
	.byte	13
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	4
	.byte	5
	.byte	12
	.byte	13
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	4
	.byte	5
	.byte	12
	.byte	13
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	4
	.byte	5
	.byte	12
	.byte	13
	.align 32
.LC84:
	.byte	6
	.byte	7
	.byte	14
	.byte	15
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	6
	.byte	7
	.byte	14
	.byte	15
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	6
	.byte	7
	.byte	14
	.byte	15
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	6
	.byte	7
	.byte	14
	.byte	15
	.align 32
.LC89:
	.byte	4
	.byte	5
	.byte	12
	.byte	13
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	6
	.byte	7
	.byte	14
	.byte	15
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	0
	.byte	1
	.byte	8
	.byte	9
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	2
	.byte	3
	.byte	10
	.byte	11
	.align 32
.LC90:
	.byte	0
	.byte	1
	.byte	8
	.byte	9
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	2
	.byte	3
	.byte	10
	.byte	11
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	4
	.byte	5
	.byte	12
	.byte	13
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	-128
	.byte	6
	.byte	7
	.byte	14
	.byte	15
	.align 32
.LC91:
	.long	32
	.long	31
	.long	30
	.long	29
	.long	28
	.long	27
	.long	26
	.long	25
	.align 32
.LC92:
	.long	96
	.long	97
	.long	98
	.long	99
	.long	100
	.long	101
	.long	102
	.long	103
	.align 32
.LC93:
	.long	128
	.long	127
	.long	126
	.long	125
	.long	124
	.long	123
	.long	122
	.long	121
	.align 32
.LC94:
	.long	0
	.long	1
	.long	2
	.long	3
	.long	4
	.long	5
	.long	6
	.long	7
	.align 32
.LC95:
	.long	96
	.long	95
	.long	94
	.long	93
	.long	92
	.long	91
	.long	90
	.long	89
	.align 32
.LC96:
	.long	32
	.long	33
	.long	34
	.long	35
	.long	36
	.long	37
	.long	38
	.long	39
	.align 32
.LC97:
	.long	64
	.long	63
	.long	62
	.long	61
	.long	60
	.long	59
	.long	58
	.long	57
	.align 32
.LC98:
	.long	64
	.long	65
	.long	66
	.long	67
	.long	68
	.long	69
	.long	70
	.long	71
	.align 32
.LC99:
	.byte	8
	.byte	9
	.byte	8
	.byte	9
	.byte	8
	.byte	9
	.byte	8
	.byte	9
	.byte	10
	.byte	11
	.byte	10
	.byte	11
	.byte	10
	.byte	11
	.byte	10
	.byte	11
	.byte	12
	.byte	13
	.byte	12
	.byte	13
	.byte	12
	.byte	13
	.byte	12
	.byte	13
	.byte	14
	.byte	15
	.byte	14
	.byte	15
	.byte	14
	.byte	15
	.byte	14
	.byte	15
	.align 32
.LC100:
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	0
	.byte	1
	.byte	1
	.byte	1
	.byte	1
	.byte	1
	.byte	1
	.byte	1
	.byte	1
	.byte	1
	.byte	1
	.byte	1
	.byte	1
	.byte	1
	.byte	1
	.byte	1
	.byte	1
	.ident	"GCC: (GNU) 15.1.1 20250729"
	.section	.note.GNU-stack,"",@progbits
