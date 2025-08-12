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
	imulq	$-1307163959, %rdx, %rdx
	sarl	$31, %ecx
	shrq	$32, %rdx
	addl	%eax, %edx
	sarl	$4, %edx
	subl	%ecx, %edx
	imull	$23, %edx, %edx
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
	subq	$96128, %rsp
	.cfi_offset 15, -24
	.cfi_offset 14, -32
	.cfi_offset 13, -40
	.cfi_offset 12, -48
	.cfi_offset 3, -56
	movq	%rdi, 40(%rsp)
	leaq	48(%rsp), %rdi
	movq	%fs:40, %rdx
	movq	%rdx, 96120(%rsp)
	movl	$16, %edx
	call	snova_pk_expander_init@PLT
	leaq	48(%rsp), %rdx
	movl	$47200, %esi
	leaq	1696(%rsp), %rdi
	call	snova_pk_expander@PLT
	movl	$2139062143, %ecx
	vmovdqa	.LC7(%rip), %xmm6
	movq	40(%rsp), %r8
	vmovd	%ecx, %xmm5
	leaq	48896(%rsp), %rdx
	leaq	1696(%rsp), %rax
	movl	$252645135, %ecx
	vmovd	%ecx, %xmm4
	leaq	96096(%rsp), %rsi
	vpbroadcastd	%xmm5, %ymm5
	movl	$-117901064, %ecx
	vmovd	%ecx, %xmm3
	vpbroadcastd	%xmm4, %ymm4
	vpbroadcastd	%xmm3, %ymm3
.L5:
	vmovdqa	(%rax), %ymm2
	vpmovzxbw	%xmm6, %ymm7
	addq	$32, %rdx
	addq	$32, %rax
	vextracti128	$0x1, %ymm2, %xmm0
	vpmovzxbw	%xmm2, %ymm1
	vpmovzxbw	%xmm0, %ymm0
	vpmullw	%ymm7, %ymm1, %ymm1
	vpmullw	%ymm7, %ymm0, %ymm0
	vpsrlw	$8, %ymm1, %ymm1
	vpsrlw	$8, %ymm0, %ymm0
	vpackuswb	%ymm0, %ymm1, %ymm1
	vpermq	$216, %ymm1, %ymm1
	vpsubb	%ymm1, %ymm2, %ymm0
	vpsrlw	$1, %ymm0, %ymm0
	vpand	%ymm0, %ymm5, %ymm0
	vpaddb	%ymm1, %ymm0, %ymm0
	vpsrlw	$4, %ymm0, %ymm0
	vpand	%ymm0, %ymm4, %ymm0
	vpaddb	%ymm0, %ymm0, %ymm1
	vpaddb	%ymm0, %ymm1, %ymm1
	vpsllw	$3, %ymm1, %ymm1
	vpand	%ymm1, %ymm3, %ymm1
	vpsubb	%ymm0, %ymm1, %ymm0
	vpsubb	%ymm0, %ymm2, %ymm2
	vmovdqa	%ymm2, -32(%rdx)
	cmpq	%rsi, %rdx
	jne	.L5
	leaq	46080(%r8), %rax
	movq	$0, 8(%rsp)
	leaq	48896(%rsp), %r14
	movq	%rax, (%rsp)
	movq	%rax, 16(%rsp)
	movq	$0, 24(%rsp)
	movq	%r8, 32(%rsp)
.L6:
	movq	8(%rsp), %rax
	movq	16(%rsp), %r13
	xorl	%r12d, %r12d
	movq	%rax, %rbx
	movq	%rax, 40(%rsp)
	salq	$4, %rbx
	addq	32(%rsp), %rbx
.L9:
	movq	%rbx, %rdi
	movl	$4, %r15d
	vzeroupper
.L7:
	movq	%r15, %rdx
	movq	%r14, %rsi
	decq	%r15
	call	memcpy@PLT
	leaq	5(%rax), %rdi
	leaq	1(%r14,%r15), %rax
	movq	%rax, %r14
	testq	%r15, %r15
	jne	.L7
	movl	%r12d, %esi
	cmpl	$23, %r12d
	je	.L13
	cmpq	$22, %r12
	je	.L37
	movl	$23, %edx
	vmovdqu	(%rax), %ymm0
	subl	%r12d, %edx
	movl	%edx, %ecx
	vmovdqu	%ymm0, 16(%rbx)
	shrl	%ecx
	cmpl	$1, %ecx
	je	.L12
	vmovdqu	32(%rax), %ymm0
	vmovdqu	%ymm0, 48(%rbx)
	cmpl	$2, %ecx
	je	.L12
	vmovdqu	64(%rax), %ymm0
	vmovdqu	%ymm0, 80(%rbx)
	cmpl	$3, %ecx
	je	.L12
	vmovdqu	96(%rax), %ymm0
	vmovdqu	%ymm0, 112(%rbx)
	cmpl	$4, %ecx
	je	.L12
	vmovdqu	128(%rax), %ymm0
	vmovdqu	%ymm0, 144(%rbx)
	cmpl	$5, %ecx
	je	.L12
	vmovdqu	160(%rax), %ymm0
	vmovdqu	%ymm0, 176(%rbx)
	cmpl	$6, %ecx
	je	.L12
	vmovdqu	192(%rax), %ymm0
	vmovdqu	%ymm0, 208(%rbx)
	cmpl	$7, %ecx
	je	.L12
	vmovdqu	224(%rax), %ymm0
	vmovdqu	%ymm0, 240(%rbx)
	cmpl	$8, %ecx
	je	.L12
	vmovdqu	256(%rax), %ymm0
	vmovdqu	%ymm0, 272(%rbx)
	cmpl	$9, %ecx
	je	.L12
	vmovdqu	288(%rax), %ymm0
	vmovdqu	%ymm0, 304(%rbx)
	cmpl	$11, %ecx
	jne	.L12
	vmovdqu	320(%rax), %ymm0
	vmovdqu	%ymm0, 336(%rbx)
.L12:
	testb	$1, %dl
	je	.L14
	andl	$-2, %edx
.L11:
	movq	40(%rsp), %rdi
	movq	%rdx, %rcx
	salq	$4, %rcx
	leaq	1(%rdi,%rdx), %rdx
	vmovdqu	(%rax,%rcx), %xmm0
	movq	32(%rsp), %rdi
	salq	$4, %rdx
	vmovdqu	%xmm0, (%rdi,%rdx)
.L14:
	movl	$23, %ecx
	subl	%esi, %ecx
	salq	$4, %rcx
	leaq	(%rcx,%rax), %r14
.L13:
	movzbl	64(%r14), %eax
	vmovdqu	(%r14), %ymm0
	incq	%r12
	addq	$80, %r14
	addq	$80, %r13
	addq	$400, %rbx
	movb	%al, -16(%r13)
	movzbl	-15(%r14), %eax
	vmovdqu	%ymm0, -80(%r13)
	vmovdqu	-48(%r14), %ymm0
	movb	%al, -15(%r13)
	movzbl	-14(%r14), %eax
	vmovdqu	%ymm0, -48(%r13)
	movb	%al, -14(%r13)
	movzbl	-13(%r14), %eax
	movb	%al, -13(%r13)
	movzbl	-12(%r14), %eax
	movb	%al, -12(%r13)
	movzbl	-11(%r14), %eax
	movb	%al, -11(%r13)
	movzbl	-10(%r14), %eax
	movb	%al, -10(%r13)
	movzbl	-9(%r14), %eax
	movb	%al, -9(%r13)
	movzbl	-8(%r14), %eax
	movb	%al, -8(%r13)
	movzbl	-7(%r14), %eax
	movb	%al, -7(%r13)
	movzbl	-6(%r14), %eax
	movb	%al, -6(%r13)
	movzbl	-5(%r14), %eax
	movb	%al, -5(%r13)
	movzbl	-4(%r14), %eax
	movb	%al, -4(%r13)
	movzbl	-3(%r14), %eax
	movb	%al, -3(%r13)
	movzbl	-2(%r14), %eax
	addq	$25, 40(%rsp)
	movb	%al, -2(%r13)
	movzbl	-1(%r14), %eax
	movb	%al, -1(%r13)
	cmpq	$24, %r12
	jne	.L9
	addq	$24, 24(%rsp)
	addq	$1920, 16(%rsp)
	addq	$576, 8(%rsp)
	movq	24(%rsp), %rax
	cmpq	$120, %rax
	jne	.L6
	movq	32(%rsp), %r8
	leaq	9600(%r8), %r9
	leaq	55680(%r8), %rdi
.L15:
	leaq	-9600(%r9), %rax
.L16:
	movzbl	1(%rax), %edx
	addq	$400, %rax
	movb	%dl, -396(%rax)
	movzbl	-398(%rax), %edx
	movb	-394(%rax), %dh
	movw	%dx, -392(%rax)
	movzbl	-397(%rax), %edx
	movb	-393(%rax), %dh
	movw	%dx, -388(%rax)
	movzbl	-389(%rax), %edx
	movb	%dl, -386(%rax)
	cmpq	%r9, %rax
	jne	.L16
	leaq	9216(%rax), %r9
	cmpq	%rdi, %r9
	jne	.L15
	leaq	-368(%r8), %rbx
	movq	%r14, 24(%rsp)
	vmovdqa	.LC5(%rip), %xmm2
	xorl	%eax, %eax
	movq	%rbx, 40(%rsp)
	leaq	16(%r8), %rbx
	vmovdqa	.LC4(%rip), %ymm0
	movl	$384, %edx
	movq	%rbx, 32(%rsp)
	movq	%rdi, 16(%rsp)
	movq	%r15, 8(%rsp)
	xorl	%r15d, %r15d
.L17:
	movq	40(%rsp), %rbx
	leaq	8464(%rdx), %r13
	movq	%rdx, %r14
	movl	$23, %r10d
	movl	$1, %r11d
	addq	$24, %r15
	leaq	(%rbx,%rdx), %r9
	movq	%rax, %rbx
	jmp	.L26
.L112:
	andl	$-2, %edi
.L21:
	movl	%edi, %ecx
	movl	$23, %esi
	incl	%r11d
	leaq	1(%rbx,%rcx), %rdi
	subq	%r10, %rsi
	salq	$4, %rdi
	vmovdqu	(%r8,%rdi), %xmm1
	movq	%r15, %rdi
	subq	%r10, %rdi
	addq	%rdi, %rcx
	vpshufb	%xmm2, %xmm1, %xmm1
	leaq	(%rcx,%rcx,2), %rcx
	leaq	(%rsi,%rcx,8), %rcx
	salq	$4, %rcx
	vmovdqu	%xmm1, (%r8,%rcx)
	cmpl	$24, %r11d
	je	.L18
.L111:
	addq	$384, %r14
	decq	%r10
	addq	$16, %r13
	addq	$25, %rbx
	addq	$400, %r9
.L26:
	leaq	24(%rbx), %rcx
	salq	$4, %rcx
	leaq	-368(%rcx), %rdi
	cmpq	%rdi, %r13
	jle	.L41
	cmpq	%rcx, %r14
	jg	.L19
.L41:
	cmpl	$23, %r11d
	je	.L39
	vmovdqu	(%r9), %ymm1
	movl	%r10d, %ecx
	movl	%r10d, %edi
	shrl	%ecx
	vpshufb	%ymm0, %ymm1, %ymm1
	vmovdqu	%xmm1, 368(%r9)
	vextracti128	$0x1, %ymm1, 752(%r9)
	cmpl	$1, %ecx
	je	.L22
	vmovdqu	32(%r9), %ymm1
	vpshufb	%ymm0, %ymm1, %ymm1
	vmovdqu	%xmm1, 1136(%r9)
	vextracti128	$0x1, %ymm1, 1520(%r9)
	cmpl	$2, %ecx
	je	.L22
	vmovdqu	64(%r9), %ymm1
	vpshufb	%ymm0, %ymm1, %ymm1
	vmovdqu	%xmm1, 1904(%r9)
	vextracti128	$0x1, %ymm1, 2288(%r9)
	cmpl	$3, %ecx
	je	.L22
	vmovdqu	96(%r9), %ymm1
	vpshufb	%ymm0, %ymm1, %ymm1
	vmovdqu	%xmm1, 2672(%r9)
	vextracti128	$0x1, %ymm1, 3056(%r9)
	cmpl	$4, %ecx
	je	.L22
	vmovdqu	128(%r9), %ymm1
	vpshufb	%ymm0, %ymm1, %ymm1
	vmovdqu	%xmm1, 3440(%r9)
	vextracti128	$0x1, %ymm1, 3824(%r9)
	cmpl	$5, %ecx
	je	.L22
	vmovdqu	160(%r9), %ymm1
	vpshufb	%ymm0, %ymm1, %ymm1
	vmovdqu	%xmm1, 4208(%r9)
	vextracti128	$0x1, %ymm1, 4592(%r9)
	cmpl	$6, %ecx
	je	.L22
	vmovdqu	192(%r9), %ymm1
	vpshufb	%ymm0, %ymm1, %ymm1
	vmovdqu	%xmm1, 4976(%r9)
	vextracti128	$0x1, %ymm1, 5360(%r9)
	cmpl	$7, %ecx
	je	.L22
	vmovdqu	224(%r9), %ymm1
	vpshufb	%ymm0, %ymm1, %ymm1
	vmovdqu	%xmm1, 5744(%r9)
	vextracti128	$0x1, %ymm1, 6128(%r9)
	cmpl	$8, %ecx
	je	.L22
	vmovdqu	256(%r9), %ymm1
	vpshufb	%ymm0, %ymm1, %ymm1
	vmovdqu	%xmm1, 6512(%r9)
	vextracti128	$0x1, %ymm1, 6896(%r9)
	cmpl	$9, %ecx
	je	.L22
	vmovdqu	288(%r9), %ymm1
	vpshufb	%ymm0, %ymm1, %ymm1
	vmovdqu	%xmm1, 7280(%r9)
	vextracti128	$0x1, %ymm1, 7664(%r9)
	cmpl	$11, %ecx
	jne	.L22
	vmovdqu	320(%r9), %ymm1
	vpshufb	%ymm0, %ymm1, %ymm1
	vmovdqu	%xmm1, 8048(%r9)
	vextracti128	$0x1, %ymm1, 8432(%r9)
.L22:
	testb	$1, %dil
	jne	.L112
	incl	%r11d
	jmp	.L111
.L19:
	leal	1(%rbx), %ecx
	leal	24(%rbx), %edi
	movslq	%ecx, %r12
	movslq	%edi, %rdi
	movq	%r12, %rcx
	leaq	-1(%r10,%r12), %r12
	salq	$4, %rdi
	salq	$4, %rcx
	salq	$4, %r12
	addq	%r8, %rdi
	addq	%r8, %rcx
	addq	32(%rsp), %r12
.L25:
	movzbl	(%rcx), %esi
	addq	$16, %rcx
	addq	$384, %rdi
	movb	%sil, -384(%rdi)
	movzbl	-15(%rcx), %esi
	movb	%sil, -380(%rdi)
	movzbl	-14(%rcx), %esi
	movb	%sil, -376(%rdi)
	movzbl	-13(%rcx), %esi
	movb	%sil, -372(%rdi)
	movzbl	-12(%rcx), %esi
	movb	%sil, -383(%rdi)
	movzbl	-11(%rcx), %esi
	movb	%sil, -379(%rdi)
	movzbl	-10(%rcx), %esi
	movb	%sil, -375(%rdi)
	movzbl	-9(%rcx), %esi
	movb	%sil, -371(%rdi)
	movzbl	-8(%rcx), %esi
	movb	%sil, -382(%rdi)
	movzbl	-7(%rcx), %esi
	movb	%sil, -378(%rdi)
	movzbl	-6(%rcx), %esi
	movb	%sil, -374(%rdi)
	movzbl	-5(%rcx), %esi
	movb	%sil, -370(%rdi)
	movzbl	-4(%rcx), %esi
	movb	%sil, -381(%rdi)
	movzbl	-3(%rcx), %esi
	movb	%sil, -377(%rdi)
	movzbl	-2(%rcx), %esi
	movb	%sil, -373(%rdi)
	movzbl	-1(%rcx), %esi
	movb	%sil, -369(%rdi)
	cmpq	%r12, %rcx
	jne	.L25
	incl	%r11d
	cmpl	$24, %r11d
	jne	.L111
.L18:
	addq	$9216, %rdx
	addq	$576, %rax
	cmpq	$120, %r15
	jne	.L17
	movq	24(%rsp), %r14
	movq	16(%rsp), %rdi
	xorl	%esi, %esi
	movl	$96, %edx
	movq	8(%rsp), %r15
	vmovdqa	.LC4(%rip), %ymm1
	movq	%r14, 32(%rsp)
	movq	(%rsp), %r10
	movq	%rdi, 40(%rsp)
.L27:
	movq	40(%rsp), %rdi
	leaq	55680(%r15), %r12
	leaq	46160(%r15), %rbx
	movl	%r15d, %r9d
	leaq	(%r8,%r15), %rax
	xorl	%r13d, %r13d
	leaq	(%rdi,%r15), %r11
	movl	%r15d, %edi
	jmp	.L34
.L31:
	vmovdqu	46080(%rax), %ymm0
	leal	64(%r9), %ecx
	movslq	%ecx, %rcx
	vpshufb	%ymm1, %ymm0, %ymm0
	vmovdqu	%xmm0, (%r11)
	vextracti128	$0x1, %ymm0, 384(%r11)
	vmovdqu	46112(%rax), %ymm0
	vpshufb	%ymm1, %ymm0, %ymm0
	vmovdqu	%xmm0, 768(%r11)
	vextracti128	$0x1, %ymm0, 1152(%r11)
	movzbl	(%r10,%rcx), %r14d
	leal	57216(%rdi), %ecx
	movslq	%ecx, %rcx
	movb	%r14b, (%r8,%rcx)
	leal	65(%r9), %ecx
	movslq	%ecx, %rcx
	movzbl	(%r10,%rcx), %r14d
	leal	57220(%rdi), %ecx
	movslq	%ecx, %rcx
	movb	%r14b, (%r8,%rcx)
	leal	66(%r9), %ecx
	movslq	%ecx, %rcx
	movzbl	(%r10,%rcx), %r14d
	leal	57224(%rdi), %ecx
	movslq	%ecx, %rcx
	movb	%r14b, (%r8,%rcx)
	leal	67(%r9), %ecx
	movslq	%ecx, %rcx
	movzbl	(%r10,%rcx), %r14d
	leal	57228(%rdi), %ecx
	movslq	%ecx, %rcx
	movb	%r14b, (%r8,%rcx)
	leal	68(%r9), %ecx
	movslq	%ecx, %rcx
	movzbl	(%r10,%rcx), %r14d
	leal	57217(%rdi), %ecx
	movslq	%ecx, %rcx
	movb	%r14b, (%r8,%rcx)
	leal	69(%r9), %ecx
	movslq	%ecx, %rcx
	movzbl	(%r10,%rcx), %r14d
	leal	57221(%rdi), %ecx
	movslq	%ecx, %rcx
	movb	%r14b, (%r8,%rcx)
	leal	70(%r9), %ecx
	movslq	%ecx, %rcx
	movzbl	(%r10,%rcx), %r14d
	leal	57225(%rdi), %ecx
	movslq	%ecx, %rcx
	movb	%r14b, (%r8,%rcx)
	leal	71(%r9), %ecx
	movslq	%ecx, %rcx
	movzbl	(%r10,%rcx), %r14d
	leal	57229(%rdi), %ecx
	movslq	%ecx, %rcx
	movb	%r14b, (%r8,%rcx)
	leal	72(%r9), %ecx
	movslq	%ecx, %rcx
	movzbl	(%r10,%rcx), %r14d
	leal	57218(%rdi), %ecx
	movslq	%ecx, %rcx
	movb	%r14b, (%r8,%rcx)
	leal	73(%r9), %ecx
	movslq	%ecx, %rcx
	movzbl	(%r10,%rcx), %r14d
	leal	57222(%rdi), %ecx
	movslq	%ecx, %rcx
	movb	%r14b, (%r8,%rcx)
	leal	74(%r9), %ecx
	movslq	%ecx, %rcx
	movzbl	(%r10,%rcx), %r14d
	leal	57226(%rdi), %ecx
	movslq	%ecx, %rcx
	movb	%r14b, (%r8,%rcx)
	leal	75(%r9), %ecx
	movslq	%ecx, %rcx
	movzbl	(%r10,%rcx), %r14d
	leal	57230(%rdi), %ecx
	movslq	%ecx, %rcx
	movb	%r14b, (%r8,%rcx)
	leal	76(%r9), %ecx
	movslq	%ecx, %rcx
	movzbl	(%r10,%rcx), %r14d
	leal	57219(%rdi), %ecx
	movslq	%ecx, %rcx
	movb	%r14b, (%r8,%rcx)
	leal	77(%r9), %ecx
	movslq	%ecx, %rcx
	movzbl	(%r10,%rcx), %r14d
	leal	57223(%rdi), %ecx
	movslq	%ecx, %rcx
	movb	%r14b, (%r8,%rcx)
	leal	78(%r9), %ecx
	movslq	%ecx, %rcx
	movzbl	(%r10,%rcx), %r14d
	leal	57227(%rdi), %ecx
	movslq	%ecx, %rcx
	movb	%r14b, (%r8,%rcx)
	leal	79(%r9), %ecx
	movslq	%ecx, %rcx
	movzbl	(%r10,%rcx), %r14d
	leal	57231(%rdi), %ecx
	movslq	%ecx, %rcx
	movb	%r14b, (%r8,%rcx)
	leaq	80(%rax), %r14
.L29:
	incl	%r13d
	addq	$16, %r12
	addq	$80, %rbx
	movq	%r14, %rax
	addq	$16, %r11
	addl	$80, %r9d
	addl	$16, %edi
	cmpl	$24, %r13d
	je	.L30
.L34:
	leaq	1552(%r12), %r14
	leaq	-80(%rbx), %rcx
	cmpq	%rcx, %r14
	jle	.L31
	cmpq	%rbx, %r12
	jge	.L31
	leal	0(%r13,%rsi), %ecx
	movl	%edx, 24(%rsp)
	leaq	80(%rax), %r14
	salq	$4, %rcx
	addq	40(%rsp), %rcx
.L28:
	movzbl	46080(%rax), %edx
	addq	$16, %rax
	addq	$384, %rcx
	movb	%dl, -384(%rcx)
	movzbl	46065(%rax), %edx
	movb	%dl, -380(%rcx)
	movzbl	46066(%rax), %edx
	movb	%dl, -376(%rcx)
	movzbl	46067(%rax), %edx
	movb	%dl, -372(%rcx)
	movzbl	46068(%rax), %edx
	movb	%dl, -383(%rcx)
	movzbl	46069(%rax), %edx
	movb	%dl, -379(%rcx)
	movzbl	46070(%rax), %edx
	movb	%dl, -375(%rcx)
	movzbl	46071(%rax), %edx
	movb	%dl, -371(%rcx)
	movzbl	46072(%rax), %edx
	movb	%dl, -382(%rcx)
	movzbl	46073(%rax), %edx
	movb	%dl, -378(%rcx)
	movzbl	46074(%rax), %edx
	movb	%dl, -374(%rcx)
	movzbl	46075(%rax), %edx
	movb	%dl, -370(%rcx)
	movzbl	46076(%rax), %edx
	movb	%dl, -381(%rcx)
	movzbl	46077(%rax), %edx
	movb	%dl, -377(%rcx)
	movzbl	46078(%rax), %edx
	movb	%dl, -373(%rcx)
	movzbl	46079(%rax), %edx
	movb	%dl, -369(%rcx)
	cmpq	%r14, %rax
	jne	.L28
	movl	24(%rsp), %edx
	jmp	.L29
.L37:
	xorl	%edx, %edx
	jmp	.L11
.L39:
	xorl	%edi, %edi
	jmp	.L21
.L30:
	addl	$120, %edx
	addq	$1920, %r15
	addq	$120, %rsi
	cmpl	$696, %edx
	jne	.L27
	movq	32(%rsp), %rsi
	leaq	65280(%r8), %rdi
	movl	$4000, %edx
	vzeroupper
	call	memcpy@PLT
	movq	96120(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L113
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
.L113:
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
	pushq	%r14
	pushq	%r13
	.cfi_offset 14, -24
	.cfi_offset 13, -32
	movq	%rdi, %r13
	pushq	%r12
	pushq	%rbx
	andq	$-32, %rsp
	subq	$768, %rsp
	.cfi_offset 12, -40
	.cfi_offset 3, -48
	movq	%fs:40, %rbx
	movq	%rbx, 760(%rsp)
	movq	%rsi, %rbx
	leaq	16(%rsp), %rdi
	call	shake256_init@PLT
	movl	$32, %edx
	leaq	16(%rsp), %rdi
	movq	%rbx, %rsi
	xorl	%ebx, %ebx
	call	shake_absorb@PLT
	leaq	16(%rsp), %rdi
	call	shake_finalize@PLT
	movl	$32, %edx
	jmp	.L116
.L118:
	leaq	1(%rax), %rdx
	movzbl	240(%rsp,%rax), %eax
	movl	$23, %esi
	movl	%eax, %ecx
	divb	%sil
	movb	%ah, 272(%rsp,%rbx)
	xorl	%eax, %eax
	cmpb	$-4, %cl
	setbe	%al
	addq	%rax, %rbx
	cmpq	$480, %rbx
	je	.L117
.L116:
	movq	%rdx, %rax
	cmpq	$32, %rdx
	jne	.L118
	leaq	16(%rsp), %rdx
	movl	$32, %esi
	leaq	240(%rsp), %rdi
	call	shake_squeeze_keep@PLT
	movzbl	240(%rsp), %eax
	movl	$23, %ecx
	movl	%eax, %edx
	divb	%cl
	movb	%ah, 272(%rsp,%rbx)
	xorl	%eax, %eax
	cmpb	$-4, %dl
	setbe	%al
	addq	%rax, %rbx
	cmpq	$480, %rbx
	je	.L117
	movl	$1, %eax
	jmp	.L118
.L117:
	leaq	16(%rsp), %rdi
	call	shake_release@PLT
	movl	$1680696365, %eax
	leaq	_snova_24_5_23_4_SNOVA_OPT_Smat(%rip), %rcx
	movq	$-2, %r9
	vmovd	%eax, %xmm2
	leaq	272(%rsp), %rsi
	movq	%r13, %rdi
	subq	%rcx, %r9
	leaq	752(%rsp), %r10
	movl	$23, %r8d
	vpbroadcastd	%xmm2, %ymm2
	jmp	.L121
.L129:
	vpextrw	$2, %xmm0, %ebx
	vpextrw	$1, %xmm0, %eax
	vpextrw	$3, %xmm0, %r11d
	addq	$4, %rsi
	vpextrw	$0, %xmm0, %edx
	vmovd	%ebx, %xmm1
	vmovd	%eax, %xmm0
	addq	$32, %rdi
	vpbroadcastw	%xmm0, %ymm0
	vpbroadcastw	%xmm1, %ymm1
	vmovd	%r11d, %xmm3
	vpmullw	32(%rcx), %ymm1, %ymm1
	vpmullw	(%rcx), %ymm0, %ymm0
	vpaddw	%ymm1, %ymm0, %ymm0
	vmovd	%edx, %xmm1
	vpbroadcastw	%xmm1, %ymm1
	vpbroadcastw	%xmm3, %ymm3
	vpmullw	64(%rcx), %ymm3, %ymm3
	vpmullw	96(%rcx), %ymm1, %ymm1
	vpaddw	%ymm3, %ymm1, %ymm1
	vpaddw	%ymm1, %ymm0, %ymm0
	vpmulhuw	%ymm2, %ymm0, %ymm3
	vpsubw	%ymm3, %ymm0, %ymm1
	vpsrlw	$1, %ymm1, %ymm1
	vpaddw	%ymm3, %ymm1, %ymm1
	vpsrlw	$4, %ymm1, %ymm1
	vpsllw	$1, %ymm1, %ymm3
	vpaddw	%ymm1, %ymm3, %ymm3
	vpsllw	$3, %ymm3, %ymm3
	vpsubw	%ymm1, %ymm3, %ymm1
	vpsubw	%ymm1, %ymm0, %ymm0
	vmovdqu	%ymm0, -32(%rdi)
	cmpq	%rsi, %r10
	je	.L128
.L121:
	movzbl	(%rsi), %r11d
	movzbl	3(%rsi), %eax
	movl	$22, %ebx
	testb	%r11b, %r11b
	setne	%dl
	subl	%r11d, %ebx
	addl	%ebx, %edx
	cmpb	$1, %al
	sbbl	%ebx, %ebx
	andl	%ebx, %edx
	movzbl	1(%rsi), %ebx
	orl	%eax, %edx
	movzbl	2(%rsi), %eax
	movb	%dl, 3(%rsi)
	movzbl	%dl, %edx
	sall	$8, %eax
	orl	%ebx, %eax
	sall	$8, %eax
	orl	%r11d, %eax
	sall	$8, %eax
	orl	%edx, %eax
	vmovq	%rax, %xmm4
	leaq	(%r9,%rdi), %rax
	vpmovzxbw	%xmm4, %xmm0
	cmpq	$124, %rax
	ja	.L129
	movzwl	64(%rcx), %eax
	movzwl	32(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	96(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm1
	vpmullw	%xmm1, %xmm0, %xmm1
	vpsrlq	$32, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpsrlq	$16, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpextrw	$0, %xmm1, %eax
	divw	%r8w
	movw	%dx, (%rdi)
	movzwl	66(%rcx), %eax
	movzwl	34(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	2(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	98(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm1
	vpmullw	%xmm1, %xmm0, %xmm1
	vpsrlq	$32, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpsrlq	$16, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpextrw	$0, %xmm1, %eax
	divw	%r8w
	movw	%dx, 2(%rdi)
	movzwl	68(%rcx), %eax
	movzwl	36(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	4(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	100(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm1
	vpmullw	%xmm1, %xmm0, %xmm1
	vpsrlq	$32, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpsrlq	$16, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpextrw	$0, %xmm1, %eax
	divw	%r8w
	movw	%dx, 4(%rdi)
	movzwl	70(%rcx), %eax
	movzwl	38(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	6(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	102(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm1
	vpmullw	%xmm1, %xmm0, %xmm1
	vpsrlq	$32, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpsrlq	$16, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpextrw	$0, %xmm1, %eax
	divw	%r8w
	movw	%dx, 6(%rdi)
	movzwl	72(%rcx), %eax
	movzwl	40(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	8(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	104(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm1
	vpmullw	%xmm1, %xmm0, %xmm1
	vpsrlq	$32, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpsrlq	$16, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpextrw	$0, %xmm1, %eax
	divw	%r8w
	movw	%dx, 8(%rdi)
	movzwl	74(%rcx), %eax
	movzwl	42(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	10(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	106(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm1
	vpmullw	%xmm1, %xmm0, %xmm1
	vpsrlq	$32, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpsrlq	$16, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpextrw	$0, %xmm1, %eax
	divw	%r8w
	movw	%dx, 10(%rdi)
	movzwl	76(%rcx), %eax
	movzwl	44(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	12(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	108(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm1
	vpmullw	%xmm1, %xmm0, %xmm1
	vpsrlq	$32, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpsrlq	$16, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpextrw	$0, %xmm1, %eax
	divw	%r8w
	movw	%dx, 12(%rdi)
	movzwl	78(%rcx), %eax
	movzwl	46(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	14(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	110(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm1
	vpmullw	%xmm1, %xmm0, %xmm1
	vpsrlq	$32, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpsrlq	$16, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpextrw	$0, %xmm1, %eax
	divw	%r8w
	movw	%dx, 14(%rdi)
	movzwl	80(%rcx), %eax
	movzwl	48(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	16(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	112(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm1
	vpmullw	%xmm1, %xmm0, %xmm1
	vpsrlq	$32, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpsrlq	$16, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpextrw	$0, %xmm1, %eax
	divw	%r8w
	movw	%dx, 16(%rdi)
	movzwl	82(%rcx), %eax
	movzwl	50(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	18(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	114(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm1
	vpmullw	%xmm1, %xmm0, %xmm1
	vpsrlq	$32, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpsrlq	$16, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpextrw	$0, %xmm1, %eax
	divw	%r8w
	movw	%dx, 18(%rdi)
	movzwl	84(%rcx), %eax
	movzwl	52(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	20(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	116(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm1
	vpmullw	%xmm1, %xmm0, %xmm1
	vpsrlq	$32, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpsrlq	$16, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpextrw	$0, %xmm1, %eax
	divw	%r8w
	movw	%dx, 20(%rdi)
	movzwl	86(%rcx), %eax
	movzwl	54(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	22(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	118(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm1
	vpmullw	%xmm1, %xmm0, %xmm1
	vpsrlq	$32, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpsrlq	$16, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpextrw	$0, %xmm1, %eax
	divw	%r8w
	movw	%dx, 22(%rdi)
	movzwl	88(%rcx), %eax
	movzwl	56(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	24(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	120(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm1
	vpmullw	%xmm1, %xmm0, %xmm1
	vpsrlq	$32, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpsrlq	$16, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpextrw	$0, %xmm1, %eax
	divw	%r8w
	movw	%dx, 24(%rdi)
	movzwl	90(%rcx), %eax
	movzwl	58(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	26(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	122(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm1
	vpmullw	%xmm1, %xmm0, %xmm1
	vpsrlq	$32, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpsrlq	$16, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpextrw	$0, %xmm1, %eax
	divw	%r8w
	movw	%dx, 26(%rdi)
	movzwl	92(%rcx), %eax
	movzwl	60(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	28(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	124(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm1
	vpmullw	%xmm1, %xmm0, %xmm1
	vpsrlq	$32, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpsrlq	$16, %xmm1, %xmm3
	vpaddw	%xmm3, %xmm1, %xmm1
	vpextrw	$0, %xmm1, %eax
	divw	%r8w
	movw	%dx, 28(%rdi)
	movzwl	94(%rcx), %eax
	movzwl	62(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	30(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	126(%rcx), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm5
	vpmullw	%xmm5, %xmm0, %xmm0
	vpsrlq	$32, %xmm0, %xmm1
	vpaddw	%xmm1, %xmm0, %xmm0
	vpsrlq	$16, %xmm0, %xmm1
	vpaddw	%xmm1, %xmm0, %xmm0
	vpextrw	$0, %xmm0, %eax
	divw	%r8w
	addq	$4, %rsi
	addq	$32, %rdi
	movw	%dx, -2(%rdi)
	cmpq	%rsi, %r10
	jne	.L121
.L128:
	movq	760(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L130
	vzeroupper
	leaq	-32(%rbp), %rsp
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%rbp
	.cfi_remember_state
	.cfi_def_cfa 7, 8
	ret
.L130:
	.cfi_restore_state
	vzeroupper
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE14:
	.size	expand_T12, .-expand_T12
	.p2align 4
	.globl	_snova_24_5_23_4_SNOVA_OPT_genkeys
	.type	_snova_24_5_23_4_SNOVA_OPT_genkeys, @function
_snova_24_5_23_4_SNOVA_OPT_genkeys:
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
	.cfi_offset 15, -24
	.cfi_offset 14, -32
	.cfi_offset 13, -40
	.cfi_offset 12, -48
	movq	%rdi, %r12
	pushq	%rbx
	andq	$-32, %rsp
	subq	$80960, %rsp
	.cfi_offset 3, -56
	movq	%rsi, 40(%rsp)
	leaq	928(%rsp), %rax
	leaq	16(%rdx), %rsi
	movq	%rax, %rdi
	leaq	57744(%rsp), %r15
	leaq	128(%rsp), %r13
	movq	%fs:40, %rbx
	movq	%rbx, 80952(%rsp)
	movq	%rdx, %rbx
	movq	%rax, 96(%rsp)
	call	expand_T12
	leaq	11664(%rsp), %rdi
	movq	%rbx, %rsi
	call	expand_public
	movl	$2000, %edx
	xorl	%esi, %esi
	leaq	9664(%rsp), %rdi
	call	memset@PLT
	vpcmpeqd	%xmm0, %xmm0, %xmm0
	movq	$0, 112(%rsp)
	movq	%r12, %rcx
	movq	%rax, 104(%rsp)
	movq	%rax, %r14
	leaq	8608(%rsp), %rax
	movq	%rbx, %r8
	movq	%rax, 120(%rsp)
	leaq	896(%rsp), %rax
	vpsrlw	$8, %xmm0, %xmm7
	leaq	11664(%rsp), %r12
	movq	%rax, 88(%rsp)
	leaq	4768(%rsp), %rbx
	vmovdqa	%xmm7, 64(%rsp)
.L147:
	movl	$3840, %edx
	xorl	%esi, %esi
	movq	%rbx, %rdi
	movq	%r8, 48(%rsp)
	movq	%rcx, 56(%rsp)
	call	memset@PLT
	movl	$800, %edx
	xorl	%esi, %esi
	movq	%r13, %rdi
	call	memset@PLT
	movq	96(%rsp), %r9
	movq	%r15, 80(%rsp)
	xorl	%eax, %eax
	movq	56(%rsp), %rcx
	movq	48(%rsp), %r8
	movq	%r14, %rdx
	vmovdqa	.LC14(%rip), %ymm11
	vmovdqa	.LC15(%rip), %ymm10
	movq	%r9, %r11
	vmovdqa	.LC16(%rip), %ymm9
	vmovdqa	.LC17(%rip), %ymm8
	vmovdqa	.LC19(%rip), %xmm12
.L132:
	movq	%rax, %r15
	movq	%r12, 56(%rsp)
	movq	%rbx, %r10
	movq	%rbx, %r14
	salq	$4, %r15
	addq	%r12, %r15
.L136:
	vpmovzxbw	(%r15), %ymm2
	movq	%r14, %rsi
	movq	%r9, %r12
	xorl	%edi, %edi
	vpshufb	%ymm11, %ymm2, %ymm5
	vpshufb	%ymm10, %ymm2, %ymm4
	vpshufb	%ymm9, %ymm2, %ymm3
	vpshufb	%ymm8, %ymm2, %ymm2
.L133:
	vmovdqa	(%r12), %ymm1
	addq	$32, %rdi
	addq	$32, %r12
	addq	$32, %rsi
	vpermq	$0, %ymm1, %ymm0
	vpermq	$85, %ymm1, %ymm6
	vpmullw	%ymm5, %ymm0, %ymm0
	vpmullw	%ymm4, %ymm6, %ymm6
	vpaddw	-32(%rsi), %ymm0, %ymm0
	vpaddw	%ymm6, %ymm0, %ymm0
	vpermq	$170, %ymm1, %ymm6
	vpermq	$255, %ymm1, %ymm1
	vpmullw	%ymm3, %ymm6, %ymm6
	vpmullw	%ymm2, %ymm1, %ymm1
	vpaddw	%ymm6, %ymm0, %ymm0
	vpaddw	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, -32(%rsi)
	cmpq	$160, %rdi
	jne	.L133
	addq	$160, %r14
	addq	$384, %r15
	cmpq	%r14, 120(%rsp)
	jne	.L136
	incq	%rax
	movq	56(%rsp), %r12
	addq	$160, %r9
	cmpq	$24, %rax
	jne	.L132
	movq	80(%rsp), %r15
	vpbroadcastd	.LC32(%rip), %ymm2
	movq	%rdx, %r14
	movq	%rbx, %rax
	vpxor	%xmm3, %xmm3, %xmm3
	movq	%r15, %rdx
.L135:
	vmovdqu	(%rdx), %ymm0
	vmovdqa	(%rax), %ymm5
	addq	$64, %rax
	addq	$32, %rdx
	vmovdqa	-32(%rax), %ymm4
	vpmovzxbw	%xmm0, %ymm1
	vpmovzxwd	%xmm5, %ymm7
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxwd	%xmm1, %ymm6
	vextracti128	$0x1, %ymm5, %xmm5
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm0, %ymm0
	vpmovzxwd	%xmm5, %ymm5
	vpmovzxwd	%xmm1, %ymm1
	vpaddd	%ymm7, %ymm6, %ymm6
	vpaddd	%ymm5, %ymm1, %ymm1
	vpmovzxwd	%xmm4, %ymm7
	vpmovzxwd	%xmm0, %ymm5
	vextracti128	$0x1, %ymm4, %xmm4
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxwd	%xmm4, %ymm4
	vpmovzxwd	%xmm0, %ymm0
	vpaddd	%ymm7, %ymm5, %ymm5
	vpaddd	%ymm4, %ymm0, %ymm0
	vpmuldq	%ymm2, %ymm6, %ymm7
	vpsrlq	$32, %ymm6, %ymm4
	vpmuldq	%ymm2, %ymm4, %ymm4
	vpshufd	$245, %ymm7, %ymm7
	vpblendd	$85, %ymm7, %ymm4, %ymm4
	vpaddd	%ymm6, %ymm4, %ymm4
	vpsrad	$4, %ymm4, %ymm4
	vpslld	$1, %ymm4, %ymm7
	vpaddd	%ymm4, %ymm7, %ymm7
	vpslld	$3, %ymm7, %ymm7
	vpsubd	%ymm4, %ymm7, %ymm4
	vpmuldq	%ymm2, %ymm1, %ymm7
	vpsubd	%ymm4, %ymm6, %ymm4
	vpsrlq	$32, %ymm1, %ymm6
	vpmuldq	%ymm2, %ymm6, %ymm6
	vpblendw	$85, %ymm4, %ymm3, %ymm4
	vpshufd	$245, %ymm7, %ymm7
	vpblendd	$85, %ymm7, %ymm6, %ymm6
	vpaddd	%ymm1, %ymm6, %ymm6
	vpsrad	$4, %ymm6, %ymm6
	vpslld	$1, %ymm6, %ymm7
	vpaddd	%ymm6, %ymm7, %ymm7
	vpslld	$3, %ymm7, %ymm7
	vpsubd	%ymm6, %ymm7, %ymm6
	vpsubd	%ymm6, %ymm1, %ymm1
	vpblendw	$85, %ymm1, %ymm3, %ymm1
	vpackusdw	%ymm1, %ymm4, %ymm1
	vpmuldq	%ymm2, %ymm5, %ymm4
	vpermq	$216, %ymm1, %ymm1
	vmovdqa	%ymm1, -64(%rax)
	vpsrlq	$32, %ymm5, %ymm1
	vpmuldq	%ymm2, %ymm1, %ymm1
	vpshufd	$245, %ymm4, %ymm4
	vpblendd	$85, %ymm4, %ymm1, %ymm1
	vpaddd	%ymm5, %ymm1, %ymm1
	vpsrad	$4, %ymm1, %ymm1
	vpslld	$1, %ymm1, %ymm4
	vpaddd	%ymm1, %ymm4, %ymm4
	vpslld	$3, %ymm4, %ymm4
	vpsubd	%ymm1, %ymm4, %ymm1
	vpsubd	%ymm1, %ymm5, %ymm4
	vpmuldq	%ymm2, %ymm0, %ymm5
	vpsrlq	$32, %ymm0, %ymm1
	vpmuldq	%ymm2, %ymm1, %ymm1
	vpshufd	$245, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm1, %ymm1
	vpaddd	%ymm0, %ymm1, %ymm1
	vpsrad	$4, %ymm1, %ymm1
	vpslld	$1, %ymm1, %ymm5
	vpaddd	%ymm1, %ymm5, %ymm5
	vpslld	$3, %ymm5, %ymm5
	vpsubd	%ymm1, %ymm5, %ymm1
	vpsubd	%ymm1, %ymm0, %ymm0
	vpblendw	$85, %ymm4, %ymm3, %ymm1
	vpblendw	$85, %ymm0, %ymm3, %ymm0
	vpackusdw	%ymm0, %ymm1, %ymm0
	vpermq	$216, %ymm0, %ymm0
	vmovdqa	%ymm0, -32(%rax)
	cmpq	%rax, 120(%rsp)
	jne	.L135
	movq	96(%rsp), %rdx
	xorl	%esi, %esi
.L137:
	movq	%r13, %rax
	movq	%r10, %r9
	xorl	%edi, %edi
.L138:
	vmovdqa	(%r9), %ymm0
	vmovdqa	(%rdx), %ymm1
	addq	$32, %rdi
	addq	$32, %r9
	addq	$32, %rax
	vpermq	$0, %ymm0, %ymm5
	vpshufb	%ymm11, %ymm1, %ymm1
	vpermq	$85, %ymm0, %ymm4
	vpmullw	%ymm5, %ymm1, %ymm1
	vpermq	$170, %ymm0, %ymm3
	vpermq	$255, %ymm0, %ymm0
	vpaddw	-32(%rax), %ymm1, %ymm1
	vmovdqa	%ymm1, -32(%rax)
	vmovdqa	(%rdx), %ymm2
	vpshufb	%ymm10, %ymm2, %ymm2
	vpmullw	%ymm4, %ymm2, %ymm2
	vpaddw	%ymm1, %ymm2, %ymm2
	vmovdqa	%ymm2, -32(%rax)
	vmovdqa	(%rdx), %ymm1
	vpshufb	%ymm9, %ymm1, %ymm1
	vpmullw	%ymm3, %ymm1, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vmovdqa	%ymm1, -32(%rax)
	vmovdqa	(%rdx), %ymm2
	vpshufb	%ymm8, %ymm2, %ymm2
	vpmullw	%ymm0, %ymm2, %ymm2
	vpaddw	%ymm1, %ymm2, %ymm1
	vmovdqa	%ymm1, -32(%rax)
	vmovdqa	32(%rdx), %ymm1
	vpshufb	%ymm11, %ymm1, %ymm1
	vpmullw	%ymm5, %ymm1, %ymm1
	vpaddw	128(%rax), %ymm1, %ymm1
	vmovdqa	%ymm1, 128(%rax)
	vmovdqa	32(%rdx), %ymm2
	vpshufb	%ymm10, %ymm2, %ymm2
	vpmullw	%ymm4, %ymm2, %ymm2
	vpaddw	%ymm1, %ymm2, %ymm2
	vmovdqa	%ymm2, 128(%rax)
	vmovdqa	32(%rdx), %ymm1
	vpshufb	%ymm9, %ymm1, %ymm1
	vpmullw	%ymm3, %ymm1, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vmovdqa	%ymm1, 128(%rax)
	vmovdqa	32(%rdx), %ymm2
	vpshufb	%ymm8, %ymm2, %ymm2
	vpmullw	%ymm0, %ymm2, %ymm2
	vpaddw	%ymm1, %ymm2, %ymm1
	vmovdqa	%ymm1, 128(%rax)
	vmovdqa	64(%rdx), %ymm1
	vpshufb	%ymm11, %ymm1, %ymm1
	vpmullw	%ymm5, %ymm1, %ymm1
	vpaddw	288(%rax), %ymm1, %ymm1
	vmovdqa	%ymm1, 288(%rax)
	vmovdqa	64(%rdx), %ymm2
	vpshufb	%ymm10, %ymm2, %ymm2
	vpmullw	%ymm4, %ymm2, %ymm2
	vpaddw	%ymm1, %ymm2, %ymm2
	vmovdqa	%ymm2, 288(%rax)
	vmovdqa	64(%rdx), %ymm1
	vpshufb	%ymm9, %ymm1, %ymm1
	vpmullw	%ymm3, %ymm1, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vmovdqa	%ymm1, 288(%rax)
	vmovdqa	64(%rdx), %ymm2
	vpshufb	%ymm8, %ymm2, %ymm2
	vpmullw	%ymm0, %ymm2, %ymm2
	vpaddw	%ymm1, %ymm2, %ymm1
	vmovdqa	%ymm1, 288(%rax)
	vmovdqa	96(%rdx), %ymm1
	vpshufb	%ymm11, %ymm1, %ymm1
	vpmullw	%ymm5, %ymm1, %ymm1
	vpaddw	448(%rax), %ymm1, %ymm1
	vmovdqa	%ymm1, 448(%rax)
	vmovdqa	96(%rdx), %ymm2
	vpshufb	%ymm10, %ymm2, %ymm2
	vpmullw	%ymm4, %ymm2, %ymm2
	vpaddw	%ymm1, %ymm2, %ymm2
	vmovdqa	%ymm2, 448(%rax)
	vmovdqa	96(%rdx), %ymm1
	vpshufb	%ymm9, %ymm1, %ymm1
	vpmullw	%ymm3, %ymm1, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vmovdqa	%ymm1, 448(%rax)
	vmovdqa	96(%rdx), %ymm2
	vpshufb	%ymm8, %ymm2, %ymm2
	vpmullw	%ymm0, %ymm2, %ymm2
	vpaddw	%ymm1, %ymm2, %ymm1
	vmovdqa	%ymm1, 448(%rax)
	vmovdqa	128(%rdx), %ymm1
	vpshufb	%ymm11, %ymm1, %ymm1
	vpmullw	%ymm5, %ymm1, %ymm1
	vpaddw	608(%rax), %ymm1, %ymm1
	vmovdqa	%ymm1, 608(%rax)
	vmovdqa	128(%rdx), %ymm2
	vpshufb	%ymm10, %ymm2, %ymm2
	vpmullw	%ymm4, %ymm2, %ymm2
	vpaddw	%ymm1, %ymm2, %ymm2
	vmovdqa	%ymm2, 608(%rax)
	vmovdqa	128(%rdx), %ymm1
	vpshufb	%ymm9, %ymm1, %ymm1
	vpmullw	%ymm3, %ymm1, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vmovdqa	%ymm1, 608(%rax)
	vmovdqa	128(%rdx), %ymm2
	vpshufb	%ymm8, %ymm2, %ymm2
	vpmullw	%ymm0, %ymm2, %ymm0
	vpaddw	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 608(%rax)
	cmpq	$160, %rdi
	jne	.L138
	addl	$5, %esi
	addq	$160, %r10
	addq	$160, %rdx
	cmpl	$120, %esi
	jne	.L137
	movl	$1680696365, %edx
	leaq	800(%r13), %rsi
	movq	%r13, %rax
	vmovd	%edx, %xmm3
	vpbroadcastd	%xmm3, %ymm3
.L140:
	vmovdqa	(%rax), %ymm2
	addq	$32, %rax
	vpmulhuw	%ymm3, %ymm2, %ymm1
	vpsubw	%ymm1, %ymm2, %ymm0
	vpsrlw	$1, %ymm0, %ymm0
	vpaddw	%ymm1, %ymm0, %ymm0
	vpsrlw	$4, %ymm0, %ymm0
	vpsllw	$1, %ymm0, %ymm1
	vpaddw	%ymm0, %ymm1, %ymm1
	vpsllw	$3, %ymm1, %ymm1
	vpsubw	%ymm0, %ymm1, %ymm0
	vpsubw	%ymm0, %ymm2, %ymm2
	vmovdqa	%ymm2, -32(%rax)
	cmpq	%rax, %rsi
	jne	.L140
	xorl	%eax, %eax
	leaq	-46080(%r15), %rdx
	movq	%rcx, %rsi
	movq	%r8, %rdi
.L141:
	movq	%rax, %r9
	movq	%r12, 80(%rsp)
	movq	%r13, %r8
	xorl	%ecx, %ecx
	movq	%r15, 56(%rsp)
	salq	$4, %r9
	addq	%rdx, %r9
.L145:
	movq	%r8, %r10
	movq	%r11, %r12
	xorl	%r15d, %r15d
.L142:
	vmovdqa	55680(%r9), %xmm2
	vmovdqa	(%r12), %xmm6
	addq	$32, %r15
	addq	$32, %r12
	vmovdqa	-16(%r12), %xmm4
	addq	$32, %r10
	vpshufb	%xmm12, %xmm2, %xmm0
	vpshufb	.LC20(%rip), %xmm2, %xmm7
	vpunpcklqdq	%xmm6, %xmm6, %xmm13
	vpsrldq	$8, %xmm0, %xmm1
	vpsrldq	$8, %xmm7, %xmm14
	vpunpckhqdq	%xmm6, %xmm6, %xmm6
	vpmovzxbw	%xmm1, %xmm1
	vpmovzxbw	%xmm14, %xmm14
	vpshufb	.LC21(%rip), %xmm2, %xmm3
	vpmullw	%xmm6, %xmm14, %xmm14
	vpmullw	%xmm13, %xmm1, %xmm1
	vpshufb	.LC22(%rip), %xmm2, %xmm2
	vpmovzxbw	%xmm0, %xmm0
	vpmovzxbw	%xmm7, %xmm7
	vpunpcklqdq	%xmm4, %xmm4, %xmm5
	vpsrldq	$8, %xmm2, %xmm15
	vpmullw	%xmm13, %xmm0, %xmm0
	vpunpckhqdq	%xmm4, %xmm4, %xmm4
	vpmullw	%xmm6, %xmm7, %xmm6
	vpmovzxbw	%xmm15, %xmm15
	vpmovzxbw	%xmm2, %xmm2
	vpmullw	%xmm4, %xmm15, %xmm15
	vpmullw	%xmm4, %xmm2, %xmm2
	vpaddw	%xmm14, %xmm1, %xmm1
	vpsrldq	$8, %xmm3, %xmm14
	vpmovzxbw	%xmm3, %xmm3
	vpmovzxbw	%xmm14, %xmm14
	vpmullw	%xmm5, %xmm3, %xmm3
	vpaddw	-16(%r10), %xmm1, %xmm1
	vpmullw	%xmm5, %xmm14, %xmm14
	vpaddw	%xmm6, %xmm0, %xmm0
	vpaddw	-32(%r10), %xmm0, %xmm0
	vpaddw	%xmm2, %xmm3, %xmm2
	vpaddw	%xmm15, %xmm14, %xmm14
	vpaddw	%xmm2, %xmm0, %xmm0
	vpaddw	%xmm14, %xmm1, %xmm1
	vmovdqa	%xmm0, -32(%r10)
	vmovdqa	%xmm1, -16(%r10)
	cmpq	$160, %r15
	jne	.L142
	addq	$5, %rcx
	addq	$160, %r8
	addq	$384, %r9
	cmpq	$25, %rcx
	jne	.L145
	incq	%rax
	movq	80(%rsp), %r12
	movq	56(%rsp), %r15
	addq	$160, %r11
	cmpq	$24, %rax
	jne	.L141
	movq	%rdi, %r8
	movl	$1680696365, %eax
	movl	$1507351, %edi
	vpbroadcastd	.LC32(%rip), %ymm4
	vmovd	%eax, %xmm13
	vmovd	%edi, %xmm7
	vpcmpeqd	%ymm3, %ymm3, %ymm3
	movq	%rsi, %rcx
	movq	%r13, %rdx
	vpbroadcastd	%xmm13, %ymm13
	vpbroadcastd	%xmm7, %ymm7
	movq	%r14, %rsi
	vpxor	%xmm5, %xmm5, %xmm5
	vpsrlw	$8, %ymm3, %ymm6
.L146:
	vmovdqa	(%rdx), %ymm3
	vmovdqa	32(%rdx), %ymm2
	addq	$64, %rdx
	addq	$32, %rsi
	vpmulhuw	%ymm13, %ymm3, %ymm1
	vpmulhuw	%ymm13, %ymm2, %ymm0
	vpsubw	%ymm1, %ymm3, %ymm14
	vpsrlw	$1, %ymm14, %ymm14
	vpaddw	%ymm1, %ymm14, %ymm14
	vpsrlw	$4, %ymm14, %ymm14
	vpsllw	$1, %ymm14, %ymm1
	vpaddw	%ymm14, %ymm1, %ymm1
	vpsllw	$3, %ymm1, %ymm1
	vpsubw	%ymm14, %ymm1, %ymm1
	vpsubw	%ymm3, %ymm1, %ymm1
	vpsubw	%ymm0, %ymm2, %ymm3
	vpsrlw	$1, %ymm3, %ymm3
	vpaddw	%ymm7, %ymm1, %ymm1
	vpaddw	%ymm0, %ymm3, %ymm3
	vpmovzxwd	%xmm1, %ymm14
	vextracti128	$0x1, %ymm1, %xmm1
	vpsrlw	$4, %ymm3, %ymm3
	vpmuldq	%ymm4, %ymm14, %ymm15
	vpsllw	$1, %ymm3, %ymm0
	vpaddw	%ymm3, %ymm0, %ymm0
	vpsllw	$3, %ymm0, %ymm0
	vpsubw	%ymm3, %ymm0, %ymm0
	vpsubw	%ymm2, %ymm0, %ymm0
	vpmovzxwd	%xmm1, %ymm2
	vpshufd	$245, %ymm15, %ymm15
	vpsrlq	$32, %ymm14, %ymm1
	vpaddw	%ymm7, %ymm0, %ymm0
	vpmuldq	%ymm4, %ymm1, %ymm1
	vpmovzxwd	%xmm0, %ymm3
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxwd	%xmm0, %ymm0
	vpblendd	$85, %ymm15, %ymm1, %ymm1
	vpaddd	%ymm14, %ymm1, %ymm1
	vpsrad	$4, %ymm1, %ymm1
	vpslld	$1, %ymm1, %ymm15
	vpaddd	%ymm1, %ymm15, %ymm15
	vpslld	$3, %ymm15, %ymm15
	vpsubd	%ymm1, %ymm15, %ymm1
	vpmuldq	%ymm4, %ymm2, %ymm15
	vpsubd	%ymm1, %ymm14, %ymm1
	vpsrlq	$32, %ymm2, %ymm14
	vpmuldq	%ymm4, %ymm14, %ymm14
	vpblendw	$85, %ymm1, %ymm5, %ymm1
	vpshufd	$245, %ymm15, %ymm15
	vpblendd	$85, %ymm15, %ymm14, %ymm14
	vpaddd	%ymm2, %ymm14, %ymm14
	vpsrad	$4, %ymm14, %ymm14
	vpslld	$1, %ymm14, %ymm15
	vpaddd	%ymm14, %ymm15, %ymm15
	vpslld	$3, %ymm15, %ymm15
	vpsubd	%ymm14, %ymm15, %ymm14
	vpsubd	%ymm14, %ymm2, %ymm2
	vpmuldq	%ymm4, %ymm3, %ymm14
	vpblendw	$85, %ymm2, %ymm5, %ymm2
	vpackusdw	%ymm2, %ymm1, %ymm2
	vpsrlq	$32, %ymm3, %ymm1
	vpmuldq	%ymm4, %ymm1, %ymm1
	vpermq	$216, %ymm2, %ymm2
	vpand	%ymm2, %ymm6, %ymm2
	vpshufd	$245, %ymm14, %ymm14
	vpblendd	$85, %ymm14, %ymm1, %ymm1
	vpaddd	%ymm3, %ymm1, %ymm1
	vpsrad	$4, %ymm1, %ymm1
	vpslld	$1, %ymm1, %ymm14
	vpaddd	%ymm1, %ymm14, %ymm14
	vpslld	$3, %ymm14, %ymm14
	vpsubd	%ymm1, %ymm14, %ymm1
	vpmuldq	%ymm4, %ymm0, %ymm14
	vpsubd	%ymm1, %ymm3, %ymm1
	vpsrlq	$32, %ymm0, %ymm3
	vpmuldq	%ymm4, %ymm3, %ymm3
	vpshufd	$245, %ymm14, %ymm14
	vpblendd	$85, %ymm14, %ymm3, %ymm3
	vpaddd	%ymm0, %ymm3, %ymm3
	vpsrad	$4, %ymm3, %ymm3
	vpslld	$1, %ymm3, %ymm14
	vpaddd	%ymm3, %ymm14, %ymm14
	vpslld	$3, %ymm14, %ymm14
	vpsubd	%ymm3, %ymm14, %ymm3
	vpsubd	%ymm3, %ymm0, %ymm3
	vpblendw	$85, %ymm1, %ymm5, %ymm0
	vpblendw	$85, %ymm3, %ymm5, %ymm1
	vpackusdw	%ymm1, %ymm0, %ymm0
	vpermq	$216, %ymm0, %ymm0
	vpand	%ymm0, %ymm6, %ymm0
	vpackuswb	%ymm0, %ymm2, %ymm0
	vpermq	$216, %ymm0, %ymm0
	vmovdqu	%ymm0, -32(%rsi)
	cmpq	88(%rsp), %rdx
	jne	.L146
	vmovdqa	896(%rsp), %xmm5
	vmovd	%eax, %xmm7
	vmovdqa	912(%rsp), %xmm4
	addq	$400, %r14
	vpbroadcastd	%xmm7, %xmm1
	vmovd	%edi, %xmm7
	addq	$120, 112(%rsp)
	addq	$1920, %r15
	vpmulhuw	%xmm1, %xmm5, %xmm0
	vpmulhuw	%xmm1, %xmm4, %xmm1
	vpbroadcastd	%xmm7, %xmm3
	vmovdqa	64(%rsp), %xmm7
	addq	$9216, %r12
	vpsubw	%xmm0, %xmm5, %xmm2
	vpsrlw	$1, %xmm2, %xmm2
	vpaddw	%xmm0, %xmm2, %xmm2
	vpsrlw	$4, %xmm2, %xmm2
	vpsllw	$1, %xmm2, %xmm0
	vpaddw	%xmm2, %xmm0, %xmm0
	vpsllw	$3, %xmm0, %xmm0
	vpsubw	%xmm2, %xmm0, %xmm0
	vpsubw	%xmm1, %xmm4, %xmm2
	vpsrlw	$1, %xmm2, %xmm2
	vpsubw	%xmm5, %xmm0, %xmm0
	vpbroadcastd	.LC32(%rip), %xmm5
	vpaddw	%xmm1, %xmm2, %xmm2
	vpaddw	%xmm3, %xmm0, %xmm0
	vpsrlw	$4, %xmm2, %xmm2
	vpsllw	$1, %xmm2, %xmm1
	vpaddw	%xmm2, %xmm1, %xmm1
	vpsllw	$3, %xmm1, %xmm1
	vpsubw	%xmm2, %xmm1, %xmm1
	vpsubw	%xmm4, %xmm1, %xmm1
	vpaddw	%xmm3, %xmm1, %xmm1
	vpmovzxwd	%xmm0, %xmm3
	vpmuldq	%xmm5, %xmm3, %xmm6
	vpsrlq	$32, %xmm3, %xmm2
	vpmovzxwd	%xmm1, %xmm4
	vpmuldq	%xmm5, %xmm2, %xmm2
	vpsrldq	$8, %xmm0, %xmm0
	vpmovzxwd	%xmm0, %xmm0
	vpsrldq	$8, %xmm1, %xmm1
	vpmovzxwd	%xmm1, %xmm1
	vpshufd	$245, %xmm6, %xmm6
	vpblendd	$5, %xmm6, %xmm2, %xmm2
	vpaddd	%xmm3, %xmm2, %xmm2
	vpsrad	$4, %xmm2, %xmm2
	vpslld	$1, %xmm2, %xmm6
	vpaddd	%xmm2, %xmm6, %xmm6
	vpslld	$3, %xmm6, %xmm6
	vpsubd	%xmm2, %xmm6, %xmm6
	vpsrlq	$32, %xmm0, %xmm2
	vpsubd	%xmm6, %xmm3, %xmm6
	vpmuldq	%xmm5, %xmm0, %xmm3
	vpmuldq	%xmm5, %xmm2, %xmm2
	vpshufd	$245, %xmm3, %xmm3
	vpblendd	$5, %xmm3, %xmm2, %xmm2
	vpaddd	%xmm0, %xmm2, %xmm2
	vpsrad	$4, %xmm2, %xmm2
	vpslld	$1, %xmm2, %xmm3
	vpaddd	%xmm2, %xmm3, %xmm3
	vpslld	$3, %xmm3, %xmm3
	vpsubd	%xmm2, %xmm3, %xmm2
	vpxor	%xmm3, %xmm3, %xmm3
	vpsubd	%xmm2, %xmm0, %xmm2
	vpblendw	$85, %xmm6, %xmm3, %xmm0
	vpblendw	$85, %xmm2, %xmm3, %xmm2
	vpmuldq	%xmm5, %xmm4, %xmm6
	vpackusdw	%xmm2, %xmm0, %xmm0
	vpsrlq	$32, %xmm4, %xmm2
	vpmuldq	%xmm5, %xmm2, %xmm2
	vpand	%xmm7, %xmm0, %xmm0
	vpshufd	$245, %xmm6, %xmm6
	vpblendd	$5, %xmm6, %xmm2, %xmm2
	vpaddd	%xmm4, %xmm2, %xmm2
	vpsrad	$4, %xmm2, %xmm2
	vpslld	$1, %xmm2, %xmm6
	vpaddd	%xmm2, %xmm6, %xmm6
	vpslld	$3, %xmm6, %xmm6
	vpsubd	%xmm2, %xmm6, %xmm2
	vpmuldq	%xmm5, %xmm1, %xmm6
	vpsubd	%xmm2, %xmm4, %xmm4
	vpsrlq	$32, %xmm1, %xmm2
	vpmuldq	%xmm5, %xmm2, %xmm2
	vpshufd	$245, %xmm6, %xmm5
	vpblendd	$5, %xmm5, %xmm2, %xmm2
	vpaddd	%xmm1, %xmm2, %xmm2
	vpsrad	$4, %xmm2, %xmm2
	vpslld	$1, %xmm2, %xmm5
	vpaddd	%xmm2, %xmm5, %xmm5
	vpslld	$3, %xmm5, %xmm5
	vpsubd	%xmm2, %xmm5, %xmm2
	vpsubd	%xmm2, %xmm1, %xmm2
	vpblendw	$85, %xmm4, %xmm3, %xmm1
	vpblendw	$85, %xmm2, %xmm3, %xmm3
	vpackusdw	%xmm3, %xmm1, %xmm1
	vpand	%xmm7, %xmm1, %xmm1
	vpackuswb	%xmm1, %xmm0, %xmm0
	vmovdqa	%xmm0, -16(%r14)
	cmpq	$600, 112(%rsp)
	je	.L223
	vzeroupper
	jmp	.L147
.L223:
	vmovdqu	(%r8), %xmm0
	movq	120(%rsp), %rdi
	xorl	%esi, %esi
	movl	$1050, %edx
	movq	120(%rsp), %r14
	movq	%rcx, %r12
	movq	%r8, %rbx
	vmovdqu	%xmm0, (%rcx)
	vzeroupper
	call	memset@PLT
	xorl	%eax, %eax
	xorl	%esi, %esi
.L148:
	movq	104(%rsp), %rdi
	movq	%rsi, 32(%rsp)
	movq	%rsi, %r10
	movl	$4, %r9d
	xorl	%r13d, %r13d
	movq	%rax, %r15
	movq	%rdi, 120(%rsp)
.L162:
	movq	%r13, %rsi
	leal	-1(%r9), %edi
	movq	120(%rsp), %r11
	movl	%r10d, %edx
	negq	%rsi
	movl	%edi, 112(%rsp)
	sall	$4, %edx
	movq	%rsi, %rcx
	leaq	17(,%rsi,4), %rsi
	leaq	16(%r11), %rax
	addl	$64, %edx
	movq	%rsi, 88(%rsp)
	leaq	4(,%rdi,4), %rsi
	movl	%r9d, %edi
	salq	$4, %rcx
	shrl	%edi
	movq	%rsi, 64(%rsp)
	movl	%r9d, %esi
	movl	%edi, 80(%rsp)
	movl	%r9d, %edi
	andl	$-2, %esi
	andl	$1, %edi
	movl	%esi, 48(%rsp)
	movl	%edi, 56(%rsp)
	movq	%rcx, 96(%rsp)
	xorl	%ecx, %ecx
.L161:
	movl	$4, %r8d
	subq	%rcx, %r8
	testl	%r8d, %r8d
	je	.L158
	movq	%rax, 24(%rsp)
	xorl	%esi, %esi
.L157:
	movl	%esi, %edi
	incl	%esi
	movzbl	(%r11,%rdi), %eax
	movb	%al, (%r14,%rdi)
	cmpl	%r8d, %esi
	jb	.L157
	movq	24(%rsp), %rax
.L158:
	movl	$3, %edi
	subq	%rcx, %rdi
	addq	%r14, %rdi
	leaq	1(%rdi), %rsi
	movq	%rsi, %r14
	testl	%r9d, %r9d
	je	.L224
	movq	88(%rsp), %r8
	addq	%rdi, %r8
	cmpq	%r8, %rax
	jnb	.L174
	movq	96(%rsp), %r8
	leaq	52(%rax,%r8), %r8
	cmpq	%r8, %r14
	jb	.L149
.L174:
	cmpq	$3, %r13
	je	.L172
	vmovq	(%rax), %xmm0
	vmovd	16(%rax), %xmm1
	cmpl	$1, 80(%rsp)
	vinsertps	$16, %xmm1, %xmm0, %xmm0
	vmovq	%xmm0, 1(%rdi)
	je	.L152
	vmovq	32(%rax), %xmm0
	vmovd	48(%rax), %xmm1
	vinsertps	$16, %xmm1, %xmm0, %xmm0
	vmovq	%xmm0, 8(%rsi)
.L152:
	movl	56(%rsp), %edi
	testl	%edi, %edi
	je	.L156
	movl	48(%rsp), %edi
.L151:
	leaq	1(%r10,%rdi), %r8
	leaq	(%rcx,%r8,4), %r8
	movl	9664(%rsp,%r8,4), %r8d
	movl	%r8d, (%rsi,%rdi,4)
.L156:
	movq	64(%rsp), %rdi
	incq	%rcx
	leaq	(%rdi,%rsi), %r14
	cmpq	$4, %rcx
	je	.L225
.L153:
	addq	$5, %r11
	addl	$4, %edx
	addq	$4, %rax
	jmp	.L161
.L172:
	xorl	%edi, %edi
	jmp	.L151
.L149:
	leal	-48(%rdx), %r8d
	movslq	%r8d, %r8
	movl	9664(%rsp,%r8), %r8d
	movl	%r8d, 1(%rdi)
	cmpl	$1, %r9d
	je	.L156
	leal	-32(%rdx), %edi
	movslq	%edi, %rdi
	movl	9664(%rsp,%rdi), %edi
	movl	%edi, 4(%rsi)
	cmpl	$2, %r9d
	je	.L156
	leal	-16(%rdx), %edi
	movslq	%edi, %rdi
	movl	9664(%rsp,%rdi), %edi
	movl	%edi, 8(%rsi)
	cmpl	$3, %r9d
	je	.L156
	movslq	%edx, %rdi
	movl	9664(%rsp,%rdi), %edi
	movl	%edi, 12(%rsi)
	jmp	.L156
.L224:
	incq	%rcx
	cmpq	$4, %rcx
	jne	.L153
	movq	32(%rsp), %rsi
	leaq	5(%r15), %rax
	addq	$400, 104(%rsp)
	addq	$25, %rsi
	cmpq	$25, %rax
	jne	.L148
	xorl	%edi, %edi
	xorl	%ecx, %ecx
	movl	$23, %esi
	jmp	.L167
.L226:
	movq	%r12, %rcx
	movb	%dl, 16(%r12,%rdi)
	movb	%dh, 17(%rcx,%rdi)
	movq	%rdx, %rcx
	shrq	$24, %rdx
	shrq	$16, %rcx
	movb	%dl, 19(%r12,%rdi)
	movb	%cl, 18(%r12,%rdi)
	addq	$4, %rdi
	cmpq	$1050, %rax
	je	.L165
	movq	%rax, %rcx
.L167:
	movzbl	8608(%rsp,%rcx), %eax
	divb	%sil
	movzbl	%ah, %edx
	leaq	1(%rcx), %rax
	movzbl	%dl, %edx
	cmpq	$1049, %rcx
	je	.L166
	movzbl	8608(%rsp,%rax), %eax
	divb	%sil
	movzbl	%ah, %eax
	movzbl	%al, %eax
	imulq	$23, %rax, %rax
	addq	%rax, %rdx
	leaq	2(%rcx), %rax
	cmpq	$1048, %rcx
	je	.L166
	movzbl	8608(%rsp,%rax), %eax
	divb	%sil
	movzbl	%ah, %eax
	movzbl	%al, %eax
	imulq	$529, %rax, %rax
	addq	%rax, %rdx
	leaq	3(%rcx), %rax
	cmpq	$1047, %rcx
	je	.L166
	movzbl	8608(%rsp,%rax), %eax
	divb	%sil
	movzbl	%ah, %eax
	movzbl	%al, %eax
	imulq	$12167, %rax, %rax
	addq	%rax, %rdx
	leaq	4(%rcx), %rax
	cmpq	$1046, %rcx
	je	.L166
	movzbl	8608(%rsp,%rax), %eax
	divb	%sil
	movzbl	%ah, %eax
	movzbl	%al, %eax
	imulq	$279841, %rax, %rax
	addq	%rax, %rdx
	leaq	5(%rcx), %rax
	cmpq	$1045, %rcx
	je	.L166
	movzbl	8608(%rsp,%rax), %eax
	divb	%sil
	movzbl	%ah, %eax
	movzbl	%al, %eax
	imulq	$6436343, %rax, %rax
	addq	%rax, %rdx
	leaq	6(%rcx), %rax
	cmpq	$1044, %rcx
	je	.L166
	movzbl	8608(%rsp,%rax), %eax
	divb	%sil
	movzbl	%ah, %eax
	movzbl	%al, %eax
	imulq	$148035889, %rax, %rax
	addq	%rax, %rdx
	leaq	7(%rcx), %rax
.L166:
	cmpq	$600, %rdi
	jne	.L226
.L165:
	vmovdqu	(%rbx), %ymm0
	movq	40(%rsp), %rax
	vmovdqu	%ymm0, (%rax)
	vmovdqu	32(%rbx), %xmm0
	vmovdqu	%xmm0, 32(%rax)
	movq	80952(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L227
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
.L225:
	.cfi_restore_state
	addq	$96, 120(%rsp)
	movl	112(%rsp), %r9d
	incq	%r13
	addq	$6, %r10
	jmp	.L162
.L227:
	vzeroupper
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE16:
	.size	_snova_24_5_23_4_SNOVA_OPT_genkeys, .-_snova_24_5_23_4_SNOVA_OPT_genkeys
	.p2align 4
	.globl	_snova_24_5_23_4_SNOVA_OPT_sk_expand
	.type	_snova_24_5_23_4_SNOVA_OPT_sk_expand, @function
_snova_24_5_23_4_SNOVA_OPT_sk_expand:
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
	andq	$-32, %rsp
	subq	$92160, %rsp
	.cfi_offset 15, -24
	.cfi_offset 14, -32
	.cfi_offset 13, -40
	.cfi_offset 12, -48
	.cfi_offset 3, -56
	movq	%fs:40, %r13
	movq	%r13, 92152(%rsp)
	movq	%rdi, %r13
	vmovdqu	-16(%rsi), %ymm0
	leaq	22848(%rsp), %rbx
	vmovdqu	%ymm0, 172000(%r13)
	leaq	134560(%r13), %r12
	vmovdqu	16(%rsi), %xmm0
	movq	%r12, %rdi
	vmovdqu	%xmm0, 172032(%r13)
	vzeroupper
	call	expand_T12
	leaq	172000(%r13), %rsi
	movq	%rbx, %rdi
	movq	%rbx, 56(%rsp)
	call	expand_public
	movq	%r13, %rdx
	movq	%rbx, %rax
	leaq	68928(%rsp), %rcx
.L229:
	vmovdqa	(%rax), %ymm0
	addq	$32, %rax
	addq	$64, %rdx
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, -64(%rdx)
	vmovdqu	%ymm0, -32(%rdx)
	cmpq	%rcx, %rax
	jne	.L229
	movl	$19200, %edx
	xorl	%esi, %esi
	leaq	448(%rsp), %rdi
	vzeroupper
	call	memset@PLT
	vmovdqa	.LC14(%rip), %ymm12
	vmovdqa	.LC15(%rip), %ymm11
	vmovdqa	.LC16(%rip), %ymm10
	vmovdqa	.LC17(%rip), %ymm9
	movq	%rax, %rdx
	movq	%rax, %r9
	leaq	18432(%r13), %r10
	xorl	%eax, %eax
.L230:
	leaq	-18432(%r10), %r11
	movq	%r12, %rsi
.L234:
	vmovdqu	(%rsi), %ymm1
	vmovdqu	32(%rsi), %ymm0
	movq	%r9, %rcx
	movq	%r11, %r8
	vmovdqu	64(%rsi), %ymm7
	vmovdqu	96(%rsi), %ymm6
	xorl	%edi, %edi
	vpshufb	%ymm10, %ymm1, %ymm4
	vmovdqu	128(%rsi), %ymm5
	vpshufb	%ymm12, %ymm1, %ymm13
	vpshufb	%ymm11, %ymm1, %ymm8
	vmovdqa	%ymm4, 416(%rsp)
	vpshufb	%ymm9, %ymm1, %ymm4
	vmovdqa	%ymm4, 384(%rsp)
	vpshufb	%ymm12, %ymm0, %ymm4
	vmovdqa	%ymm4, 352(%rsp)
	vpshufb	%ymm11, %ymm0, %ymm4
	vmovdqa	%ymm4, 320(%rsp)
	vpshufb	%ymm10, %ymm0, %ymm4
	vmovdqa	%ymm4, 288(%rsp)
	vpshufb	%ymm9, %ymm0, %ymm4
	vmovdqa	%ymm4, 256(%rsp)
	vpshufb	%ymm12, %ymm7, %ymm4
	vmovdqa	%ymm4, 224(%rsp)
	vpshufb	%ymm11, %ymm7, %ymm4
	vmovdqa	%ymm4, 192(%rsp)
.L231:
	vmovdqu	(%r8), %ymm0
	addq	$32, %rdi
	addq	$32, %r8
	addq	$32, %rcx
	vpermq	$0, %ymm0, %ymm4
	vpermq	$85, %ymm0, %ymm3
	vpermq	$170, %ymm0, %ymm2
	vpmullw	%ymm3, %ymm8, %ymm14
	vpmullw	%ymm4, %ymm13, %ymm1
	vpermq	$255, %ymm0, %ymm0
	vpmullw	384(%rsp), %ymm0, %ymm15
	vpaddw	%ymm14, %ymm1, %ymm1
	vpmullw	416(%rsp), %ymm2, %ymm14
	vpaddw	%ymm15, %ymm14, %ymm14
	vpmullw	256(%rsp), %ymm0, %ymm15
	vpaddw	-32(%rcx), %ymm1, %ymm1
	vpaddw	%ymm14, %ymm1, %ymm1
	vpmullw	320(%rsp), %ymm3, %ymm14
	vmovdqa	%ymm1, -32(%rcx)
	vpmullw	352(%rsp), %ymm4, %ymm1
	vpaddw	%ymm14, %ymm1, %ymm1
	vpmullw	288(%rsp), %ymm2, %ymm14
	vpaddw	736(%rcx), %ymm1, %ymm1
	vpaddw	%ymm15, %ymm14, %ymm14
	vpshufb	%ymm9, %ymm7, %ymm15
	vpmullw	%ymm0, %ymm15, %ymm15
	vpaddw	%ymm14, %ymm1, %ymm1
	vpmullw	192(%rsp), %ymm3, %ymm14
	vmovdqa	%ymm1, 736(%rcx)
	vpmullw	224(%rsp), %ymm4, %ymm1
	vpaddw	%ymm14, %ymm1, %ymm1
	vpshufb	%ymm10, %ymm7, %ymm14
	vpmullw	%ymm2, %ymm14, %ymm14
	vpaddw	1504(%rcx), %ymm1, %ymm1
	vpaddw	%ymm15, %ymm14, %ymm14
	vpshufb	%ymm9, %ymm6, %ymm15
	vpaddw	%ymm14, %ymm1, %ymm1
	vpmullw	%ymm0, %ymm15, %ymm15
	vpshufb	%ymm11, %ymm6, %ymm14
	vmovdqa	%ymm1, 1504(%rcx)
	vpshufb	%ymm12, %ymm6, %ymm1
	vpmullw	%ymm3, %ymm14, %ymm14
	vpmullw	%ymm4, %ymm1, %ymm1
	vpaddw	%ymm14, %ymm1, %ymm1
	vpshufb	%ymm10, %ymm6, %ymm14
	vpmullw	%ymm2, %ymm14, %ymm14
	vpaddw	2272(%rcx), %ymm1, %ymm1
	vpaddw	%ymm15, %ymm14, %ymm14
	vpaddw	%ymm14, %ymm1, %ymm1
	vmovdqa	%ymm1, 2272(%rcx)
	vpshufb	%ymm12, %ymm5, %ymm1
	vpmullw	%ymm4, %ymm1, %ymm1
	vpshufb	%ymm11, %ymm5, %ymm4
	vpmullw	%ymm3, %ymm4, %ymm3
	vpaddw	%ymm3, %ymm1, %ymm1
	vpaddw	3040(%rcx), %ymm1, %ymm3
	vpshufb	%ymm10, %ymm5, %ymm1
	vpmullw	%ymm2, %ymm1, %ymm1
	vpshufb	%ymm9, %ymm5, %ymm2
	vpmullw	%ymm0, %ymm2, %ymm0
	vpaddw	%ymm0, %ymm1, %ymm0
	vpaddw	%ymm0, %ymm3, %ymm0
	vmovdqa	%ymm0, 3040(%rcx)
	cmpq	$768, %rdi
	jne	.L231
	addq	$768, %r11
	addq	$160, %rsi
	cmpq	%r10, %r11
	jne	.L234
	addl	$24, %eax
	leaq	18432(%r11), %r10
	addq	$3840, %r9
	cmpl	$120, %eax
	jne	.L230
	leaq	138400(%r13), %rcx
	leaq	78528(%rsp), %rax
	vpxor	%xmm4, %xmm4, %xmm4
	movl	$-1307163959, %esi
	vmovd	%esi, %xmm3
	leaq	88128(%rsp), %rdi
	vpbroadcastd	%xmm3, %ymm3
.L235:
	vmovdqa	(%rax), %ymm0
	vmovdqa	(%rdx), %ymm2
	addq	$32, %rax
	addq	$64, %rcx
	vmovdqa	32(%rdx), %ymm5
	addq	$64, %rdx
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
	vpaddd	%ymm7, %ymm5, %ymm5
	vpsrad	$4, %ymm5, %ymm5
	vpslld	$1, %ymm5, %ymm6
	vpaddd	%ymm5, %ymm6, %ymm6
	vpslld	$3, %ymm6, %ymm6
	vpsubd	%ymm5, %ymm6, %ymm5
	vpsubd	%ymm5, %ymm7, %ymm6
	vpmuldq	%ymm3, %ymm1, %ymm7
	vpsrlq	$32, %ymm1, %ymm5
	vpmuldq	%ymm3, %ymm5, %ymm5
	vpshufd	$245, %ymm7, %ymm7
	vpblendd	$85, %ymm7, %ymm5, %ymm5
	vpaddd	%ymm1, %ymm5, %ymm5
	vpsrad	$4, %ymm5, %ymm5
	vpslld	$1, %ymm5, %ymm7
	vpaddd	%ymm5, %ymm7, %ymm7
	vpslld	$3, %ymm7, %ymm7
	vpsubd	%ymm5, %ymm7, %ymm5
	vpsubd	%ymm5, %ymm1, %ymm1
	vpblendw	$85, %ymm6, %ymm4, %ymm5
	vpblendw	$85, %ymm1, %ymm4, %ymm1
	vpackusdw	%ymm1, %ymm5, %ymm1
	vpmuldq	%ymm3, %ymm2, %ymm5
	vpermq	$216, %ymm1, %ymm1
	vmovdqu	%ymm1, -64(%rcx)
	vpsrlq	$32, %ymm2, %ymm1
	vpmuldq	%ymm3, %ymm1, %ymm1
	vpshufd	$245, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm1, %ymm1
	vpaddd	%ymm2, %ymm1, %ymm1
	vpsrad	$4, %ymm1, %ymm1
	vpslld	$1, %ymm1, %ymm5
	vpaddd	%ymm1, %ymm5, %ymm5
	vpslld	$3, %ymm5, %ymm5
	vpsubd	%ymm1, %ymm5, %ymm1
	vpmuldq	%ymm3, %ymm0, %ymm5
	vpsubd	%ymm1, %ymm2, %ymm2
	vpsrlq	$32, %ymm0, %ymm1
	vpmuldq	%ymm3, %ymm1, %ymm1
	vpshufd	$245, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm1, %ymm1
	vpaddd	%ymm0, %ymm1, %ymm1
	vpsrad	$4, %ymm1, %ymm1
	vpslld	$1, %ymm1, %ymm5
	vpaddd	%ymm1, %ymm5, %ymm5
	vpslld	$3, %ymm5, %ymm5
	vpsubd	%ymm1, %ymm5, %ymm1
	vpsubd	%ymm1, %ymm0, %ymm1
	vpblendw	$85, %ymm2, %ymm4, %ymm0
	vpblendw	$85, %ymm1, %ymm4, %ymm1
	vpackusdw	%ymm1, %ymm0, %ymm0
	vpermq	$216, %ymm0, %ymm0
	vmovdqu	%ymm0, -32(%rcx)
	cmpq	%rdi, %rax
	jne	.L235
	leaq	_snova_24_5_23_4_SNOVA_OPT_Smat(%rip), %r10
	movq	%rax, %rsi
	movq	%r13, %rax
	movq	%r13, 40(%rsp)
	subq	%r10, %rax
	leaq	19648(%rsp), %rcx
	movl	$2987803337, %r12d
	movl	$23, %r15d
	addq	$167198, %rax
	movq	%rcx, 48(%rsp)
	movq	%rcx, %r8
	leaq	91328(%rsp), %r14
	movq	%rax, 416(%rsp)
	leaq	89728(%rsp), %rax
	leaq	164000(%r13), %rcx
	movq	%rax, 96(%rsp)
	movl	$1680696365, %eax
	leaq	21248(%rsp), %rbx
	vmovd	%eax, %xmm1
	vpbroadcastd	%xmm1, %ymm1
.L249:
	movzbl	(%rsi), %eax
	movq	%r8, %rdi
	movq	%rcx, 320(%rsp)
	movq	%rsi, 352(%rsp)
	movb	%al, (%r8)
	movq	1(%rsi), %rax
	movq	%r8, 384(%rsp)
	movq	%rax, 1(%r8)
	movl	9(%rsi), %eax
	movl	%eax, 9(%r8)
	movzwl	13(%rsi), %eax
	movw	%ax, 13(%r8)
	movzbl	15(%rsi), %eax
	movb	%al, 15(%r8)
	call	gf_mat_det
	leaq	_snova_24_5_23_4_SNOVA_OPT_Smat(%rip), %r10
	movq	384(%rsp), %r8
	movq	352(%rsp), %rsi
	testb	%al, %al
	movzwl	32(%r10), %r13d
	movq	320(%rsp), %rcx
	jne	.L240
	movzwl	34(%r10), %r11d
	movzwl	%r13w, %eax
	movzwl	38(%r10), %edi
	movzwl	40(%r10), %edx
	movzwl	42(%r10), %r9d
	movl	%eax, 64(%rsp)
	movzwl	36(%r10), %eax
	movl	%r11d, 124(%rsp)
	movzwl	60(%r10), %r11d
	movl	%edi, 140(%rsp)
	movl	%eax, 132(%rsp)
	movzwl	52(%r10), %edi
	movzwl	44(%r10), %eax
	movl	%edx, 148(%rsp)
	movl	%r9d, 156(%rsp)
	movzwl	48(%r10), %edx
	movzwl	56(%r10), %r9d
	movl	%r11d, 352(%rsp)
	movl	%eax, 164(%rsp)
	movzwl	62(%r10), %r11d
	movzwl	46(%r10), %eax
	movl	%edx, 176(%rsp)
	movl	%edi, 188(%rsp)
	movzwl	50(%r10), %edx
	movzwl	54(%r10), %edi
	movl	%r9d, 256(%rsp)
	movzwl	58(%r10), %r9d
	movl	%eax, 72(%rsp)
	movl	%edx, 76(%rsp)
	movl	%edi, 80(%rsp)
	movl	%r9d, 84(%rsp)
	movl	%r11d, 88(%rsp)
	movl	%r11d, 384(%rsp)
	movl	352(%rsp), %r11d
	movl	%r9d, 288(%rsp)
	movl	256(%rsp), %r9d
	movl	%edi, 192(%rsp)
	movl	188(%rsp), %edi
	movl	%edx, 180(%rsp)
	movl	176(%rsp), %edx
	movl	%eax, 168(%rsp)
	movl	164(%rsp), %eax
	movl	%r11d, 320(%rsp)
	movl	124(%rsp), %r11d
	movl	%r9d, 224(%rsp)
	movl	156(%rsp), %r9d
	movl	%edi, 184(%rsp)
	movl	140(%rsp), %edi
	movl	%edx, 172(%rsp)
	movl	148(%rsp), %edx
	movl	%eax, 160(%rsp)
	movl	132(%rsp), %eax
	movw	%r13w, 122(%rsp)
	movq	%rbx, 112(%rsp)
	movq	%r8, %rbx
	movq	%r14, 104(%rsp)
	movzwl	%r13w, %r14d
	movl	%r11d, %r13d
	movl	%r9d, 152(%rsp)
	movl	%edx, 144(%rsp)
	movl	%edi, 136(%rsp)
	movl	%eax, 128(%rsp)
	movb	$22, 92(%rsp)
	jmp	.L239
.L263:
	movl	132(%rsp), %edi
	addl	64(%rsp), %r14d
	addl	124(%rsp), %r13d
	addl	%edi, 128(%rsp)
	movl	140(%rsp), %edi
	addl	%edi, 136(%rsp)
	movl	148(%rsp), %edi
	addl	%edi, 144(%rsp)
	movl	156(%rsp), %edi
	addl	%edi, 152(%rsp)
	movl	164(%rsp), %edi
	addl	%edi, 160(%rsp)
	movl	72(%rsp), %edi
	addl	%edi, 168(%rsp)
	movl	176(%rsp), %edi
	addl	%edi, 172(%rsp)
	movl	76(%rsp), %edi
	addl	%edi, 180(%rsp)
	movl	188(%rsp), %edi
	addl	%edi, 184(%rsp)
	movl	80(%rsp), %edi
	addl	%edi, 192(%rsp)
	movl	256(%rsp), %edi
	addl	%edi, 224(%rsp)
	movl	84(%rsp), %edi
	addl	%edi, 288(%rsp)
	movl	352(%rsp), %edi
	addl	%edi, 320(%rsp)
	movl	88(%rsp), %edi
	addl	%edi, 384(%rsp)
	decb	92(%rsp)
	je	.L266
.L239:
	movzbl	(%rbx), %edi
	movq	%rsi, 24(%rsp)
	movq	%rcx, 32(%rsp)
	leal	(%rdi,%r14), %eax
	movq	%rax, %rdi
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	movb	%dil, (%rbx)
	movzbl	1(%rbx), %edi
	leal	(%rdi,%r13), %eax
	movq	%rax, %rdi
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	movb	%dil, 1(%rbx)
	movzbl	2(%rbx), %edi
	addl	128(%rsp), %edi
	movl	%edi, %eax
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	movb	%dil, 2(%rbx)
	movzbl	3(%rbx), %edi
	addl	136(%rsp), %edi
	movl	%edi, %eax
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	movb	%dil, 3(%rbx)
	movzbl	4(%rbx), %edi
	addl	144(%rsp), %edi
	movl	%edi, %eax
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	movb	%dil, 4(%rbx)
	movzbl	5(%rbx), %edi
	addl	152(%rsp), %edi
	movl	%edi, %eax
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	movb	%dil, 5(%rbx)
	movzbl	6(%rbx), %edi
	addl	160(%rsp), %edi
	movl	%edi, %eax
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	xorl	%edx, %edx
	movb	%dil, 6(%rbx)
	movzbl	7(%rbx), %edi
	addl	168(%rsp), %edi
	movl	%edi, %eax
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	movb	%dil, 7(%rbx)
	movzbl	8(%rbx), %edi
	addl	172(%rsp), %edi
	movl	%edi, %eax
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	movb	%dil, 8(%rbx)
	movzbl	9(%rbx), %edi
	addl	180(%rsp), %edi
	movl	%edi, %eax
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	movb	%dil, 9(%rbx)
	movzbl	10(%rbx), %edi
	addl	184(%rsp), %edi
	movl	%edi, %eax
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	movb	%dil, 10(%rbx)
	movzbl	11(%rbx), %edi
	movzbl	13(%rbx), %r11d
	addl	192(%rsp), %edi
	movl	%edi, %eax
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	movb	%dil, 11(%rbx)
	movzbl	12(%rbx), %edi
	addl	224(%rsp), %edi
	movl	%edi, %eax
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	addl	288(%rsp), %r11d
	movl	%r11d, %eax
	movb	%r11b, %dl
	movzbl	14(%rbx), %r11d
	movb	%dil, 12(%rbx)
	imulq	%r12, %rax
	movzbl	15(%rbx), %edi
	addl	320(%rsp), %r11d
	addl	384(%rsp), %edi
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subb	%al, %dl
	movl	%r11d, %eax
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %r11d
	movl	%r11d, %eax
	movb	%al, %dh
	movl	%edi, %eax
	imulq	%r12, %rax
	movw	%dx, 13(%rbx)
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	movb	%dil, 15(%rbx)
	movq	%rbx, %rdi
	call	gf_mat_det
	movq	32(%rsp), %rcx
	movq	24(%rsp), %rsi
	testb	%al, %al
	je	.L263
.L266:
	movq	%rbx, %r8
	movzwl	122(%rsp), %r13d
	movq	104(%rsp), %r14
	movq	112(%rsp), %rbx
.L240:
	movzbl	1600(%rsi), %eax
	movq	%rbx, %rdi
	movq	%r8, 320(%rsp)
	movq	%rcx, 352(%rsp)
	movb	%al, (%rbx)
	movq	1601(%rsi), %rax
	movq	%rsi, 384(%rsp)
	movq	%rax, 1(%rbx)
	movl	1609(%rsi), %eax
	movl	%eax, 9(%rbx)
	movzwl	1613(%rsi), %eax
	movw	%ax, 13(%rbx)
	movzbl	1615(%rsi), %eax
	movb	%al, 15(%rbx)
	call	gf_mat_det
	movq	384(%rsp), %rsi
	movq	352(%rsp), %rcx
	leaq	_snova_24_5_23_4_SNOVA_OPT_Smat(%rip), %r10
	testb	%al, %al
	movq	320(%rsp), %r8
	jne	.L238
	movzwl	34(%r10), %r11d
	movzwl	%r13w, %eax
	movzwl	38(%r10), %edi
	movzwl	40(%r10), %edx
	movzwl	42(%r10), %r9d
	movl	%eax, 104(%rsp)
	movzwl	36(%r10), %eax
	movl	%r11d, 384(%rsp)
	movzwl	60(%r10), %r11d
	movl	%edi, 180(%rsp)
	movl	%eax, 176(%rsp)
	movzwl	52(%r10), %edi
	movzwl	44(%r10), %eax
	movl	%edx, 188(%rsp)
	movl	%r9d, 168(%rsp)
	movzwl	48(%r10), %edx
	movzwl	56(%r10), %r9d
	movl	%r11d, 160(%rsp)
	movl	%eax, 320(%rsp)
	movzwl	62(%r10), %r11d
	movzwl	46(%r10), %eax
	movl	%edx, 124(%rsp)
	movl	%edi, 136(%rsp)
	movzwl	50(%r10), %edx
	movzwl	54(%r10), %edi
	movl	%r9d, 148(%rsp)
	movzwl	58(%r10), %r9d
	movl	%eax, 92(%rsp)
	movl	%edx, 72(%rsp)
	movl	%edi, 76(%rsp)
	movl	%r9d, 80(%rsp)
	movl	%r11d, 84(%rsp)
	movl	%r11d, 164(%rsp)
	movl	160(%rsp), %r11d
	movl	%r9d, 152(%rsp)
	movl	148(%rsp), %r9d
	movl	%edi, 140(%rsp)
	movl	136(%rsp), %edi
	movl	%edx, 128(%rsp)
	movl	124(%rsp), %edx
	movl	%eax, 288(%rsp)
	movl	320(%rsp), %eax
	movl	%r11d, 156(%rsp)
	movl	384(%rsp), %r11d
	movl	%r9d, 144(%rsp)
	movl	168(%rsp), %r9d
	movl	%edi, 132(%rsp)
	movl	180(%rsp), %edi
	movl	%edx, 256(%rsp)
	movl	188(%rsp), %edx
	movl	%eax, 352(%rsp)
	movl	176(%rsp), %eax
	movq	%r14, 112(%rsp)
	movl	%r11d, %r14d
	movl	%r9d, 192(%rsp)
	movl	%edx, 172(%rsp)
	movl	%edi, 224(%rsp)
	movl	%eax, 184(%rsp)
	movb	$22, 88(%rsp)
	movw	%r13w, 122(%rsp)
	jmp	.L244
.L265:
	movl	176(%rsp), %edi
	addl	104(%rsp), %r13d
	addl	384(%rsp), %r14d
	addl	%edi, 184(%rsp)
	movl	180(%rsp), %edi
	addl	%edi, 224(%rsp)
	movl	188(%rsp), %edi
	addl	%edi, 172(%rsp)
	movl	168(%rsp), %edi
	addl	%edi, 192(%rsp)
	movl	320(%rsp), %edi
	addl	%edi, 352(%rsp)
	movl	92(%rsp), %edi
	addl	%edi, 288(%rsp)
	movl	124(%rsp), %edi
	addl	%edi, 256(%rsp)
	movl	72(%rsp), %edi
	addl	%edi, 128(%rsp)
	movl	136(%rsp), %edi
	addl	%edi, 132(%rsp)
	movl	76(%rsp), %edi
	addl	%edi, 140(%rsp)
	movl	148(%rsp), %edi
	addl	%edi, 144(%rsp)
	movl	80(%rsp), %edi
	addl	%edi, 152(%rsp)
	movl	160(%rsp), %edi
	addl	%edi, 156(%rsp)
	movl	84(%rsp), %edi
	addl	%edi, 164(%rsp)
	decb	88(%rsp)
	je	.L267
.L244:
	movzbl	(%rbx), %edi
	movq	%rsi, 24(%rsp)
	movq	%r8, 32(%rsp)
	leal	(%rdi,%r13), %eax
	movq	%rcx, 64(%rsp)
	movq	%rax, %rdi
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	movb	%dil, (%rbx)
	movzbl	1(%rbx), %edi
	leal	(%rdi,%r14), %eax
	movq	%rax, %rdi
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	movb	%dil, 1(%rbx)
	movzbl	2(%rbx), %edi
	addl	184(%rsp), %edi
	movl	%edi, %eax
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	movb	%dil, 2(%rbx)
	movzbl	3(%rbx), %edi
	addl	224(%rsp), %edi
	movl	%edi, %eax
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	movb	%dil, 3(%rbx)
	movzbl	4(%rbx), %edi
	addl	172(%rsp), %edi
	movl	%edi, %eax
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	movb	%dil, 4(%rbx)
	movzbl	5(%rbx), %edi
	addl	192(%rsp), %edi
	movl	%edi, %eax
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	movb	%dil, 5(%rbx)
	movzbl	6(%rbx), %edi
	addl	352(%rsp), %edi
	movl	%edi, %eax
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	xorl	%edx, %edx
	movb	%dil, 6(%rbx)
	movzbl	7(%rbx), %edi
	addl	288(%rsp), %edi
	movl	%edi, %eax
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	movb	%dil, 7(%rbx)
	movzbl	8(%rbx), %edi
	addl	256(%rsp), %edi
	movl	%edi, %eax
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	movb	%dil, 8(%rbx)
	movzbl	9(%rbx), %edi
	addl	128(%rsp), %edi
	movl	%edi, %eax
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	movb	%dil, 9(%rbx)
	movzbl	10(%rbx), %edi
	addl	132(%rsp), %edi
	movzbl	13(%rbx), %r11d
	movl	%edi, %eax
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	movb	%dil, 10(%rbx)
	movzbl	11(%rbx), %edi
	addl	140(%rsp), %edi
	movl	%edi, %eax
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	movb	%dil, 11(%rbx)
	movzbl	12(%rbx), %edi
	addl	144(%rsp), %edi
	movl	%edi, %eax
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	addl	152(%rsp), %r11d
	movl	%r11d, %eax
	movb	%r11b, %dl
	movzbl	14(%rbx), %r11d
	movb	%dil, 12(%rbx)
	imulq	%r12, %rax
	movzbl	15(%rbx), %edi
	addl	156(%rsp), %r11d
	addl	164(%rsp), %edi
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subb	%al, %dl
	movl	%r11d, %eax
	imulq	%r12, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %r11d
	movl	%r11d, %eax
	movb	%al, %dh
	movl	%edi, %eax
	imulq	%r12, %rax
	movw	%dx, 13(%rbx)
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	movb	%dil, 15(%rbx)
	movq	%rbx, %rdi
	call	gf_mat_det
	movq	64(%rsp), %rcx
	movq	32(%rsp), %r8
	leaq	_snova_24_5_23_4_SNOVA_OPT_Smat(%rip), %r10
	testb	%al, %al
	movq	24(%rsp), %rsi
	je	.L265
.L267:
	movzwl	122(%rsp), %r13d
	movq	112(%rsp), %r14
.L238:
	movzbl	(%r14), %r9d
	movzbl	3(%r14), %edi
	movl	$22, %eax
	testb	%r9b, %r9b
	setne	%dl
	subl	%r9d, %eax
	addl	%edx, %eax
	cmpb	$1, %dil
	sbbl	%edx, %edx
	andl	%edx, %eax
	orl	%edi, %eax
	movzbl	1(%r14), %edi
	movzbl	%al, %edx
	movb	%al, 3(%r14)
	movzbl	2(%r14), %eax
	sall	$8, %eax
	orl	%edi, %eax
	movzbl	%r9b, %edi
	sall	$8, %eax
	orl	%edi, %eax
	movq	416(%rsp), %rdi
	sall	$8, %eax
	orl	%edx, %eax
	subq	$3200, %rdi
	vmovd	%eax, %xmm0
	vpmovzxbw	%xmm0, %xmm0
	vpextrw	$3, %xmm0, %r9d
	vpextrw	$2, %xmm0, %r11d
	vpextrw	$1, %xmm0, %eax
	vpextrw	$0, %xmm0, %edx
	cmpq	$124, %rdi
	jbe	.L269
	vmovd	%eax, %xmm0
	vmovd	%r11d, %xmm2
	vmovd	%r9d, %xmm3
	vpbroadcastw	%xmm0, %ymm0
	vpbroadcastw	%xmm2, %ymm2
	vpbroadcastw	%xmm3, %ymm3
	vpmullw	32(%r10), %ymm2, %ymm2
	vpmullw	(%r10), %ymm0, %ymm0
	vpaddw	%ymm2, %ymm0, %ymm0
	vmovd	%edx, %xmm2
	vpbroadcastw	%xmm2, %ymm2
	vpmullw	64(%r10), %ymm3, %ymm3
	vpmullw	96(%r10), %ymm2, %ymm2
	vpaddw	%ymm3, %ymm2, %ymm2
	vpaddw	%ymm2, %ymm0, %ymm0
	vpmulhuw	%ymm1, %ymm0, %ymm3
	vpsubw	%ymm3, %ymm0, %ymm2
	vpsrlw	$1, %ymm2, %ymm2
	vpaddw	%ymm3, %ymm2, %ymm2
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$1, %ymm2, %ymm3
	vpaddw	%ymm2, %ymm3, %ymm3
	vpsllw	$3, %ymm3, %ymm3
	vpsubw	%ymm2, %ymm3, %ymm2
	vpsubw	%ymm2, %ymm0, %ymm0
	vmovdqu	%ymm0, (%rcx)
.L246:
	movzbl	400(%r14), %edi
	movzbl	403(%r14), %r9d
	movl	$22, %eax
	testb	%dil, %dil
	setne	%dl
	subl	%edi, %eax
	addl	%edx, %eax
	cmpb	$1, %r9b
	sbbl	%edx, %edx
	andl	%edx, %eax
	orl	%r9d, %eax
	movzbl	401(%r14), %r9d
	movzbl	%al, %edx
	movb	%al, 403(%r14)
	movzbl	402(%r14), %eax
	sall	$8, %eax
	orl	%r9d, %eax
	sall	$8, %eax
	orl	%edi, %eax
	sall	$8, %eax
	orl	%edx, %eax
	cmpq	$124, 416(%rsp)
	vmovd	%eax, %xmm0
	vpmovzxbw	%xmm0, %xmm0
	jbe	.L247
	vpextrw	$3, %xmm0, %r9d
	vpextrw	$0, %xmm0, %eax
	vpextrw	$2, %xmm0, %edx
	vpextrw	$1, %xmm0, %edi
	vmovd	%r9d, %xmm2
	vmovd	%eax, %xmm0
	vpbroadcastw	%xmm0, %ymm0
	vpbroadcastw	%xmm2, %ymm2
	vmovd	%edi, %xmm3
	vpmullw	64(%r10), %ymm2, %ymm2
	vpmullw	96(%r10), %ymm0, %ymm0
	vpaddw	%ymm2, %ymm0, %ymm0
	vmovd	%edx, %xmm2
	vpbroadcastw	%xmm2, %ymm2
	vpbroadcastw	%xmm3, %ymm3
	vpmullw	(%r10), %ymm3, %ymm3
	vpmullw	32(%r10), %ymm2, %ymm2
	vpaddw	%ymm3, %ymm2, %ymm2
	vpaddw	%ymm2, %ymm0, %ymm0
	vpmulhuw	%ymm1, %ymm0, %ymm3
	vpsubw	%ymm3, %ymm0, %ymm2
	vpsrlw	$1, %ymm2, %ymm2
	vpaddw	%ymm3, %ymm2, %ymm2
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$1, %ymm2, %ymm3
	vpaddw	%ymm2, %ymm3, %ymm3
	vpsllw	$3, %ymm3, %ymm3
	vpsubw	%ymm2, %ymm3, %ymm2
	vpsubw	%ymm2, %ymm0, %ymm0
	vmovdqu	%ymm0, 3200(%rcx)
.L248:
	addq	$16, %rsi
	addq	$32, 416(%rsp)
	addq	$16, %r8
	addq	$32, %rcx
	addq	$4, %r14
	addq	$16, %rbx
	cmpq	%rsi, 96(%rsp)
	jne	.L249
	movq	40(%rsp), %r13
	movq	48(%rsp), %rcx
	leaq	21248(%rsp), %rdx
	leaq	160800(%r13), %rax
.L250:
	vmovdqa	(%rcx), %ymm0
	addq	$32, %rdx
	addq	$64, %rax
	addq	$32, %rcx
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, -3264(%rax)
	vmovdqu	%ymm0, -3232(%rax)
	vmovdqa	-32(%rdx), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, -64(%rax)
	vmovdqu	%ymm0, -32(%rax)
	cmpq	56(%rsp), %rdx
	jne	.L250
	vmovdqa	91328(%rsp), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 170400(%r13)
	vmovdqu	%ymm0, 170432(%r13)
	vmovdqu	91728(%rsp), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 171200(%r13)
	vmovdqu	%ymm0, 171232(%r13)
	vmovdqa	91360(%rsp), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 170464(%r13)
	vmovdqu	%ymm0, 170496(%r13)
	vmovdqu	91760(%rsp), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 171264(%r13)
	vmovdqu	%ymm0, 171296(%r13)
	vmovdqa	91392(%rsp), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 170528(%r13)
	vmovdqu	%ymm0, 170560(%r13)
	vmovdqu	91792(%rsp), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 171328(%r13)
	vmovdqu	%ymm0, 171360(%r13)
	vmovdqa	91424(%rsp), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 170592(%r13)
	vmovdqu	%ymm0, 170624(%r13)
	vmovdqu	91824(%rsp), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 171392(%r13)
	vmovdqu	%ymm0, 171424(%r13)
	vmovdqa	91456(%rsp), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 170656(%r13)
	vmovdqu	%ymm0, 170688(%r13)
	vmovdqu	91856(%rsp), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 171456(%r13)
	vmovdqu	%ymm0, 171488(%r13)
	vmovdqa	91488(%rsp), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 170720(%r13)
	vmovdqu	%ymm0, 170752(%r13)
	vmovdqu	91888(%rsp), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 171520(%r13)
	vmovdqu	%ymm0, 171552(%r13)
	vmovdqa	91520(%rsp), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 170784(%r13)
	vmovdqu	%ymm0, 170816(%r13)
	vmovdqu	91920(%rsp), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 171584(%r13)
	vmovdqu	%ymm0, 171616(%r13)
	vmovdqa	91552(%rsp), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 170848(%r13)
	vmovdqu	%ymm0, 170880(%r13)
	vmovdqu	91952(%rsp), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 171648(%r13)
	vmovdqu	%ymm0, 171680(%r13)
	vmovdqa	91584(%rsp), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 170912(%r13)
	vmovdqu	%ymm0, 170944(%r13)
	vmovdqu	91984(%rsp), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 171712(%r13)
	vmovdqu	%ymm0, 171744(%r13)
	vmovdqa	91616(%rsp), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 170976(%r13)
	vmovdqu	%ymm0, 171008(%r13)
	vmovdqu	92016(%rsp), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 171776(%r13)
	vmovdqu	%ymm0, 171808(%r13)
	vmovdqa	91648(%rsp), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 171040(%r13)
	vmovdqu	%ymm0, 171072(%r13)
	vmovdqu	92048(%rsp), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 171840(%r13)
	vmovdqu	%ymm0, 171872(%r13)
	vmovdqa	91680(%rsp), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 171104(%r13)
	vmovdqu	%ymm0, 171136(%r13)
	vmovdqu	92080(%rsp), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 171904(%r13)
	vmovdqu	%ymm0, 171936(%r13)
	vmovdqa	91712(%rsp), %xmm0
	vpmovzxbw	%xmm0, %xmm1
	vpsrldq	$8, %xmm0, %xmm0
	vpmovzxbw	%xmm0, %xmm0
	vmovdqu	%xmm1, 171168(%r13)
	vmovdqu	%xmm0, 171184(%r13)
	vmovdqa	92112(%rsp), %xmm0
	vpmovzxbw	%xmm0, %xmm1
	vpsrldq	$8, %xmm0, %xmm0
	vpmovzxbw	%xmm0, %xmm0
	vmovdqu	%xmm1, 171968(%r13)
	vmovdqu	%xmm0, 171984(%r13)
	movq	92152(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L270
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
	movzwl	64(%r10), %eax
	movzwl	32(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	96(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 3200(%rcx)
	movzwl	66(%r10), %eax
	movzwl	34(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	2(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	98(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 3202(%rcx)
	movzwl	68(%r10), %eax
	movzwl	36(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	4(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	100(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 3204(%rcx)
	movzwl	70(%r10), %eax
	movzwl	38(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	6(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	102(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 3206(%rcx)
	movzwl	72(%r10), %eax
	movzwl	40(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	8(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	104(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 3208(%rcx)
	movzwl	74(%r10), %eax
	movzwl	42(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	10(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	106(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 3210(%rcx)
	movzwl	76(%r10), %eax
	movzwl	44(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	12(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	108(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 3212(%rcx)
	movzwl	78(%r10), %eax
	movzwl	46(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	14(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	110(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 3214(%rcx)
	movzwl	80(%r10), %eax
	movzwl	48(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	16(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	112(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 3216(%rcx)
	movzwl	82(%r10), %eax
	movzwl	50(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	18(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	114(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 3218(%rcx)
	movzwl	84(%r10), %eax
	movzwl	52(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	20(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	116(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 3220(%rcx)
	movzwl	86(%r10), %eax
	movzwl	54(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	22(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	118(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 3222(%rcx)
	movzwl	88(%r10), %eax
	movzwl	56(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	24(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	120(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 3224(%rcx)
	movzwl	90(%r10), %eax
	movzwl	58(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	26(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	122(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 3226(%rcx)
	movzwl	92(%r10), %eax
	movzwl	60(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	28(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	124(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 3228(%rcx)
	movzwl	94(%r10), %eax
	movzwl	62(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	30(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	126(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm7
	vpmullw	%xmm7, %xmm0, %xmm0
	vpsrlq	$32, %xmm0, %xmm2
	vpaddw	%xmm2, %xmm0, %xmm0
	vpsrlq	$16, %xmm0, %xmm2
	vpaddw	%xmm2, %xmm0, %xmm0
	vpextrw	$0, %xmm0, %eax
	divw	%r15w
	movw	%dx, 3230(%rcx)
	jmp	.L248
.L269:
	imulw	(%r10), %ax
	imull	%r11d, %r13d
	addl	%eax, %r13d
	movzwl	64(%r10), %eax
	imull	%r9d, %eax
	leal	0(%r13,%rax), %edi
	movzwl	96(%r10), %eax
	imull	%edx, %eax
	xorl	%edx, %edx
	addl	%edi, %eax
	divw	%r15w
	movw	%dx, (%rcx)
	movzwl	66(%r10), %eax
	movzwl	34(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	2(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	98(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 2(%rcx)
	movzwl	68(%r10), %eax
	movzwl	36(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	4(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	100(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 4(%rcx)
	movzwl	70(%r10), %eax
	movzwl	38(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	6(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	102(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 6(%rcx)
	movzwl	72(%r10), %eax
	movzwl	40(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	8(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	104(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 8(%rcx)
	movzwl	74(%r10), %eax
	movzwl	42(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	10(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	106(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 10(%rcx)
	movzwl	76(%r10), %eax
	movzwl	44(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	12(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	108(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 12(%rcx)
	movzwl	78(%r10), %eax
	movzwl	46(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	14(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	110(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 14(%rcx)
	movzwl	80(%r10), %eax
	movzwl	48(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	16(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	112(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 16(%rcx)
	movzwl	82(%r10), %eax
	movzwl	50(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	18(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	114(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 18(%rcx)
	movzwl	84(%r10), %eax
	movzwl	52(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	20(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	116(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 20(%rcx)
	movzwl	86(%r10), %eax
	movzwl	54(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	22(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	118(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 22(%rcx)
	movzwl	88(%r10), %eax
	movzwl	56(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	24(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	120(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 24(%rcx)
	movzwl	90(%r10), %eax
	movzwl	58(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	26(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	122(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 26(%rcx)
	movzwl	92(%r10), %eax
	movzwl	60(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	28(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	124(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm2
	vpmullw	%xmm2, %xmm0, %xmm2
	vpsrlq	$32, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpsrlq	$16, %xmm2, %xmm3
	vpaddw	%xmm3, %xmm2, %xmm2
	vpextrw	$0, %xmm2, %eax
	divw	%r15w
	movw	%dx, 28(%rcx)
	movzwl	94(%r10), %eax
	movzwl	62(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	30(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	movzwl	126(%r10), %edx
	salq	$16, %rax
	orq	%rdx, %rax
	xorl	%edx, %edx
	vmovq	%rax, %xmm7
	vpmullw	%xmm7, %xmm0, %xmm0
	vpsrlq	$32, %xmm0, %xmm2
	vpaddw	%xmm2, %xmm0, %xmm0
	vpsrlq	$16, %xmm0, %xmm2
	vpaddw	%xmm2, %xmm0, %xmm0
	vpextrw	$0, %xmm0, %eax
	divw	%r15w
	movw	%dx, 30(%rcx)
	jmp	.L246
.L270:
	vzeroupper
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE17:
	.size	_snova_24_5_23_4_SNOVA_OPT_sk_expand, .-_snova_24_5_23_4_SNOVA_OPT_sk_expand
	.p2align 4
	.globl	_snova_24_5_23_4_SNOVA_OPT_sign
	.type	_snova_24_5_23_4_SNOVA_OPT_sign, @function
_snova_24_5_23_4_SNOVA_OPT_sign:
.LFB18:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%r15
	pushq	%r14
	pushq	%r13
	.cfi_offset 15, -24
	.cfi_offset 14, -32
	.cfi_offset 13, -40
	movq	%rcx, %r13
	pushq	%r12
	.cfi_offset 12, -48
	movq	%rdx, %r12
	pushq	%rbx
	.cfi_offset 3, -56
	movq	%rsi, %rbx
	andq	$-32, %rsp
	subq	$53056, %rsp
	movq	%rdi, 232(%rsp)
	leaq	36672(%rsp), %r15
	movq	%r15, %rdi
	movq	%fs:40, %r14
	movq	%r14, 53048(%rsp)
	movq	%r8, %r14
	movq	%r15, 120(%rsp)
	call	shake256_init@PLT
	movq	232(%rsp), %rax
	movl	$16, %edx
	movq	%r15, %rdi
	leaq	172000(%rax), %rsi
	call	shake_absorb@PLT
	movq	%r13, %rdx
	movq	%r12, %rsi
	movq	%r15, %rdi
	call	shake_absorb@PLT
	movl	$16, %edx
	movq	%r15, %rdi
	movq	%r14, %rsi
	call	shake_absorb@PLT
	movq	%r15, %rdi
	call	shake_finalize@PLT
	leaq	52112(%rsp), %rax
	movq	%r15, %rdx
	movl	$80, %esi
	movq	%rax, %rdi
	movq	%rax, 40(%rsp)
	call	shake_squeeze@PLT
	xorl	%edi, %edi
	xorl	%ecx, %ecx
	movabsq	$7218291159277650633, %r8
	cmpq	$45, %rdi
	ja	.L364
.L584:
	movzbl	52113(%rsp,%rdi), %esi
	movzbl	52112(%rsp,%rdi), %eax
	leaq	2(%rdi), %r9
	salq	$8, %rsi
	xorq	%rax, %rsi
	cmpq	$44, %rdi
	je	.L272
	movzbl	52112(%rsp,%r9), %eax
	leaq	4(%rdi), %r9
	salq	$16, %rax
	xorq	%rsi, %rax
	movzbl	52115(%rsp,%rdi), %esi
	salq	$24, %rsi
	xorq	%rax, %rsi
.L272:
	movq	%rsi, %rax
	mulq	%r8
	movq	%rsi, %rax
	subq	%rdx, %rax
	shrq	%rax
	addq	%rax, %rdx
	shrq	$4, %rdx
	imulq	$23, %rdx, %rax
	movq	%rdx, %r10
	subq	%rax, %rsi
	movb	%sil, 52032(%rsp,%rcx)
	cmpq	$79, %rcx
	je	.L273
	movq	%rdx, %rax
	mulq	%r8
	movq	%r10, %rax
	subq	%rdx, %rax
	shrq	%rax
	leaq	(%rdx,%rax), %rsi
	shrq	$4, %rsi
	imulq	$23, %rsi, %rax
	subq	%rax, %r10
	movb	%r10b, 52033(%rsp,%rcx)
	cmpq	$78, %rcx
	je	.L273
	movq	%rsi, %rax
	mulq	%r8
	movq	%rsi, %rax
	subq	%rdx, %rax
	shrq	%rax
	addq	%rax, %rdx
	shrq	$4, %rdx
	imulq	$23, %rdx, %rax
	movq	%rdx, %r10
	subq	%rax, %rsi
	movb	%sil, 52034(%rsp,%rcx)
	cmpq	$77, %rcx
	je	.L273
	movq	%rdx, %rax
	mulq	%r8
	movq	%r10, %rax
	subq	%rdx, %rax
	shrq	%rax
	leaq	(%rdx,%rax), %rsi
	shrq	$4, %rsi
	imulq	$23, %rsi, %rax
	subq	%rax, %r10
	movb	%r10b, 52035(%rsp,%rcx)
	cmpq	$76, %rcx
	je	.L273
	movq	%rsi, %rax
	mulq	%r8
	movq	%rsi, %rax
	subq	%rdx, %rax
	shrq	%rax
	addq	%rax, %rdx
	shrq	$4, %rdx
	imulq	$23, %rdx, %rax
	movq	%rdx, %r10
	subq	%rax, %rsi
	movb	%sil, 52036(%rsp,%rcx)
	cmpq	$75, %rcx
	je	.L273
	movq	%rdx, %rax
	mulq	%r8
	movq	%r10, %rax
	subq	%rdx, %rax
	shrq	%rax
	leaq	(%rdx,%rax), %rsi
	shrq	$4, %rsi
	imulq	$23, %rsi, %rax
	subq	%rax, %r10
	movb	%r10b, 52037(%rsp,%rcx)
	cmpq	$74, %rcx
	je	.L273
	movq	%rsi, %rax
	mulq	%r8
	movq	%rsi, %rax
	subq	%rdx, %rax
	shrq	%rax
	addq	%rdx, %rax
	shrq	$4, %rax
	imulq	$23, %rax, %rax
	subq	%rax, %rsi
	movb	%sil, 52038(%rsp,%rcx)
	addq	$7, %rcx
	cmpq	$80, %rcx
	je	.L273
	cmpq	$45, %rdi
	ja	.L275
	movq	%r9, %rdi
	cmpq	$45, %rdi
	jbe	.L584
.L364:
	movq	%rdi, %r9
	xorl	%esi, %esi
	jmp	.L272
.L275:
	movb	$0, 52032(%rsp,%rcx)
	cmpq	$79, %rcx
	je	.L273
	movb	$0, 52033(%rsp,%rcx)
	cmpq	$78, %rcx
	je	.L273
	movb	$0, 52034(%rsp,%rcx)
	cmpq	$77, %rcx
	je	.L273
	movb	$0, 52035(%rsp,%rcx)
	cmpq	$76, %rcx
	je	.L273
	movb	$0, 52036(%rsp,%rcx)
	cmpq	$75, %rcx
	je	.L273
	movb	$0, 52037(%rsp,%rcx)
	cmpq	$74, %rcx
	je	.L273
	movb	$0, 52038(%rsp,%rcx)
	addq	$7, %rcx
	cmpq	$80, %rcx
	jne	.L275
.L273:
	leaq	10752(%rsp), %rax
	vpxor	%xmm0, %xmm0, %xmm0
	xorl	%ecx, %ecx
	movq	%rbx, 112(%rsp)
	movq	%rax, 224(%rsp)
	leaq	23712(%rsp), %rax
	xorl	%r12d, %r12d
	vmovdqa	%ymm0, 576(%rsp)
	vmovdqa	%ymm0, 608(%rsp)
	vmovdqa	%ymm0, 640(%rsp)
	vmovdqa	%ymm0, 672(%rsp)
	vmovdqa	%ymm0, 704(%rsp)
	vpxor	%xmm0, %xmm0, %xmm0
	movw	%cx, 736(%rsp)
	movq	%rax, 168(%rsp)
	movq	%r14, 24(%rsp)
	vmovdqa	%ymm0, 52576(%rsp)
	vmovdqa	%ymm0, 52608(%rsp)
	vmovdqa	%ymm0, 52640(%rsp)
	vmovdqa	%ymm0, 52672(%rsp)
	vmovdqa	%ymm0, 52704(%rsp)
	vmovdqa	%ymm0, 52736(%rsp)
	vmovdqa	%ymm0, 52768(%rsp)
	vmovdqa	%ymm0, 52800(%rsp)
	vmovdqa	%ymm0, 52832(%rsp)
	vmovdqa	%ymm0, 52864(%rsp)
	vmovdqa	%ymm0, 52896(%rsp)
	vmovdqa	%ymm0, 52928(%rsp)
	vmovdqa	%ymm0, 52960(%rsp)
	vmovdqa	%ymm0, 52992(%rsp)
	vpxor	%xmm0, %xmm0, %xmm0
	vmovdqa	%xmm0, 53024(%rsp)
.L356:
	movq	224(%rsp), %rdi
	xorl	%esi, %esi
	movl	$12960, %edx
	vzeroupper
	call	memset@PLT
	movq	168(%rsp), %rdi
	movl	$12960, %edx
	xorl	%esi, %esi
	call	memset@PLT
	leal	1(%r12), %eax
	movb	%al, 255(%rsp)
	cmpb	$-1, %al
	je	.L585
	leaq	768(%rsp), %rdi
	call	shake256_init@PLT
	movq	232(%rsp), %rax
	movl	$32, %edx
	leaq	768(%rsp), %rdi
	leaq	172016(%rax), %rsi
	call	shake_absorb@PLT
	movq	40(%rsp), %rsi
	movl	$80, %edx
	leaq	768(%rsp), %rdi
	call	shake_absorb@PLT
	leaq	255(%rsp), %rsi
	movl	$1, %edx
	leaq	768(%rsp), %rdi
	call	shake_absorb@PLT
	leaq	768(%rsp), %rdi
	call	shake_finalize@PLT
	leaq	52192(%rsp), %rdi
	leaq	768(%rsp), %rdx
	movl	$384, %esi
	call	shake_squeeze@PLT
	xorl	%edi, %edi
	xorl	%ecx, %ecx
	movabsq	$7218291159277650633, %r8
	cmpq	$219, %rdi
	ja	.L366
.L586:
	movzbl	52193(%rsp,%rdi), %edx
	movzbl	52192(%rsp,%rdi), %eax
	leaq	4(%rdi), %r10
	movzbl	52195(%rsp,%rdi), %esi
	salq	$8, %rdx
	xorq	%rax, %rdx
	movzbl	52194(%rsp,%rdi), %eax
	salq	$24, %rsi
	salq	$16, %rax
	xorq	%rdx, %rax
	xorq	%rax, %rsi
.L278:
	movq	%rsi, %rax
	mulq	%r8
	movq	%rsi, %rax
	subq	%rdx, %rax
	shrq	%rax
	addq	%rax, %rdx
	shrq	$4, %rdx
	imulq	$23, %rdx, %rax
	movq	%rdx, %r9
	subq	%rax, %rsi
	movb	%sil, 52576(%rsp,%rcx)
	cmpq	$383, %rcx
	je	.L279
	movq	%rdx, %rax
	mulq	%r8
	movq	%r9, %rax
	subq	%rdx, %rax
	shrq	%rax
	leaq	(%rdx,%rax), %rsi
	shrq	$4, %rsi
	imulq	$23, %rsi, %rax
	subq	%rax, %r9
	movb	%r9b, 52577(%rsp,%rcx)
	cmpq	$382, %rcx
	je	.L279
	movq	%rsi, %rax
	mulq	%r8
	movq	%rsi, %rax
	subq	%rdx, %rax
	shrq	%rax
	addq	%rax, %rdx
	shrq	$4, %rdx
	imulq	$23, %rdx, %rax
	movq	%rdx, %r9
	subq	%rax, %rsi
	movb	%sil, 52578(%rsp,%rcx)
	cmpq	$381, %rcx
	je	.L279
	movq	%rdx, %rax
	mulq	%r8
	movq	%r9, %rax
	subq	%rdx, %rax
	shrq	%rax
	leaq	(%rdx,%rax), %rsi
	shrq	$4, %rsi
	imulq	$23, %rsi, %rax
	subq	%rax, %r9
	movb	%r9b, 52579(%rsp,%rcx)
	cmpq	$380, %rcx
	je	.L279
	movq	%rsi, %rax
	mulq	%r8
	movq	%rsi, %rax
	subq	%rdx, %rax
	shrq	%rax
	addq	%rax, %rdx
	shrq	$4, %rdx
	imulq	$23, %rdx, %rax
	movq	%rdx, %r9
	subq	%rax, %rsi
	movb	%sil, 52580(%rsp,%rcx)
	cmpq	$379, %rcx
	je	.L279
	movq	%rdx, %rax
	mulq	%r8
	movq	%r9, %rax
	subq	%rdx, %rax
	shrq	%rax
	leaq	(%rdx,%rax), %rsi
	shrq	$4, %rsi
	imulq	$23, %rsi, %rax
	subq	%rax, %r9
	movb	%r9b, 52581(%rsp,%rcx)
	cmpq	$378, %rcx
	je	.L279
	movq	%rsi, %rax
	mulq	%r8
	movq	%rsi, %rax
	subq	%rdx, %rax
	shrq	%rax
	addq	%rdx, %rax
	shrq	$4, %rax
	imulq	$23, %rax, %rax
	subq	%rax, %rsi
	movb	%sil, 52582(%rsp,%rcx)
	addq	$7, %rcx
	cmpq	$384, %rcx
	je	.L279
	cmpq	$219, %rdi
	ja	.L281
	movq	%r10, %rdi
	cmpq	$219, %rdi
	jbe	.L586
.L366:
	movq	%rdi, %r10
	xorl	%esi, %esi
	jmp	.L278
.L585:
	movq	112(%rsp), %rbx
	movl	$-1, 200(%rsp)
	vpxor	%xmm0, %xmm0, %xmm0
	vmovdqu	%ymm0, 224(%rbx)
	vmovdqu	%ymm0, (%rbx)
	vmovdqu	%ymm0, 32(%rbx)
	vmovdqu	%ymm0, 64(%rbx)
	vmovdqu	%ymm0, 96(%rbx)
	vmovdqu	%ymm0, 128(%rbx)
	vmovdqu	%ymm0, 160(%rbx)
	vmovdqu	%ymm0, 192(%rbx)
	vmovdqu	%ymm0, 250(%rbx)
.L271:
	movq	53048(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L587
	movl	200(%rsp), %eax
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
.L281:
	.cfi_restore_state
	movb	$0, 52576(%rsp,%rcx)
	cmpq	$383, %rcx
	je	.L279
	movb	$0, 52577(%rsp,%rcx)
	cmpq	$382, %rcx
	je	.L279
	movb	$0, 52578(%rsp,%rcx)
	cmpq	$381, %rcx
	je	.L279
	movb	$0, 52579(%rsp,%rcx)
	cmpq	$380, %rcx
	je	.L279
	movb	$0, 52580(%rsp,%rcx)
	cmpq	$379, %rcx
	je	.L279
	movb	$0, 52581(%rsp,%rcx)
	cmpq	$378, %rcx
	je	.L279
	movb	$0, 52582(%rsp,%rcx)
	addq	$7, %rcx
	cmpq	$384, %rcx
	jne	.L281
.L279:
	vpxor	%xmm0, %xmm0, %xmm0
	leaq	4480(%rsp), %r12
	xorl	%esi, %esi
	movl	$3072, %edx
	vmovdqa	%ymm0, 256(%rsp)
	movq	%r12, %rdi
	vmovdqa	%ymm0, 288(%rsp)
	vmovdqa	%ymm0, 320(%rsp)
	vmovdqa	%ymm0, 352(%rsp)
	vmovdqa	%ymm0, 384(%rsp)
	vzeroupper
	call	memset@PLT
	leaq	52960(%rsp), %rax
	vmovdqa	.LC17(%rip), %ymm13
	movq	%rax, 128(%rsp)
	leaq	_snova_24_5_23_4_SNOVA_OPT_Smat(%rip), %rdi
	movq	%r12, %rsi
	xorl	%ecx, %ecx
.L282:
	vmovdqa	(%rdi), %ymm2
	movq	%rsi, %rdx
	leaq	52576(%rsp), %rax
	vpshufb	.LC14(%rip), %ymm2, %ymm5
	vpshufb	.LC15(%rip), %ymm2, %ymm4
	vpshufb	.LC16(%rip), %ymm2, %ymm3
	vpshufb	%ymm13, %ymm2, %ymm2
.L283:
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
	cmpq	128(%rsp), %rax
	jne	.L283
	addq	$24, %rcx
	addq	$768, %rsi
	addq	$32, %rdi
	cmpq	$96, %rcx
	jne	.L282
	movl	$1680696365, %edx
	leaq	3072(%r12), %rcx
	movq	%r12, %rax
	vmovd	%edx, %xmm3
	vpbroadcastd	%xmm3, %ymm3
.L285:
	vmovdqa	(%rax), %ymm2
	addq	$32, %rax
	vpmulhuw	%ymm3, %ymm2, %ymm1
	vpsubw	%ymm1, %ymm2, %ymm0
	vpsrlw	$1, %ymm0, %ymm0
	vpaddw	%ymm1, %ymm0, %ymm0
	vpsrlw	$4, %ymm0, %ymm0
	vpsllw	$1, %ymm0, %ymm1
	vpaddw	%ymm0, %ymm1, %ymm1
	vpsllw	$3, %ymm1, %ymm1
	vpsubw	%ymm0, %ymm1, %ymm0
	vpsubw	%ymm0, %ymm2, %ymm2
	vmovdqa	%ymm2, -32(%rax)
	cmpq	%rcx, %rax
	jne	.L285
	movq	120(%rsp), %rbx
	xorl	%esi, %esi
	movl	$15360, %edx
	vzeroupper
	movq	%rbx, %rdi
	call	memset@PLT
	leaq	1920(%rsp), %rax
	movl	$2560, %edx
	xorl	%esi, %esi
	movq	%rax, %rdi
	movq	%rax, 208(%rsp)
	call	memset@PLT
	movq	232(%rsp), %rax
	vmovdqa	.LC17(%rip), %ymm13
	movq	%rbx, %rsi
	movq	%rbx, %rdx
	xorl	%ecx, %ecx
	addq	$18432, %rax
.L286:
	movq	%rdx, %rbx
	movl	$4, %r13d
	xorl	%edi, %edi
.L292:
	movq	%r12, %r14
	movq	%rax, %r10
	xorl	%r11d, %r11d
	subq	%rdi, %r14
.L290:
	vmovdqa	(%r14), %ymm3
	leaq	-18432(%r10), %r8
	movq	%rbx, %r9
	vpermq	$0, %ymm3, %ymm6
	vpermq	$85, %ymm3, %ymm5
	vpermq	$170, %ymm3, %ymm4
	vpermq	$255, %ymm3, %ymm3
.L287:
	vmovdqu	(%r8), %ymm1
	addq	$768, %r8
	addq	$32, %r9
	vpshufb	.LC14(%rip), %ymm1, %ymm0
	vpshufb	.LC15(%rip), %ymm1, %ymm2
	vpmullw	%ymm2, %ymm5, %ymm2
	vpmullw	%ymm0, %ymm6, %ymm0
	vpaddw	%ymm2, %ymm0, %ymm0
	vpshufb	.LC16(%rip), %ymm1, %ymm2
	vpshufb	%ymm13, %ymm1, %ymm1
	vpmullw	%ymm2, %ymm4, %ymm2
	vpmullw	%ymm1, %ymm3, %ymm1
	vpaddw	-32(%r9), %ymm0, %ymm0
	vpaddw	%ymm1, %ymm2, %ymm1
	vpaddw	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, -32(%r9)
	cmpq	%r10, %r8
	jne	.L287
	incq	%r11
	addq	$32, %r14
	leaq	32(%r8), %r10
	cmpq	$24, %r11
	jne	.L290
	addq	$384, %r13
	addq	$768, %rbx
	subq	$768, %rdi
	cmpq	$1540, %r13
	jne	.L292
	addq	$24, %rcx
	addq	$18432, %rax
	addq	$3072, %rdx
	cmpq	$120, %rcx
	jne	.L286
	movq	120(%rsp), %rax
	movl	$1680696365, %edx
	vmovd	%edx, %xmm3
	leaq	15360(%rax), %rcx
	vpbroadcastd	%xmm3, %ymm3
.L293:
	vmovdqa	(%rax), %ymm2
	addq	$32, %rax
	vpmulhuw	%ymm3, %ymm2, %ymm1
	vpsubw	%ymm1, %ymm2, %ymm0
	vpsrlw	$1, %ymm0, %ymm0
	vpaddw	%ymm1, %ymm0, %ymm0
	vpsrlw	$4, %ymm0, %ymm0
	vpsllw	$1, %ymm0, %ymm1
	vpaddw	%ymm0, %ymm1, %ymm1
	vpsllw	$3, %ymm1, %ymm1
	vpsubw	%ymm0, %ymm1, %ymm0
	vpsubw	%ymm0, %ymm2, %ymm2
	vmovdqa	%ymm2, -32(%rax)
	cmpq	%rcx, %rax
	jne	.L293
	movq	208(%rsp), %r8
	vmovdqa	.LC34(%rip), %ymm0
	xorl	%eax, %eax
	movl	$1536, %edi
.L294:
	leal	-1536(%rdi), %r9d
	movq	%r8, %rcx
	movq	%rsi, %r10
.L298:
	movq	%r12, %rdx
	movq	%r10, %rbx
	xorl	%r11d, %r11d
.L295:
	vmovdqa	(%rbx), %ymm2
	vmovq	(%rdx), %xmm1
	vmovq	8(%rdx), %xmm8
	vmovq	16(%rdx), %xmm6
	vperm2i128	$0, %ymm1, %ymm1, %ymm1
	vperm2i128	$0, %ymm8, %ymm8, %ymm8
	vmovq	24(%rdx), %xmm7
	addq	$32, %r11
	vpermq	$0, %ymm2, %ymm5
	vpermq	$85, %ymm2, %ymm4
	vpshufb	%ymm0, %ymm1, %ymm1
	addq	$32, %rbx
	vpshufb	%ymm0, %ymm8, %ymm8
	vpmullw	%ymm5, %ymm1, %ymm1
	vperm2i128	$0, %ymm6, %ymm6, %ymm6
	addq	$32, %rdx
	vpmullw	%ymm4, %ymm8, %ymm8
	vperm2i128	$0, %ymm7, %ymm7, %ymm7
	vpermq	$170, %ymm2, %ymm3
	vpshufb	%ymm0, %ymm6, %ymm6
	vpermq	$255, %ymm2, %ymm2
	vpshufb	%ymm0, %ymm7, %ymm7
	vpmullw	%ymm2, %ymm7, %ymm7
	vpmullw	%ymm3, %ymm6, %ymm6
	vpaddw	%ymm8, %ymm1, %ymm1
	vpaddw	(%rcx), %ymm1, %ymm1
	vpaddw	%ymm7, %ymm6, %ymm6
	vpaddw	%ymm6, %ymm1, %ymm1
	vmovdqa	%ymm1, (%rcx)
	vmovq	736(%rdx), %xmm1
	vmovq	744(%rdx), %xmm8
	vmovq	752(%rdx), %xmm6
	vperm2i128	$0, %ymm1, %ymm1, %ymm1
	vperm2i128	$0, %ymm8, %ymm8, %ymm8
	vmovq	760(%rdx), %xmm7
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
	vpaddw	128(%rcx), %ymm1, %ymm1
	vpaddw	%ymm7, %ymm6, %ymm6
	vpaddw	%ymm6, %ymm1, %ymm1
	vmovdqa	%ymm1, 128(%rcx)
	vmovq	1504(%rdx), %xmm1
	vmovq	1512(%rdx), %xmm8
	vmovq	1520(%rdx), %xmm6
	vperm2i128	$0, %ymm1, %ymm1, %ymm1
	vperm2i128	$0, %ymm8, %ymm8, %ymm8
	vmovq	1528(%rdx), %xmm7
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
	vpaddw	256(%rcx), %ymm1, %ymm1
	vpaddw	%ymm7, %ymm6, %ymm6
	vpaddw	%ymm6, %ymm1, %ymm1
	vmovdqa	%ymm1, 256(%rcx)
	vmovq	2272(%rdx), %xmm1
	vmovq	2280(%rdx), %xmm8
	vmovq	2288(%rdx), %xmm6
	vperm2i128	$0, %ymm1, %ymm1, %ymm1
	vperm2i128	$0, %ymm8, %ymm8, %ymm8
	vmovq	2296(%rdx), %xmm7
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
	vpaddw	384(%rcx), %ymm1, %ymm1
	vpmullw	%ymm2, %ymm4, %ymm2
	vpaddw	%ymm2, %ymm3, %ymm2
	vpaddw	%ymm2, %ymm1, %ymm1
	vmovdqa	%ymm1, 384(%rcx)
	cmpq	$768, %r11
	jne	.L295
	addl	$384, %r9d
	addq	$768, %r10
	addq	$32, %rcx
	cmpl	%edi, %r9d
	jne	.L298
	addl	$4, %eax
	leal	1536(%r9), %edi
	addq	$3072, %rsi
	addq	$512, %r8
	cmpl	$20, %eax
	jne	.L294
	movq	208(%rsp), %rax
	movl	$1680696365, %edx
	vmovd	%edx, %xmm3
	leaq	2560(%rax), %rcx
	vpbroadcastd	%xmm3, %ymm3
.L299:
	vmovdqa	(%rax), %ymm2
	addq	$32, %rax
	vpmulhuw	%ymm3, %ymm2, %ymm1
	vpsubw	%ymm1, %ymm2, %ymm0
	vpsrlw	$1, %ymm0, %ymm0
	vpaddw	%ymm1, %ymm0, %ymm0
	vpsrlw	$4, %ymm0, %ymm0
	vpsllw	$1, %ymm0, %ymm1
	vpaddw	%ymm0, %ymm1, %ymm1
	vpsllw	$3, %ymm1, %ymm1
	vpsubw	%ymm0, %ymm1, %ymm0
	vpsubw	%ymm0, %ymm2, %ymm2
	vmovdqa	%ymm2, -32(%rax)
	cmpq	%rcx, %rax
	jne	.L299
	movq	232(%rsp), %rbx
	movl	$80, 176(%rsp)
	leaq	52032(%rsp), %r13
	leaq	256(%rsp), %r15
	movq	$0, 184(%rsp)
	movq	224(%rsp), %r14
	movl	$23, %r11d
	leaq	171200(%rbx), %rax
	movl	$0, 216(%rsp)
	movq	%rax, 200(%rsp)
	movq	%rax, 160(%rsp)
	movq	208(%rsp), %rax
	movq	%rbx, 192(%rsp)
	movl	$2987803337, %ebx
	addq	$512, %rax
	movq	%rax, 32(%rsp)
	movl	$1680696365, %eax
	vmovd	%eax, %xmm3
	vpbroadcastd	%xmm3, %ymm3
.L300:
	movzbl	0(%r13), %eax
	movl	216(%rsp), %r8d
	addl	$23, %eax
	movl	%eax, 152(%rsp)
	movzbl	1(%r13), %eax
	leal	23(%rax), %r10d
	movzbl	2(%r13), %eax
	leal	23(%rax), %r9d
	movzbl	3(%r13), %eax
	addl	$23, %eax
	movl	%eax, 144(%rsp)
	movzbl	4(%r13), %eax
	addl	$23, %eax
	movl	%eax, 136(%rsp)
	movzbl	5(%r13), %eax
	addl	$23, %eax
	movl	%eax, 104(%rsp)
	movzbl	6(%r13), %eax
	addl	$23, %eax
	movl	%eax, 100(%rsp)
	movzbl	7(%r13), %eax
	addl	$23, %eax
	movl	%eax, 88(%rsp)
	movzbl	8(%r13), %eax
	addl	$23, %eax
	movl	%eax, 96(%rsp)
	movzbl	9(%r13), %eax
	addl	$23, %eax
	movl	%eax, 80(%rsp)
	movzbl	10(%r13), %eax
	addl	$23, %eax
	movl	%eax, 76(%rsp)
	movzbl	11(%r13), %eax
	addl	$23, %eax
	movl	%eax, 72(%rsp)
	movzbl	12(%r13), %eax
	addl	$23, %eax
	movl	%eax, 68(%rsp)
	movzbl	13(%r13), %eax
	addl	$23, %eax
	movl	%eax, 64(%rsp)
	movzbl	14(%r13), %eax
	addl	$23, %eax
	movl	%eax, 60(%rsp)
	movzbl	15(%r13), %eax
	addl	$23, %eax
	movl	%eax, 56(%rsp)
	movl	184(%rsp), %eax
	leal	0(,%rax,4), %ecx
	movq	192(%rsp), %rax
	movq	160(%rsp), %rsi
	movl	%r10d, 20(%rsp)
	leaq	157600(%rax), %rdi
.L302:
	movl	$3435973837, %edx
	movl	%r8d, %eax
	movslq	%ecx, %r10
	vpbroadcastw	(%rsi), %ymm8
	imulq	%rdx, %rax
	movl	%r8d, %edx
	vpbroadcastw	2(%rsi), %ymm7
	vpbroadcastw	4(%rsi), %ymm6
	vpbroadcastw	6(%rsi), %ymm5
	vpxor	%xmm0, %xmm0, %xmm0
	shrq	$34, %rax
	leal	(%rax,%rax,4), %eax
	subl	%eax, %edx
	movq	208(%rsp), %rax
	movslq	%edx, %rdx
	salq	$9, %rdx
	addq	%rdx, %rax
	addq	32(%rsp), %rdx
	movq	%rax, 48(%rsp)
	movq	232(%rsp), %rax
	leaq	(%rax,%r10,2), %r10
	movq	48(%rsp), %rax
.L301:
	vpmullw	32(%rax), %ymm7, %ymm2
	vpmullw	64(%rax), %ymm6, %ymm4
	vpmullw	(%rax), %ymm8, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpmullw	96(%rax), %ymm5, %ymm2
	vpaddw	%ymm4, %ymm2, %ymm2
	subq	$-128, %rax
	addq	$2, %r10
	vpaddw	%ymm2, %ymm1, %ymm1
	vpmulhuw	%ymm3, %ymm1, %ymm4
	vpsubw	%ymm4, %ymm1, %ymm2
	vpsrlw	$1, %ymm2, %ymm2
	vpaddw	%ymm4, %ymm2, %ymm2
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$1, %ymm2, %ymm4
	vpaddw	%ymm2, %ymm4, %ymm4
	vpsllw	$3, %ymm4, %ymm4
	vpsubw	%ymm2, %ymm4, %ymm2
	vpsubw	%ymm2, %ymm1, %ymm1
	vpbroadcastw	170398(%r10), %ymm2
	vpmullw	%ymm2, %ymm1, %ymm1
	vpaddw	%ymm1, %ymm0, %ymm0
	cmpq	%rdx, %rax
	jne	.L301
	vpmulhuw	%ymm3, %ymm0, %ymm2
	addl	$4, %ecx
	incl	%r8d
	addq	$32, %rdi
	addq	$8, %rsi
	vpsubw	%ymm2, %ymm0, %ymm1
	vpsrlw	$1, %ymm1, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsrlw	$4, %ymm1, %ymm1
	vpsllw	$1, %ymm1, %ymm2
	vpaddw	%ymm1, %ymm2, %ymm2
	vpsllw	$3, %ymm2, %ymm2
	vpsubw	%ymm1, %ymm2, %ymm1
	vmovdqu	3168(%rdi), %ymm2
	vpsubw	%ymm1, %ymm0, %ymm0
	vpermq	$0, %ymm2, %ymm4
	vpshufb	.LC14(%rip), %ymm0, %ymm1
	vpermq	$85, %ymm2, %ymm5
	vpmullw	%ymm4, %ymm1, %ymm1
	vpshufb	.LC15(%rip), %ymm0, %ymm4
	vpmullw	%ymm5, %ymm4, %ymm4
	vpermq	$170, %ymm2, %ymm5
	vpermq	$255, %ymm2, %ymm2
	vpaddw	%ymm4, %ymm1, %ymm1
	vpshufb	.LC16(%rip), %ymm0, %ymm4
	vpshufb	%ymm13, %ymm0, %ymm0
	vpmullw	%ymm5, %ymm4, %ymm4
	vpmullw	%ymm2, %ymm0, %ymm0
	vmovdqu	-32(%rdi), %ymm5
	vpaddw	%ymm0, %ymm4, %ymm0
	vpaddw	%ymm0, %ymm1, %ymm0
	vpermq	$0, %ymm0, %ymm2
	vpermq	$85, %ymm0, %ymm8
	vpermq	$170, %ymm0, %ymm4
	vpmulhuw	%ymm3, %ymm2, %ymm10
	vpmulhuw	%ymm3, %ymm8, %ymm9
	vpermq	$255, %ymm0, %ymm1
	vpmulhuw	%ymm3, %ymm4, %ymm7
	vpmulhuw	%ymm3, %ymm1, %ymm6
	vpsubw	%ymm10, %ymm2, %ymm0
	vpsrlw	$1, %ymm0, %ymm0
	vpaddw	%ymm10, %ymm0, %ymm0
	vpsrlw	$4, %ymm0, %ymm0
	vpsllw	$1, %ymm0, %ymm10
	vpaddw	%ymm0, %ymm10, %ymm10
	vpsllw	$3, %ymm10, %ymm10
	vpsubw	%ymm0, %ymm10, %ymm0
	vpsubw	%ymm0, %ymm2, %ymm0
	vpshufb	.LC14(%rip), %ymm5, %ymm2
	vpmullw	%ymm2, %ymm0, %ymm0
	vpsubw	%ymm9, %ymm8, %ymm2
	vpsrlw	$1, %ymm2, %ymm2
	vpaddw	%ymm9, %ymm2, %ymm2
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$1, %ymm2, %ymm9
	vpaddw	%ymm2, %ymm9, %ymm9
	vpsllw	$3, %ymm9, %ymm9
	vpsubw	%ymm2, %ymm9, %ymm2
	vpsubw	%ymm2, %ymm8, %ymm2
	vpshufb	.LC15(%rip), %ymm5, %ymm8
	vpmullw	%ymm8, %ymm2, %ymm2
	vpaddw	%ymm2, %ymm0, %ymm0
	vpsubw	%ymm7, %ymm4, %ymm2
	vpsrlw	$1, %ymm2, %ymm2
	vpaddw	(%r15), %ymm0, %ymm0
	vpaddw	%ymm7, %ymm2, %ymm2
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$1, %ymm2, %ymm7
	vpaddw	%ymm2, %ymm7, %ymm7
	vpsllw	$3, %ymm7, %ymm7
	vpsubw	%ymm2, %ymm7, %ymm2
	vpsubw	%ymm2, %ymm4, %ymm2
	vpshufb	.LC16(%rip), %ymm5, %ymm4
	vpshufb	%ymm13, %ymm5, %ymm5
	vpmullw	%ymm4, %ymm2, %ymm2
	vpsubw	%ymm6, %ymm1, %ymm4
	vpsrlw	$1, %ymm4, %ymm4
	vpaddw	%ymm6, %ymm4, %ymm4
	vpsrlw	$4, %ymm4, %ymm4
	vpsllw	$1, %ymm4, %ymm6
	vpaddw	%ymm4, %ymm6, %ymm6
	vpsllw	$3, %ymm6, %ymm6
	vpsubw	%ymm4, %ymm6, %ymm4
	vpsubw	%ymm4, %ymm1, %ymm1
	vpmullw	%ymm5, %ymm1, %ymm1
	vpaddw	%ymm1, %ymm2, %ymm2
	vpaddw	%ymm2, %ymm0, %ymm0
	vmovdqa	%ymm0, (%r15)
	cmpl	176(%rsp), %ecx
	jne	.L302
	movzwl	2(%r15), %eax
	xorl	%edx, %edx
	movl	20(%rsp), %r10d
	movl	144(%rsp), %r8d
	movl	136(%rsp), %edi
	divw	%r11w
	movl	104(%rsp), %esi
	movzwl	%dx, %edx
	subl	%edx, %r10d
	xorl	%edx, %edx
	movl	%r10d, %eax
	imulq	%rbx, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %r10d
	movzwl	4(%r15), %eax
	divw	%r11w
	movzwl	%dx, %edx
	subl	%edx, %r9d
	xorl	%edx, %edx
	movl	%r9d, %eax
	imulq	%rbx, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %r9d
	movzwl	6(%r15), %eax
	divw	%r11w
	movzwl	%dx, %edx
	subl	%edx, %r8d
	xorl	%edx, %edx
	movl	%r8d, %eax
	imulq	%rbx, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %r8d
	movzwl	8(%r15), %eax
	divw	%r11w
	movzwl	%dx, %edx
	subl	%edx, %edi
	xorl	%edx, %edx
	movl	%edi, %eax
	imulq	%rbx, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edi
	movzwl	10(%r15), %eax
	divw	%r11w
	movzwl	%dx, %edx
	subl	%edx, %esi
	movl	%esi, %eax
	imulq	%rbx, %rax
	shrq	$36, %rax
	xorl	%edx, %edx
	imull	$23, %eax, %eax
	subl	%eax, %esi
	movzwl	12(%r15), %eax
	divw	%r11w
	movzwl	%dx, %eax
	movl	100(%rsp), %edx
	subl	%eax, %edx
	movl	%edx, %eax
	imulq	%rbx, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edx
	movzwl	14(%r15), %eax
	movl	%edx, 176(%rsp)
	xorl	%edx, %edx
	divw	%r11w
	movzwl	%dx, %eax
	movl	88(%rsp), %edx
	subl	%eax, %edx
	movl	%edx, %eax
	imulq	%rbx, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edx
	movzwl	16(%r15), %eax
	movl	%edx, 144(%rsp)
	xorl	%edx, %edx
	divw	%r11w
	movzwl	%dx, %eax
	movl	96(%rsp), %edx
	subl	%eax, %edx
	movl	%edx, %eax
	imulq	%rbx, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edx
	movzwl	18(%r15), %eax
	movl	%edx, 136(%rsp)
	xorl	%edx, %edx
	divw	%r11w
	movzwl	%dx, %eax
	movl	80(%rsp), %edx
	subl	%eax, %edx
	movl	%edx, %eax
	imulq	%rbx, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edx
	movzwl	20(%r15), %eax
	movl	%edx, 104(%rsp)
	xorl	%edx, %edx
	divw	%r11w
	movzwl	%dx, %eax
	movl	76(%rsp), %edx
	subl	%eax, %edx
	movl	%edx, %eax
	imulq	%rbx, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edx
	movzwl	22(%r15), %eax
	movl	%edx, 100(%rsp)
	xorl	%edx, %edx
	divw	%r11w
	movzwl	%dx, %eax
	movl	72(%rsp), %edx
	subl	%eax, %edx
	movl	%edx, %eax
	imulq	%rbx, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edx
	movzwl	24(%r15), %eax
	movl	%edx, 88(%rsp)
	xorl	%edx, %edx
	divw	%r11w
	movzwl	%dx, %eax
	movl	68(%rsp), %edx
	subl	%eax, %edx
	movl	%edx, %eax
	imulq	%rbx, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edx
	movzwl	26(%r15), %eax
	movl	%edx, 96(%rsp)
	xorl	%edx, %edx
	divw	%r11w
	movzwl	%dx, %eax
	movl	64(%rsp), %edx
	subl	%eax, %edx
	movl	%edx, %eax
	imulq	%rbx, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edx
	movl	%edx, 80(%rsp)
	movzwl	28(%r15), %eax
	xorl	%edx, %edx
	divw	%r11w
	movzwl	%dx, %eax
	movl	60(%rsp), %edx
	subl	%eax, %edx
	movl	%edx, %eax
	imulq	%rbx, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	addq	$16, %r13
	addq	$32, %r15
	addq	$2592, %r14
	subl	%eax, %edx
	movzwl	-2(%r15), %eax
	movw	%si, -1622(%r14)
	leal	80(%rcx), %esi
	movl	%edx, 76(%rsp)
	xorl	%edx, %edx
	divw	%r11w
	movw	%r10w, -2270(%r14)
	movw	%r9w, -2108(%r14)
	movw	%r8w, -1946(%r14)
	movw	%di, -1784(%r14)
	movzwl	%dx, %eax
	movl	56(%rsp), %edx
	subl	%eax, %edx
	movl	%edx, %eax
	imulq	%rbx, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edx
	vpextrw	$0, %xmm0, %eax
	movl	%edx, 72(%rsp)
	xorl	%edx, %edx
	divw	%r11w
	movzwl	%dx, %eax
	movl	152(%rsp), %edx
	subl	%eax, %edx
	movl	%edx, %eax
	imulq	%rbx, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edx
	movzwl	176(%rsp), %eax
	movw	%dx, -2432(%r14)
	movw	%ax, -1460(%r14)
	movzwl	144(%rsp), %eax
	movw	%ax, -1298(%r14)
	movzwl	136(%rsp), %eax
	movw	%ax, -1136(%r14)
	movzwl	104(%rsp), %eax
	movw	%ax, -974(%r14)
	movzwl	100(%rsp), %eax
	movw	%ax, -812(%r14)
	movzwl	88(%rsp), %eax
	movw	%ax, -650(%r14)
	movzwl	96(%rsp), %eax
	movw	%ax, -488(%r14)
	movzwl	80(%rsp), %eax
	movw	%ax, -326(%r14)
	movzwl	76(%rsp), %eax
	movw	%ax, -164(%r14)
	movzwl	72(%rsp), %eax
	movw	%ax, -2(%r14)
	incl	216(%rsp)
	addq	$640, 192(%rsp)
	addq	$20, 184(%rsp)
	addq	$160, 160(%rsp)
	movl	216(%rsp), %eax
	movl	%esi, 176(%rsp)
	cmpl	$5, %eax
	jne	.L300
	leaq	7552(%rsp), %r15
	movl	$3200, %edx
	xorl	%esi, %esi
	movq	%r15, %rdi
	vzeroupper
	call	memset@PLT
	vmovdqa	.LC17(%rip), %ymm13
	xorl	%edx, %edx
	xorl	%r9d, %r9d
.L304:
	movq	%rax, %r8
	movq	%rdx, %rdi
	xorl	%esi, %esi
.L310:
	movq	232(%rsp), %rbx
	movq	%rdi, %rcx
	movq	%r12, %r13
	salq	$5, %rcx
	addq	%rcx, %rbx
	movq	%r8, %rcx
	movq	%rbx, 216(%rsp)
	xorl	%ebx, %ebx
.L308:
	movq	216(%rsp), %r11
	movq	%r13, %r10
	xorl	%r14d, %r14d
.L305:
	vmovdqa	(%r10), %ymm2
	vmovdqu	138400(%r11), %ymm1
	addq	$64, %r14
	addq	$64, %r10
	vmovdqa	-32(%r10), %ymm3
	addq	$64, %r11
	vpermq	$0, %ymm2, %ymm4
	vpshufb	.LC14(%rip), %ymm1, %ymm0
	vpermq	$85, %ymm2, %ymm5
	vpmullw	%ymm4, %ymm0, %ymm0
	vpshufb	.LC15(%rip), %ymm1, %ymm4
	vpmullw	%ymm5, %ymm4, %ymm4
	vpermq	$170, %ymm2, %ymm5
	vpermq	$255, %ymm2, %ymm2
	vpaddw	%ymm4, %ymm0, %ymm0
	vpshufb	.LC16(%rip), %ymm1, %ymm4
	vpshufb	%ymm13, %ymm1, %ymm1
	vpmullw	%ymm5, %ymm4, %ymm4
	vpmullw	%ymm2, %ymm1, %ymm1
	vpaddw	(%rcx), %ymm0, %ymm0
	vpaddw	%ymm1, %ymm4, %ymm1
	vpaddw	%ymm1, %ymm0, %ymm0
	vpermq	$0, %ymm3, %ymm1
	vmovdqa	%ymm0, (%rcx)
	vmovdqu	138368(%r11), %ymm2
	vpshufb	.LC14(%rip), %ymm2, %ymm4
	vpshufb	.LC15(%rip), %ymm2, %ymm5
	vpmullw	%ymm4, %ymm1, %ymm1
	vpermq	$85, %ymm3, %ymm4
	vpmullw	%ymm5, %ymm4, %ymm4
	vpaddw	%ymm4, %ymm1, %ymm1
	vpermq	$170, %ymm3, %ymm4
	vpermq	$255, %ymm3, %ymm3
	vpaddw	%ymm0, %ymm1, %ymm0
	vpshufb	.LC16(%rip), %ymm2, %ymm1
	vpmullw	%ymm4, %ymm1, %ymm4
	vpshufb	%ymm13, %ymm2, %ymm1
	vpmullw	%ymm3, %ymm1, %ymm1
	vpaddw	%ymm1, %ymm4, %ymm1
	vpaddw	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, (%rcx)
	cmpq	$768, %r14
	jne	.L305
	addl	$24, %ebx
	addq	$768, %r13
	addq	$160, %rcx
	cmpl	$96, %ebx
	jne	.L308
	incq	%rsi
	addq	$24, %rdi
	addq	$32, %r8
	cmpq	$5, %rsi
	jne	.L310
	addq	$5, %r9
	addq	$120, %rdx
	addq	$640, %rax
	cmpq	$25, %r9
	jne	.L304
	movl	$1680696365, %edx
	leaq	3200(%r15), %rcx
	movq	%r15, %rax
	vmovd	%edx, %xmm3
	vpbroadcastd	%xmm3, %ymm3
.L311:
	vmovdqa	(%rax), %ymm2
	addq	$32, %rax
	vpmulhuw	%ymm3, %ymm2, %ymm1
	vpsubw	%ymm1, %ymm2, %ymm0
	vpsrlw	$1, %ymm0, %ymm0
	vpaddw	%ymm1, %ymm0, %ymm0
	vpsrlw	$4, %ymm0, %ymm0
	vpsllw	$1, %ymm0, %ymm1
	vpaddw	%ymm0, %ymm1, %ymm1
	vpsllw	$3, %ymm1, %ymm1
	vpsubw	%ymm0, %ymm1, %ymm0
	vpsubw	%ymm0, %ymm2, %ymm2
	vmovdqa	%ymm2, -32(%rax)
	cmpq	%rcx, %rax
	jne	.L311
	leaq	576(%rsp), %rax
	movq	232(%rsp), %r12
	xorl	%edi, %edi
	vpxor	%xmm3, %xmm3, %xmm3
	movq	%rax, 88(%rsp)
	leaq	992(%rsp), %rax
	xorl	%r8d, %r8d
	movq	%r15, %r11
	movq	%rax, 176(%rsp)
	movl	$1680696365, %eax
	movq	%r12, %rcx
	xorl	%r12d, %r12d
	vmovd	%eax, %xmm1
	xorl	%eax, %eax
	vpbroadcastd	%xmm1, %ymm1
.L312:
	leal	1(%r12), %ebx
	movl	%r12d, 136(%rsp)
	movq	200(%rsp), %rdx
	movl	%edi, %r10d
	movl	%ebx, 144(%rsp)
	movl	%eax, %ebx
	leal	80(%rax), %eax
	leal	2(%r12), %r13d
	movl	%eax, 100(%rsp)
	leal	3(%r12), %r14d
	leaq	160800(%rcx), %r15
	movl	%edi, %r9d
	movl	%r12d, %eax
.L317:
	movl	$3435973837, %r12d
	movl	%r10d, %edi
	vpbroadcastw	(%rdx), %ymm7
	vpbroadcastw	6(%rdx), %ymm6
	imulq	%r12, %rdi
	vpbroadcastw	2(%rdx), %ymm5
	vpbroadcastw	4(%rdx), %ymm4
	vmovdqa	%ymm3, 416(%rsp)
	vmovdqa	%ymm3, 448(%rsp)
	leaq	416(%rsp), %rsi
	vmovdqa	%ymm3, 480(%rsp)
	shrq	$34, %rdi
	vmovdqa	%ymm3, 512(%rsp)
	leal	(%rdi,%rdi,4), %r12d
	movl	%r10d, %edi
	vmovdqa	%ymm3, 544(%rsp)
	subl	%r12d, %edi
	vmovdqa	%ymm3, 992(%rsp)
	movslq	%edi, %rdi
	vmovdqa	%ymm3, 1024(%rsp)
	leaq	(%rdi,%rdi,4), %rdi
	vmovdqa	%ymm3, 1056(%rsp)
	salq	$7, %rdi
	vmovdqa	%ymm3, 1088(%rsp)
	vmovdqa	%ymm3, 1120(%rsp)
	addq	%r11, %rdi
.L313:
	vpmullw	(%rdi), %ymm7, %ymm0
	vpaddw	(%rsi), %ymm0, %ymm0
	vpmullw	480(%rdi), %ymm6, %ymm2
	vpmullw	320(%rdi), %ymm4, %ymm8
	addq	$32, %rsi
	addq	$32, %rdi
	vpaddw	%ymm2, %ymm0, %ymm0
	vpmullw	128(%rdi), %ymm5, %ymm2
	vpaddw	%ymm8, %ymm2, %ymm2
	vpaddw	%ymm2, %ymm0, %ymm0
	vmovdqa	%ymm0, -32(%rsi)
	cmpq	%rsi, 88(%rsp)
	jne	.L313
	vmovdqa	416(%rsp), %ymm4
	vpmulhuw	%ymm1, %ymm4, %ymm2
	vpsubw	%ymm2, %ymm4, %ymm0
	vpsrlw	$1, %ymm0, %ymm0
	vpaddw	%ymm2, %ymm0, %ymm0
	vpsrlw	$4, %ymm0, %ymm0
	vpsllw	$1, %ymm0, %ymm2
	vpaddw	%ymm0, %ymm2, %ymm2
	vpsllw	$3, %ymm2, %ymm2
	vpsubw	%ymm0, %ymm2, %ymm0
	vmovdqa	448(%rsp), %ymm2
	vpsubw	%ymm0, %ymm4, %ymm4
	vpmulhuw	%ymm1, %ymm2, %ymm5
	vpshufb	.LC16(%rip), %ymm4, %ymm12
	vmovdqa	%ymm4, 416(%rsp)
	vpsubw	%ymm5, %ymm2, %ymm0
	vpsrlw	$1, %ymm0, %ymm0
	vpaddw	%ymm5, %ymm0, %ymm0
	vpsrlw	$4, %ymm0, %ymm0
	vpsllw	$1, %ymm0, %ymm5
	vpaddw	%ymm0, %ymm5, %ymm5
	vpsllw	$3, %ymm5, %ymm5
	vpsubw	%ymm0, %ymm5, %ymm0
	vpsubw	%ymm0, %ymm2, %ymm2
	vmovdqa	480(%rsp), %ymm0
	vmovdqa	%ymm2, 448(%rsp)
	vpmulhuw	%ymm1, %ymm0, %ymm6
	vpsubw	%ymm6, %ymm0, %ymm5
	vpsrlw	$1, %ymm5, %ymm5
	vpaddw	%ymm6, %ymm5, %ymm5
	vpsrlw	$4, %ymm5, %ymm5
	vpsllw	$1, %ymm5, %ymm6
	vpaddw	%ymm5, %ymm6, %ymm6
	vpsllw	$3, %ymm6, %ymm6
	vpsubw	%ymm5, %ymm6, %ymm5
	vmovdqa	512(%rsp), %ymm6
	vpsubw	%ymm5, %ymm0, %ymm0
	vpmulhuw	%ymm1, %ymm6, %ymm7
	vmovdqa	%ymm0, 480(%rsp)
	vpsubw	%ymm7, %ymm6, %ymm5
	vpsrlw	$1, %ymm5, %ymm5
	vpaddw	%ymm7, %ymm5, %ymm5
	vpsrlw	$4, %ymm5, %ymm5
	vpsllw	$1, %ymm5, %ymm7
	vpaddw	%ymm5, %ymm7, %ymm7
	vpsllw	$3, %ymm7, %ymm7
	vpsubw	%ymm5, %ymm7, %ymm5
	vpsubw	%ymm5, %ymm6, %ymm6
	vmovdqa	544(%rsp), %ymm5
	vmovdqa	%ymm6, 512(%rsp)
	vpmulhuw	%ymm1, %ymm5, %ymm8
	vpsubw	%ymm8, %ymm5, %ymm7
	vpsrlw	$1, %ymm7, %ymm7
	vpaddw	%ymm8, %ymm7, %ymm7
	vpsrlw	$4, %ymm7, %ymm7
	vpsllw	$1, %ymm7, %ymm8
	vpaddw	%ymm7, %ymm8, %ymm8
	vpsllw	$3, %ymm8, %ymm8
	vpsubw	%ymm7, %ymm8, %ymm7
	vmovdqu	(%r15), %ymm8
	vpsubw	%ymm7, %ymm5, %ymm5
	vpshufb	%ymm13, %ymm4, %ymm7
	vpermq	$0, %ymm8, %ymm10
	vpermq	$85, %ymm8, %ymm9
	vpermq	$170, %ymm8, %ymm11
	vmovdqa	%ymm5, 544(%rsp)
	vpermq	$255, %ymm8, %ymm8
	vpmullw	%ymm11, %ymm12, %ymm12
	vpmullw	%ymm8, %ymm7, %ymm7
	vpaddw	%ymm7, %ymm12, %ymm12
	vpshufb	.LC14(%rip), %ymm4, %ymm7
	vpmullw	%ymm10, %ymm7, %ymm14
	vpshufb	.LC15(%rip), %ymm4, %ymm7
	vpmullw	%ymm9, %ymm7, %ymm7
	vpaddw	%ymm7, %ymm14, %ymm7
	vpaddw	%ymm7, %ymm12, %ymm4
	vpshufb	.LC16(%rip), %ymm2, %ymm12
	vpshufb	%ymm13, %ymm2, %ymm7
	vpmullw	%ymm8, %ymm7, %ymm7
	vpmullw	%ymm11, %ymm12, %ymm12
	vpaddw	%ymm7, %ymm12, %ymm12
	vpshufb	.LC14(%rip), %ymm2, %ymm7
	vpmullw	%ymm10, %ymm7, %ymm14
	vpshufb	.LC15(%rip), %ymm2, %ymm7
	vpmullw	%ymm9, %ymm7, %ymm7
	vpaddw	%ymm7, %ymm14, %ymm7
	vpaddw	%ymm7, %ymm12, %ymm2
	vpshufb	.LC14(%rip), %ymm0, %ymm12
	vpshufb	.LC15(%rip), %ymm0, %ymm7
	vpmullw	%ymm9, %ymm7, %ymm7
	vpmullw	%ymm10, %ymm12, %ymm12
	vpaddw	%ymm7, %ymm12, %ymm12
	vpshufb	.LC16(%rip), %ymm0, %ymm7
	vpmullw	%ymm11, %ymm7, %ymm14
	vpshufb	%ymm13, %ymm0, %ymm7
	vpmullw	%ymm8, %ymm7, %ymm7
	vpaddw	%ymm7, %ymm14, %ymm7
	vpaddw	%ymm7, %ymm12, %ymm0
	vpshufb	.LC14(%rip), %ymm6, %ymm7
	vpshufb	.LC15(%rip), %ymm6, %ymm12
	vpmullw	%ymm9, %ymm12, %ymm12
	vpmullw	%ymm10, %ymm7, %ymm7
	vpaddw	%ymm12, %ymm7, %ymm7
	vpshufb	.LC16(%rip), %ymm6, %ymm12
	vpshufb	%ymm13, %ymm6, %ymm6
	vpmullw	%ymm11, %ymm12, %ymm12
	vpmullw	%ymm8, %ymm6, %ymm6
	vpaddw	%ymm6, %ymm12, %ymm6
	vpaddw	%ymm6, %ymm7, %ymm7
	vpshufb	.LC16(%rip), %ymm5, %ymm6
	vpmullw	%ymm11, %ymm6, %ymm6
	vpshufb	%ymm13, %ymm5, %ymm11
	vpmullw	%ymm8, %ymm11, %ymm8
	vpaddw	%ymm8, %ymm6, %ymm6
	vpshufb	.LC14(%rip), %ymm5, %ymm8
	vpshufb	.LC15(%rip), %ymm5, %ymm5
	vpmullw	%ymm10, %ymm8, %ymm8
	vpmullw	%ymm9, %ymm5, %ymm5
	vmovdqu	3200(%r15), %ymm9
	vpshufb	.LC14(%rip), %ymm9, %ymm11
	vpshufb	.LC15(%rip), %ymm9, %ymm10
	vpshufb	.LC16(%rip), %ymm9, %ymm12
	vpshufb	%ymm13, %ymm9, %ymm9
	vpaddw	%ymm5, %ymm8, %ymm5
	vpmulhuw	%ymm1, %ymm4, %ymm8
	vpaddw	%ymm5, %ymm6, %ymm6
	vpsubw	%ymm8, %ymm4, %ymm5
	vpsrlw	$1, %ymm5, %ymm5
	vpaddw	%ymm8, %ymm5, %ymm5
	vpsrlw	$4, %ymm5, %ymm5
	vpsllw	$1, %ymm5, %ymm8
	vpaddw	%ymm5, %ymm8, %ymm8
	vpsllw	$3, %ymm8, %ymm8
	vpsubw	%ymm5, %ymm8, %ymm5
	vpmulhuw	%ymm1, %ymm2, %ymm8
	vpsubw	%ymm5, %ymm4, %ymm4
	vpsubw	%ymm8, %ymm2, %ymm5
	vpsrlw	$1, %ymm5, %ymm5
	vpaddw	%ymm8, %ymm5, %ymm5
	vpsrlw	$4, %ymm5, %ymm5
	vpsllw	$1, %ymm5, %ymm8
	vpaddw	%ymm5, %ymm8, %ymm8
	vpsllw	$3, %ymm8, %ymm8
	vpsubw	%ymm5, %ymm8, %ymm5
	vpmulhuw	%ymm1, %ymm0, %ymm8
	vpsubw	%ymm5, %ymm2, %ymm2
	vpsubw	%ymm8, %ymm0, %ymm5
	vpsrlw	$1, %ymm5, %ymm5
	vpaddw	%ymm8, %ymm5, %ymm5
	vpsrlw	$4, %ymm5, %ymm5
	vpsllw	$1, %ymm5, %ymm8
	vpaddw	%ymm5, %ymm8, %ymm8
	vpsllw	$3, %ymm8, %ymm8
	vpsubw	%ymm5, %ymm8, %ymm5
	vpmulhuw	%ymm1, %ymm7, %ymm8
	vpsubw	%ymm5, %ymm0, %ymm0
	vpsubw	%ymm8, %ymm7, %ymm5
	vpsrlw	$1, %ymm5, %ymm5
	vpaddw	%ymm8, %ymm5, %ymm5
	vpsrlw	$4, %ymm5, %ymm5
	vpsllw	$1, %ymm5, %ymm8
	vpaddw	%ymm5, %ymm8, %ymm8
	vpsllw	$3, %ymm8, %ymm8
	vpsubw	%ymm5, %ymm8, %ymm8
	vpsubw	%ymm8, %ymm7, %ymm8
	vpmulhuw	%ymm1, %ymm6, %ymm7
	vpsubw	%ymm7, %ymm6, %ymm5
	vpsrlw	$1, %ymm5, %ymm5
	vpaddw	%ymm7, %ymm5, %ymm5
	vpsrlw	$4, %ymm5, %ymm5
	vpsllw	$1, %ymm5, %ymm7
	vpaddw	%ymm5, %ymm7, %ymm7
	vpsllw	$3, %ymm7, %ymm7
	vpsubw	%ymm5, %ymm7, %ymm5
	vpermq	$255, %ymm4, %ymm7
	vpsubw	%ymm5, %ymm6, %ymm5
	vpmullw	%ymm9, %ymm7, %ymm7
	vpermq	$170, %ymm4, %ymm6
	vpmullw	%ymm12, %ymm6, %ymm6
	vpaddw	%ymm6, %ymm7, %ymm7
	vpermq	$85, %ymm4, %ymm6
	vpermq	$0, %ymm4, %ymm4
	vpmullw	%ymm10, %ymm6, %ymm6
	vpmullw	%ymm11, %ymm4, %ymm4
	vpaddw	%ymm4, %ymm6, %ymm4
	vpermq	$170, %ymm2, %ymm6
	vpaddw	%ymm4, %ymm7, %ymm7
	vpmullw	%ymm12, %ymm6, %ymm6
	vpermq	$255, %ymm2, %ymm4
	vpmullw	%ymm9, %ymm4, %ymm4
	vpaddw	%ymm4, %ymm6, %ymm6
	vpermq	$0, %ymm2, %ymm4
	vpermq	$85, %ymm2, %ymm2
	vpmullw	%ymm11, %ymm4, %ymm4
	vpmullw	%ymm10, %ymm2, %ymm2
	vpaddw	%ymm2, %ymm4, %ymm2
	vpermq	$170, %ymm0, %ymm4
	vpaddw	%ymm2, %ymm6, %ymm6
	vpmullw	%ymm12, %ymm4, %ymm4
	vpermq	$255, %ymm0, %ymm2
	vpmullw	%ymm9, %ymm2, %ymm2
	vpaddw	%ymm2, %ymm4, %ymm4
	vpermq	$0, %ymm0, %ymm2
	vpermq	$85, %ymm0, %ymm0
	vpmullw	%ymm11, %ymm2, %ymm2
	vpmullw	%ymm10, %ymm0, %ymm0
	vpaddw	%ymm0, %ymm2, %ymm0
	vpermq	$0, %ymm8, %ymm2
	vpaddw	%ymm0, %ymm4, %ymm4
	vpmullw	%ymm11, %ymm2, %ymm2
	vpermq	$85, %ymm8, %ymm0
	vpmullw	%ymm10, %ymm0, %ymm0
	vpaddw	%ymm0, %ymm2, %ymm2
	vpermq	$170, %ymm8, %ymm0
	vpmullw	%ymm12, %ymm0, %ymm14
	vpermq	$255, %ymm8, %ymm0
	vpermq	$255, %ymm5, %ymm8
	vpmullw	%ymm9, %ymm0, %ymm0
	vpmullw	%ymm9, %ymm8, %ymm8
	vpaddw	%ymm0, %ymm14, %ymm0
	vpaddw	%ymm0, %ymm2, %ymm2
	vpermq	$170, %ymm5, %ymm0
	vpmullw	%ymm12, %ymm0, %ymm0
	vpaddw	%ymm8, %ymm0, %ymm0
	vpermq	$0, %ymm5, %ymm8
	vpermq	$85, %ymm5, %ymm5
	vpmullw	%ymm11, %ymm8, %ymm8
	vpmullw	%ymm10, %ymm5, %ymm5
	vpaddw	%ymm5, %ymm8, %ymm5
	vpmulhuw	%ymm1, %ymm7, %ymm8
	vpaddw	%ymm5, %ymm0, %ymm0
	vpsubw	%ymm8, %ymm7, %ymm5
	vpsrlw	$1, %ymm5, %ymm5
	vpaddw	%ymm8, %ymm5, %ymm5
	vpsrlw	$4, %ymm5, %ymm5
	vpsllw	$1, %ymm5, %ymm8
	vpaddw	%ymm5, %ymm8, %ymm8
	vpsllw	$3, %ymm8, %ymm8
	vpsubw	%ymm5, %ymm8, %ymm5
	vpsubw	%ymm5, %ymm7, %ymm7
	vmovdqa	%ymm7, 992(%rsp)
	vpmulhuw	%ymm1, %ymm6, %ymm7
	vpsubw	%ymm7, %ymm6, %ymm5
	vpsrlw	$1, %ymm5, %ymm5
	vpaddw	%ymm7, %ymm5, %ymm5
	vpsrlw	$4, %ymm5, %ymm5
	vpsllw	$1, %ymm5, %ymm7
	vpaddw	%ymm5, %ymm7, %ymm7
	vpsllw	$3, %ymm7, %ymm7
	vpsubw	%ymm5, %ymm7, %ymm5
	vpsubw	%ymm5, %ymm6, %ymm6
	vmovdqa	%ymm6, 1024(%rsp)
	vpmulhuw	%ymm1, %ymm4, %ymm6
	vpsubw	%ymm6, %ymm4, %ymm5
	vpsrlw	$1, %ymm5, %ymm5
	vpaddw	%ymm6, %ymm5, %ymm5
	vpsrlw	$4, %ymm5, %ymm5
	vpsllw	$1, %ymm5, %ymm6
	vpaddw	%ymm5, %ymm6, %ymm6
	vpsllw	$3, %ymm6, %ymm6
	vpsubw	%ymm5, %ymm6, %ymm5
	vpsubw	%ymm5, %ymm4, %ymm4
	vpmulhuw	%ymm1, %ymm2, %ymm5
	vmovdqa	%ymm4, 1056(%rsp)
	movq	168(%rsp), %rdi
	movq	232(%rsp), %r12
	movq	$0, 216(%rsp)
	movq	%rdi, %rsi
	addq	%r8, %rdi
	movl	%r9d, 96(%rsp)
	movq	%rdi, 160(%rsp)
	movq	176(%rsp), %rdi
	vpsubw	%ymm5, %ymm2, %ymm4
	movq	%rsi, 80(%rsp)
	vpsrlw	$1, %ymm4, %ymm4
	movq	%rdi, 104(%rsp)
	movslq	136(%rsp), %rdi
	vpaddw	%ymm5, %ymm4, %ymm4
	vpsrlw	$4, %ymm4, %ymm4
	leaq	(%r12,%rdi,2), %rdi
	vpsllw	$1, %ymm4, %ymm5
	movq	%rdi, 208(%rsp)
	movslq	144(%rsp), %rdi
	vpaddw	%ymm4, %ymm5, %ymm5
	vpsllw	$3, %ymm5, %ymm5
	leaq	(%r12,%rdi,2), %rdi
	vpsubw	%ymm4, %ymm5, %ymm4
	movq	%rdi, 184(%rsp)
	movslq	%r13d, %rdi
	vpsubw	%ymm4, %ymm2, %ymm2
	vpmulhuw	%ymm1, %ymm0, %ymm4
	leaq	(%r12,%rdi,2), %rdi
	vmovdqa	%ymm2, 1088(%rsp)
	movq	%rdi, 152(%rsp)
	movslq	%r14d, %rdi
	leaq	(%r12,%rdi,2), %rdi
	movq	104(%rsp), %r12
	movl	%r13d, 104(%rsp)
	movq	%rdi, 192(%rsp)
	vpsubw	%ymm4, %ymm0, %ymm2
	vpsrlw	$1, %ymm2, %ymm2
	vpaddw	%ymm4, %ymm2, %ymm2
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$1, %ymm2, %ymm4
	vpaddw	%ymm2, %ymm4, %ymm4
	vpsllw	$3, %ymm4, %ymm4
	vpsubw	%ymm2, %ymm4, %ymm2
	vpsubw	%ymm2, %ymm0, %ymm0
	vmovdqa	%ymm0, 1120(%rsp)
.L314:
	movq	160(%rsp), %rdi
	xorl	%r9d, %r9d
.L315:
	movq	208(%rsp), %rsi
	addq	$648, %rdi
	movzwl	157600(%rsi,%r9), %r13d
	movq	152(%rsp), %rsi
	movzwl	157600(%rsi,%r9), %esi
	vmovd	%r13d, %xmm0
	movq	184(%rsp), %r13
	vmovd	%esi, %xmm2
	movq	192(%rsp), %rsi
	vpinsrw	$1, 157600(%r13,%r9), %xmm0, %xmm0
	vpinsrw	$1, 157600(%rsi,%r9), %xmm2, %xmm2
	addq	$8, %r9
	vpunpckldq	%xmm2, %xmm0, %xmm0
	vmovdqa	(%r12), %ymm2
	vpunpcklqdq	%xmm0, %xmm0, %xmm0
	vinserti128	$1, %xmm0, %ymm0, %ymm0
	vpshufb	.LC14(%rip), %ymm2, %ymm2
	vpmullw	%ymm2, %ymm0, %ymm2
	vpaddw	-648(%rdi), %ymm2, %ymm2
	vmovdqu	%ymm2, -648(%rdi)
	vmovdqa	(%r12), %ymm2
	vpshufb	.LC15(%rip), %ymm2, %ymm2
	vpmullw	%ymm2, %ymm0, %ymm2
	vpaddw	-486(%rdi), %ymm2, %ymm2
	vmovdqu	%ymm2, -486(%rdi)
	vmovdqa	(%r12), %ymm2
	vpshufb	.LC16(%rip), %ymm2, %ymm2
	vpmullw	%ymm2, %ymm0, %ymm2
	vpaddw	-324(%rdi), %ymm2, %ymm2
	vmovdqu	%ymm2, -324(%rdi)
	vmovdqa	(%r12), %ymm2
	vpshufb	%ymm13, %ymm2, %ymm2
	vpmullw	%ymm2, %ymm0, %ymm0
	vpaddw	-162(%rdi), %ymm0, %ymm0
	vmovdqu	%ymm0, -162(%rdi)
	cmpq	$32, %r9
	jne	.L315
	addq	$16, 216(%rsp)
	addq	$32, %r12
	addq	$32, 160(%rsp)
	cmpq	$80, 216(%rsp)
	jne	.L314
	movl	104(%rsp), %r13d
	addl	$4, %ebx
	addl	$16, 136(%rsp)
	incl	%r10d
	addl	$16, 144(%rsp)
	movl	96(%rsp), %r9d
	addl	$16, %r14d
	addq	$32, %r15
	movq	80(%rsp), %rsi
	addl	$16, %r13d
	addq	$8, %rdx
	cmpl	100(%rsp), %ebx
	jne	.L317
	leal	1(%r9), %edi
	addq	$160, 200(%rsp)
	addq	$2592, %r8
	addq	$640, %rcx
	leal	320(%rax), %r12d
	cmpl	$5, %edi
	je	.L368
	movl	%ebx, %eax
	jmp	.L312
.L368:
	movq	232(%rsp), %r13
	movl	$1680696365, %eax
	movq	168(%rsp), %r14
	movq	%rsi, %rbx
	vmovd	%eax, %xmm0
	vmovdqa	.LC35(%rip), %ymm8
	movq	%r11, %r15
	xorl	%r9d, %r9d
	movq	%r13, %rcx
	vpxor	%xmm6, %xmm6, %xmm6
	vpbroadcastd	%xmm0, %ymm0
.L318:
	leaq	6(%r13), %rdi
	leaq	157600(%rcx), %rax
	movl	%r9d, %esi
	xorl	%edx, %edx
	movq	%rdi, 200(%rsp)
	leal	20(%r9), %edi
	leaq	2(%r13), %r11
	movl	%edi, 208(%rsp)
	leaq	4(%r13), %r12
	movq	%rcx, %rdi
	movq	%r13, %rcx
	movq	%rax, 216(%rsp)
	movq	%rbx, %rax
.L323:
	movl	%esi, %r8d
	movl	$3435973837, %ebx
	vmovdqa	%ymm6, 416(%rsp)
	leaq	416(%rsp), %r10
	imulq	%rbx, %r8
	vmovdqa	%ymm6, 448(%rsp)
	vmovdqa	%ymm6, 480(%rsp)
	vmovdqa	%ymm6, 512(%rsp)
	shrq	$34, %r8
	vmovdqa	%ymm6, 544(%rsp)
	leal	(%r8,%r8,4), %r13d
	movl	%esi, %r8d
	vmovdqa	%ymm6, 992(%rsp)
	subl	%r13d, %r8d
	vmovdqa	%ymm6, 1024(%rsp)
	xorl	%r13d, %r13d
	movslq	%r8d, %r8
	vmovdqa	%ymm6, 1056(%rsp)
	leaq	(%r8,%r8,4), %r8
	vmovdqa	%ymm6, 1088(%rsp)
	salq	$7, %r8
	vmovdqa	%ymm6, 1120(%rsp)
	addq	%r15, %r8
.L319:
	vpbroadcastw	170400(%rdx,%r11), %ymm1
	vpbroadcastw	170400(%rdx,%rcx), %ymm2
	addq	$32, %r13
	addq	$32, %r10
	movq	200(%rsp), %rbx
	vpbroadcastw	170400(%rdx,%r12), %ymm3
	addq	$32, %r8
	vpmullw	-32(%r8), %ymm2, %ymm2
	vpmullw	128(%r8), %ymm1, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpbroadcastw	170400(%rdx,%rbx), %ymm2
	vpaddw	-32(%r10), %ymm1, %ymm1
	vpmullw	288(%r8), %ymm3, %ymm3
	vpmullw	448(%r8), %ymm2, %ymm2
	vpaddw	%ymm3, %ymm2, %ymm2
	vpaddw	%ymm2, %ymm1, %ymm1
	vmovdqa	%ymm1, -32(%r10)
	cmpq	$160, %r13
	jne	.L319
	vmovdqa	416(%rsp), %ymm5
	vmovdqa	448(%rsp), %ymm4
	movq	%r14, %r10
	xorl	%ebx, %ebx
	vmovdqa	480(%rsp), %ymm3
	movq	216(%rsp), %r13
	vpmulhuw	%ymm0, %ymm5, %ymm2
	vpsubw	%ymm2, %ymm5, %ymm1
	vpsrlw	$1, %ymm1, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsrlw	$4, %ymm1, %ymm1
	vpsllw	$1, %ymm1, %ymm2
	vpaddw	%ymm1, %ymm2, %ymm2
	vpsllw	$3, %ymm2, %ymm2
	vpsubw	%ymm1, %ymm2, %ymm1
	vpmulhuw	%ymm0, %ymm4, %ymm2
	vpsubw	%ymm1, %ymm5, %ymm5
	vpshufb	%ymm8, %ymm5, %ymm12
	vmovdqa	%ymm5, 416(%rsp)
	vpermq	$78, %ymm12, %ymm14
	vpor	%ymm14, %ymm12, %ymm12
	vpshufb	.LC36(%rip), %ymm5, %ymm14
	vpsubw	%ymm2, %ymm4, %ymm1
	vpermq	$78, %ymm14, %ymm15
	vpsrlw	$1, %ymm1, %ymm1
	vpor	%ymm15, %ymm14, %ymm14
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsrlw	$4, %ymm1, %ymm1
	vpsllw	$1, %ymm1, %ymm2
	vpaddw	%ymm1, %ymm2, %ymm2
	vpsllw	$3, %ymm2, %ymm2
	vpsubw	%ymm1, %ymm2, %ymm1
	vpmulhuw	%ymm0, %ymm3, %ymm2
	vpsubw	%ymm1, %ymm4, %ymm4
	vmovdqa	%ymm4, 448(%rsp)
	vpsubw	%ymm2, %ymm3, %ymm1
	vpsrlw	$1, %ymm1, %ymm1
	vpaddw	%ymm2, %ymm1, %ymm1
	vpsrlw	$4, %ymm1, %ymm1
	vpsllw	$1, %ymm1, %ymm2
	vpaddw	%ymm1, %ymm2, %ymm2
	vpsllw	$3, %ymm2, %ymm2
	vpsubw	%ymm1, %ymm2, %ymm1
	vmovdqa	512(%rsp), %ymm2
	vpsubw	%ymm1, %ymm3, %ymm3
	vpmulhuw	%ymm0, %ymm2, %ymm7
	vmovdqa	%ymm3, 480(%rsp)
	vpsubw	%ymm7, %ymm2, %ymm1
	vpsrlw	$1, %ymm1, %ymm1
	vpaddw	%ymm7, %ymm1, %ymm1
	vpsrlw	$4, %ymm1, %ymm1
	vpsllw	$1, %ymm1, %ymm7
	vpaddw	%ymm1, %ymm7, %ymm7
	vpsllw	$3, %ymm7, %ymm7
	vpsubw	%ymm1, %ymm7, %ymm1
	vpsubw	%ymm1, %ymm2, %ymm2
	vmovdqa	544(%rsp), %ymm1
	vmovdqa	%ymm2, 512(%rsp)
	vpmulhuw	%ymm0, %ymm1, %ymm9
	vpsubw	%ymm9, %ymm1, %ymm7
	vpsrlw	$1, %ymm7, %ymm7
	vpaddw	%ymm9, %ymm7, %ymm7
	vpsrlw	$4, %ymm7, %ymm7
	vpsllw	$1, %ymm7, %ymm9
	vpaddw	%ymm7, %ymm9, %ymm9
	vpsllw	$3, %ymm9, %ymm9
	vpsubw	%ymm7, %ymm9, %ymm7
	vpsubw	%ymm7, %ymm1, %ymm1
	vmovdqu	0(%r13), %ymm7
	vmovdqa	%ymm1, 544(%rsp)
	vpshufb	.LC15(%rip), %ymm7, %ymm10
	vpshufb	.LC14(%rip), %ymm7, %ymm11
	vpshufb	.LC16(%rip), %ymm7, %ymm9
	vpmullw	%ymm10, %ymm14, %ymm14
	vpmullw	%ymm11, %ymm12, %ymm12
	vpshufb	%ymm13, %ymm7, %ymm7
	vpaddw	%ymm14, %ymm12, %ymm12
	vpshufb	.LC37(%rip), %ymm5, %ymm14
	vpshufb	.LC38(%rip), %ymm5, %ymm5
	vpermq	$78, %ymm14, %ymm15
	vpor	%ymm15, %ymm14, %ymm14
	vpermq	$78, %ymm5, %ymm15
	vpor	%ymm15, %ymm5, %ymm5
	vpmullw	%ymm7, %ymm14, %ymm14
	vpmullw	%ymm9, %ymm5, %ymm5
	vpaddw	%ymm5, %ymm14, %ymm14
	vpshufb	.LC38(%rip), %ymm4, %ymm5
	vpaddw	%ymm14, %ymm12, %ymm12
	vpermq	$78, %ymm5, %ymm14
	vpor	%ymm14, %ymm5, %ymm5
	vpshufb	.LC37(%rip), %ymm4, %ymm14
	vpermq	$78, %ymm14, %ymm15
	vpmullw	%ymm9, %ymm5, %ymm5
	vpor	%ymm15, %ymm14, %ymm14
	vpmullw	%ymm7, %ymm14, %ymm14
	vpaddw	%ymm14, %ymm5, %ymm5
	vpshufb	.LC36(%rip), %ymm4, %ymm14
	vpshufb	%ymm8, %ymm4, %ymm4
	vpermq	$78, %ymm14, %ymm15
	vpor	%ymm15, %ymm14, %ymm14
	vpermq	$78, %ymm4, %ymm15
	vpor	%ymm15, %ymm4, %ymm4
	vpmullw	%ymm10, %ymm14, %ymm14
	vpmullw	%ymm11, %ymm4, %ymm4
	vpaddw	%ymm4, %ymm14, %ymm14
	vpshufb	.LC37(%rip), %ymm3, %ymm4
	vpaddw	%ymm14, %ymm5, %ymm5
	vpermq	$78, %ymm4, %ymm14
	vpor	%ymm14, %ymm4, %ymm4
	vpshufb	.LC38(%rip), %ymm3, %ymm14
	vpermq	$78, %ymm14, %ymm15
	vpmullw	%ymm7, %ymm4, %ymm4
	vpor	%ymm15, %ymm14, %ymm14
	vpmullw	%ymm9, %ymm14, %ymm14
	vpaddw	%ymm14, %ymm4, %ymm4
	vpshufb	.LC36(%rip), %ymm3, %ymm14
	vpshufb	%ymm8, %ymm3, %ymm3
	vpermq	$78, %ymm14, %ymm15
	vpor	%ymm15, %ymm14, %ymm14
	vpermq	$78, %ymm3, %ymm15
	vpor	%ymm15, %ymm3, %ymm3
	vpmullw	%ymm10, %ymm14, %ymm14
	vpmullw	%ymm11, %ymm3, %ymm3
	vpaddw	%ymm3, %ymm14, %ymm14
	vpshufb	%ymm8, %ymm2, %ymm3
	vpaddw	%ymm14, %ymm4, %ymm4
	vpermq	$78, %ymm3, %ymm14
	vpor	%ymm14, %ymm3, %ymm14
	vpshufb	.LC36(%rip), %ymm2, %ymm3
	vpermq	$78, %ymm3, %ymm15
	vpmullw	%ymm11, %ymm14, %ymm14
	vpor	%ymm15, %ymm3, %ymm3
	vpmullw	%ymm10, %ymm3, %ymm3
	vpaddw	%ymm3, %ymm14, %ymm14
	vpshufb	.LC38(%rip), %ymm2, %ymm3
	vpshufb	.LC37(%rip), %ymm2, %ymm2
	vpermq	$78, %ymm3, %ymm15
	vpor	%ymm15, %ymm3, %ymm3
	vpermq	$78, %ymm2, %ymm15
	vpor	%ymm15, %ymm2, %ymm2
	vpmullw	%ymm9, %ymm3, %ymm3
	vpmullw	%ymm7, %ymm2, %ymm2
	vpaddw	%ymm2, %ymm3, %ymm2
	vpshufb	%ymm8, %ymm1, %ymm3
	vpaddw	%ymm2, %ymm14, %ymm2
	vpermq	$78, %ymm3, %ymm14
	vpor	%ymm14, %ymm3, %ymm3
	vpmullw	%ymm11, %ymm3, %ymm11
	vpshufb	.LC36(%rip), %ymm1, %ymm3
	vpermq	$78, %ymm3, %ymm14
	vpor	%ymm14, %ymm3, %ymm3
	vpmullw	%ymm10, %ymm3, %ymm3
	vpaddw	%ymm3, %ymm11, %ymm10
	vpshufb	.LC38(%rip), %ymm1, %ymm3
	vpshufb	.LC37(%rip), %ymm1, %ymm1
	vpermq	$78, %ymm3, %ymm11
	vpor	%ymm11, %ymm3, %ymm3
	vpmullw	%ymm9, %ymm3, %ymm3
	vpermq	$78, %ymm1, %ymm9
	vpor	%ymm9, %ymm1, %ymm1
	vpmulhuw	%ymm0, %ymm5, %ymm9
	vpmullw	%ymm7, %ymm1, %ymm1
	vpmulhuw	%ymm0, %ymm12, %ymm7
	vpaddw	%ymm1, %ymm3, %ymm1
	vpsubw	%ymm7, %ymm12, %ymm3
	vpsrlw	$1, %ymm3, %ymm3
	vpaddw	%ymm1, %ymm10, %ymm1
	vpaddw	%ymm7, %ymm3, %ymm3
	vpsrlw	$4, %ymm3, %ymm3
	vpsllw	$1, %ymm3, %ymm7
	vpaddw	%ymm3, %ymm7, %ymm7
	vpsllw	$3, %ymm7, %ymm7
	vpsubw	%ymm3, %ymm7, %ymm7
	vpsubw	%ymm9, %ymm5, %ymm3
	vpsrlw	$1, %ymm3, %ymm3
	vpsubw	%ymm7, %ymm12, %ymm7
	vpaddw	%ymm9, %ymm3, %ymm3
	vpsrlw	$4, %ymm3, %ymm3
	vpsllw	$1, %ymm3, %ymm9
	vpaddw	%ymm3, %ymm9, %ymm9
	vpsllw	$3, %ymm9, %ymm9
	vpsubw	%ymm3, %ymm9, %ymm3
	vpmulhuw	%ymm0, %ymm4, %ymm9
	vpsubw	%ymm3, %ymm5, %ymm5
	vpsubw	%ymm9, %ymm4, %ymm3
	vpsrlw	$1, %ymm3, %ymm3
	vpaddw	%ymm9, %ymm3, %ymm3
	vpsrlw	$4, %ymm3, %ymm3
	vpsllw	$1, %ymm3, %ymm9
	vpaddw	%ymm3, %ymm9, %ymm9
	vpsllw	$3, %ymm9, %ymm9
	vpsubw	%ymm3, %ymm9, %ymm3
	vpmulhuw	%ymm0, %ymm2, %ymm9
	vpsubw	%ymm3, %ymm4, %ymm3
	vpsubw	%ymm9, %ymm2, %ymm4
	vpsrlw	$1, %ymm4, %ymm4
	vpaddw	%ymm9, %ymm4, %ymm4
	vpsrlw	$4, %ymm4, %ymm4
	vpsllw	$1, %ymm4, %ymm9
	vpaddw	%ymm4, %ymm9, %ymm9
	vpsllw	$3, %ymm9, %ymm9
	vpsubw	%ymm4, %ymm9, %ymm4
	vpmulhuw	%ymm0, %ymm1, %ymm9
	vpsubw	%ymm4, %ymm2, %ymm2
	vpsubw	%ymm9, %ymm1, %ymm4
	vpsrlw	$1, %ymm4, %ymm4
	vpaddw	%ymm9, %ymm4, %ymm4
	vpsrlw	$4, %ymm4, %ymm4
	vpsllw	$1, %ymm4, %ymm9
	vpaddw	%ymm4, %ymm9, %ymm9
	vpsllw	$3, %ymm9, %ymm9
	vpsubw	%ymm4, %ymm9, %ymm4
	vmovdqu	9600(%r13), %ymm9
	vpsubw	%ymm4, %ymm1, %ymm1
	vpshufb	.LC15(%rip), %ymm7, %ymm4
	vpshufb	.LC14(%rip), %ymm7, %ymm14
	movl	%r9d, 192(%rsp)
	vpermq	$0, %ymm9, %ymm11
	vpermq	$85, %ymm9, %ymm10
	vpermq	$170, %ymm9, %ymm12
	movq	%r14, 184(%rsp)
	vpmullw	%ymm11, %ymm14, %ymm14
	vpmullw	%ymm10, %ymm4, %ymm4
	vpermq	$255, %ymm9, %ymm9
	movq	%rdx, 160(%rsp)
	vpshufb	.LC15(%rip), %ymm5, %ymm15
	movq	%rax, 152(%rsp)
	movq	176(%rsp), %r8
	vpmullw	%ymm10, %ymm15, %ymm15
	movq	%rdi, 144(%rsp)
	movq	%rcx, 136(%rsp)
	movl	%esi, 104(%rsp)
	movq	%r15, %rsi
	vpaddw	%ymm14, %ymm4, %ymm4
	vpshufb	%ymm13, %ymm7, %ymm14
	vpshufb	.LC16(%rip), %ymm7, %ymm7
	vpmullw	%ymm12, %ymm7, %ymm7
	vpmullw	%ymm9, %ymm14, %ymm14
	vpaddw	%ymm7, %ymm14, %ymm14
	vpshufb	.LC14(%rip), %ymm5, %ymm7
	vpmullw	%ymm11, %ymm7, %ymm7
	vpaddw	%ymm14, %ymm4, %ymm4
	vpshufb	%ymm13, %ymm5, %ymm14
	vpshufb	.LC16(%rip), %ymm5, %ymm5
	vpmullw	%ymm9, %ymm14, %ymm14
	vpaddw	%ymm7, %ymm15, %ymm15
	vpmullw	%ymm12, %ymm5, %ymm7
	vpaddw	%ymm7, %ymm14, %ymm14
	vpshufb	.LC14(%rip), %ymm3, %ymm7
	vpaddw	%ymm14, %ymm15, %ymm5
	vpshufb	.LC15(%rip), %ymm3, %ymm15
	vpshufb	%ymm13, %ymm3, %ymm14
	vpmullw	%ymm11, %ymm7, %ymm7
	vpmullw	%ymm10, %ymm15, %ymm15
	vpshufb	.LC16(%rip), %ymm3, %ymm3
	vpmullw	%ymm9, %ymm14, %ymm14
	vpaddw	%ymm7, %ymm15, %ymm15
	vpmullw	%ymm12, %ymm3, %ymm7
	vpaddw	%ymm7, %ymm14, %ymm14
	vpshufb	.LC14(%rip), %ymm2, %ymm7
	vpaddw	%ymm14, %ymm15, %ymm3
	vpshufb	.LC15(%rip), %ymm2, %ymm15
	vpshufb	%ymm13, %ymm2, %ymm14
	vpmullw	%ymm11, %ymm7, %ymm7
	vpmullw	%ymm10, %ymm15, %ymm15
	vpshufb	.LC16(%rip), %ymm2, %ymm2
	vpmullw	%ymm9, %ymm14, %ymm14
	vpaddw	%ymm7, %ymm15, %ymm15
	vpmullw	%ymm12, %ymm2, %ymm7
	vpaddw	%ymm7, %ymm14, %ymm14
	vpshufb	.LC16(%rip), %ymm1, %ymm7
	vpmullw	%ymm12, %ymm7, %ymm12
	vpshufb	%ymm13, %ymm1, %ymm7
	vpaddw	%ymm14, %ymm15, %ymm2
	vpmullw	%ymm9, %ymm7, %ymm7
	vpaddw	%ymm7, %ymm12, %ymm12
	vpshufb	.LC14(%rip), %ymm1, %ymm7
	vpmullw	%ymm11, %ymm7, %ymm9
	vpshufb	.LC15(%rip), %ymm1, %ymm7
	vpmullw	%ymm10, %ymm7, %ymm7
	vpaddw	%ymm7, %ymm9, %ymm7
	vpmulhuw	%ymm0, %ymm4, %ymm9
	vpaddw	%ymm7, %ymm12, %ymm1
	vpsubw	%ymm9, %ymm4, %ymm7
	vpsrlw	$1, %ymm7, %ymm7
	vpaddw	%ymm9, %ymm7, %ymm7
	vpsrlw	$4, %ymm7, %ymm7
	vpsllw	$1, %ymm7, %ymm9
	vpaddw	%ymm7, %ymm9, %ymm9
	vpsllw	$3, %ymm9, %ymm9
	vpsubw	%ymm7, %ymm9, %ymm7
	vpsubw	%ymm7, %ymm4, %ymm4
	vpmulhuw	%ymm0, %ymm5, %ymm7
	vmovdqa	%ymm4, 992(%rsp)
	vpsubw	%ymm7, %ymm5, %ymm4
	vpsrlw	$1, %ymm4, %ymm4
	vpaddw	%ymm7, %ymm4, %ymm4
	vpsrlw	$4, %ymm4, %ymm4
	vpsllw	$1, %ymm4, %ymm7
	vpaddw	%ymm4, %ymm7, %ymm7
	vpsllw	$3, %ymm7, %ymm7
	vpsubw	%ymm4, %ymm7, %ymm4
	vpsubw	%ymm4, %ymm5, %ymm5
	vmovdqa	%ymm5, 1024(%rsp)
	vpmulhuw	%ymm0, %ymm3, %ymm5
	vpsubw	%ymm5, %ymm3, %ymm4
	vpsrlw	$1, %ymm4, %ymm4
	vpaddw	%ymm5, %ymm4, %ymm4
	vpsrlw	$4, %ymm4, %ymm4
	vpsllw	$1, %ymm4, %ymm5
	vpaddw	%ymm4, %ymm5, %ymm5
	vpsllw	$3, %ymm5, %ymm5
	vpsubw	%ymm4, %ymm5, %ymm4
	vpsubw	%ymm4, %ymm3, %ymm3
	vpmulhuw	%ymm0, %ymm2, %ymm4
	vmovdqa	%ymm3, 1056(%rsp)
	vpsubw	%ymm4, %ymm2, %ymm3
	vpsrlw	$1, %ymm3, %ymm3
	vpaddw	%ymm4, %ymm3, %ymm3
	vpsrlw	$4, %ymm3, %ymm3
	vpsllw	$1, %ymm3, %ymm4
	vpaddw	%ymm3, %ymm4, %ymm4
	vpsllw	$3, %ymm4, %ymm4
	vpsubw	%ymm3, %ymm4, %ymm3
	vpsubw	%ymm3, %ymm2, %ymm2
	vpmulhuw	%ymm0, %ymm1, %ymm3
	vmovdqa	%ymm2, 1088(%rsp)
	vpsubw	%ymm3, %ymm1, %ymm2
	vpsrlw	$1, %ymm2, %ymm2
	vpaddw	%ymm3, %ymm2, %ymm2
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$1, %ymm2, %ymm3
	vpaddw	%ymm2, %ymm3, %ymm3
	vpsllw	$3, %ymm3, %ymm3
	vpsubw	%ymm2, %ymm3, %ymm2
	vpsubw	%ymm2, %ymm1, %ymm1
	vmovdqa	%ymm1, 1120(%rsp)
	vmovdqu	3200(%r13), %ymm1
	vpshufb	%ymm8, %ymm1, %ymm7
	vpshufb	.LC36(%rip), %ymm1, %ymm5
	vpshufb	.LC38(%rip), %ymm1, %ymm4
	vpermq	$78, %ymm7, %ymm2
	vpshufb	.LC37(%rip), %ymm1, %ymm1
	vpor	%ymm2, %ymm7, %ymm7
	vpermq	$78, %ymm5, %ymm2
	vpor	%ymm2, %ymm5, %ymm5
	vpermq	$78, %ymm4, %ymm2
	vpor	%ymm2, %ymm4, %ymm4
	vpermq	$78, %ymm1, %ymm2
	vpor	%ymm2, %ymm1, %ymm3
.L320:
	movl	%ebx, 100(%rsp)
	movq	%r10, %rax
	xorl	%edx, %edx
	leaq	2(%r8), %r15
	leaq	4(%r8), %r14
	leaq	6(%r8), %r13
.L321:
	movzwl	(%r8,%rdx), %ebx
	movzwl	(%r15,%rdx), %r9d
	addq	$648, %rax
	movzwl	(%r14,%rdx), %edi
	movzwl	0(%r13,%rdx), %ecx
	addq	$8, %rdx
	vmovd	%ebx, %xmm2
	vmovd	%r9d, %xmm9
	vpinsrw	$1, %ebx, %xmm2, %xmm1
	vpinsrw	$1, %r9d, %xmm9, %xmm2
	vmovd	%ecx, %xmm10
	vpunpckldq	%xmm2, %xmm2, %xmm2
	vmovd	%edi, %xmm9
	vpunpckldq	%xmm1, %xmm1, %xmm1
	vpunpcklqdq	%xmm2, %xmm1, %xmm1
	vpinsrw	$1, %edi, %xmm9, %xmm2
	vpinsrw	$1, %ecx, %xmm10, %xmm9
	vpunpckldq	%xmm2, %xmm2, %xmm2
	vpunpckldq	%xmm9, %xmm9, %xmm9
	vpunpcklqdq	%xmm9, %xmm2, %xmm2
	vinserti128	$0x1, %xmm2, %ymm1, %ymm1
	vpmullw	%ymm7, %ymm1, %ymm2
	vpaddw	-648(%rax), %ymm2, %ymm2
	vmovdqu	%ymm2, -648(%rax)
	vpmullw	%ymm5, %ymm1, %ymm2
	vpaddw	-486(%rax), %ymm2, %ymm2
	vmovdqu	%ymm2, -486(%rax)
	vpmullw	%ymm4, %ymm1, %ymm2
	vpmullw	%ymm3, %ymm1, %ymm1
	vpaddw	-324(%rax), %ymm2, %ymm2
	vpaddw	-162(%rax), %ymm1, %ymm1
	vmovdqu	%ymm2, -324(%rax)
	vmovdqu	%ymm1, -162(%rax)
	cmpq	$32, %rdx
	jne	.L321
	movl	100(%rsp), %ebx
	addq	$32, %r10
	addq	$32, %r8
	addl	$4, %ebx
	cmpl	$20, %ebx
	jne	.L320
	movq	%rsi, %r15
	movl	104(%rsp), %esi
	movq	160(%rsp), %rdx
	addq	$32, 216(%rsp)
	movl	192(%rsp), %r9d
	incl	%esi
	movq	184(%rsp), %r14
	movq	152(%rsp), %rax
	addq	$8, %rdx
	movq	144(%rsp), %rdi
	movq	136(%rsp), %rcx
	cmpl	208(%rsp), %esi
	jne	.L323
	incl	%r9d
	leaq	160(%rcx), %r13
	movq	%rax, %rbx
	addq	$2592, %r14
	leaq	640(%rdi), %rcx
	cmpl	$5, %r9d
	jne	.L318
	movq	224(%rsp), %rax
	movl	$-1307163959, %edx
	vpxor	%xmm2, %xmm2, %xmm2
	vmovd	%edx, %xmm0
	leaq	12960(%rax), %rcx
	vpbroadcastd	%xmm0, %ymm0
.L324:
	vmovdqu	(%rbx), %ymm3
	vmovdqu	(%rax), %ymm1
	addq	$162, %rax
	addq	$162, %rbx
	vpmovzxwd	%xmm3, %ymm4
	vpmovzxwd	%xmm1, %ymm5
	vextracti128	$0x1, %ymm3, %xmm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpaddd	%ymm4, %ymm5, %ymm5
	vpmovzxwd	%xmm3, %ymm3
	vpmovzxwd	%xmm1, %ymm1
	vpaddd	%ymm3, %ymm1, %ymm4
	vpmuldq	%ymm0, %ymm5, %ymm3
	vpsrlq	$32, %ymm5, %ymm1
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpshufd	$245, %ymm3, %ymm3
	vpblendd	$85, %ymm3, %ymm1, %ymm1
	vpaddd	%ymm5, %ymm1, %ymm1
	vpsrad	$4, %ymm1, %ymm1
	vpslld	$1, %ymm1, %ymm3
	vpaddd	%ymm1, %ymm3, %ymm3
	vpslld	$3, %ymm3, %ymm3
	vpsubd	%ymm1, %ymm3, %ymm3
	vpsrlq	$32, %ymm4, %ymm1
	vpsubd	%ymm3, %ymm5, %ymm3
	vpmuldq	%ymm0, %ymm4, %ymm5
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpblendw	$85, %ymm3, %ymm2, %ymm3
	vpshufd	$245, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm1, %ymm1
	vpaddd	%ymm4, %ymm1, %ymm1
	vpsrad	$4, %ymm1, %ymm1
	vpslld	$1, %ymm1, %ymm5
	vpaddd	%ymm1, %ymm5, %ymm5
	vpslld	$3, %ymm5, %ymm5
	vpsubd	%ymm1, %ymm5, %ymm1
	vpsubd	%ymm1, %ymm4, %ymm1
	vpblendw	$85, %ymm1, %ymm2, %ymm1
	vpackusdw	%ymm1, %ymm3, %ymm1
	vmovdqu	-130(%rax), %ymm3
	vpermq	$216, %ymm1, %ymm1
	vmovdqu	%ymm1, -162(%rax)
	vpmovzxwd	%xmm3, %ymm5
	vextracti128	$0x1, %ymm3, %xmm3
	vmovdqu	-130(%rbx), %ymm1
	vpmovzxwd	%xmm3, %ymm3
	vpmovzxwd	%xmm1, %ymm4
	vextracti128	$0x1, %ymm1, %xmm1
	vpaddd	%ymm4, %ymm5, %ymm5
	vpmovzxwd	%xmm1, %ymm1
	vpaddd	%ymm3, %ymm1, %ymm4
	vpmuldq	%ymm0, %ymm5, %ymm3
	vpsrlq	$32, %ymm5, %ymm1
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpshufd	$245, %ymm3, %ymm3
	vpblendd	$85, %ymm3, %ymm1, %ymm1
	vpaddd	%ymm5, %ymm1, %ymm1
	vpsrad	$4, %ymm1, %ymm1
	vpslld	$1, %ymm1, %ymm3
	vpaddd	%ymm1, %ymm3, %ymm3
	vpslld	$3, %ymm3, %ymm3
	vpsubd	%ymm1, %ymm3, %ymm3
	vpsrlq	$32, %ymm4, %ymm1
	vpsubd	%ymm3, %ymm5, %ymm3
	vpmuldq	%ymm0, %ymm4, %ymm5
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpblendw	$85, %ymm3, %ymm2, %ymm3
	vpshufd	$245, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm1, %ymm1
	vpaddd	%ymm4, %ymm1, %ymm1
	vpsrad	$4, %ymm1, %ymm1
	vpslld	$1, %ymm1, %ymm5
	vpaddd	%ymm1, %ymm5, %ymm5
	vpslld	$3, %ymm5, %ymm5
	vpsubd	%ymm1, %ymm5, %ymm1
	vpsubd	%ymm1, %ymm4, %ymm1
	vpblendw	$85, %ymm1, %ymm2, %ymm1
	vpackusdw	%ymm1, %ymm3, %ymm1
	vmovdqu	-98(%rax), %ymm3
	vpermq	$216, %ymm1, %ymm1
	vmovdqu	%ymm1, -130(%rax)
	vpmovzxwd	%xmm3, %ymm4
	vextracti128	$0x1, %ymm3, %xmm3
	vmovdqu	-98(%rbx), %ymm1
	vpmovzxwd	%xmm3, %ymm3
	vpmovzxwd	%xmm1, %ymm5
	vextracti128	$0x1, %ymm1, %xmm1
	vpaddd	%ymm4, %ymm5, %ymm5
	vpmovzxwd	%xmm1, %ymm1
	vpaddd	%ymm3, %ymm1, %ymm4
	vpmuldq	%ymm0, %ymm5, %ymm3
	vpsrlq	$32, %ymm5, %ymm1
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpshufd	$245, %ymm3, %ymm3
	vpblendd	$85, %ymm3, %ymm1, %ymm1
	vpaddd	%ymm5, %ymm1, %ymm1
	vpsrad	$4, %ymm1, %ymm1
	vpslld	$1, %ymm1, %ymm3
	vpaddd	%ymm1, %ymm3, %ymm3
	vpslld	$3, %ymm3, %ymm3
	vpsubd	%ymm1, %ymm3, %ymm3
	vpsrlq	$32, %ymm4, %ymm1
	vpsubd	%ymm3, %ymm5, %ymm3
	vpmuldq	%ymm0, %ymm4, %ymm5
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpblendw	$85, %ymm3, %ymm2, %ymm3
	vpshufd	$245, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm1, %ymm1
	vpaddd	%ymm4, %ymm1, %ymm1
	vpsrad	$4, %ymm1, %ymm1
	vpslld	$1, %ymm1, %ymm5
	vpaddd	%ymm1, %ymm5, %ymm5
	vpslld	$3, %ymm5, %ymm5
	vpsubd	%ymm1, %ymm5, %ymm1
	vpsubd	%ymm1, %ymm4, %ymm1
	vpblendw	$85, %ymm1, %ymm2, %ymm1
	vpackusdw	%ymm1, %ymm3, %ymm1
	vmovdqu	-66(%rax), %ymm3
	vpermq	$216, %ymm1, %ymm1
	vmovdqu	%ymm1, -98(%rax)
	vpmovzxwd	%xmm3, %ymm5
	vextracti128	$0x1, %ymm3, %xmm3
	vmovdqu	-66(%rbx), %ymm1
	vpmovzxwd	%xmm3, %ymm3
	vpmovzxwd	%xmm1, %ymm4
	vextracti128	$0x1, %ymm1, %xmm1
	vpaddd	%ymm4, %ymm5, %ymm5
	vpmovzxwd	%xmm1, %ymm1
	vpaddd	%ymm3, %ymm1, %ymm4
	vpmuldq	%ymm0, %ymm5, %ymm3
	vpsrlq	$32, %ymm5, %ymm1
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpshufd	$245, %ymm3, %ymm3
	vpblendd	$85, %ymm3, %ymm1, %ymm1
	vpaddd	%ymm5, %ymm1, %ymm1
	vpsrad	$4, %ymm1, %ymm1
	vpslld	$1, %ymm1, %ymm3
	vpaddd	%ymm1, %ymm3, %ymm3
	vpslld	$3, %ymm3, %ymm3
	vpsubd	%ymm1, %ymm3, %ymm3
	vpsrlq	$32, %ymm4, %ymm1
	vpsubd	%ymm3, %ymm5, %ymm3
	vpmuldq	%ymm0, %ymm4, %ymm5
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpblendw	$85, %ymm3, %ymm2, %ymm3
	vpshufd	$245, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm1, %ymm1
	vpaddd	%ymm4, %ymm1, %ymm1
	vpsrad	$4, %ymm1, %ymm1
	vpslld	$1, %ymm1, %ymm5
	vpaddd	%ymm1, %ymm5, %ymm5
	vpslld	$3, %ymm5, %ymm5
	vpsubd	%ymm1, %ymm5, %ymm1
	vpsubd	%ymm1, %ymm4, %ymm1
	vpblendw	$85, %ymm1, %ymm2, %ymm1
	vpackusdw	%ymm1, %ymm3, %ymm1
	vmovdqu	-34(%rax), %ymm3
	vpermq	$216, %ymm1, %ymm1
	vmovdqu	%ymm1, -66(%rax)
	vpmovzxwd	%xmm3, %ymm4
	vextracti128	$0x1, %ymm3, %xmm3
	vmovdqu	-34(%rbx), %ymm1
	vpmovzxwd	%xmm3, %ymm3
	vpmovzxwd	%xmm1, %ymm5
	vextracti128	$0x1, %ymm1, %xmm1
	vpaddd	%ymm4, %ymm5, %ymm5
	vpmovzxwd	%xmm1, %ymm1
	vpaddd	%ymm3, %ymm1, %ymm4
	vpmuldq	%ymm0, %ymm5, %ymm3
	vpsrlq	$32, %ymm5, %ymm1
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpshufd	$245, %ymm3, %ymm3
	vpblendd	$85, %ymm3, %ymm1, %ymm1
	vpaddd	%ymm5, %ymm1, %ymm1
	vpsrad	$4, %ymm1, %ymm1
	vpslld	$1, %ymm1, %ymm3
	vpaddd	%ymm1, %ymm3, %ymm3
	vpslld	$3, %ymm3, %ymm3
	vpsubd	%ymm1, %ymm3, %ymm3
	vpsrlq	$32, %ymm4, %ymm1
	vpsubd	%ymm3, %ymm5, %ymm3
	vpmuldq	%ymm0, %ymm4, %ymm5
	vpmuldq	%ymm0, %ymm1, %ymm1
	vpblendw	$85, %ymm3, %ymm2, %ymm3
	vpshufd	$245, %ymm5, %ymm5
	vpblendd	$85, %ymm5, %ymm1, %ymm1
	vpaddd	%ymm4, %ymm1, %ymm1
	vpsrad	$4, %ymm1, %ymm1
	vpslld	$1, %ymm1, %ymm5
	vpaddd	%ymm1, %ymm5, %ymm5
	vpslld	$3, %ymm5, %ymm5
	vpsubd	%ymm1, %ymm5, %ymm1
	vpsubd	%ymm1, %ymm4, %ymm1
	vpblendw	$85, %ymm1, %ymm2, %ymm1
	vpackusdw	%ymm1, %ymm3, %ymm1
	vpermq	$216, %ymm1, %ymm1
	vmovdqu	%ymm1, -34(%rax)
	cmpq	%rax, %rcx
	jne	.L324
	movl	$0, 192(%rsp)
	movl	$1680696365, %eax
	movq	224(%rsp), %rcx
	xorl	%r11d, %r11d
	movq	$0, 208(%rsp)
	vmovd	%eax, %xmm2
	movl	$162, %r15d
	xorl	%r8d, %r8d
	movq	$0, 160(%rsp)
	vpbroadcastd	%xmm2, %ymm1
	leaq	162(%rcx), %rsi
	movl	$23, %ebx
	movq	$0, 184(%rsp)
	movl	192(%rsp), %eax
	vpbroadcastd	%xmm2, %xmm2
	movl	$80, 216(%rsp)
	movl	$0, 200(%rsp)
.L342:
	leal	1(%rax), %edi
	cmpl	$79, %eax
	je	.L332
	movl	$79, %r13d
	leaq	-2(%r11), %rax
	movq	%r15, %r9
	movq	%rsi, %r12
	subl	%edi, %r13d
	movq	%rax, 152(%rsp)
	addq	184(%rsp), %r13
	imulq	$162, %r13, %r13
	addq	$324, %r13
	jmp	.L331
.L588:
	vmovd	%r10d, %xmm0
	leaq	(%r12,%r8), %rax
	vpbroadcastw	%xmm0, %ymm0
	vpand	(%r12), %ymm0, %ymm3
	vpaddw	-162(%rsi), %ymm3, %ymm3
	vmovdqu	%ymm3, -162(%rsi)
	vpand	32(%r12), %ymm0, %ymm3
	vpaddw	-130(%rsi), %ymm3, %ymm3
	vmovdqu	%ymm3, -130(%rsi)
	vpand	64(%r12), %ymm0, %ymm3
	vpaddw	-98(%rsi), %ymm3, %ymm3
	vmovdqu	%ymm3, -98(%rsi)
	vpand	96(%r12), %ymm0, %ymm3
	vpaddw	-66(%rsi), %ymm3, %ymm3
	vmovdqu	%ymm3, -66(%rsi)
	vpand	128(%r12), %ymm0, %ymm0
	vpaddw	-34(%rsi), %ymm0, %ymm0
	vmovdqu	%ymm0, -34(%rsi)
	andw	-2(%rax,%r15), %r10w
	addw	%r10w, -2(%rsi)
.L329:
	addq	$162, %r9
	addq	$162, %r12
	cmpq	%r13, %r9
	je	.L332
.L331:
	movq	152(%rsp), %rax
	cmpw	$1, (%rcx)
	sbbl	%r10d, %r10d
	subq	%r9, %rax
	cmpq	$28, %rax
	ja	.L588
	leaq	-162(%rsi), %rax
	.p2align 5
	.p2align 4,,10
	.p2align 3
.L330:
	leaq	(%rax,%r8), %rdx
	movzwl	(%rdx,%r9), %r14d
	andl	%r10d, %r14d
	addw	%r14w, (%rax)
	addq	$2, %rax
	cmpq	%rsi, %rax
	jne	.L330
	jmp	.L329
.L332:
	vmovdqu	-162(%rsi), %ymm6
	vmovdqu	-130(%rsi), %ymm5
	xorl	%edx, %edx
	movl	$2987803337, %r14d
	vmovdqu	-98(%rsi), %ymm4
	movzwl	-2(%rsi), %eax
	movq	%rsi, %r9
	vpmulhuw	%ymm1, %ymm6, %ymm3
	vmovdqu	-34(%rsi), %ymm8
	divw	%bx
	vpsubw	%ymm3, %ymm6, %ymm0
	xorl	%eax, %eax
	vpsrlw	$1, %ymm0, %ymm0
	vpaddw	%ymm3, %ymm0, %ymm0
	vpsrlw	$4, %ymm0, %ymm0
	vpsllw	$1, %ymm0, %ymm3
	vpaddw	%ymm0, %ymm3, %ymm3
	vpsllw	$3, %ymm3, %ymm3
	vpsubw	%ymm0, %ymm3, %ymm0
	vpmulhuw	%ymm1, %ymm5, %ymm3
	vpsubw	%ymm0, %ymm6, %ymm6
	vmovdqu	%ymm6, -162(%rsi)
	vpsubw	%ymm3, %ymm5, %ymm0
	vpsrlw	$1, %ymm0, %ymm0
	vpaddw	%ymm3, %ymm0, %ymm0
	movw	%dx, -2(%rsi)
	vpsrlw	$4, %ymm0, %ymm0
	vpsllw	$1, %ymm0, %ymm3
	vpaddw	%ymm0, %ymm3, %ymm3
	vpsllw	$3, %ymm3, %ymm3
	vpsubw	%ymm0, %ymm3, %ymm0
	vpmulhuw	%ymm1, %ymm4, %ymm3
	vpsubw	%ymm0, %ymm5, %ymm5
	vmovdqu	%ymm5, -130(%rsi)
	vpsubw	%ymm3, %ymm4, %ymm0
	vpsrlw	$1, %ymm0, %ymm0
	vpaddw	%ymm3, %ymm0, %ymm0
	vpsrlw	$4, %ymm0, %ymm0
	vpsllw	$1, %ymm0, %ymm3
	vpaddw	%ymm0, %ymm3, %ymm3
	vpsllw	$3, %ymm3, %ymm3
	vpsubw	%ymm0, %ymm3, %ymm0
	vmovdqu	-66(%rsi), %ymm3
	vpsubw	%ymm0, %ymm4, %ymm4
	vpmulhuw	%ymm1, %ymm3, %ymm7
	vmovdqu	%ymm4, -98(%rsi)
	vpsubw	%ymm7, %ymm3, %ymm0
	vpsrlw	$1, %ymm0, %ymm0
	vpaddw	%ymm7, %ymm0, %ymm0
	vpsrlw	$4, %ymm0, %ymm0
	vpsllw	$1, %ymm0, %ymm7
	vpaddw	%ymm0, %ymm7, %ymm7
	vpsllw	$3, %ymm7, %ymm7
	vpsubw	%ymm0, %ymm7, %ymm0
	vpmulhuw	%ymm1, %ymm8, %ymm7
	vpsubw	%ymm0, %ymm3, %ymm3
	vmovdqu	%ymm3, -66(%rsi)
	vpsubw	%ymm7, %ymm8, %ymm0
	vpsrlw	$1, %ymm0, %ymm0
	vpaddw	%ymm7, %ymm0, %ymm0
	vpsrlw	$4, %ymm0, %ymm0
	vpsllw	$1, %ymm0, %ymm7
	vpaddw	%ymm0, %ymm7, %ymm7
	vpsllw	$3, %ymm7, %ymm7
	vpsubw	%ymm0, %ymm7, %ymm0
	vpsubw	%ymm0, %ymm8, %ymm0
	vmovdqu	%ymm0, -34(%rsi)
	movzwl	(%rcx), %r10d
	testw	%r10w, %r10w
	movl	%r10d, %r12d
	sete	%al
	imull	%r10d, %r12d
	orl	%eax, 200(%rsp)
	imull	%r12d, %r12d
	movl	%r12d, %eax
	imulq	%r14, %rax
	shrq	$36, %rax
	imull	$23, %eax, %r13d
	movl	%r12d, %eax
	subl	%r13d, %eax
	imull	%eax, %r10d
	imull	%eax, %eax
	movl	%r10d, %r12d
	movl	%eax, %r10d
	imulq	%r14, %rax
	shrq	$36, %rax
	imull	$23, %eax, %r13d
	movl	%r10d, %eax
	movl	%r12d, %r10d
	subl	%r13d, %eax
	movl	%r12d, %r13d
	imull	%eax, %eax
	imulq	%r14, %r13
	movl	%eax, %r12d
	imulq	%r14, %r12
	shrq	$36, %r13
	imull	$23, %r13d, %r13d
	shrq	$36, %r12
	imull	$23, %r12d, %r12d
	subl	%r13d, %r10d
	subl	%r12d, %eax
	imull	%r10d, %eax
	movl	%eax, %r10d
	imulq	%r14, %r10
	shrq	$36, %r10
	imull	$23, %r10d, %r10d
	subl	%r10d, %eax
	vmovd	%eax, %xmm7
	mulb	%dl
	xorl	%edx, %edx
	vpbroadcastw	%xmm7, %ymm7
	vpmullw	%ymm6, %ymm7, %ymm6
	vpmullw	%ymm5, %ymm7, %ymm5
	vpmullw	%ymm4, %ymm7, %ymm4
	vpmullw	%ymm3, %ymm7, %ymm3
	vpmullw	%ymm7, %ymm0, %ymm0
	divw	%bx
	vpmulhuw	%ymm1, %ymm6, %ymm8
	decl	216(%rsp)
	vpsubw	%ymm8, %ymm6, %ymm7
	vpsrlw	$1, %ymm7, %ymm7
	vpaddw	%ymm8, %ymm7, %ymm7
	vpsrlw	$4, %ymm7, %ymm7
	vpsllw	$1, %ymm7, %ymm8
	vpaddw	%ymm7, %ymm8, %ymm8
	vpsllw	$3, %ymm8, %ymm8
	vpsubw	%ymm7, %ymm8, %ymm7
	vpsubw	%ymm7, %ymm6, %ymm6
	vpmulhuw	%ymm1, %ymm5, %ymm7
	vmovdqu	%ymm6, -162(%rsi)
	movw	%dx, -2(%rsi)
	vpsubw	%ymm7, %ymm5, %ymm6
	vpsrlw	$1, %ymm6, %ymm6
	vpaddw	%ymm7, %ymm6, %ymm6
	vpsrlw	$4, %ymm6, %ymm6
	vpsllw	$1, %ymm6, %ymm7
	vpaddw	%ymm6, %ymm7, %ymm7
	vpsllw	$3, %ymm7, %ymm7
	vpsubw	%ymm6, %ymm7, %ymm6
	vpsubw	%ymm6, %ymm5, %ymm5
	vpmulhuw	%ymm1, %ymm4, %ymm6
	vmovdqu	%ymm5, -130(%rsi)
	vpsubw	%ymm6, %ymm4, %ymm5
	vpsrlw	$1, %ymm5, %ymm5
	vpaddw	%ymm6, %ymm5, %ymm5
	vpsrlw	$4, %ymm5, %ymm5
	vpsllw	$1, %ymm5, %ymm6
	vpaddw	%ymm5, %ymm6, %ymm6
	vpsllw	$3, %ymm6, %ymm6
	vpsubw	%ymm5, %ymm6, %ymm5
	vpsubw	%ymm5, %ymm4, %ymm4
	vpmulhuw	%ymm1, %ymm3, %ymm5
	vmovdqu	%ymm4, -98(%rsi)
	vpsubw	%ymm5, %ymm3, %ymm4
	vpsrlw	$1, %ymm4, %ymm4
	vpaddw	%ymm5, %ymm4, %ymm4
	vpsrlw	$4, %ymm4, %ymm4
	vpsllw	$1, %ymm4, %ymm5
	vpaddw	%ymm4, %ymm5, %ymm5
	vpsllw	$3, %ymm5, %ymm5
	vpsubw	%ymm4, %ymm5, %ymm4
	vpsubw	%ymm4, %ymm3, %ymm3
	vpmulhuw	%ymm1, %ymm0, %ymm4
	vmovdqu	%ymm3, -66(%rsi)
	vpsubw	%ymm4, %ymm0, %ymm3
	vpsrlw	$1, %ymm3, %ymm3
	vpaddw	%ymm4, %ymm3, %ymm3
	vpsrlw	$4, %ymm3, %ymm3
	vpsllw	$1, %ymm3, %ymm4
	vpaddw	%ymm3, %ymm4, %ymm4
	vpsllw	$3, %ymm4, %ymm4
	vpsubw	%ymm3, %ymm4, %ymm3
	vpsubw	%ymm3, %ymm0, %ymm0
	vmovdqu	%ymm0, -34(%rsi)
	je	.L589
	movl	$79, %eax
	leaq	-324(%r8), %rdx
	leaq	-162(%r8), %r13
	addq	$162, %rsi
	subl	%edi, %eax
	movq	%r13, %r10
	imulq	$162, %rax, %rax
	subq	%rax, %rdx
	leaq	-2(%r8), %rax
	movq	%rdx, 152(%rsp)
	movq	%rsi, %rdx
	movq	%rax, 144(%rsp)
	jmp	.L336
.L591:
	vmovd	%r12d, %xmm0
	leaq	(%rdx,%r8), %rax
	vpbroadcastw	%xmm0, %ymm0
	vpmullw	-162(%r9), %ymm0, %ymm3
	vpaddw	-162(%rdx), %ymm3, %ymm3
	vmovdqu	%ymm3, -162(%rdx)
	vpmullw	-130(%r9), %ymm0, %ymm3
	vpaddw	-130(%rdx), %ymm3, %ymm3
	vmovdqu	%ymm3, -130(%rdx)
	vpmullw	-98(%r9), %ymm0, %ymm3
	vpaddw	-98(%rdx), %ymm3, %ymm3
	vmovdqu	%ymm3, -98(%rdx)
	vpmullw	-66(%r9), %ymm0, %ymm3
	vpaddw	-66(%rdx), %ymm3, %ymm3
	vmovdqu	%ymm3, -66(%rdx)
	vpmullw	-34(%r9), %ymm0, %ymm0
	vpaddw	-34(%rdx), %ymm0, %ymm0
	vmovdqu	%ymm0, -34(%rdx)
	imulw	-2(%r9), %r12w
	addw	%r12w, -164(%rax,%r15)
.L334:
	subq	$162, %r10
	addq	$162, %rdx
	cmpq	152(%rsp), %r10
	je	.L590
.L336:
	movq	160(%rsp), %r14
	leaq	(%rdx,%r15), %rax
	movl	%ebx, %r12d
	subw	-324(%rax,%r14), %r12w
	movq	144(%rsp), %rax
	subq	%r10, %rax
	cmpq	$28, %rax
	ja	.L591
	movl	%edi, 136(%rsp)
	leaq	-162(%rdx), %rax
	.p2align 5
	.p2align 4,,10
	.p2align 3
.L335:
	leaq	(%rax,%r10), %rdi
	movzwl	(%rdi,%r11), %r14d
	imull	%r12d, %r14d
	addw	%r14w, (%rax)
	addq	$2, %rax
	cmpq	%rdx, %rax
	jne	.L335
	movl	136(%rsp), %edi
	jmp	.L334
.L590:
	movl	192(%rsp), %eax
	subl	$64, %eax
	cmpl	$14, %eax
	jbe	.L369
	movzwl	164(%rcx), %eax
	movl	216(%rsp), %edx
	vmovd	%eax, %xmm0
	movzwl	488(%rcx), %eax
	shrl	$4, %edx
	vpinsrw	$1, 326(%rcx), %xmm0, %xmm0
	vmovd	%eax, %xmm5
	movzwl	812(%rcx), %eax
	vpinsrw	$1, 650(%rcx), %xmm5, %xmm5
	vmovd	%eax, %xmm3
	movzwl	1136(%rcx), %eax
	vpinsrw	$1, 974(%rcx), %xmm3, %xmm3
	vpunpckldq	%xmm5, %xmm0, %xmm0
	vmovd	%eax, %xmm4
	movzwl	1460(%rcx), %eax
	vpinsrw	$1, 1298(%rcx), %xmm4, %xmm4
	vpunpckldq	%xmm4, %xmm3, %xmm3
	vpunpcklqdq	%xmm3, %xmm0, %xmm0
	vmovd	%eax, %xmm3
	movzwl	1784(%rcx), %eax
	vpinsrw	$1, 1622(%rcx), %xmm3, %xmm3
	vmovd	%eax, %xmm6
	movzwl	2108(%rcx), %eax
	vpinsrw	$1, 1946(%rcx), %xmm6, %xmm6
	vmovd	%eax, %xmm4
	movzwl	2432(%rcx), %eax
	vpinsrw	$1, 2270(%rcx), %xmm4, %xmm4
	vpunpckldq	%xmm6, %xmm3, %xmm3
	vmovd	%eax, %xmm5
	vpinsrw	$1, 2594(%rcx), %xmm5, %xmm5
	vpunpckldq	%xmm5, %xmm4, %xmm4
	vpunpcklqdq	%xmm4, %xmm3, %xmm3
	vinserti128	$0x1, %xmm3, %ymm0, %ymm0
	vpmulhuw	%ymm1, %ymm0, %ymm4
	vpsubw	%ymm4, %ymm0, %ymm3
	vpsrlw	$1, %ymm3, %ymm3
	vpaddw	%ymm4, %ymm3, %ymm3
	vpsrlw	$4, %ymm3, %ymm3
	vpsllw	$1, %ymm3, %ymm4
	vpaddw	%ymm3, %ymm4, %ymm4
	vpsllw	$3, %ymm4, %ymm4
	vpsubw	%ymm3, %ymm4, %ymm3
	vpsubw	%ymm3, %ymm0, %ymm0
	vpextrw	$0, %xmm0, 164(%rcx)
	vpextrw	$1, %xmm0, 326(%rcx)
	vpextrw	$2, %xmm0, 488(%rcx)
	vpextrw	$3, %xmm0, 650(%rcx)
	vpextrw	$4, %xmm0, 812(%rcx)
	vpextrw	$5, %xmm0, 974(%rcx)
	vpextrw	$6, %xmm0, 1136(%rcx)
	vpextrw	$7, %xmm0, 1298(%rcx)
	vextracti128	$0x1, %ymm0, %xmm0
	vpextrw	$0, %xmm0, 1460(%rcx)
	vpextrw	$1, %xmm0, 1622(%rcx)
	vpextrw	$2, %xmm0, 1784(%rcx)
	vpextrw	$3, %xmm0, 1946(%rcx)
	vpextrw	$4, %xmm0, 2108(%rcx)
	vpextrw	$5, %xmm0, 2270(%rcx)
	vpextrw	$6, %xmm0, 2432(%rcx)
	vpextrw	$7, %xmm0, 2594(%rcx)
	cmpl	$1, %edx
	je	.L338
	movzwl	2756(%rcx), %eax
	vmovd	%eax, %xmm0
	movzwl	3080(%rcx), %eax
	vpinsrw	$1, 2918(%rcx), %xmm0, %xmm0
	vmovd	%eax, %xmm5
	movzwl	3404(%rcx), %eax
	vpinsrw	$1, 3242(%rcx), %xmm5, %xmm5
	vmovd	%eax, %xmm3
	movzwl	3728(%rcx), %eax
	vpinsrw	$1, 3566(%rcx), %xmm3, %xmm3
	vpunpckldq	%xmm5, %xmm0, %xmm0
	vmovd	%eax, %xmm4
	movzwl	4052(%rcx), %eax
	vpinsrw	$1, 3890(%rcx), %xmm4, %xmm4
	vpunpckldq	%xmm4, %xmm3, %xmm3
	vpunpcklqdq	%xmm3, %xmm0, %xmm0
	vmovd	%eax, %xmm3
	movzwl	4376(%rcx), %eax
	vpinsrw	$1, 4214(%rcx), %xmm3, %xmm3
	vmovd	%eax, %xmm6
	movzwl	4700(%rcx), %eax
	vpinsrw	$1, 4538(%rcx), %xmm6, %xmm6
	vmovd	%eax, %xmm4
	movzwl	5024(%rcx), %eax
	vpinsrw	$1, 4862(%rcx), %xmm4, %xmm4
	vpunpckldq	%xmm6, %xmm3, %xmm3
	vmovd	%eax, %xmm5
	vpinsrw	$1, 5186(%rcx), %xmm5, %xmm5
	vpunpckldq	%xmm5, %xmm4, %xmm4
	vpunpcklqdq	%xmm4, %xmm3, %xmm3
	vinserti128	$0x1, %xmm3, %ymm0, %ymm0
	vpmulhuw	%ymm1, %ymm0, %ymm4
	vpsubw	%ymm4, %ymm0, %ymm3
	vpsrlw	$1, %ymm3, %ymm3
	vpaddw	%ymm4, %ymm3, %ymm3
	vpsrlw	$4, %ymm3, %ymm3
	vpsllw	$1, %ymm3, %ymm4
	vpaddw	%ymm3, %ymm4, %ymm4
	vpsllw	$3, %ymm4, %ymm4
	vpsubw	%ymm3, %ymm4, %ymm3
	vpsubw	%ymm3, %ymm0, %ymm0
	vpextrw	$0, %xmm0, 2756(%rcx)
	vpextrw	$1, %xmm0, 2918(%rcx)
	vpextrw	$2, %xmm0, 3080(%rcx)
	vpextrw	$3, %xmm0, 3242(%rcx)
	vpextrw	$4, %xmm0, 3404(%rcx)
	vpextrw	$5, %xmm0, 3566(%rcx)
	vpextrw	$6, %xmm0, 3728(%rcx)
	vpextrw	$7, %xmm0, 3890(%rcx)
	vextracti128	$0x1, %ymm0, %xmm0
	vpextrw	$0, %xmm0, 4052(%rcx)
	vpextrw	$1, %xmm0, 4214(%rcx)
	vpextrw	$2, %xmm0, 4376(%rcx)
	vpextrw	$3, %xmm0, 4538(%rcx)
	vpextrw	$4, %xmm0, 4700(%rcx)
	vpextrw	$5, %xmm0, 4862(%rcx)
	vpextrw	$6, %xmm0, 5024(%rcx)
	vpextrw	$7, %xmm0, 5186(%rcx)
	cmpl	$2, %edx
	je	.L338
	movzwl	5348(%rcx), %eax
	vmovd	%eax, %xmm0
	movzwl	5672(%rcx), %eax
	vpinsrw	$1, 5510(%rcx), %xmm0, %xmm0
	vmovd	%eax, %xmm5
	movzwl	5996(%rcx), %eax
	vpinsrw	$1, 5834(%rcx), %xmm5, %xmm5
	vmovd	%eax, %xmm3
	movzwl	6320(%rcx), %eax
	vpinsrw	$1, 6158(%rcx), %xmm3, %xmm3
	vpunpckldq	%xmm5, %xmm0, %xmm0
	vmovd	%eax, %xmm4
	movzwl	6644(%rcx), %eax
	vpinsrw	$1, 6482(%rcx), %xmm4, %xmm4
	vpunpckldq	%xmm4, %xmm3, %xmm3
	vpunpcklqdq	%xmm3, %xmm0, %xmm0
	vmovd	%eax, %xmm3
	movzwl	6968(%rcx), %eax
	vpinsrw	$1, 6806(%rcx), %xmm3, %xmm3
	vmovd	%eax, %xmm6
	movzwl	7292(%rcx), %eax
	vpinsrw	$1, 7130(%rcx), %xmm6, %xmm6
	vmovd	%eax, %xmm4
	movzwl	7616(%rcx), %eax
	vpinsrw	$1, 7454(%rcx), %xmm4, %xmm4
	vpunpckldq	%xmm6, %xmm3, %xmm3
	vmovd	%eax, %xmm5
	vpinsrw	$1, 7778(%rcx), %xmm5, %xmm5
	vpunpckldq	%xmm5, %xmm4, %xmm4
	vpunpcklqdq	%xmm4, %xmm3, %xmm3
	vinserti128	$0x1, %xmm3, %ymm0, %ymm0
	vpmulhuw	%ymm1, %ymm0, %ymm4
	vpsubw	%ymm4, %ymm0, %ymm3
	vpsrlw	$1, %ymm3, %ymm3
	vpaddw	%ymm4, %ymm3, %ymm3
	vpsrlw	$4, %ymm3, %ymm3
	vpsllw	$1, %ymm3, %ymm4
	vpaddw	%ymm3, %ymm4, %ymm4
	vpsllw	$3, %ymm4, %ymm4
	vpsubw	%ymm3, %ymm4, %ymm3
	vpsubw	%ymm3, %ymm0, %ymm0
	vpextrw	$0, %xmm0, 5348(%rcx)
	vpextrw	$1, %xmm0, 5510(%rcx)
	vpextrw	$2, %xmm0, 5672(%rcx)
	vpextrw	$3, %xmm0, 5834(%rcx)
	vpextrw	$4, %xmm0, 5996(%rcx)
	vpextrw	$5, %xmm0, 6158(%rcx)
	vpextrw	$6, %xmm0, 6320(%rcx)
	vpextrw	$7, %xmm0, 6482(%rcx)
	vextracti128	$0x1, %ymm0, %xmm0
	vpextrw	$0, %xmm0, 6644(%rcx)
	vpextrw	$1, %xmm0, 6806(%rcx)
	vpextrw	$2, %xmm0, 6968(%rcx)
	vpextrw	$3, %xmm0, 7130(%rcx)
	vpextrw	$4, %xmm0, 7292(%rcx)
	vpextrw	$5, %xmm0, 7454(%rcx)
	vpextrw	$6, %xmm0, 7616(%rcx)
	vpextrw	$7, %xmm0, 7778(%rcx)
	cmpl	$4, %edx
	jne	.L338
	movzwl	7940(%rcx), %eax
	vmovd	%eax, %xmm0
	movzwl	8264(%rcx), %eax
	vpinsrw	$1, 8102(%rcx), %xmm0, %xmm0
	vmovd	%eax, %xmm5
	movzwl	8588(%rcx), %eax
	vpinsrw	$1, 8426(%rcx), %xmm5, %xmm5
	vmovd	%eax, %xmm3
	movzwl	8912(%rcx), %eax
	vpinsrw	$1, 8750(%rcx), %xmm3, %xmm3
	vpunpckldq	%xmm5, %xmm0, %xmm0
	vmovd	%eax, %xmm4
	movzwl	9236(%rcx), %eax
	vpinsrw	$1, 9074(%rcx), %xmm4, %xmm4
	vpunpckldq	%xmm4, %xmm3, %xmm3
	vpunpcklqdq	%xmm3, %xmm0, %xmm0
	vmovd	%eax, %xmm3
	movzwl	9560(%rcx), %eax
	vpinsrw	$1, 9398(%rcx), %xmm3, %xmm3
	vmovd	%eax, %xmm6
	movzwl	9884(%rcx), %eax
	vpinsrw	$1, 9722(%rcx), %xmm6, %xmm6
	vmovd	%eax, %xmm4
	movzwl	10208(%rcx), %eax
	vpinsrw	$1, 10046(%rcx), %xmm4, %xmm4
	vpunpckldq	%xmm6, %xmm3, %xmm3
	vmovd	%eax, %xmm5
	vpinsrw	$1, 10370(%rcx), %xmm5, %xmm5
	vpunpckldq	%xmm5, %xmm4, %xmm4
	vpunpcklqdq	%xmm4, %xmm3, %xmm3
	vinserti128	$0x1, %xmm3, %ymm0, %ymm0
	vpmulhuw	%ymm1, %ymm0, %ymm4
	vpsubw	%ymm4, %ymm0, %ymm3
	vpsrlw	$1, %ymm3, %ymm3
	vpaddw	%ymm4, %ymm3, %ymm3
	vpsrlw	$4, %ymm3, %ymm3
	vpsllw	$1, %ymm3, %ymm4
	vpaddw	%ymm3, %ymm4, %ymm4
	vpsllw	$3, %ymm4, %ymm4
	vpsubw	%ymm3, %ymm4, %ymm3
	vpsubw	%ymm3, %ymm0, %ymm0
	vpextrw	$0, %xmm0, 7940(%rcx)
	vpextrw	$1, %xmm0, 8102(%rcx)
	vpextrw	$2, %xmm0, 8264(%rcx)
	vpextrw	$3, %xmm0, 8426(%rcx)
	vpextrw	$4, %xmm0, 8588(%rcx)
	vpextrw	$5, %xmm0, 8750(%rcx)
	vpextrw	$6, %xmm0, 8912(%rcx)
	vpextrw	$7, %xmm0, 9074(%rcx)
	vextracti128	$0x1, %ymm0, %xmm0
	vpextrw	$0, %xmm0, 9236(%rcx)
	vpextrw	$1, %xmm0, 9398(%rcx)
	vpextrw	$2, %xmm0, 9560(%rcx)
	vpextrw	$3, %xmm0, 9722(%rcx)
	vpextrw	$4, %xmm0, 9884(%rcx)
	vpextrw	$5, %xmm0, 10046(%rcx)
	vpextrw	$6, %xmm0, 10208(%rcx)
	vpextrw	$7, %xmm0, 10370(%rcx)
.L338:
	movq	208(%rsp), %rax
	leaq	164(%rax), %r10
	testb	$15, 216(%rsp)
	je	.L339
	movl	216(%rsp), %eax
	andl	$-16, %eax
	leal	(%rax,%rdi), %r8d
.L337:
	movl	184(%rsp), %edx
	addl	%eax, %edx
	leal	-72(%rdx), %r9d
	cmpl	$6, %r9d
	jbe	.L592
	imulq	$162, %rax, %rax
	movq	208(%rsp), %r10
	movl	$79, %r9d
	subl	%edx, %r9d
	addq	$164, %r10
	addq	%r10, %rax
	addq	224(%rsp), %rax
	movzwl	(%rax), %edx
	vmovd	%edx, %xmm0
	movzwl	324(%rax), %edx
	vpinsrw	$1, 162(%rax), %xmm0, %xmm0
	vmovd	%edx, %xmm5
	movzwl	648(%rax), %edx
	vpinsrw	$1, 486(%rax), %xmm5, %xmm5
	vmovd	%edx, %xmm3
	movzwl	972(%rax), %edx
	vpinsrw	$1, 810(%rax), %xmm3, %xmm3
	vpunpckldq	%xmm5, %xmm0, %xmm0
	vmovd	%edx, %xmm4
	vpinsrw	$1, 1134(%rax), %xmm4, %xmm4
	vpunpckldq	%xmm4, %xmm3, %xmm3
	vpunpcklqdq	%xmm3, %xmm0, %xmm0
	vpmulhuw	%xmm2, %xmm0, %xmm4
	vpsubw	%xmm4, %xmm0, %xmm3
	vpsrlw	$1, %xmm3, %xmm3
	vpaddw	%xmm4, %xmm3, %xmm3
	vpsrlw	$4, %xmm3, %xmm3
	vpsllw	$1, %xmm3, %xmm4
	vpaddw	%xmm3, %xmm4, %xmm4
	vpsllw	$3, %xmm4, %xmm4
	vpsubw	%xmm3, %xmm4, %xmm3
	vpsubw	%xmm3, %xmm0, %xmm0
	vpextrw	$0, %xmm0, (%rax)
	vpextrw	$1, %xmm0, 162(%rax)
	vpextrw	$2, %xmm0, 324(%rax)
	vpextrw	$3, %xmm0, 486(%rax)
	vpextrw	$4, %xmm0, 648(%rax)
	vpextrw	$5, %xmm0, 810(%rax)
	vpextrw	$6, %xmm0, 972(%rax)
	vpextrw	$7, %xmm0, 1134(%rax)
	testb	$7, %r9b
	je	.L339
	andl	$-8, %r9d
	addl	%r9d, %r8d
.L340:
	movslq	%r8d, %rax
	movslq	%edi, %r9
	xorl	%edx, %edx
	leaq	(%rax,%rax,8), %rax
	leaq	(%rax,%rax,8), %r12
	addq	%r9, %r12
	movzwl	10752(%rsp,%r12,2), %eax
	divw	%bx
	leal	1(%r8), %eax
	movw	%dx, 10752(%rsp,%r12,2)
	cmpl	$79, %r8d
	je	.L339
	cltq
	xorl	%edx, %edx
	leaq	(%rax,%rax,8), %rax
	leaq	(%rax,%rax,8), %r12
	addq	%r9, %r12
	movzwl	10752(%rsp,%r12,2), %eax
	divw	%bx
	leal	2(%r8), %eax
	movw	%dx, 10752(%rsp,%r12,2)
	cmpl	$78, %r8d
	je	.L339
	cltq
	xorl	%edx, %edx
	leaq	(%rax,%rax,8), %rax
	leaq	(%rax,%rax,8), %r12
	addq	%r9, %r12
	movzwl	10752(%rsp,%r12,2), %eax
	divw	%bx
	leal	3(%r8), %eax
	movw	%dx, 10752(%rsp,%r12,2)
	cmpl	$77, %r8d
	je	.L339
	cltq
	xorl	%edx, %edx
	leaq	(%rax,%rax,8), %rax
	leaq	(%rax,%rax,8), %r12
	addq	%r9, %r12
	movzwl	10752(%rsp,%r12,2), %eax
	divw	%bx
	leal	4(%r8), %eax
	movw	%dx, 10752(%rsp,%r12,2)
	cmpl	$76, %r8d
	je	.L339
	cltq
	xorl	%edx, %edx
	leaq	(%rax,%rax,8), %rax
	leaq	(%rax,%rax,8), %r12
	addq	%r9, %r12
	movzwl	10752(%rsp,%r12,2), %eax
	divw	%bx
	leal	5(%r8), %eax
	movw	%dx, 10752(%rsp,%r12,2)
	cmpl	$75, %r8d
	je	.L339
	cltq
	xorl	%edx, %edx
	leaq	(%rax,%rax,8), %rax
	leaq	(%rax,%rax,8), %r12
	addq	%r9, %r12
	movzwl	10752(%rsp,%r12,2), %eax
	divw	%bx
	leal	6(%r8), %eax
	movw	%dx, 10752(%rsp,%r12,2)
	cmpl	$74, %r8d
	je	.L339
	cltq
	xorl	%edx, %edx
	leaq	(%rax,%rax,8), %rax
	leaq	(%rax,%rax,8), %r8
	addq	%r9, %r8
	movzwl	10752(%rsp,%r8,2), %eax
	divw	%bx
	movw	%dx, 10752(%rsp,%r8,2)
.L339:
	incq	184(%rsp)
	addq	$164, %rcx
	addq	$162, %r15
	addq	$162, %r11
	subq	$160, 160(%rsp)
	movq	%r13, %r8
	movl	%edi, %eax
	movq	%r10, 208(%rsp)
	movl	%edi, 192(%rsp)
	jmp	.L342
.L592:
	movq	208(%rsp), %rax
	leaq	164(%rax), %r10
	jmp	.L340
.L369:
	movl	%edi, %r8d
	xorl	%eax, %eax
	jmp	.L337
.L589:
	movl	200(%rsp), %edx
	testl	%edx, %edx
	je	.L593
.L344:
	movzbl	255(%rsp), %r12d
	jmp	.L356
.L593:
	xorl	%eax, %eax
	vpxor	%xmm0, %xmm0, %xmm0
	leaq	734(%rsp), %rsi
	movl	$6478, %r13d
	movw	%ax, 736(%rsp)
	movq	224(%rsp), %rax
	movl	$79, %r10d
	xorl	%r9d, %r9d
	vmovdqa	%ymm0, 576(%rsp)
	movl	$80, %edi
	movl	$23, %r15d
	movl	$2987803337, %r14d
	leaq	12958(%rax), %r11
	vmovdqa	%ymm0, 608(%rsp)
	vmovdqa	%ymm0, 640(%rsp)
	movq	%r11, %r8
	vmovdqa	%ymm0, 672(%rsp)
	vmovdqa	%ymm0, 704(%rsp)
	jmp	.L351
.L595:
	leal	-1(%r9), %eax
	movl	%edi, %edx
	movl	%r9d, %ecx
	cmpl	$14, %eax
	jbe	.L371
	vmovdqu	2(%rsi), %ymm0
	movl	%r9d, %eax
	shrl	$4, %eax
	vpmullw	(%r8), %ymm0, %ymm0
	cmpl	$1, %eax
	je	.L347
	vmovdqu	34(%rsi), %ymm1
	vpmullw	32(%r8), %ymm1, %ymm1
	vpaddw	%ymm1, %ymm0, %ymm0
	cmpl	$2, %eax
	je	.L347
	vmovdqu	66(%rsi), %ymm1
	vpmullw	64(%r8), %ymm1, %ymm1
	vpaddw	%ymm1, %ymm0, %ymm0
	cmpl	$4, %eax
	jne	.L347
	vmovdqu	96(%r8), %ymm1
	vpmullw	98(%rsi), %ymm1, %ymm1
	vpaddw	%ymm1, %ymm0, %ymm0
.L347:
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
	je	.L348
	andl	$-16, %ecx
	leal	(%rdi,%rcx), %edx
.L346:
	leal	(%rcx,%r10), %r12d
	leal	-72(%r12), %ebx
	cmpl	$6, %ebx
	jbe	.L349
	leaq	1(%r10,%rcx), %rax
	leaq	1(%r13,%rcx), %rcx
	movl	$79, %ebx
	vmovdqu	10752(%rsp,%rcx,2), %xmm0
	subl	%r12d, %ebx
	vpmullw	576(%rsp,%rax,2), %xmm0, %xmm0
	vpaddw	%xmm1, %xmm0, %xmm0
	vpsrldq	$8, %xmm0, %xmm1
	vpaddw	%xmm1, %xmm0, %xmm0
	vpsrldq	$4, %xmm0, %xmm1
	vpaddw	%xmm1, %xmm0, %xmm0
	vpsrldq	$2, %xmm0, %xmm1
	vpaddw	%xmm1, %xmm0, %xmm0
	vpextrw	$0, %xmm0, %eax
	testb	$7, %bl
	je	.L348
	andl	$-8, %ebx
	addl	%ebx, %edx
.L349:
	movslq	%r10d, %rcx
	movslq	%edx, %r12
	leaq	(%rcx,%rcx,8), %rcx
	leaq	(%rcx,%rcx,8), %rcx
	leaq	(%rcx,%r12), %rbx
	movzwl	10752(%rsp,%rbx,2), %ebx
	imulw	576(%rsp,%r12,2), %bx
	addl	%ebx, %eax
	leal	1(%rdx), %ebx
	cmpl	$79, %edx
	je	.L348
	movslq	%ebx, %rbx
	leaq	(%rcx,%rbx), %r12
	movzwl	576(%rsp,%rbx,2), %ebx
	imulw	10752(%rsp,%r12,2), %bx
	leal	2(%rdx), %r12d
	addl	%ebx, %eax
	cmpl	$78, %edx
	je	.L348
	movslq	%r12d, %r12
	leaq	(%rcx,%r12), %rbx
	movzwl	10752(%rsp,%rbx,2), %ebx
	imulw	576(%rsp,%r12,2), %bx
	addl	%ebx, %eax
	leal	3(%rdx), %ebx
	cmpl	$77, %edx
	je	.L348
	movslq	%ebx, %rbx
	leaq	(%rcx,%rbx), %r12
	movzwl	576(%rsp,%rbx,2), %ebx
	imulw	10752(%rsp,%r12,2), %bx
	leal	4(%rdx), %r12d
	addl	%ebx, %eax
	cmpl	$76, %edx
	je	.L348
	movslq	%r12d, %r12
	leaq	(%rcx,%r12), %rbx
	movzwl	10752(%rsp,%rbx,2), %ebx
	imulw	576(%rsp,%r12,2), %bx
	leal	5(%rdx), %r12d
	addl	%ebx, %eax
	cmpl	$75, %edx
	je	.L348
	movslq	%r12d, %r12
	leaq	(%rcx,%r12), %rbx
	movzwl	10752(%rsp,%rbx,2), %ebx
	imulw	576(%rsp,%r12,2), %bx
	addl	%ebx, %eax
	leal	6(%rdx), %ebx
	cmpl	$74, %edx
	je	.L348
	movslq	%ebx, %rbx
	leaq	(%rcx,%rbx), %rdx
	movzwl	576(%rsp,%rbx,2), %ecx
	imulw	10752(%rsp,%rdx,2), %cx
	addl	%ecx, %eax
.L348:
	xorl	%edx, %edx
	divw	%r15w
	movzwl	%dx, %eax
.L345:
	movzwl	(%r11), %edx
	incq	%r9
	decq	%r10
	subq	$162, %r11
	subq	$2, %rsi
	subq	$164, %r8
	subq	$82, %r13
	addl	$23, %edx
	subl	%eax, %edx
	movl	%edx, %eax
	imulq	%r14, %rax
	shrq	$36, %rax
	imull	$23, %eax, %eax
	subl	%eax, %edx
	movw	%dx, 2(%rsi)
	decl	%edi
	je	.L594
.L351:
	cmpl	$80, %edi
	jne	.L595
	xorl	%eax, %eax
	jmp	.L345
.L371:
	xorl	%ecx, %ecx
	vpxor	%xmm1, %xmm1, %xmm1
	xorl	%eax, %eax
	jmp	.L346
.L594:
	vpcmpeqd	%ymm0, %ymm0, %ymm0
	movq	176(%rsp), %rbx
	xorl	%esi, %esi
	movl	$928, %edx
	vpsrlw	$8, %ymm0, %ymm0
	vpand	608(%rsp), %ymm0, %ymm2
	vpand	576(%rsp), %ymm0, %ymm1
	movq	%rbx, %rdi
	vpackuswb	%ymm2, %ymm1, %ymm1
	vpermq	$216, %ymm1, %ymm1
	vmovdqa	%ymm1, 52960(%rsp)
	vpand	640(%rsp), %ymm0, %ymm1
	vpand	672(%rsp), %ymm0, %ymm0
	vpackuswb	%ymm0, %ymm1, %ymm0
	vpermq	$216, %ymm0, %ymm0
	vmovdqa	%ymm0, 52992(%rsp)
	vpcmpeqd	%xmm0, %xmm0, %xmm0
	vpsrlw	$8, %xmm0, %xmm0
	vpand	704(%rsp), %xmm0, %xmm1
	vpand	720(%rsp), %xmm0, %xmm0
	vpackuswb	%xmm0, %xmm1, %xmm0
	vmovdqa	%xmm0, 53024(%rsp)
	vzeroupper
	call	memset@PLT
	movq	232(%rsp), %rbx
	vmovdqa	.LC17(%rip), %ymm13
	movq	%rax, 160(%rsp)
	leaq	134560(%rbx), %r12
	leaq	1760(%rsp), %rbx
	movq	%rbx, 176(%rsp)
	movq	%rax, %rbx
.L352:
	movzwl	584(%rsp), %esi
	movzwl	588(%rsp), %r15d
	addq	$32, %rbx
	addq	$160, %r12
	vmovdqu	-160(%r12), %ymm2
	movzwl	576(%rsp), %r9d
	vmovd	%esi, %xmm0
	vmovd	%r15d, %xmm1
	movzwl	580(%rsp), %r14d
	movzwl	600(%rsp), %ecx
	vpinsrw	$1, 590(%rsp), %xmm1, %xmm1
	vpinsrw	$1, 586(%rsp), %xmm0, %xmm0
	vpshufb	.LC15(%rip), %ymm2, %ymm3
	vpshufb	.LC14(%rip), %ymm2, %ymm4
	movzwl	604(%rsp), %r13d
	movzwl	624(%rsp), %r10d
	vpunpckldq	%xmm1, %xmm0, %xmm0
	movzwl	592(%rsp), %r8d
	movzwl	596(%rsp), %r11d
	vpunpcklqdq	%xmm0, %xmm0, %xmm0
	movzwl	628(%rsp), %eax
	movzwl	608(%rsp), %edi
	movw	%r10w, 184(%rsp)
	vperm2i128	$0, %ymm0, %ymm0, %ymm1
	vmovd	%r9d, %xmm0
	movzwl	632(%rsp), %r10d
	movzwl	616(%rsp), %edx
	vpmullw	%ymm3, %ymm1, %ymm1
	vmovd	%r14d, %xmm3
	vpinsrw	$1, 578(%rsp), %xmm0, %xmm0
	movw	%ax, 216(%rsp)
	vpinsrw	$1, 582(%rsp), %xmm3, %xmm3
	movzwl	636(%rsp), %eax
	movw	%r10w, 192(%rsp)
	movzwl	612(%rsp), %r10d
	vpunpckldq	%xmm3, %xmm0, %xmm0
	vmovd	%r13d, %xmm3
	vpunpcklqdq	%xmm0, %xmm0, %xmm0
	vpinsrw	$1, 606(%rsp), %xmm3, %xmm3
	movw	%r10w, 208(%rsp)
	vinserti128	$1, %xmm0, %ymm0, %ymm0
	movzwl	620(%rsp), %r10d
	vpmullw	%ymm4, %ymm0, %ymm0
	vpshufb	%ymm13, %ymm2, %ymm4
	vpshufb	.LC16(%rip), %ymm2, %ymm2
	vpaddw	%ymm0, %ymm1, %ymm1
	vmovd	%ecx, %xmm0
	vpinsrw	$1, 602(%rsp), %xmm0, %xmm0
	vpaddw	-32(%rbx), %ymm1, %ymm1
	vpunpckldq	%xmm3, %xmm0, %xmm0
	vpunpcklqdq	%xmm0, %xmm0, %xmm0
	vperm2i128	$0, %ymm0, %ymm0, %ymm3
	vmovd	%r8d, %xmm0
	vpmullw	%ymm4, %ymm3, %ymm3
	vmovd	%r11d, %xmm4
	vpinsrw	$1, 594(%rsp), %xmm0, %xmm0
	vpinsrw	$1, 598(%rsp), %xmm4, %xmm4
	vpunpckldq	%xmm4, %xmm0, %xmm0
	vpunpcklqdq	%xmm0, %xmm0, %xmm0
	vinserti128	$1, %xmm0, %ymm0, %ymm0
	vpmullw	%ymm2, %ymm0, %ymm0
	vmovdqu	-128(%r12), %ymm2
	vpshufb	.LC15(%rip), %ymm2, %ymm4
	vpshufb	.LC14(%rip), %ymm2, %ymm5
	vpaddw	%ymm0, %ymm3, %ymm3
	vmovd	%edx, %xmm0
	vpaddw	%ymm3, %ymm1, %ymm3
	vmovd	%r10d, %xmm1
	vpinsrw	$1, 618(%rsp), %xmm0, %xmm0
	vpinsrw	$1, 622(%rsp), %xmm1, %xmm1
	vpunpckldq	%xmm1, %xmm0, %xmm0
	vpunpcklqdq	%xmm0, %xmm0, %xmm0
	vperm2i128	$0, %ymm0, %ymm0, %ymm1
	vmovd	%edi, %xmm0
	vpinsrw	$1, 610(%rsp), %xmm0, %xmm0
	vpmullw	%ymm4, %ymm1, %ymm1
	vmovd	208(%rsp), %xmm4
	vpinsrw	$1, 614(%rsp), %xmm4, %xmm4
	vpunpckldq	%xmm4, %xmm0, %xmm0
	vpshufb	%ymm13, %ymm2, %ymm4
	vpshufb	.LC16(%rip), %ymm2, %ymm2
	vpunpcklqdq	%xmm0, %xmm0, %xmm0
	vinserti128	$1, %xmm0, %ymm0, %ymm0
	vpmullw	%ymm5, %ymm0, %ymm0
	vpaddw	%ymm0, %ymm1, %ymm1
	vmovd	192(%rsp), %xmm0
	vpinsrw	$1, 634(%rsp), %xmm0, %xmm0
	vpaddw	%ymm3, %ymm1, %ymm1
	vmovd	%eax, %xmm3
	vpinsrw	$1, 638(%rsp), %xmm3, %xmm3
	vpunpckldq	%xmm3, %xmm0, %xmm0
	vmovd	184(%rsp), %xmm3
	vpinsrw	$1, 626(%rsp), %xmm3, %xmm3
	vpunpcklqdq	%xmm0, %xmm0, %xmm0
	vinserti128	$1, %xmm0, %ymm0, %ymm0
	vpmullw	%ymm4, %ymm0, %ymm0
	vmovd	216(%rsp), %xmm4
	vpinsrw	$1, 630(%rsp), %xmm4, %xmm4
	vpunpckldq	%xmm4, %xmm3, %xmm3
	vpunpcklqdq	%xmm3, %xmm3, %xmm3
	vinserti128	$1, %xmm3, %ymm3, %ymm3
	vpmullw	%ymm2, %ymm3, %ymm2
	vpaddw	%ymm2, %ymm0, %ymm0
	vpaddw	%ymm0, %ymm1, %ymm0
	vmovdqa	%ymm0, -32(%rbx)
	movzwl	688(%rsp), %eax
	movzwl	640(%rsp), %esi
	movzwl	644(%rsp), %r15d
	movzwl	648(%rsp), %r9d
	vmovd	%esi, %xmm1
	movzwl	656(%rsp), %ecx
	movzwl	664(%rsp), %r8d
	movw	%ax, 184(%rsp)
	movzwl	696(%rsp), %eax
	vmovd	%r15d, %xmm3
	movzwl	668(%rsp), %r11d
	movzwl	672(%rsp), %edx
	movzwl	680(%rsp), %edi
	movzwl	652(%rsp), %r14d
	movzwl	660(%rsp), %r13d
	movw	%ax, 192(%rsp)
	movzwl	676(%rsp), %r10d
	vpinsrw	$1, 646(%rsp), %xmm3, %xmm3
	vpinsrw	$1, 642(%rsp), %xmm1, %xmm1
	vmovdqu	-96(%r12), %ymm2
	movzwl	684(%rsp), %eax
	vpunpckldq	%xmm3, %xmm1, %xmm1
	vpshufb	.LC14(%rip), %ymm2, %ymm4
	vmovd	%r9d, %xmm3
	vpunpcklqdq	%xmm1, %xmm1, %xmm1
	vpinsrw	$1, 650(%rsp), %xmm3, %xmm3
	vpshufb	.LC15(%rip), %ymm2, %ymm5
	movw	%ax, 208(%rsp)
	vinserti128	$1, %xmm1, %ymm1, %ymm1
	movzwl	692(%rsp), %eax
	vpmullw	%ymm4, %ymm1, %ymm1
	vmovd	%r14d, %xmm4
	vpinsrw	$1, 654(%rsp), %xmm4, %xmm4
	movw	%ax, 216(%rsp)
	movzwl	700(%rsp), %eax
	vpunpckldq	%xmm4, %xmm3, %xmm3
	vpshufb	.LC16(%rip), %ymm2, %ymm4
	vpshufb	%ymm13, %ymm2, %ymm2
	vpunpcklqdq	%xmm3, %xmm3, %xmm3
	vinserti128	$1, %xmm3, %ymm3, %ymm3
	vpmullw	%ymm5, %ymm3, %ymm3
	vpaddw	%ymm3, %ymm1, %ymm1
	vmovd	%r13d, %xmm3
	vpaddw	%ymm0, %ymm1, %ymm1
	vmovd	%ecx, %xmm0
	vpinsrw	$1, 662(%rsp), %xmm3, %xmm3
	vpinsrw	$1, 658(%rsp), %xmm0, %xmm0
	vpunpckldq	%xmm3, %xmm0, %xmm0
	vmovd	%r8d, %xmm3
	vpunpcklqdq	%xmm0, %xmm0, %xmm0
	vpinsrw	$1, 666(%rsp), %xmm3, %xmm3
	vinserti128	$1, %xmm0, %ymm0, %ymm0
	vpmullw	%ymm4, %ymm0, %ymm0
	vmovd	%r11d, %xmm4
	vpinsrw	$1, 670(%rsp), %xmm4, %xmm4
	vpunpckldq	%xmm4, %xmm3, %xmm3
	vpunpcklqdq	%xmm3, %xmm3, %xmm3
	vinserti128	$1, %xmm3, %ymm3, %ymm3
	vpmullw	%ymm2, %ymm3, %ymm2
	vmovd	%r10d, %xmm3
	vpinsrw	$1, 678(%rsp), %xmm3, %xmm3
	vpaddw	%ymm2, %ymm0, %ymm0
	vmovdqu	-64(%r12), %ymm2
	vpaddw	%ymm0, %ymm1, %ymm1
	vmovd	%edx, %xmm0
	vpinsrw	$1, 674(%rsp), %xmm0, %xmm0
	vpshufb	.LC14(%rip), %ymm2, %ymm4
	vpshufb	.LC15(%rip), %ymm2, %ymm5
	vpunpckldq	%xmm3, %xmm0, %xmm0
	vmovd	%edi, %xmm3
	vpunpcklqdq	%xmm0, %xmm0, %xmm0
	vpinsrw	$1, 682(%rsp), %xmm3, %xmm3
	vinserti128	$1, %xmm0, %ymm0, %ymm0
	vpmullw	%ymm4, %ymm0, %ymm0
	vmovd	208(%rsp), %xmm4
	vpinsrw	$1, 686(%rsp), %xmm4, %xmm4
	vpunpckldq	%xmm4, %xmm3, %xmm3
	vpshufb	.LC16(%rip), %ymm2, %ymm4
	vpshufb	%ymm13, %ymm2, %ymm2
	vpunpcklqdq	%xmm3, %xmm3, %xmm3
	vinserti128	$1, %xmm3, %ymm3, %ymm3
	vpmullw	%ymm5, %ymm3, %ymm3
	vpaddw	%ymm3, %ymm0, %ymm0
	vmovd	216(%rsp), %xmm3
	vpinsrw	$1, 694(%rsp), %xmm3, %xmm3
	vpaddw	%ymm1, %ymm0, %ymm1
	vmovd	184(%rsp), %xmm0
	vpinsrw	$1, 690(%rsp), %xmm0, %xmm0
	vpunpckldq	%xmm3, %xmm0, %xmm0
	vmovd	192(%rsp), %xmm3
	vpinsrw	$1, 698(%rsp), %xmm3, %xmm3
	vpunpcklqdq	%xmm0, %xmm0, %xmm0
	vinserti128	$1, %xmm0, %ymm0, %ymm0
	vpmullw	%ymm4, %ymm0, %ymm0
	vmovd	%eax, %xmm4
	vpinsrw	$1, 702(%rsp), %xmm4, %xmm4
	vpunpckldq	%xmm4, %xmm3, %xmm3
	vpunpcklqdq	%xmm3, %xmm3, %xmm3
	vinserti128	$1, %xmm3, %ymm3, %ymm3
	vpmullw	%ymm2, %ymm3, %ymm2
	vpaddw	%ymm2, %ymm0, %ymm0
	vpaddw	%ymm0, %ymm1, %ymm0
	vmovdqa	%ymm0, -32(%rbx)
	movzwl	712(%rsp), %ecx
	movzwl	716(%rsp), %r11d
	vmovdqu	-32(%r12), %ymm2
	movzwl	704(%rsp), %edi
	vmovd	%ecx, %xmm1
	vmovd	%r11d, %xmm3
	movzwl	708(%rsp), %r10d
	movzwl	728(%rsp), %edx
	vpinsrw	$1, 718(%rsp), %xmm3, %xmm3
	vpinsrw	$1, 714(%rsp), %xmm1, %xmm1
	vpshufb	.LC15(%rip), %ymm2, %ymm4
	vpshufb	.LC14(%rip), %ymm2, %ymm5
	movzwl	732(%rsp), %r9d
	movzwl	720(%rsp), %esi
	vpunpckldq	%xmm3, %xmm1, %xmm1
	vmovd	%edi, %xmm3
	movzwl	724(%rsp), %r8d
	vpunpcklqdq	%xmm1, %xmm1, %xmm1
	vpinsrw	$1, 706(%rsp), %xmm3, %xmm3
	vinserti128	$1, %xmm1, %ymm1, %ymm1
	vpmullw	%ymm4, %ymm1, %ymm1
	vmovd	%r10d, %xmm4
	vpinsrw	$1, 710(%rsp), %xmm4, %xmm4
	vpunpckldq	%xmm4, %xmm3, %xmm3
	vpshufb	%ymm13, %ymm2, %ymm4
	vpshufb	.LC16(%rip), %ymm2, %ymm2
	vpunpcklqdq	%xmm3, %xmm3, %xmm3
	vinserti128	$1, %xmm3, %ymm3, %ymm3
	vpmullw	%ymm5, %ymm3, %ymm3
	vpaddw	%ymm3, %ymm1, %ymm1
	vmovd	%r9d, %xmm3
	vpaddw	%ymm0, %ymm1, %ymm1
	vmovd	%edx, %xmm0
	vpinsrw	$1, 734(%rsp), %xmm3, %xmm3
	vpinsrw	$1, 730(%rsp), %xmm0, %xmm0
	vpunpckldq	%xmm3, %xmm0, %xmm0
	vmovd	%esi, %xmm3
	vpunpcklqdq	%xmm0, %xmm0, %xmm0
	vpinsrw	$1, 722(%rsp), %xmm3, %xmm3
	vinserti128	$1, %xmm0, %ymm0, %ymm0
	vpmullw	%ymm4, %ymm0, %ymm0
	vmovd	%r8d, %xmm4
	vpinsrw	$1, 726(%rsp), %xmm4, %xmm4
	vpunpckldq	%xmm4, %xmm3, %xmm3
	vpunpcklqdq	%xmm3, %xmm3, %xmm3
	vinserti128	$1, %xmm3, %ymm3, %ymm3
	vpmullw	%ymm2, %ymm3, %ymm2
	vpaddw	%ymm2, %ymm0, %ymm0
	vpaddw	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, -32(%rbx)
	cmpq	%rbx, 176(%rsp)
	jne	.L352
	movl	$1680696365, %ecx
	vpcmpeqd	%ymm4, %ymm4, %ymm4
	movq	160(%rsp), %rax
	leaq	52576(%rsp), %rdx
	vmovd	%ecx, %xmm7
	vpsrlw	$8, %ymm4, %ymm4
	vpxor	%xmm5, %xmm5, %xmm5
	movl	$1507351, %ecx
	vmovd	%ecx, %xmm6
	movl	$-1307163959, %ecx
	vpbroadcastd	%xmm7, %ymm7
	vmovd	%ecx, %xmm3
	vpbroadcastd	%xmm6, %ymm6
	vpbroadcastd	%xmm3, %ymm3
.L353:
	vmovdqa	(%rax), %ymm2
	vmovdqa	32(%rax), %ymm1
	addq	$32, %rdx
	addq	$64, %rax
	vmovdqa	-32(%rdx), %ymm10
	vpmulhuw	%ymm7, %ymm2, %ymm11
	vpmulhuw	%ymm7, %ymm1, %ymm9
	vpmovzxbw	%xmm10, %ymm8
	vpsubw	%ymm11, %ymm2, %ymm0
	vpaddw	%ymm6, %ymm2, %ymm2
	vpsrlw	$1, %ymm0, %ymm0
	vpaddw	%ymm11, %ymm0, %ymm0
	vpsrlw	$4, %ymm0, %ymm0
	vpsllw	$1, %ymm0, %ymm11
	vpaddw	%ymm0, %ymm11, %ymm11
	vpsllw	$3, %ymm11, %ymm11
	vpsubw	%ymm0, %ymm11, %ymm0
	vpsubw	%ymm0, %ymm8, %ymm8
	vextracti128	$0x1, %ymm10, %xmm0
	vpaddw	%ymm2, %ymm8, %ymm8
	vpmovzxbw	%xmm0, %ymm2
	vpsubw	%ymm9, %ymm1, %ymm0
	vpsrlw	$1, %ymm0, %ymm0
	vpaddw	%ymm6, %ymm1, %ymm1
	vpaddw	%ymm9, %ymm0, %ymm0
	vpsrlw	$4, %ymm0, %ymm0
	vpsllw	$1, %ymm0, %ymm9
	vpaddw	%ymm0, %ymm9, %ymm9
	vpsllw	$3, %ymm9, %ymm9
	vpsubw	%ymm0, %ymm9, %ymm0
	vpmovzxwd	%xmm8, %ymm9
	vpmuldq	%ymm3, %ymm9, %ymm10
	vpsubw	%ymm0, %ymm2, %ymm0
	vpsrlq	$32, %ymm9, %ymm2
	vpaddw	%ymm1, %ymm0, %ymm0
	vextracti128	$0x1, %ymm8, %xmm1
	vpmuldq	%ymm3, %ymm2, %ymm2
	vpmovzxwd	%xmm1, %ymm1
	vpmovzxwd	%xmm0, %ymm8
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxwd	%xmm0, %ymm0
	vpshufd	$245, %ymm10, %ymm10
	vpblendd	$85, %ymm10, %ymm2, %ymm2
	vpaddd	%ymm9, %ymm2, %ymm2
	vpsrad	$4, %ymm2, %ymm2
	vpslld	$1, %ymm2, %ymm10
	vpaddd	%ymm2, %ymm10, %ymm10
	vpslld	$3, %ymm10, %ymm10
	vpsubd	%ymm2, %ymm10, %ymm2
	vpmuldq	%ymm3, %ymm1, %ymm10
	vpsubd	%ymm2, %ymm9, %ymm2
	vpsrlq	$32, %ymm1, %ymm9
	vpmuldq	%ymm3, %ymm9, %ymm9
	vpblendw	$85, %ymm2, %ymm5, %ymm2
	vpshufd	$245, %ymm10, %ymm10
	vpblendd	$85, %ymm10, %ymm9, %ymm9
	vpaddd	%ymm1, %ymm9, %ymm9
	vpsrad	$4, %ymm9, %ymm9
	vpslld	$1, %ymm9, %ymm10
	vpaddd	%ymm9, %ymm10, %ymm10
	vpslld	$3, %ymm10, %ymm10
	vpsubd	%ymm9, %ymm10, %ymm9
	vpsubd	%ymm9, %ymm1, %ymm1
	vpmuldq	%ymm3, %ymm8, %ymm9
	vpblendw	$85, %ymm1, %ymm5, %ymm1
	vpackusdw	%ymm1, %ymm2, %ymm1
	vpsrlq	$32, %ymm8, %ymm2
	vpmuldq	%ymm3, %ymm2, %ymm2
	vpermq	$216, %ymm1, %ymm1
	vpand	%ymm1, %ymm4, %ymm1
	vpshufd	$245, %ymm9, %ymm9
	vpblendd	$85, %ymm9, %ymm2, %ymm2
	vpaddd	%ymm8, %ymm2, %ymm2
	vpsrad	$4, %ymm2, %ymm2
	vpslld	$1, %ymm2, %ymm9
	vpaddd	%ymm2, %ymm9, %ymm9
	vpslld	$3, %ymm9, %ymm9
	vpsubd	%ymm2, %ymm9, %ymm2
	vpmuldq	%ymm3, %ymm0, %ymm9
	vpsubd	%ymm2, %ymm8, %ymm8
	vpsrlq	$32, %ymm0, %ymm2
	vpmuldq	%ymm3, %ymm2, %ymm2
	vpshufd	$245, %ymm9, %ymm9
	vpblendd	$85, %ymm9, %ymm2, %ymm2
	vpaddd	%ymm0, %ymm2, %ymm2
	vpsrad	$4, %ymm2, %ymm2
	vpslld	$1, %ymm2, %ymm9
	vpaddd	%ymm2, %ymm9, %ymm9
	vpslld	$3, %ymm9, %ymm9
	vpsubd	%ymm2, %ymm9, %ymm2
	vpsubd	%ymm2, %ymm0, %ymm2
	vpblendw	$85, %ymm8, %ymm5, %ymm0
	vpblendw	$85, %ymm2, %ymm5, %ymm2
	vpackusdw	%ymm2, %ymm0, %ymm0
	vpermq	$216, %ymm0, %ymm0
	vpand	%ymm0, %ymm4, %ymm0
	vpackuswb	%ymm0, %ymm1, %ymm0
	vpermq	$216, %ymm0, %ymm0
	vmovdqa	%ymm0, -32(%rdx)
	cmpq	128(%rsp), %rdx
	jne	.L353
	leaq	52577(%rsp), %rax
	leaq	53041(%rsp), %rsi
	xorl	%ecx, %ecx
.L354:
	movzbl	5(%rax), %ebx
	cmpb	%bl, 8(%rax)
	movzbl	2(%rax), %ebx
	sete	%dl
	cmpb	%bl, 11(%rax)
	movzbl	6(%rax), %ebx
	sete	%dil
	andl	%edi, %edx
	cmpb	%bl, 12(%rax)
	movzbl	10(%rax), %ebx
	sete	%dil
	andl	%edi, %edx
	cmpb	%bl, 13(%rax)
	movzbl	1(%rax), %ebx
	sete	%dil
	andl	%edi, %edx
	cmpb	%bl, 7(%rax)
	movzbl	(%rax), %ebx
	sete	%dil
	cmpb	%bl, 3(%rax)
	sete	%r8b
	addq	$16, %rax
	andl	%r8d, %edi
	andl	%edi, %edx
	movzbl	%dl, %edx
	addl	%edx, %ecx
	cmpq	%rsi, %rax
	jne	.L354
	testl	%ecx, %ecx
	jg	.L344
	movq	112(%rsp), %rbx
	movq	24(%rsp), %r14
	xorl	%r8d, %r8d
	xorl	%edi, %edi
	movl	$23, %esi
	jmp	.L355
.L360:
	movq	%rdx, %rax
	shrq	$24, %rdx
	shrq	$16, %rax
	movb	%dl, 3(%rbx,%r8)
	movb	%al, 2(%rbx,%r8)
	addq	$4, %r8
	cmpq	$464, %rcx
	je	.L359
	movq	%rcx, %rdi
.L355:
	movzbl	52576(%rsp,%rdi), %eax
	leaq	1(%rdi), %rcx
	divb	%sil
	movzbl	%ah, %edx
	movzbl	%dl, %edx
	cmpq	$463, %rdi
	je	.L357
.L362:
	movzbl	52576(%rsp,%rcx), %eax
	leaq	2(%rdi), %rcx
	divb	%sil
	movzbl	%ah, %eax
	movzbl	%al, %eax
	imulq	$23, %rax, %rax
	addq	%rax, %rdx
	cmpq	$462, %rdi
	je	.L357
	movzbl	52576(%rsp,%rcx), %eax
	leaq	3(%rdi), %rcx
	divb	%sil
	movzbl	%ah, %eax
	movzbl	%al, %eax
	imulq	$529, %rax, %rax
	addq	%rax, %rdx
	cmpq	$461, %rdi
	je	.L357
	movzbl	52576(%rsp,%rcx), %eax
	leaq	4(%rdi), %rcx
	divb	%sil
	movzbl	%ah, %eax
	movzbl	%al, %eax
	imulq	$12167, %rax, %rax
	addq	%rax, %rdx
	cmpq	$460, %rdi
	je	.L357
	movzbl	52576(%rsp,%rcx), %eax
	leaq	5(%rdi), %rcx
	divb	%sil
	movzbl	%ah, %eax
	movzbl	%al, %eax
	imulq	$279841, %rax, %rax
	addq	%rax, %rdx
	cmpq	$459, %rdi
	je	.L357
	movzbl	52576(%rsp,%rcx), %eax
	leaq	6(%rdi), %rcx
	divb	%sil
	movzbl	%ah, %eax
	movzbl	%al, %eax
	imulq	$6436343, %rax, %rax
	addq	%rax, %rdx
	cmpq	$458, %rdi
	je	.L357
	movzbl	52576(%rsp,%rcx), %eax
	leaq	7(%rdi), %rcx
	divb	%sil
	movzbl	%ah, %eax
	movzbl	%al, %eax
	imulq	$148035889, %rax, %rax
	addq	%rax, %rdx
.L357:
	cmpq	$266, %r8
	je	.L359
	movq	%r8, %rax
	movb	%dl, (%rbx,%r8)
	movb	%dh, 1(%rbx,%rax)
	cmpq	$264, %r8
	jne	.L360
	cmpq	$464, %rcx
	je	.L359
	cmpq	$463, %rcx
	je	.L359
	movzbl	52576(%rsp,%rcx), %eax
	movq	%rcx, %rdi
	movl	$266, %r8d
	incq	%rcx
	divb	%sil
	movzbl	%ah, %edx
	movzbl	%dl, %edx
	jmp	.L362
.L359:
	vmovdqu	(%r14), %xmm0
	vmovdqu	%xmm0, 266(%rbx)
	jmp	.L271
.L587:
	vzeroupper
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE18:
	.size	_snova_24_5_23_4_SNOVA_OPT_sign, .-_snova_24_5_23_4_SNOVA_OPT_sign
	.p2align 4
	.globl	_snova_24_5_23_4_SNOVA_OPT_pk_expand
	.type	_snova_24_5_23_4_SNOVA_OPT_pk_expand, @function
_snova_24_5_23_4_SNOVA_OPT_pk_expand:
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
	pushq	%r12
	pushq	%rbx
	andq	$-32, %rsp
	subq	$101536, %rsp
	.cfi_offset 15, -24
	.cfi_offset 14, -32
	.cfi_offset 13, -40
	.cfi_offset 12, -48
	.cfi_offset 3, -56
	movq	%rdi, 176(%rsp)
	movq	%fs:40, %rbx
	movq	%rbx, 101528(%rsp)
	movq	%rsi, %rbx
	vmovdqu	(%rbx), %xmm0
	movq	%rbx, %rsi
	vmovdqu	%xmm0, 138560(%rdi)
	leaq	400(%rsp), %rdi
	call	snova_pk_expander_init@PLT
	leaq	400(%rsp), %rdx
	movl	$47200, %esi
	leaq	7104(%rsp), %rdi
	call	snova_pk_expander@PLT
	movl	$2139062143, %esi
	leaq	54304(%rsp), %rcx
	vmovdqa	.LC7(%rip), %xmm6
	vmovd	%esi, %xmm5
	movl	$252645135, %esi
	leaq	7104(%rsp), %rax
	movq	%rcx, %rdx
	vmovd	%esi, %xmm4
	movl	$-117901064, %esi
	vpbroadcastd	%xmm5, %ymm5
	movq	%rcx, %rdi
	vmovd	%esi, %xmm3
	vpbroadcastd	%xmm4, %ymm4
	vpbroadcastd	%xmm3, %ymm3
.L597:
	vmovdqa	(%rax), %ymm2
	vpmovzxbw	%xmm6, %ymm7
	addq	$32, %rax
	addq	$32, %rcx
	vextracti128	$0x1, %ymm2, %xmm0
	vpmovzxbw	%xmm2, %ymm1
	vpmovzxbw	%xmm0, %ymm0
	vpmullw	%ymm7, %ymm1, %ymm1
	vpmullw	%ymm7, %ymm0, %ymm0
	vpsrlw	$8, %ymm1, %ymm1
	vpsrlw	$8, %ymm0, %ymm0
	vpackuswb	%ymm0, %ymm1, %ymm1
	vpermq	$216, %ymm1, %ymm1
	vpsubb	%ymm1, %ymm2, %ymm0
	vpsrlw	$1, %ymm0, %ymm0
	vpand	%ymm0, %ymm5, %ymm0
	vpaddb	%ymm1, %ymm0, %ymm0
	vpsrlw	$4, %ymm0, %ymm0
	vpand	%ymm0, %ymm4, %ymm0
	vpaddb	%ymm0, %ymm0, %ymm1
	vpaddb	%ymm0, %ymm1, %ymm1
	vpsllw	$3, %ymm1, %ymm1
	vpand	%ymm1, %ymm3, %ymm1
	vpsubb	%ymm0, %ymm1, %ymm0
	vpsubb	%ymm0, %ymm2, %ymm2
	vmovdqa	%ymm2, -32(%rcx)
	cmpq	%rdi, %rax
	jne	.L597
	movq	176(%rsp), %rax
	movq	%rbx, 232(%rsp)
	movq	%rdx, %rsi
	xorl	%r13d, %r13d
	leaq	900(%rax), %rdi
	leaq	896(%rax), %r12
	movq	%rdi, 392(%rsp)
	leaq	902(%rax), %rdi
	leaq	898(%rax), %r15
	movq	%rdi, 384(%rsp)
	leaq	904(%rax), %rdi
	leaq	12(%rax), %r14
	movq	%rdi, 376(%rsp)
	leaq	906(%rax), %rdi
	movq	%rdi, 368(%rsp)
	leaq	908(%rax), %rdi
	movq	%rdi, 360(%rsp)
	leaq	910(%rax), %rdi
	movq	%rdi, 352(%rsp)
	leaq	912(%rax), %rdi
	movq	%rdi, 344(%rsp)
	leaq	914(%rax), %rdi
	movq	%rdi, 336(%rsp)
	leaq	916(%rax), %rdi
	movq	%rdi, 328(%rsp)
	leaq	918(%rax), %rdi
	movq	%rdi, 320(%rsp)
	leaq	920(%rax), %rdi
	movq	%rdi, 312(%rsp)
	leaq	922(%rax), %rdi
	movq	%rdi, 304(%rsp)
	leaq	924(%rax), %rdi
	movq	%rdi, 296(%rsp)
	leaq	926(%rax), %rdi
	movq	%rdi, 288(%rsp)
	leaq	30(%rax), %rdi
	movq	%rdi, 280(%rsp)
	leaq	20(%rax), %rdi
	movq	%rdi, 272(%rsp)
	leaq	22(%rax), %rdi
	movq	%rdi, 264(%rsp)
	leaq	10(%rax), %rdi
	movq	%rdi, 256(%rsp)
.L606:
	leaq	-882(%r12), %rax
	movq	%r13, 224(%rsp)
	leaq	-896(%r12), %rcx
	xorl	%edi, %edi
	imulq	$29, %r13, %rbx
	movq	%rax, 240(%rsp)
	leaq	-128(%r12), %r11
	xorl	%edx, %edx
	movq	%r12, 248(%rsp)
	xorl	%r10d, %r10d
	jmp	.L599
.L771:
	vmovdqu	10(%rsi), %ymm0
	movl	$23, %r9d
	subl	%r10d, %r9d
	vpmovzxbw	%xmm0, %ymm1
	movl	%r9d, %r8d
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	shrl	%r8d
	vmovdqu	%ymm1, 32(%rcx)
	vmovdqu	%ymm0, 64(%rcx)
	cmpl	$1, %r8d
	je	.L602
	vmovdqu	32(%rax), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 96(%rcx)
	vmovdqu	%ymm0, 128(%rcx)
	cmpl	$2, %r8d
	je	.L602
	vmovdqu	64(%rax), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 160(%rcx)
	vmovdqu	%ymm0, 192(%rcx)
	cmpl	$3, %r8d
	je	.L602
	vmovdqu	96(%rax), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 224(%rcx)
	vmovdqu	%ymm0, 256(%rcx)
	cmpl	$4, %r8d
	je	.L602
	vmovdqu	128(%rax), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 288(%rcx)
	vmovdqu	%ymm0, 320(%rcx)
	cmpl	$5, %r8d
	je	.L602
	vmovdqu	160(%rax), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 352(%rcx)
	vmovdqu	%ymm0, 384(%rcx)
	cmpl	$6, %r8d
	je	.L602
	vmovdqu	192(%rax), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 416(%rcx)
	vmovdqu	%ymm0, 448(%rcx)
	cmpl	$7, %r8d
	je	.L602
	vmovdqu	224(%rax), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 480(%rcx)
	vmovdqu	%ymm0, 512(%rcx)
	cmpl	$8, %r8d
	je	.L602
	vmovdqu	256(%rax), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 544(%rcx)
	vmovdqu	%ymm0, 576(%rcx)
	cmpl	$9, %r8d
	je	.L602
	vmovdqu	288(%rax), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 608(%rcx)
	vmovdqu	%ymm0, 640(%rcx)
	cmpl	$11, %r8d
	jne	.L602
	vmovdqu	320(%rax), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, 672(%rcx)
	vmovdqu	%ymm0, 704(%rcx)
.L602:
	testb	$1, %r9b
	je	.L604
	andl	$-2, %r9d
.L601:
	movl	%r9d, %r8d
	leaq	1(%r8,%rbx), %r9
	salq	$4, %r8
	vmovdqu	(%rax,%r8), %xmm0
	salq	$5, %r9
	addq	176(%rsp), %r9
	vpmovzxbw	%xmm0, %xmm1
	vpsrldq	$8, %xmm0, %xmm0
	vpmovzxbw	%xmm0, %xmm0
	vmovdqu	%xmm1, (%r9)
	vmovdqu	%xmm0, 16(%r9)
.L604:
	movl	$22, %eax
	subl	%r13d, %eax
	salq	$4, %rax
	leaq	26(%rsi,%rax), %rax
.L603:
	vmovdqu	(%rax), %ymm0
	movzbl	64(%rax), %esi
	incq	%r10
	addq	$960, %rcx
	movq	248(%rsp), %r9
	movq	360(%rsp), %r8
	addq	$928, %r11
	addq	$30, %rbx
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	addq	$960, %rdi
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, -928(%r11)
	vmovdqu	%ymm0, -896(%r11)
	vmovdqu	32(%rax), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, -864(%r11)
	vmovdqu	%ymm0, -832(%r11)
	movw	%si, (%r9,%rdx)
	movzbl	65(%rax), %esi
	movq	392(%rsp), %r9
	movw	%si, (%r15,%rdx)
	movzbl	66(%rax), %esi
	movw	%si, (%r9,%rdx)
	movzbl	67(%rax), %esi
	movq	384(%rsp), %r9
	movw	%si, (%r9,%rdx)
	movzbl	68(%rax), %esi
	movq	376(%rsp), %r9
	movw	%si, (%r9,%rdx)
	movzbl	69(%rax), %esi
	movq	368(%rsp), %r9
	movw	%si, (%r9,%rdx)
	movzbl	70(%rax), %esi
	movq	352(%rsp), %r9
	movw	%si, (%r8,%rdx)
	movzbl	71(%rax), %esi
	movq	344(%rsp), %r8
	movw	%si, (%r9,%rdx)
	movzbl	72(%rax), %esi
	movw	%si, (%r8,%rdx)
	movzbl	73(%rax), %esi
	movq	336(%rsp), %r9
	movq	328(%rsp), %r8
	movw	%si, (%r9,%rdx)
	movzbl	74(%rax), %esi
	movq	320(%rsp), %r9
	movw	%si, (%r8,%rdx)
	movzbl	75(%rax), %esi
	movq	312(%rsp), %r8
	movw	%si, (%r9,%rdx)
	movzbl	76(%rax), %esi
	movq	304(%rsp), %r9
	movw	%si, (%r8,%rdx)
	movzbl	77(%rax), %esi
	movq	296(%rsp), %r8
	movw	%si, (%r9,%rdx)
	movzbl	78(%rax), %esi
	movq	288(%rsp), %r9
	movw	%si, (%r8,%rdx)
	movzbl	79(%rax), %esi
	movw	%si, (%r9,%rdx)
	leaq	80(%rax), %rsi
	addq	$928, %rdx
	cmpq	$24, %r10
	je	.L770
.L599:
	vmovd	(%rsi), %xmm0
	movzbl	4(%rsi), %eax
	movl	%r10d, %r13d
	movq	256(%rsp), %r8
	movq	240(%rsp), %r9
	vpmovzxbw	%xmm0, %xmm1
	vpsrld	$16, %xmm0, %xmm0
	vpmovzxbw	%xmm0, %xmm0
	vmovd	%xmm1, (%rcx)
	vmovd	%xmm0, 4(%rcx)
	movw	%ax, (%r8,%rdi)
	movzbl	5(%rsi), %eax
	movq	272(%rsp), %r8
	movw	%ax, (%r14,%rdi)
	movzbl	6(%rsi), %eax
	movw	%ax, (%r9,%rdi)
	movzbl	7(%rsi), %eax
	movq	264(%rsp), %r9
	movw	%ax, (%r8,%rdi)
	movzbl	8(%rsi), %eax
	movq	280(%rsp), %r8
	movw	%ax, (%r9,%rdi)
	movzbl	9(%rsi), %eax
	movw	%ax, (%r8,%rdi)
	leaq	10(%rsi), %rax
	cmpl	$23, %r10d
	je	.L603
	cmpq	$22, %r10
	jne	.L771
	xorl	%r9d, %r9d
	jmp	.L601
.L770:
	movq	224(%rsp), %r13
	movq	248(%rsp), %r12
	addq	$26912, %r15
	addq	$26912, %r14
	addq	$26912, 392(%rsp)
	addq	$29, %r13
	addq	$26912, 384(%rsp)
	addq	$26912, %r12
	addq	$26912, 376(%rsp)
	addq	$26912, 368(%rsp)
	addq	$26912, 360(%rsp)
	addq	$26912, 352(%rsp)
	addq	$26912, 344(%rsp)
	addq	$26912, 336(%rsp)
	addq	$26912, 328(%rsp)
	addq	$26912, 320(%rsp)
	addq	$26912, 312(%rsp)
	addq	$26912, 304(%rsp)
	addq	$26912, 296(%rsp)
	addq	$26912, 288(%rsp)
	addq	$26912, 280(%rsp)
	addq	$26912, 272(%rsp)
	addq	$26912, 264(%rsp)
	addq	$26912, 256(%rsp)
	cmpq	$145, %r13
	jne	.L606
	leaq	3104(%rsp), %r12
	movl	$4000, %edx
	movq	232(%rsp), %rbx
	vzeroupper
	movq	%r12, %rdi
	xorl	%r15d, %r15d
	call	memcpy@PLT
	movl	$1050, %edx
	xorl	%esi, %esi
	leaq	2048(%rsp), %rdi
	call	memset@PLT
	xorl	%r9d, %r9d
	xorl	%ecx, %ecx
	movabsq	$7218291159277650633, %r10
	movq	%rax, %r8
	cmpq	$599, %r9
	ja	.L655
.L772:
	movzbl	17(%rbx,%r9), %edx
	movzbl	16(%rbx,%r9), %eax
	leaq	4(%r9), %r11
	movzbl	19(%rbx,%r9), %esi
	salq	$8, %rdx
	xorq	%rax, %rdx
	movzbl	18(%rbx,%r9), %eax
	salq	$24, %rsi
	salq	$16, %rax
	xorq	%rdx, %rax
	xorq	%rax, %rsi
.L607:
	movq	%rsi, %rax
	mulq	%r10
	movq	%rsi, %rax
	subq	%rdx, %rax
	shrq	%rax
	leaq	(%rdx,%rax), %rdi
	shrq	$4, %rdi
	imulq	$23, %rdi, %rax
	subq	%rax, %rsi
	movb	%sil, 2048(%rsp,%rcx)
	cmpq	$1049, %rcx
	je	.L769
	movq	%rdi, %rax
	mulq	%r10
	movq	%rdi, %rax
	subq	%rdx, %rax
	shrq	%rax
	addq	%rax, %rdx
	shrq	$4, %rdx
	imulq	$23, %rdx, %rax
	movq	%rdx, %rsi
	subq	%rax, %rdi
	movb	%dil, 2049(%rsp,%rcx)
	cmpq	$1048, %rcx
	je	.L768
	movq	%rdx, %rax
	mulq	%r10
	movq	%rsi, %rax
	subq	%rdx, %rax
	shrq	%rax
	leaq	(%rdx,%rax), %rdi
	shrq	$4, %rdi
	imulq	$23, %rdi, %rax
	subq	%rax, %rsi
	movb	%sil, 2050(%rsp,%rcx)
	cmpq	$1047, %rcx
	je	.L769
	movq	%rdi, %rax
	mulq	%r10
	movq	%rdi, %rax
	subq	%rdx, %rax
	shrq	%rax
	addq	%rax, %rdx
	shrq	$4, %rdx
	imulq	$23, %rdx, %rax
	movq	%rdx, %rsi
	subq	%rax, %rdi
	movb	%dil, 2051(%rsp,%rcx)
	cmpq	$1046, %rcx
	je	.L768
	movq	%rdx, %rax
	mulq	%r10
	movq	%rsi, %rax
	subq	%rdx, %rax
	shrq	%rax
	leaq	(%rdx,%rax), %rdi
	shrq	$4, %rdi
	imulq	$23, %rdi, %rax
	subq	%rax, %rsi
	movb	%sil, 2052(%rsp,%rcx)
	cmpq	$1045, %rcx
	je	.L769
	movq	%rdi, %rax
	mulq	%r10
	movq	%rdi, %rax
	subq	%rdx, %rax
	shrq	%rax
	addq	%rax, %rdx
	shrq	$4, %rdx
	imulq	$23, %rdx, %rax
	movq	%rdx, %rsi
	subq	%rax, %rdi
	movb	%dil, 2053(%rsp,%rcx)
	cmpq	$1044, %rcx
	je	.L768
	movq	%rdx, %rax
	mulq	%r10
	movq	%rsi, %rax
	subq	%rdx, %rax
	shrq	%rax
	addq	%rdx, %rax
	shrq	$4, %rax
	imulq	$23, %rax, %rdx
	orl	%eax, %r15d
	subq	%rdx, %rsi
	movb	%sil, 2054(%rsp,%rcx)
	addq	$7, %rcx
	cmpq	$1050, %rcx
	je	.L609
	cmpq	$599, %r9
	ja	.L617
	movq	%r11, %r9
	cmpq	$599, %r9
	jbe	.L772
.L655:
	movq	%r9, %r11
	xorl	%esi, %esi
	jmp	.L607
.L617:
	movb	$0, 2048(%rsp,%rcx)
	cmpq	$1049, %rcx
	je	.L609
	movb	$0, 2049(%rsp,%rcx)
	cmpq	$1048, %rcx
	je	.L609
	movb	$0, 2050(%rsp,%rcx)
	cmpq	$1047, %rcx
	je	.L609
	movb	$0, 2051(%rsp,%rcx)
	cmpq	$1046, %rcx
	je	.L609
	movb	$0, 2052(%rsp,%rcx)
	cmpq	$1045, %rcx
	je	.L609
	movb	$0, 2053(%rsp,%rcx)
	cmpq	$1044, %rcx
	je	.L609
	movb	$0, 2054(%rsp,%rcx)
	addq	$7, %rcx
	cmpq	$1050, %rcx
	jne	.L617
	jmp	.L609
	.p2align 4,,10
	.p2align 3
.L768:
	orl	%esi, %r15d
.L609:
	testl	%r15d, %r15d
	jne	.L657
	movq	176(%rsp), %rbx
	movl	%r15d, 336(%rsp)
	movq	%r8, %r14
	xorl	%edx, %edx
	xorl	%edi, %edi
	movl	$2880, %eax
	leaq	23040(%rbx), %r8
	movq	%rbx, %r15
.L619:
	movl	%eax, 368(%rsp)
	leaq	(%r8,%rdx), %r10
	movl	$-1, %r11d
	movl	$24, %ebx
	movl	$3, 360(%rsp)
	movq	$16, 352(%rsp)
	movq	%rdi, 328(%rsp)
	movq	%rax, 320(%rsp)
	movq	%rdx, 312(%rsp)
	movq	%r12, 304(%rsp)
	movq	%r8, %r12
.L631:
	movl	360(%rsp), %ecx
	leal	1(%rbx), %eax
	movq	%r10, 296(%rsp)
	leaq	32(%r10), %rdx
	movl	%eax, 392(%rsp)
	movl	368(%rsp), %eax
	movq	%r10, %r8
	leaq	4(,%rcx,4), %rcx
	movq	%rcx, 384(%rsp)
	movq	352(%rsp), %rcx
	leal	0(,%rax,4), %edi
	movl	$3, %eax
	leal	64(%rdi), %r9d
	movl	%eax, %r10d
	leaq	-24(,%rcx,8), %rsi
	incq	%rcx
	movq	%rsi, 376(%rsp)
	movq	%rcx, 344(%rsp)
	cmpl	$2, %eax
	jbe	.L628
.L774:
	vmovd	(%r14), %xmm0
	leal	1(%rax), %ecx
	vpmovzxbw	%xmm0, %xmm1
	vpsrld	$16, %xmm0, %xmm0
	vpmovzxbw	%xmm0, %xmm0
	vmovd	%xmm1, (%r8)
	vmovd	%xmm0, 4(%r8)
	testb	$3, %cl
	je	.L621
	andl	$-4, %ecx
	movl	%ecx, %esi
	leal	(%rdi,%rcx), %r10d
	leal	1(%rcx,%rdi), %ecx
	addq	%r14, %rsi
	movslq	%r10d, %r10
	movslq	%ecx, %rcx
	movzbl	(%rsi), %r13d
	addq	$2, %rsi
	movw	%r13w, (%r15,%r10,2)
	movzbl	-1(%rsi), %r10d
	movw	%r10w, (%r15,%rcx,2)
.L620:
	movzbl	(%rsi), %esi
	leal	3(%rdi), %ecx
	movslq	%ecx, %rcx
	movw	%si, (%r15,%rcx,2)
.L621:
	leaq	(%r14,%rax), %rcx
	cmpl	$29, 392(%rsp)
	leaq	1(%rcx), %r14
	je	.L622
	cmpl	$2, %r11d
	jbe	.L623
	movq	376(%rsp), %rsi
	addq	%rdx, %rsi
	cmpq	%rsi, %r14
	jnb	.L660
	movq	344(%rsp), %rsi
	addq	%rcx, %rsi
	cmpq	%rsi, %rdx
	jb	.L623
.L660:
	vmovdqu	1(%rcx), %xmm0
	vpmovzxbw	%xmm0, %xmm1
	vpsrldq	$8, %xmm0, %xmm0
	vpmovzxbw	%xmm0, %xmm0
	vmovq	%xmm1, (%rdx)
	vpextrq	$1, %xmm1, 32(%rdx)
	vmovq	%xmm0, 64(%rdx)
	vpextrq	$1, %xmm0, 96(%rdx)
.L627:
	movq	384(%rsp), %rsi
	leaq	1(%rcx,%rsi), %r14
	subq	$1, %rax
	jb	.L773
.L625:
	addl	$4, %edi
	addq	$10, %r8
	addq	$8, %rdx
	addl	$4, %r9d
	movl	%eax, %r10d
	cmpl	$2, %eax
	ja	.L774
.L628:
	movl	$3, %ecx
	movzbl	(%r14), %esi
	subl	%eax, %ecx
	addl	%edi, %ecx
	movslq	%ecx, %rcx
	movw	%si, (%r15,%rcx,2)
	movl	$4, %ecx
	subl	%eax, %ecx
	cmpl	$4, %ecx
	je	.L621
	movzbl	1(%r14), %esi
	addl	%edi, %ecx
	movslq	%ecx, %rcx
	movw	%si, (%r15,%rcx,2)
	cmpl	$1, %r10d
	je	.L621
	leaq	2(%r14), %rsi
	jmp	.L620
	.p2align 4,,10
	.p2align 3
.L773:
	movq	296(%rsp), %r10
	decl	360(%rsp)
	incl	%r11d
	addl	$120, 368(%rsp)
	movl	392(%rsp), %ebx
	subq	$4, 352(%rsp)
	addq	$960, %r10
	jmp	.L631
.L622:
	subq	$1, %rax
	jnb	.L625
	movq	328(%rsp), %rdi
	movq	320(%rsp), %rax
	movq	%r12, %r8
	movq	312(%rsp), %rdx
	movq	304(%rsp), %r12
	addq	$29, %rdi
	addq	$3364, %rax
	addq	$26912, %rdx
	cmpq	$145, %rdi
	jne	.L619
	movq	176(%rsp), %rdi
	movl	336(%rsp), %r15d
	xorl	%r8d, %r8d
	movl	$928, %edx
	vmovdqa	.LC41(%rip), %ymm3
	vmovdqa	.LC42(%rip), %ymm2
	xorl	%r9d, %r9d
	leaq	8(%rdi), %rax
	leaq	2(%rdi), %rsi
	movq	%rax, 168(%rsp)
	leaq	4(%rdi), %rax
	movq	%rax, 160(%rsp)
	leaq	16(%rdi), %rax
	movq	%rax, 152(%rsp)
	leaq	6(%rdi), %rax
	movq	%rax, 144(%rsp)
	leaq	24(%rdi), %rax
	movq	%rax, 136(%rsp)
.L639:
	leaq	25088(%rdx), %rax
	movq	%rdx, 344(%rsp)
	movl	%r9d, %ebx
	xorl	%r11d, %r11d
	movq	%rax, 376(%rsp)
	leaq	-2(%rsi), %rax
	movl	$29, %r10d
	movq	%rax, 192(%rsp)
	leaq	10(%rsi), %rax
	movq	%rax, 120(%rsp)
	leaq	16(%rsi), %rax
	movq	%rax, 104(%rsp)
	leaq	12(%rsi), %rax
	movq	%rax, 112(%rsp)
	leaq	24(%rsi), %rax
	movq	%rax, 88(%rsp)
	leaq	20(%rsi), %rax
	movq	%rax, 96(%rsp)
	leaq	26(%rsi), %rax
	movq	%rdx, 184(%rsp)
	movq	%rax, 80(%rsp)
	movl	%r9d, 44(%rsp)
	movq	%rdx, 32(%rsp)
	movq	%rsi, 128(%rsp)
	movq	%r8, 24(%rsp)
	movl	%r15d, 40(%rsp)
	movq	%r12, 16(%rsp)
.L637:
	movq	128(%rsp), %rax
	movq	168(%rsp), %rdx
	movzwl	(%rax,%r11), %eax
	movw	%ax, (%rdx,%r11)
	movq	160(%rsp), %rax
	movq	152(%rsp), %rdx
	movzwl	(%rax,%r11), %eax
	movw	%ax, (%rdx,%r11)
	movq	144(%rsp), %rax
	movq	136(%rsp), %rdx
	movzwl	(%rax,%r11), %eax
	movw	%ax, (%rdx,%r11)
	movq	120(%rsp), %rax
	movq	104(%rsp), %rdx
	movzwl	(%rax,%r11), %eax
	movw	%ax, (%rdx,%r11)
	movq	112(%rsp), %rax
	movq	88(%rsp), %rdx
	movzwl	(%rax,%r11), %eax
	movw	%ax, (%rdx,%r11)
	movq	96(%rsp), %rax
	movq	80(%rsp), %rdx
	movzwl	(%rax,%r11), %eax
	movw	%ax, (%rdx,%r11)
	decl	%r10d
	je	.L775
	movq	344(%rsp), %rdx
	leaq	-896(%rdx), %rax
	cmpq	376(%rsp), %rax
	jge	.L661
	cmpq	%rdx, 184(%rsp)
	jg	.L632
.L661:
	movq	192(%rsp), %rax
	leaq	32(%rax), %rcx
	leaq	928(%rax), %rdx
	xorl	%eax, %eax
	.p2align 6
	.p2align 4,,10
	.p2align 3
.L634:
	vmovdqu	(%rcx), %ymm0
	incl	%eax
	addq	$928, %rdx
	addq	$32, %rcx
	vpshufb	%ymm3, %ymm0, %ymm1
	vpshufb	%ymm2, %ymm0, %ymm0
	vpermq	$78, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vmovdqu	%ymm0, -928(%rdx)
	cmpl	%r10d, %eax
	jb	.L634
.L635:
	addq	$928, 184(%rsp)
	addl	$480, %ebx
	addq	$960, %r11
	addq	$960, 344(%rsp)
	addq	$32, 376(%rsp)
	addq	$960, 192(%rsp)
	jmp	.L637
.L623:
	vmovd	1(%rcx), %xmm0
	leal	-48(%r9), %esi
	movslq	%esi, %rsi
	vpmovzxbw	%xmm0, %xmm0
	vmovq	%xmm0, (%r15,%rsi,2)
	cmpl	$27, %ebx
	je	.L627
	vmovd	5(%rcx), %xmm0
	leal	-32(%r9), %esi
	movslq	%esi, %rsi
	vpmovzxbw	%xmm0, %xmm0
	vmovq	%xmm0, (%r15,%rsi,2)
	cmpl	$26, %ebx
	je	.L627
	vmovd	9(%rcx), %xmm0
	leal	-16(%r9), %esi
	movslq	%esi, %rsi
	vpmovzxbw	%xmm0, %xmm0
	vmovq	%xmm0, (%r15,%rsi,2)
	cmpl	$25, %ebx
	je	.L627
	vmovd	13(%rcx), %xmm0
	movslq	%r9d, %rsi
	vpmovzxbw	%xmm0, %xmm0
	vmovq	%xmm0, (%r15,%rsi,2)
	jmp	.L627
.L769:
	orl	%edi, %r15d
	jmp	.L609
.L632:
	movl	%r10d, %eax
	movq	%r11, (%rsp)
	salq	$5, %rax
	movl	%r10d, 8(%rsp)
	movq	%rax, 240(%rsp)
	leal	16(%rbx), %eax
	cltq
	movl	%ebx, 12(%rsp)
	leaq	(%rdi,%rax,2), %r15
	leal	464(%rbx), %eax
	cltq
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 288(%rsp)
	leal	17(%rbx), %eax
	cltq
	leaq	(%rdi,%rax,2), %r14
	leal	468(%rbx), %eax
	cltq
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 392(%rsp)
	leal	18(%rbx), %eax
	cltq
	leaq	(%rdi,%rax,2), %r13
	leal	472(%rbx), %eax
	cltq
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 368(%rsp)
	leal	19(%rbx), %eax
	cltq
	leaq	(%rdi,%rax,2), %r12
	leal	476(%rbx), %eax
	cltq
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 224(%rsp)
	leal	20(%rbx), %eax
	cltq
	leaq	(%rdi,%rax,2), %r9
	leal	465(%rbx), %eax
	cltq
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 360(%rsp)
	leal	21(%rbx), %eax
	cltq
	leaq	(%rdi,%rax,2), %r8
	leal	469(%rbx), %eax
	cltq
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 216(%rsp)
	leal	22(%rbx), %eax
	cltq
	leaq	(%rdi,%rax,2), %rsi
	leal	473(%rbx), %eax
	cltq
	movq	%rsi, 200(%rsp)
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 336(%rsp)
	leal	23(%rbx), %eax
	cltq
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 296(%rsp)
	leal	477(%rbx), %eax
	cltq
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 352(%rsp)
	leal	24(%rbx), %eax
	cltq
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 280(%rsp)
	leal	466(%rbx), %eax
	cltq
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 304(%rsp)
	leal	25(%rbx), %eax
	cltq
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 48(%rsp)
	leal	470(%rbx), %eax
	cltq
	leaq	(%rdi,%rax,2), %rdx
	leal	26(%rbx), %eax
	cltq
	movq	%rdx, 232(%rsp)
	leaq	(%rdi,%rax,2), %rdx
	leal	474(%rbx), %eax
	cltq
	movq	%rdx, 72(%rsp)
	leaq	(%rdi,%rax,2), %rcx
	leal	27(%rbx), %eax
	cltq
	movq	%rcx, 256(%rsp)
	leaq	(%rdi,%rax,2), %rcx
	leal	478(%rbx), %eax
	cltq
	movq	%rcx, 64(%rsp)
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 312(%rsp)
	leal	28(%rbx), %eax
	cltq
	movq	64(%rsp), %r10
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 264(%rsp)
	leal	467(%rbx), %eax
	cltq
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 248(%rsp)
	leal	29(%rbx), %eax
	cltq
	leaq	(%rdi,%rax,2), %rax
	movq	%rax, 56(%rsp)
	leal	471(%rbx), %eax
	cltq
	leaq	(%rdi,%rax,2), %rdx
	leal	30(%rbx), %eax
	cltq
	movq	%rdx, 328(%rsp)
	movq	56(%rsp), %r11
	leaq	(%rdi,%rax,2), %rdx
	leal	475(%rbx), %eax
	cltq
	movq	%rdx, 320(%rsp)
	leaq	(%rdi,%rax,2), %rdx
	leal	31(%rbx), %eax
	cltq
	movq	%rdx, 272(%rsp)
	leaq	(%rdi,%rax,2), %rcx
	leal	479(%rbx), %eax
	cltq
	movq	%rcx, 208(%rsp)
	leaq	(%rdi,%rax,2), %rdx
	xorl	%eax, %eax
	movq	%rdx, 384(%rsp)
	movq	48(%rsp), %rbx
	xorl	%edx, %edx
	movq	%rdi, 64(%rsp)
	movq	72(%rsp), %rdi
.L636:
	movzwl	(%r15,%rax), %esi
	movq	288(%rsp), %rcx
	movw	%si, (%rcx,%rdx)
	movq	392(%rsp), %rcx
	movzwl	(%r14,%rax), %esi
	movw	%si, (%rcx,%rdx)
	movq	368(%rsp), %rcx
	movzwl	0(%r13,%rax), %esi
	movw	%si, (%rcx,%rdx)
	movq	224(%rsp), %rcx
	movzwl	(%r12,%rax), %esi
	movw	%si, (%rcx,%rdx)
	movq	360(%rsp), %rcx
	movzwl	(%r9,%rax), %esi
	movw	%si, (%rcx,%rdx)
	movq	216(%rsp), %rcx
	movzwl	(%r8,%rax), %esi
	movw	%si, (%rcx,%rdx)
	movq	200(%rsp), %rsi
	movq	336(%rsp), %rcx
	movzwl	(%rsi,%rax), %esi
	movw	%si, (%rcx,%rdx)
	movq	296(%rsp), %rcx
	movq	352(%rsp), %rsi
	movzwl	(%rcx,%rax), %ecx
	movw	%cx, (%rsi,%rdx)
	movq	280(%rsp), %rcx
	movzwl	(%rcx,%rax), %esi
	movq	304(%rsp), %rcx
	movw	%si, (%rcx,%rdx)
	movq	232(%rsp), %rcx
	movzwl	(%rbx,%rax), %esi
	movw	%si, (%rcx,%rdx)
	movzwl	(%rdi,%rax), %esi
	movq	256(%rsp), %rcx
	movw	%si, (%rcx,%rdx)
	movq	312(%rsp), %rcx
	movzwl	(%r10,%rax), %esi
	movw	%si, (%rcx,%rdx)
	movq	264(%rsp), %rcx
	movq	248(%rsp), %rsi
	movzwl	(%rcx,%rax), %ecx
	movw	%cx, (%rsi,%rdx)
	movq	328(%rsp), %rsi
	movzwl	(%r11,%rax), %ecx
	movw	%cx, (%rsi,%rdx)
	movq	320(%rsp), %rsi
	movq	272(%rsp), %rcx
	movzwl	(%rsi,%rax), %esi
	movw	%si, (%rcx,%rdx)
	movq	208(%rsp), %rsi
	movq	384(%rsp), %rcx
	movzwl	(%rsi,%rax), %esi
	addq	$32, %rax
	movw	%si, (%rcx,%rdx)
	addq	$928, %rdx
	cmpq	240(%rsp), %rax
	jne	.L636
	movl	12(%rsp), %ebx
	movq	(%rsp), %r11
	movl	8(%rsp), %r10d
	movq	64(%rsp), %rdi
	jmp	.L635
.L775:
	movq	24(%rsp), %r8
	movl	44(%rsp), %r9d
	movq	32(%rsp), %rdx
	movq	128(%rsp), %rsi
	addq	$29, %r8
	addq	$26912, 168(%rsp)
	movl	40(%rsp), %r15d
	addl	$13456, %r9d
	addq	$26912, 160(%rsp)
	movq	16(%rsp), %r12
	addq	$26912, %rdx
	addq	$26912, %rsi
	addq	$26912, 152(%rsp)
	addq	$26912, 144(%rsp)
	addq	$26912, 136(%rsp)
	cmpq	$145, %r8
	jne	.L639
	movq	176(%rsp), %rax
	movl	%r15d, 368(%rsp)
	leaq	_snova_24_5_23_4_SNOVA_OPT_Smat(%rip), %rbx
	movl	$2987803337, %r13d
	leaq	134560(%rax), %r14
	leaq	6304(%rsp), %rax
	movq	%rax, 384(%rsp)
	leaq	4704(%rsp), %rax
	movq	%rax, 376(%rsp)
.L649:
	movzbl	(%r12), %eax
	movq	%r14, %rdi
	movb	%al, (%r14)
	movq	1(%r12), %rax
	movq	%rax, 1(%r14)
	movl	9(%r12), %eax
	movl	%eax, 9(%r14)
	movzwl	13(%r12), %eax
	movw	%ax, 13(%r14)
	movzbl	15(%r12), %eax
	movb	%al, 15(%r14)
	call	gf_mat_det
	testb	%al, %al
	jne	.L643
	movl	$1, %r15d
	jmp	.L640
	.p2align 4,,10
	.p2align 3
.L753:
	incl	%r15d
	cmpl	$23, %r15d
	je	.L643
.L640:
	movzwl	32(%rbx), %eax
	movzbl	(%r14), %ecx
	movq	%r14, %rdi
	imull	%r15d, %eax
	addl	%eax, %ecx
	movq	%rcx, %rax
	imulq	%r13, %rcx
	shrq	$36, %rcx
	imull	$23, %ecx, %ecx
	subl	%ecx, %eax
	movzbl	1(%r14), %ecx
	movb	%al, (%r14)
	movzwl	34(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %ecx
	movq	%rcx, %rax
	imulq	%r13, %rcx
	shrq	$36, %rcx
	imull	$23, %ecx, %ecx
	subl	%ecx, %eax
	movzbl	2(%r14), %ecx
	movb	%al, 1(%r14)
	movzwl	36(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %ecx
	movq	%rcx, %rax
	imulq	%r13, %rcx
	shrq	$36, %rcx
	imull	$23, %ecx, %ecx
	subl	%ecx, %eax
	movzbl	3(%r14), %ecx
	movb	%al, 2(%r14)
	movzwl	38(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %ecx
	movq	%rcx, %rax
	imulq	%r13, %rcx
	shrq	$36, %rcx
	imull	$23, %ecx, %ecx
	subl	%ecx, %eax
	movzbl	4(%r14), %ecx
	movb	%al, 3(%r14)
	movzwl	40(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %ecx
	movq	%rcx, %rax
	imulq	%r13, %rcx
	shrq	$36, %rcx
	imull	$23, %ecx, %ecx
	subl	%ecx, %eax
	movzbl	5(%r14), %ecx
	movb	%al, 4(%r14)
	movzwl	42(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %ecx
	movq	%rcx, %rax
	imulq	%r13, %rcx
	shrq	$36, %rcx
	imull	$23, %ecx, %ecx
	subl	%ecx, %eax
	movzbl	6(%r14), %ecx
	movb	%al, 5(%r14)
	movzwl	44(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %ecx
	movq	%rcx, %rax
	imulq	%r13, %rcx
	shrq	$36, %rcx
	imull	$23, %ecx, %ecx
	subl	%ecx, %eax
	movzbl	7(%r14), %ecx
	movb	%al, 6(%r14)
	movzwl	46(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %ecx
	movq	%rcx, %rax
	imulq	%r13, %rcx
	shrq	$36, %rcx
	imull	$23, %ecx, %ecx
	subl	%ecx, %eax
	movzbl	8(%r14), %ecx
	movb	%al, 7(%r14)
	movzwl	48(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %ecx
	movq	%rcx, %rax
	imulq	%r13, %rcx
	shrq	$36, %rcx
	imull	$23, %ecx, %ecx
	subl	%ecx, %eax
	movzbl	9(%r14), %ecx
	movb	%al, 8(%r14)
	movzwl	50(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %ecx
	movq	%rcx, %rax
	imulq	%r13, %rcx
	shrq	$36, %rcx
	imull	$23, %ecx, %ecx
	subl	%ecx, %eax
	movzbl	10(%r14), %ecx
	movb	%al, 9(%r14)
	movzwl	52(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %ecx
	movq	%rcx, %rax
	imulq	%r13, %rcx
	shrq	$36, %rcx
	imull	$23, %ecx, %ecx
	subl	%ecx, %eax
	movb	%al, 10(%r14)
	movzwl	54(%rbx), %eax
	movzbl	11(%r14), %ecx
	imull	%r15d, %eax
	addl	%eax, %ecx
	movq	%rcx, %rax
	imulq	%r13, %rcx
	shrq	$36, %rcx
	imull	$23, %ecx, %ecx
	subl	%ecx, %eax
	movzbl	12(%r14), %ecx
	movb	%al, 11(%r14)
	movzwl	56(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %ecx
	movq	%rcx, %rax
	imulq	%r13, %rcx
	shrq	$36, %rcx
	imull	$23, %ecx, %ecx
	subl	%ecx, %eax
	movzbl	13(%r14), %ecx
	movb	%al, 12(%r14)
	movzwl	58(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %ecx
	movq	%rcx, %rax
	imulq	%r13, %rcx
	shrq	$36, %rcx
	imull	$23, %ecx, %ecx
	subl	%ecx, %eax
	movzbl	14(%r14), %ecx
	movb	%al, 13(%r14)
	movzwl	60(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %ecx
	movq	%rcx, %rax
	imulq	%r13, %rcx
	shrq	$36, %rcx
	imull	$23, %ecx, %ecx
	subl	%ecx, %eax
	movzbl	15(%r14), %ecx
	movb	%al, 14(%r14)
	movzwl	62(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %ecx
	movq	%rcx, %rax
	imulq	%r13, %rcx
	shrq	$36, %rcx
	imull	$23, %ecx, %ecx
	subl	%ecx, %eax
	movb	%al, 15(%r14)
	call	gf_mat_det
	testb	%al, %al
	je	.L753
.L643:
	movzbl	1600(%r12), %eax
	leaq	1600(%r14), %rdi
	movq	%rdi, 392(%rsp)
	movb	%al, 1600(%r14)
	movq	1601(%r12), %rax
	movq	%rax, 1601(%r14)
	movl	1609(%r12), %eax
	movl	%eax, 1609(%r14)
	movzwl	1613(%r12), %eax
	movw	%ax, 1613(%r14)
	movzbl	1615(%r12), %eax
	movb	%al, 1615(%r14)
	call	gf_mat_det
	testb	%al, %al
	jne	.L642
	movl	$1, %r15d
	jmp	.L641
	.p2align 4,,10
	.p2align 3
.L754:
	incl	%r15d
	cmpl	$23, %r15d
	je	.L642
.L641:
	movzwl	32(%rbx), %eax
	movzbl	1600(%r14), %esi
	imull	%r15d, %eax
	addl	%eax, %esi
	movq	%rsi, %rax
	imulq	%r13, %rsi
	shrq	$36, %rsi
	imull	$23, %esi, %esi
	subl	%esi, %eax
	movzbl	1601(%r14), %esi
	movb	%al, 1600(%r14)
	movzwl	34(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %esi
	movq	%rsi, %rax
	imulq	%r13, %rsi
	shrq	$36, %rsi
	imull	$23, %esi, %esi
	subl	%esi, %eax
	movzbl	1602(%r14), %esi
	movb	%al, 1601(%r14)
	movzwl	36(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %esi
	movq	%rsi, %rax
	imulq	%r13, %rsi
	shrq	$36, %rsi
	imull	$23, %esi, %esi
	subl	%esi, %eax
	movzbl	1603(%r14), %esi
	movb	%al, 1602(%r14)
	movzwl	38(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %esi
	movq	%rsi, %rax
	imulq	%r13, %rsi
	shrq	$36, %rsi
	imull	$23, %esi, %esi
	subl	%esi, %eax
	movzbl	1604(%r14), %esi
	movb	%al, 1603(%r14)
	movzwl	40(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %esi
	movq	%rsi, %rax
	imulq	%r13, %rsi
	shrq	$36, %rsi
	imull	$23, %esi, %esi
	subl	%esi, %eax
	movzbl	1605(%r14), %esi
	movb	%al, 1604(%r14)
	movzwl	42(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %esi
	movq	%rsi, %rax
	imulq	%r13, %rsi
	shrq	$36, %rsi
	imull	$23, %esi, %esi
	subl	%esi, %eax
	movzbl	1606(%r14), %esi
	movb	%al, 1605(%r14)
	movzwl	44(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %esi
	movq	%rsi, %rax
	imulq	%r13, %rsi
	shrq	$36, %rsi
	imull	$23, %esi, %esi
	subl	%esi, %eax
	movzbl	1607(%r14), %esi
	movb	%al, 1606(%r14)
	movzwl	46(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %esi
	movq	%rsi, %rax
	imulq	%r13, %rsi
	shrq	$36, %rsi
	imull	$23, %esi, %esi
	subl	%esi, %eax
	movzbl	1608(%r14), %esi
	movb	%al, 1607(%r14)
	movzwl	48(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %esi
	movq	%rsi, %rax
	imulq	%r13, %rsi
	shrq	$36, %rsi
	imull	$23, %esi, %esi
	subl	%esi, %eax
	movzbl	1609(%r14), %esi
	movb	%al, 1608(%r14)
	movzwl	50(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %esi
	movq	%rsi, %rax
	imulq	%r13, %rsi
	shrq	$36, %rsi
	imull	$23, %esi, %esi
	subl	%esi, %eax
	movzbl	1610(%r14), %esi
	movb	%al, 1609(%r14)
	movzwl	52(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %esi
	movq	%rsi, %rax
	imulq	%r13, %rsi
	shrq	$36, %rsi
	imull	$23, %esi, %esi
	subl	%esi, %eax
	movb	%al, 1610(%r14)
	movzwl	54(%rbx), %eax
	movzbl	1611(%r14), %esi
	movq	392(%rsp), %rdi
	imull	%r15d, %eax
	addl	%eax, %esi
	movq	%rsi, %rax
	imulq	%r13, %rsi
	shrq	$36, %rsi
	imull	$23, %esi, %esi
	subl	%esi, %eax
	movzbl	1612(%r14), %esi
	movb	%al, 1611(%r14)
	movzwl	56(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %esi
	movq	%rsi, %rax
	imulq	%r13, %rsi
	shrq	$36, %rsi
	imull	$23, %esi, %esi
	subl	%esi, %eax
	movzbl	1613(%r14), %esi
	movb	%al, 1612(%r14)
	movzwl	58(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %esi
	movq	%rsi, %rax
	imulq	%r13, %rsi
	shrq	$36, %rsi
	imull	$23, %esi, %esi
	subl	%esi, %eax
	movzbl	1614(%r14), %esi
	movb	%al, 1613(%r14)
	movzwl	60(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %esi
	movq	%rsi, %rax
	imulq	%r13, %rsi
	shrq	$36, %rsi
	imull	$23, %esi, %esi
	subl	%esi, %eax
	movzbl	1615(%r14), %esi
	movb	%al, 1614(%r14)
	movzwl	62(%rbx), %eax
	imull	%r15d, %eax
	addl	%eax, %esi
	movq	%rsi, %rax
	imulq	%r13, %rsi
	shrq	$36, %rsi
	imull	$23, %esi, %esi
	subl	%esi, %eax
	movb	%al, 1615(%r14)
	call	gf_mat_det
	testb	%al, %al
	je	.L754
.L642:
	movq	384(%rsp), %rax
	cmpb	$0, 3(%rax)
	movq	%rax, %rdi
	jne	.L646
	movzbl	(%rax), %ecx
	movl	$23, %eax
	subl	%ecx, %eax
	cmpb	$1, %cl
	sbbb	$0, %al
	movb	%al, 3(%rdi)
.L646:
	cmpb	$0, 403(%rdi)
	jne	.L648
	movzbl	400(%rdi), %ecx
	movl	$23, %eax
	subl	%ecx, %eax
	cmpb	$1, %cl
	sbbb	$0, %al
	movb	%al, 403(%rdi)
.L648:
	addq	$16, %r12
	addq	$4, 384(%rsp)
	addq	$16, %r14
	cmpq	%r12, 376(%rsp)
	jne	.L649
	movq	176(%rsp), %rax
	vmovdqa	6304(%rsp), %ymm0
	movl	368(%rsp), %r15d
	vmovdqu	%ymm0, 137760(%rax)
	vmovdqa	6336(%rsp), %ymm0
	vmovdqu	%ymm0, 137792(%rax)
	vmovdqa	6368(%rsp), %ymm0
	vmovdqu	%ymm0, 137824(%rax)
	vmovdqa	6400(%rsp), %ymm0
	vmovdqu	%ymm0, 137856(%rax)
	vmovdqa	6432(%rsp), %ymm0
	vmovdqu	%ymm0, 137888(%rax)
	vmovdqa	6464(%rsp), %ymm0
	vmovdqu	%ymm0, 137920(%rax)
	vmovdqa	6496(%rsp), %ymm0
	vmovdqu	%ymm0, 137952(%rax)
	vmovdqa	6528(%rsp), %ymm0
	vmovdqu	%ymm0, 137984(%rax)
	vmovdqa	6560(%rsp), %ymm0
	vmovdqu	%ymm0, 138016(%rax)
	vmovdqa	6592(%rsp), %ymm0
	vmovdqu	%ymm0, 138048(%rax)
	vmovdqa	6624(%rsp), %ymm0
	vmovdqu	%ymm0, 138080(%rax)
	vmovdqa	6656(%rsp), %ymm0
	vmovdqu	%ymm0, 138112(%rax)
	vmovdqa	6688(%rsp), %xmm0
	vmovdqu	%xmm0, 138144(%rax)
	vmovdqu	6704(%rsp), %ymm0
	vmovdqu	%ymm0, 138160(%rax)
	vmovdqu	6736(%rsp), %ymm0
	vmovdqu	%ymm0, 138192(%rax)
	vmovdqu	6768(%rsp), %ymm0
	vmovdqu	%ymm0, 138224(%rax)
	vmovdqu	6800(%rsp), %ymm0
	vmovdqu	%ymm0, 138256(%rax)
	vmovdqu	6832(%rsp), %ymm0
	vmovdqu	%ymm0, 138288(%rax)
	vmovdqu	6864(%rsp), %ymm0
	vmovdqu	%ymm0, 138320(%rax)
	vmovdqu	6896(%rsp), %ymm0
	vmovdqu	%ymm0, 138352(%rax)
	vmovdqu	6928(%rsp), %ymm0
	vmovdqu	%ymm0, 138384(%rax)
	vmovdqu	6960(%rsp), %ymm0
	vmovdqu	%ymm0, 138416(%rax)
	vmovdqu	6992(%rsp), %ymm0
	vmovdqu	%ymm0, 138448(%rax)
	vmovdqu	7024(%rsp), %ymm0
	vmovdqu	%ymm0, 138480(%rax)
	vmovdqu	7056(%rsp), %ymm0
	vmovdqu	%ymm0, 138512(%rax)
	vmovdqa	7088(%rsp), %xmm0
	vmovdqu	%xmm0, 138544(%rax)
	vzeroupper
.L596:
	movq	101528(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L776
	leaq	-40(%rbp), %rsp
	movl	%r15d, %eax
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	.cfi_remember_state
	.cfi_def_cfa 7, 8
	ret
.L657:
	.cfi_restore_state
	movl	$-1, %r15d
	jmp	.L596
.L776:
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE19:
	.size	_snova_24_5_23_4_SNOVA_OPT_pk_expand, .-_snova_24_5_23_4_SNOVA_OPT_pk_expand
	.p2align 4
	.globl	_snova_24_5_23_4_SNOVA_OPT_verify
	.type	_snova_24_5_23_4_SNOVA_OPT_verify, @function
_snova_24_5_23_4_SNOVA_OPT_verify:
.LFB20:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	xorl	%r8d, %r8d
	movabsq	$7218291159277650633, %r9
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
	.cfi_offset 12, -48
	movq	%rsi, %r12
	pushq	%rbx
	andq	$-64, %rsp
	subq	$10880, %rsp
	.cfi_offset 3, -56
	movq	%rcx, 56(%rsp)
	xorl	%ecx, %ecx
	movq	%rdx, 64(%rsp)
	movq	%fs:40, %rbx
	movq	%rbx, 10872(%rsp)
	xorl	%ebx, %ebx
	cmpq	$265, %r8
	ja	.L814
.L915:
	movzbl	1(%r12,%r8), %esi
	movzbl	(%r12,%r8), %eax
	leaq	2(%r8), %r10
	salq	$8, %rsi
	xorq	%rax, %rsi
	cmpq	$264, %r8
	je	.L778
	movzbl	2(%r12,%r8), %eax
	leaq	4(%r8), %r10
	salq	$16, %rax
	xorq	%rsi, %rax
	movzbl	3(%r12,%r8), %esi
	salq	$24, %rsi
	xorq	%rax, %rsi
.L778:
	movq	%rsi, %rax
	mulq	%r9
	movq	%rsi, %rax
	subq	%rdx, %rax
	shrq	%rax
	addq	%rdx, %rax
	shrq	$4, %rax
	movq	%rax, %rdi
	imulq	$23, %rax, %rax
	subq	%rax, %rsi
	movq	%rdi, %rax
	mulq	%r9
	movq	%rdi, %rax
	movb	%sil, 7200(%rsp,%rcx)
	subq	%rdx, %rax
	shrq	%rax
	addq	%rax, %rdx
	movq	%rdi, %rax
	shrq	$4, %rdx
	movq	%rdx, %r11
	imulq	$23, %rdx, %rdx
	subq	%rdx, %rax
	movb	%al, 7201(%rsp,%rcx)
	cmpq	$462, %rcx
	je	.L914
	movq	%r11, %rax
	mulq	%r9
	movq	%r11, %rax
	subq	%rdx, %rax
	shrq	%rax
	leaq	(%rdx,%rax), %rsi
	shrq	$4, %rsi
	imulq	$23, %rsi, %rax
	subq	%rax, %r11
	movb	%r11b, 7202(%rsp,%rcx)
	cmpq	$461, %rcx
	je	.L912
	movq	%rsi, %rax
	mulq	%r9
	movq	%rsi, %rax
	subq	%rdx, %rax
	shrq	%rax
	leaq	(%rdx,%rax), %rdi
	shrq	$4, %rdi
	imulq	$23, %rdi, %rax
	subq	%rax, %rsi
	movb	%sil, 7203(%rsp,%rcx)
	cmpq	$460, %rcx
	je	.L913
	movq	%rdi, %rax
	mulq	%r9
	movq	%rdi, %rax
	subq	%rdx, %rax
	shrq	%rax
	leaq	(%rdx,%rax), %rsi
	shrq	$4, %rsi
	imulq	$23, %rsi, %rax
	subq	%rax, %rdi
	movb	%dil, 7204(%rsp,%rcx)
	cmpq	$459, %rcx
	je	.L912
	movq	%rsi, %rax
	mulq	%r9
	movq	%rsi, %rax
	subq	%rdx, %rax
	shrq	%rax
	leaq	(%rdx,%rax), %rdi
	shrq	$4, %rdi
	imulq	$23, %rdi, %rax
	subq	%rax, %rsi
	movb	%sil, 7205(%rsp,%rcx)
	cmpq	$458, %rcx
	je	.L913
	movq	%rdi, %rax
	mulq	%r9
	movq	%rdi, %rax
	subq	%rdx, %rax
	shrq	%rax
	addq	%rdx, %rax
	shrq	$4, %rax
	imulq	$23, %rax, %rdx
	orl	%eax, %ebx
	subq	%rdx, %rdi
	movb	%dil, 7206(%rsp,%rcx)
	addq	$7, %rcx
	cmpq	$464, %rcx
	je	.L780
	cmpq	$265, %r8
	ja	.L787
	movq	%r10, %r8
	cmpq	$265, %r8
	jbe	.L915
.L814:
	movq	%r8, %r10
	xorl	%esi, %esi
	jmp	.L778
.L787:
	movb	$0, 7200(%rsp,%rcx)
	cmpq	$463, %rcx
	je	.L780
	movb	$0, 7201(%rsp,%rcx)
	cmpq	$462, %rcx
	je	.L780
	movb	$0, 7202(%rsp,%rcx)
	cmpq	$461, %rcx
	je	.L780
	movb	$0, 7203(%rsp,%rcx)
	cmpq	$460, %rcx
	je	.L780
	movb	$0, 7204(%rsp,%rcx)
	cmpq	$459, %rcx
	je	.L780
	movb	$0, 7205(%rsp,%rcx)
	cmpq	$458, %rcx
	je	.L780
	movb	$0, 7206(%rsp,%rcx)
	addq	$7, %rcx
	cmpq	$464, %rcx
	jne	.L787
.L780:
	testl	%ebx, %ebx
	jne	.L791
	leaq	134560(%r13), %rax
	leaq	7664(%rsp), %rdi
	movl	$1600, %edx
	movq	%rax, %rsi
	movq	%rdi, 72(%rsp)
	movq	%rax, 88(%rsp)
	call	memcpy@PLT
	leaq	9264(%rsp), %rax
	leaq	136160(%r13), %rsi
	movl	$1600, %edx
	movq	%rax, %rdi
	movq	%rax, 80(%rsp)
	call	memcpy@PLT
	leaq	7201(%rsp), %rax
	leaq	7665(%rsp), %rsi
	xorl	%ecx, %ecx
.L790:
	movzbl	5(%rax), %edi
	movzbl	(%rax), %r11d
	cmpb	%dil, 8(%rax)
	movzbl	2(%rax), %edi
	sete	%dl
	cmpb	%dil, 11(%rax)
	sete	%dil
	andl	%edi, %edx
	movzbl	6(%rax), %edi
	cmpb	%dil, 12(%rax)
	sete	%dil
	andl	%edi, %edx
	movzbl	13(%rax), %edi
	cmpb	%dil, 10(%rax)
	sete	%dil
	andl	%edi, %edx
	movzbl	1(%rax), %edi
	cmpb	%dil, 7(%rax)
	sete	%dil
	cmpb	%r11b, 3(%rax)
	sete	%r8b
	addq	$16, %rax
	andl	%r8d, %edi
	andl	%edi, %edx
	movzbl	%dl, %edx
	addl	%edx, %ecx
	cmpq	%rax, %rsi
	jne	.L790
	testl	%ecx, %ecx
	jg	.L791
	leaq	3328(%rsp), %r14
	xorl	%esi, %esi
	movl	$3712, %edx
	movq	%r14, %rdi
	call	memset@PLT
	leaq	_snova_24_5_23_4_SNOVA_OPT_Smat(%rip), %rdi
	movq	%r14, %rsi
	xorl	%ecx, %ecx
	leaq	7664(%rsp), %r8
.L792:
	vmovdqa	(%rdi), %ymm3
	movq	%rsi, %rdx
	leaq	7200(%rsp), %rax
	vpshufb	.LC14(%rip), %ymm3, %ymm6
	vpshufb	.LC15(%rip), %ymm3, %ymm5
	vpshufb	.LC16(%rip), %ymm3, %ymm4
	vpshufb	.LC17(%rip), %ymm3, %ymm3
.L793:
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
	jne	.L793
	incq	%rcx
	addq	$32, %rsi
	addq	$32, %rdi
	cmpq	$4, %rcx
	jne	.L792
	movl	$1680696365, %edx
	leaq	3712(%r14), %r15
	movq	%r14, %rax
	vmovd	%edx, %xmm3
	vpbroadcastd	%xmm3, %ymm3
.L795:
	vmovdqa	(%rax), %ymm2
	addq	$32, %rax
	vpmulhuw	%ymm3, %ymm2, %ymm1
	vpsubw	%ymm1, %ymm2, %ymm0
	vpsrlw	$1, %ymm0, %ymm0
	vpaddw	%ymm1, %ymm0, %ymm0
	vpsrlw	$4, %ymm0, %ymm0
	vpsllw	$1, %ymm0, %ymm1
	vpaddw	%ymm0, %ymm1, %ymm1
	vpsllw	$3, %ymm1, %ymm1
	vpsubw	%ymm0, %ymm1, %ymm0
	vpsubw	%ymm0, %ymm2, %ymm2
	vmovdqa	%ymm2, -32(%rax)
	cmpq	%rax, %r15
	jne	.L795
	vpxor	%xmm0, %xmm0, %xmm0
	xorl	%esi, %esi
	leaq	768(%rsp), %rdi
	movl	$2560, %edx
	vmovdqa	%ymm0, 384(%rsp)
	vmovdqa	%ymm0, 416(%rsp)
	vmovdqa	%ymm0, 448(%rsp)
	vmovdqa	%ymm0, 480(%rsp)
	vmovdqa	%ymm0, 512(%rsp)
	vzeroupper
	call	memset@PLT
	movl	$1680696365, %edx
	vmovdqa	.LC34(%rip), %ymm13
	movq	%rax, %rdi
	vmovd	%edx, %xmm11
	vmovdqa	.LC47(%rip), %ymm12
	movq	%r13, %r8
	movq	%r13, %rax
	movq	%rdi, %rsi
	vpbroadcastd	%xmm11, %ymm11
.L796:
	movq	%rax, %r10
	movq	%r14, %r9
.L799:
	vpxor	%xmm0, %xmm0, %xmm0
	movq	%r14, %rdx
	movq	%r10, %rcx
	vmovdqa	%ymm0, %ymm1
	vmovdqa	%ymm0, %ymm5
	vmovdqa	%ymm0, %ymm6
.L797:
	vmovdqu	(%rcx), %ymm2
	vpbroadcastq	8(%rdx), %ymm8
	subq	$-128, %rdx
	addq	$32, %rcx
	vpbroadcastq	-128(%rdx), %ymm10
	vpshufb	.LC15(%rip), %ymm2, %ymm7
	vpshufb	.LC14(%rip), %ymm2, %ymm4
	vpshufb	.LC16(%rip), %ymm2, %ymm3
	vpmullw	%ymm8, %ymm7, %ymm8
	vpmullw	%ymm10, %ymm4, %ymm10
	vpshufb	.LC17(%rip), %ymm2, %ymm2
	vpaddw	%ymm10, %ymm8, %ymm9
	vpbroadcastq	-112(%rdx), %ymm8
	vpbroadcastq	-104(%rdx), %ymm10
	vpmullw	%ymm8, %ymm3, %ymm8
	vpmullw	%ymm10, %ymm2, %ymm10
	vpaddw	%ymm10, %ymm8, %ymm8
	vpbroadcastq	-72(%rdx), %ymm10
	vpaddw	%ymm8, %ymm9, %ymm8
	vpaddw	%ymm8, %ymm6, %ymm6
	vpbroadcastq	-80(%rdx), %ymm8
	vpmullw	%ymm10, %ymm2, %ymm10
	vpmullw	%ymm8, %ymm3, %ymm8
	vpaddw	%ymm10, %ymm8, %ymm9
	vpbroadcastq	-88(%rdx), %ymm8
	vpbroadcastq	-96(%rdx), %ymm10
	vpmullw	%ymm8, %ymm7, %ymm8
	vpmullw	%ymm10, %ymm4, %ymm10
	vpaddw	%ymm10, %ymm8, %ymm8
	vpbroadcastq	-64(%rdx), %ymm10
	vpaddw	%ymm8, %ymm9, %ymm8
	vpaddw	%ymm8, %ymm5, %ymm5
	vpbroadcastq	-56(%rdx), %ymm8
	vpmullw	%ymm10, %ymm4, %ymm10
	vpmullw	%ymm8, %ymm7, %ymm8
	vpaddw	%ymm10, %ymm8, %ymm9
	vpbroadcastq	-48(%rdx), %ymm8
	vpbroadcastq	-40(%rdx), %ymm10
	vpmullw	%ymm8, %ymm3, %ymm8
	vpmullw	%ymm10, %ymm2, %ymm10
	vpaddw	%ymm10, %ymm8, %ymm8
	vpaddw	%ymm8, %ymm9, %ymm8
	vpaddw	%ymm8, %ymm1, %ymm1
	vpbroadcastq	-16(%rdx), %ymm8
	vpmullw	%ymm8, %ymm3, %ymm3
	vpbroadcastq	-8(%rdx), %ymm8
	vpmullw	%ymm8, %ymm2, %ymm2
	vpaddw	%ymm2, %ymm3, %ymm2
	vpbroadcastq	-24(%rdx), %ymm3
	vpmullw	%ymm3, %ymm7, %ymm3
	vpbroadcastq	-32(%rdx), %ymm7
	vpmullw	%ymm7, %ymm4, %ymm4
	vpaddw	%ymm4, %ymm3, %ymm3
	vpaddw	%ymm3, %ymm2, %ymm2
	vpaddw	%ymm2, %ymm0, %ymm0
	cmpq	%rdx, %r15
	jne	.L797
	vpmulhuw	%ymm11, %ymm6, %ymm3
	movq	%rsi, %rdx
	movq	%r9, %rcx
	xorl	%r11d, %r11d
	vpsubw	%ymm3, %ymm6, %ymm2
	vpsrlw	$1, %ymm2, %ymm2
	vpaddw	%ymm3, %ymm2, %ymm2
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$1, %ymm2, %ymm3
	vpaddw	%ymm2, %ymm3, %ymm3
	vpsllw	$3, %ymm3, %ymm3
	vpsubw	%ymm2, %ymm3, %ymm2
	vpmulhuw	%ymm11, %ymm5, %ymm3
	vpsubw	%ymm2, %ymm6, %ymm6
	vpsrldq	$8, %xmm6, %xmm4
	vpbroadcastq	%xmm6, %ymm10
	vextracti128	$0x1, %ymm6, %xmm6
	vpbroadcastq	%xmm4, %ymm4
	vpsubw	%ymm3, %ymm5, %ymm2
	vpsrlw	$1, %ymm2, %ymm2
	vpaddw	%ymm3, %ymm2, %ymm2
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$1, %ymm2, %ymm3
	vpaddw	%ymm2, %ymm3, %ymm3
	vpsllw	$3, %ymm3, %ymm3
	vpsubw	%ymm2, %ymm3, %ymm2
	vpmulhuw	%ymm11, %ymm1, %ymm3
	vpsubw	%ymm2, %ymm5, %ymm5
	vpbroadcastq	%xmm5, %ymm9
	vpsubw	%ymm3, %ymm1, %ymm2
	vpsrlw	$1, %ymm2, %ymm2
	vpaddw	%ymm3, %ymm2, %ymm2
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$1, %ymm2, %ymm3
	vpaddw	%ymm2, %ymm3, %ymm3
	vpsllw	$3, %ymm3, %ymm3
	vpsubw	%ymm2, %ymm3, %ymm2
	vpmulhuw	%ymm11, %ymm0, %ymm3
	vpsubw	%ymm2, %ymm1, %ymm1
	vpbroadcastq	%xmm1, %ymm8
	vpsubw	%ymm3, %ymm0, %ymm2
	vpsrlw	$1, %ymm2, %ymm2
	vpaddw	%ymm3, %ymm2, %ymm2
	vpsrlw	$4, %ymm2, %ymm2
	vpsllw	$1, %ymm2, %ymm3
	vpaddw	%ymm2, %ymm3, %ymm3
	vpsllw	$3, %ymm3, %ymm3
	vpsubw	%ymm2, %ymm3, %ymm2
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
	vmovdqa	%ymm15, 224(%rsp)
	vpbroadcastq	%xmm6, %ymm15
	vpsrldq	$8, %xmm6, %xmm6
	vpbroadcastq	%xmm6, %ymm6
	vmovdqa	%ymm15, 256(%rsp)
	vpbroadcastq	%xmm1, %ymm15
	vpsrldq	$8, %xmm1, %xmm1
	vmovdqa	%ymm14, 288(%rsp)
	vpbroadcastq	%xmm0, %ymm14
	vpsrldq	$8, %xmm0, %xmm0
	vmovdqa	%ymm6, 160(%rsp)
	vpbroadcastq	%xmm5, %ymm6
	vpbroadcastq	%xmm1, %ymm5
	vmovdqa	%ymm6, 128(%rsp)
	vpbroadcastq	%xmm0, %ymm6
	vmovdqa	%ymm15, 320(%rsp)
	vmovdqa	%ymm14, 352(%rsp)
	vmovdqa	%ymm5, 96(%rsp)
	vmovdqa	%ymm6, 192(%rsp)
.L798:
	vmovdqa	(%rcx), %ymm0
	addq	$32, %r11
	addq	$32, %rcx
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
	vmovdqa	-32(%rcx), %ymm1
	vperm2i128	$0, %ymm1, %ymm1, %ymm1
	vpshufb	%ymm12, %ymm1, %ymm1
	vpmullw	%ymm1, %ymm4, %ymm14
	vpaddw	%ymm6, %ymm14, %ymm14
	vpmullw	%ymm1, %ymm3, %ymm6
	vmovdqa	%ymm14, -128(%rdx)
	vpaddw	%ymm5, %ymm6, %ymm6
	vpmullw	%ymm1, %ymm2, %ymm5
	vpmullw	224(%rsp), %ymm1, %ymm1
	vpaddw	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm6, -96(%rdx)
	vmovdqa	%ymm1, -32(%rdx)
	vpaddw	%ymm15, %ymm5, %ymm5
	vmovdqa	%ymm5, -64(%rdx)
	vmovdqa	-32(%rcx), %ymm0
	vperm2i128	$17, %ymm0, %ymm0, %ymm0
	vpshufb	%ymm13, %ymm0, %ymm0
	vpmullw	256(%rsp), %ymm0, %ymm15
	vpaddw	%ymm14, %ymm15, %ymm14
	vpmullw	288(%rsp), %ymm0, %ymm15
	vpaddw	%ymm6, %ymm15, %ymm6
	vpmullw	320(%rsp), %ymm0, %ymm15
	vpmullw	352(%rsp), %ymm0, %ymm0
	vpaddw	%ymm5, %ymm15, %ymm5
	vpaddw	%ymm1, %ymm0, %ymm1
	vmovdqa	%ymm14, -128(%rdx)
	vmovdqa	%ymm6, -96(%rdx)
	vmovdqa	%ymm5, -64(%rdx)
	vmovdqa	%ymm1, -32(%rdx)
	vmovdqa	-32(%rcx), %ymm0
	vperm2i128	$17, %ymm0, %ymm0, %ymm0
	vpshufb	%ymm12, %ymm0, %ymm0
	vpmullw	160(%rsp), %ymm0, %ymm15
	vpaddw	%ymm14, %ymm15, %ymm14
	vmovdqa	%ymm14, -128(%rdx)
	vpmullw	128(%rsp), %ymm0, %ymm14
	vpaddw	%ymm6, %ymm14, %ymm6
	vmovdqa	%ymm6, -96(%rdx)
	vpmullw	96(%rsp), %ymm0, %ymm6
	vpmullw	192(%rsp), %ymm0, %ymm0
	vpaddw	%ymm5, %ymm6, %ymm5
	vpaddw	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm5, -64(%rdx)
	vmovdqa	%ymm0, -32(%rdx)
	cmpq	$128, %r11
	jne	.L798
	subq	$-128, %r9
	addq	$928, %r10
	cmpq	%r9, %r15
	jne	.L799
	addq	$26912, %rax
	addq	$512, %rsi
	cmpq	%rax, 88(%rsp)
	jne	.L796
	movl	$1680696365, %edx
	leaq	2560(%rdi), %rcx
	movq	%rdi, %rax
	vmovd	%edx, %xmm3
	vpbroadcastd	%xmm3, %ymm3
.L801:
	vmovdqa	(%rax), %ymm2
	addq	$32, %rax
	vpmulhuw	%ymm3, %ymm2, %ymm1
	vpsubw	%ymm1, %ymm2, %ymm0
	vpsrlw	$1, %ymm0, %ymm0
	vpaddw	%ymm1, %ymm0, %ymm0
	vpsrlw	$4, %ymm0, %ymm0
	vpsllw	$1, %ymm0, %ymm1
	vpaddw	%ymm0, %ymm1, %ymm1
	vpsllw	$3, %ymm1, %ymm1
	vpsubw	%ymm0, %ymm1, %ymm0
	vpsubw	%ymm0, %ymm2, %ymm2
	vmovdqa	%ymm2, -32(%rax)
	cmpq	%rcx, %rax
	jne	.L801
	leaq	512(%rdi), %rdx
	movq	80(%rsp), %r15
	movq	72(%rsp), %rax
	leaq	384(%rsp), %rsi
	movq	%rdx, 256(%rsp)
	movl	$1680696365, %edx
	vmovdqa	.LC48(%rip), %ymm12
	xorl	%ecx, %ecx
	vmovd	%edx, %xmm3
	vmovd	%edx, %xmm7
	vmovdqa	.LC19(%rip), %xmm14
	vmovdqa	.LC20(%rip), %xmm15
	vpbroadcastd	%xmm3, %ymm3
	vpbroadcastd	%xmm7, %xmm13
	movl	%ebx, %r9d
.L802:
	leaq	80(%r8), %rbx
	movl	%ecx, %r14d
	movq	%r8, %rdx
	movq	%rax, %r11
	movq	%rbx, 352(%rsp)
	movq	%r15, %r10
.L804:
	movl	$3435973837, %ebx
	movl	%r14d, %r8d
	vpxor	%xmm7, %xmm7, %xmm7
	movq	%rax, 224(%rsp)
	imulq	%rbx, %r8
	vpinsrw	$0, 138160(%rdx), %xmm7, %xmm0
	vpxor	%xmm5, %xmm5, %xmm5
	movl	%r14d, %ebx
	vinserti128	$0x1, %xmm7, %ymm0, %ymm0
	shrq	$34, %r8
	vperm2i128	$0, %ymm0, %ymm0, %ymm0
	leal	(%r8,%r8,4), %r8d
	vpshufb	%ymm12, %ymm0, %ymm0
	subl	%r8d, %ebx
	vpmovzxbw	%xmm0, %ymm4
	vextracti128	$0x1, %ymm0, %xmm0
	movslq	%ebx, %rbx
	vpmovzxbw	%xmm0, %ymm1
	vpinsrw	$0, 138162(%rdx), %xmm7, %xmm0
	salq	$9, %rbx
	leaq	(%rdi,%rbx), %r8
	vinserti128	$0x1, %xmm7, %ymm0, %ymm0
	movq	%r8, 320(%rsp)
	vperm2i128	$0, %ymm0, %ymm0, %ymm0
	movq	256(%rsp), %r8
	vpshufb	%ymm12, %ymm0, %ymm0
	addq	%r8, %rbx
	vpmovzxbw	%xmm0, %ymm6
	vextracti128	$0x1, %ymm0, %xmm0
	movq	320(%rsp), %r8
	movq	%rbx, 288(%rsp)
	vpmovzxbw	%xmm0, %ymm0
	movq	%rdx, %rbx
.L803:
	vpmullw	64(%r8), %ymm6, %ymm7
	vpmullw	32(%r8), %ymm1, %ymm8
	vpmullw	96(%r8), %ymm0, %ymm2
	vpaddw	%ymm7, %ymm2, %ymm2
	vpmullw	(%r8), %ymm4, %ymm7
	vpaddw	%ymm8, %ymm7, %ymm7
	movzbl	137760(%rbx), %eax
	subq	$-128, %r8
	vpaddw	%ymm7, %ymm2, %ymm2
	incq	%rbx
	vpmulhuw	%ymm3, %ymm2, %ymm8
	vpsubw	%ymm8, %ymm2, %ymm7
	vpsrlw	$1, %ymm7, %ymm7
	vpaddw	%ymm8, %ymm7, %ymm7
	vpsrlw	$4, %ymm7, %ymm7
	vpsllw	$1, %ymm7, %ymm8
	vpaddw	%ymm7, %ymm8, %ymm8
	vpsllw	$3, %ymm8, %ymm8
	vpsubw	%ymm7, %ymm8, %ymm7
	vpsubw	%ymm7, %ymm2, %ymm2
	vmovd	%eax, %xmm7
	vpbroadcastw	%xmm7, %ymm7
	vpmullw	%ymm7, %ymm2, %ymm2
	vpaddw	%ymm2, %ymm5, %ymm5
	cmpq	288(%rsp), %r8
	jne	.L803
	vpmulhuw	%ymm3, %ymm5, %ymm1
	addq	$4, %rdx
	movq	224(%rsp), %rax
	incl	%r14d
	addq	$16, %r10
	addq	$16, %r11
	vpsubw	%ymm1, %ymm5, %ymm0
	vpsrlw	$1, %ymm0, %ymm0
	vpaddw	%ymm1, %ymm0, %ymm0
	vpsrlw	$4, %ymm0, %ymm0
	vpsllw	$1, %ymm0, %ymm1
	vpaddw	%ymm0, %ymm1, %ymm1
	vpsllw	$3, %ymm1, %ymm1
	vpsubw	%ymm0, %ymm1, %ymm1
	vpsubw	%ymm1, %ymm5, %ymm1
	vmovdqa	-16(%r10), %xmm5
	vpshufb	.LC16(%rip), %ymm1, %ymm2
	vpshufb	.LC17(%rip), %ymm1, %ymm4
	vpshufd	$170, %xmm5, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vpmullw	%ymm2, %ymm0, %ymm0
	vpshufd	$255, %xmm5, %xmm2
	vpmovzxbw	%xmm2, %ymm2
	vpmullw	%ymm4, %ymm2, %ymm2
	vpshufb	.LC14(%rip), %ymm1, %ymm4
	vpaddw	%ymm2, %ymm0, %ymm0
	vpshufd	$0, %xmm5, %xmm2
	vpmovzxbw	%xmm2, %ymm2
	vpmullw	%ymm4, %ymm2, %ymm2
	vpshufb	.LC15(%rip), %ymm1, %ymm4
	vpshufd	$85, %xmm5, %xmm1
	vpmovzxbw	%xmm1, %ymm1
	vpmullw	%ymm4, %ymm1, %ymm1
	vmovdqa	-16(%r11), %xmm4
	vpshufb	%xmm15, %xmm4, %xmm9
	vpshufb	.LC21(%rip), %xmm4, %xmm8
	vpsrldq	$8, %xmm9, %xmm10
	vpmovzxbw	%xmm10, %xmm10
	vpaddw	%ymm1, %ymm2, %ymm1
	vpaddw	%ymm1, %ymm0, %ymm0
	vpermq	$224, %ymm0, %ymm7
	vpermq	$229, %ymm0, %ymm6
	vpermq	$234, %ymm0, %ymm5
	vpmulhuw	%xmm13, %xmm7, %xmm2
	vpermq	$239, %ymm0, %ymm0
	vpsubw	%xmm2, %xmm7, %xmm1
	vpsrlw	$1, %xmm1, %xmm1
	vpaddw	%xmm2, %xmm1, %xmm1
	vpsrlw	$4, %xmm1, %xmm1
	vpsllw	$1, %xmm1, %xmm2
	vpaddw	%xmm1, %xmm2, %xmm2
	vpsllw	$3, %xmm2, %xmm2
	vpsubw	%xmm1, %xmm2, %xmm1
	vpmulhuw	%xmm13, %xmm6, %xmm2
	vpsubw	%xmm1, %xmm7, %xmm7
	vpsubw	%xmm2, %xmm6, %xmm1
	vpsrlw	$1, %xmm1, %xmm1
	vpaddw	%xmm2, %xmm1, %xmm1
	vpsrlw	$4, %xmm1, %xmm1
	vpsllw	$1, %xmm1, %xmm2
	vpaddw	%xmm1, %xmm2, %xmm2
	vpsllw	$3, %xmm2, %xmm2
	vpsubw	%xmm1, %xmm2, %xmm1
	vpmulhuw	%xmm13, %xmm5, %xmm2
	vpsubw	%xmm1, %xmm6, %xmm6
	vpmullw	%xmm6, %xmm10, %xmm10
	vpsubw	%xmm2, %xmm5, %xmm1
	vpsrlw	$1, %xmm1, %xmm1
	vpaddw	%xmm2, %xmm1, %xmm1
	vpsrlw	$4, %xmm1, %xmm1
	vpsllw	$1, %xmm1, %xmm2
	vpaddw	%xmm1, %xmm2, %xmm2
	vpsllw	$3, %xmm2, %xmm2
	vpsubw	%xmm1, %xmm2, %xmm1
	vpmulhuw	%xmm13, %xmm0, %xmm2
	vpsubw	%xmm1, %xmm5, %xmm5
	vpsubw	%xmm2, %xmm0, %xmm1
	vpsrlw	$1, %xmm1, %xmm1
	vpaddw	%xmm2, %xmm1, %xmm1
	vpsrlw	$4, %xmm1, %xmm1
	vpsllw	$1, %xmm1, %xmm2
	vpaddw	%xmm1, %xmm2, %xmm2
	vpsllw	$3, %xmm2, %xmm2
	vpsubw	%xmm1, %xmm2, %xmm1
	vpsubw	%xmm1, %xmm0, %xmm1
	vpshufb	%xmm14, %xmm4, %xmm0
	vpshufb	.LC22(%rip), %xmm4, %xmm4
	vpsrldq	$8, %xmm0, %xmm2
	vpsrldq	$8, %xmm4, %xmm11
	vpmovzxbw	%xmm0, %xmm0
	vpmovzxbw	%xmm2, %xmm2
	vpmullw	%xmm7, %xmm0, %xmm0
	vpmovzxbw	%xmm11, %xmm11
	vpmullw	%xmm7, %xmm2, %xmm2
	vpmovzxbw	%xmm9, %xmm7
	vpmovzxbw	%xmm4, %xmm4
	vpmullw	%xmm6, %xmm7, %xmm6
	vpmullw	%xmm1, %xmm11, %xmm11
	vpmullw	%xmm1, %xmm4, %xmm1
	vpaddw	%xmm10, %xmm2, %xmm2
	vpsrldq	$8, %xmm8, %xmm10
	vpaddw	%xmm6, %xmm0, %xmm0
	vpmovzxbw	%xmm10, %xmm10
	vpmovzxbw	%xmm8, %xmm6
	vpmullw	%xmm5, %xmm10, %xmm10
	vpmullw	%xmm5, %xmm6, %xmm5
	vpaddw	16(%rsi), %xmm2, %xmm2
	vpaddw	(%rsi), %xmm0, %xmm0
	vpaddw	%xmm11, %xmm10, %xmm10
	vpaddw	%xmm1, %xmm5, %xmm1
	vpaddw	%xmm10, %xmm2, %xmm2
	vpaddw	%xmm1, %xmm0, %xmm0
	vmovdqa	%xmm0, (%rsi)
	vmovdqa	%xmm2, 16(%rsi)
	cmpq	%rdx, 352(%rsp)
	jne	.L804
	incl	%ecx
	addq	$32, %rsi
	addq	$320, %r15
	addq	$320, %rax
	cmpl	$5, %ecx
	je	.L805
	movq	352(%rsp), %r8
	jmp	.L802
.L913:
	orl	%edi, %ebx
	jmp	.L780
.L809:
	movb	$0, 7040(%rsp,%rcx)
	cmpq	$79, %rcx
	je	.L807
	movb	$0, 7041(%rsp,%rcx)
	cmpq	$78, %rcx
	je	.L807
	movb	$0, 7042(%rsp,%rcx)
	cmpq	$77, %rcx
	je	.L807
	movb	$0, 7043(%rsp,%rcx)
	cmpq	$76, %rcx
	je	.L807
	movb	$0, 7044(%rsp,%rcx)
	cmpq	$75, %rcx
	je	.L807
	movb	$0, 7045(%rsp,%rcx)
	cmpq	$74, %rcx
	je	.L807
	movb	$0, 7046(%rsp,%rcx)
	addq	$7, %rcx
	cmpq	$80, %rcx
	jne	.L809
.L807:
	vmovdqa	7040(%rsp), %ymm1
	vpxor	%xmm3, %xmm3, %xmm3
	vpmovzxbw	%xmm1, %ymm0
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm1, %ymm1
	vpcmpeqw	%ymm6, %ymm0, %ymm0
	vpcmpeqw	%ymm5, %ymm1, %ymm1
	vpcmpeqw	%ymm3, %ymm0, %ymm0
	vpcmpeqw	%ymm3, %ymm1, %ymm1
	vpor	%ymm1, %ymm0, %ymm0
	vptest	%ymm0, %ymm0
	jne	.L818
	vmovdqa	7072(%rsp), %ymm1
	movl	$16, %edx
	movl	$64, %eax
	vextracti128	$0x1, %ymm1, %xmm0
	vpmovzxbw	%xmm1, %ymm1
	vpmovzxbw	%xmm0, %ymm0
	vpcmpeqw	%ymm2, %ymm1, %ymm1
	vpcmpeqw	%ymm4, %ymm0, %ymm0
	vpcmpeqw	%ymm3, %ymm1, %ymm1
	vpcmpeqw	%ymm3, %ymm0, %ymm0
	vpor	%ymm1, %ymm0, %ymm0
	vptest	%ymm0, %ymm0
	jne	.L916
.L811:
	cltq
	leal	-1(%rdx), %esi
	xorl	%edx, %edx
	leaq	384(%rsp,%rax,2), %rcx
	leaq	7040(%rsp,%rax), %rax
	jmp	.L812
.L918:
	cmpq	%rdx, %rsi
	je	.L917
	incq	%rdx
.L812:
	movzbl	(%rax,%rdx), %edi
	cmpw	(%rcx,%rdx,2), %di
	je	.L918
	vzeroupper
.L791:
	movl	$-1, %ebx
.L777:
	movq	10872(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L919
	leaq	-40(%rbp), %rsp
	movl	%ebx, %eax
	popq	%rbx
	popq	%r12
	popq	%r13
	popq	%r14
	popq	%r15
	popq	%rbp
	.cfi_remember_state
	.cfi_def_cfa 7, 8
	ret
.L912:
	.cfi_restore_state
	orl	%esi, %ebx
	jmp	.L780
.L914:
	orl	%r11d, %ebx
	jmp	.L780
.L805:
	vmovdqa	384(%rsp), %ymm6
	vmovdqa	416(%rsp), %ymm5
	leaq	544(%rsp), %rdi
	movl	%r9d, %ebx
	vmovdqa	448(%rsp), %ymm2
	vmovdqa	480(%rsp), %ymm4
	vpmulhuw	%ymm3, %ymm6, %ymm1
	vmovdqa	512(%rsp), %ymm7
	vpsubw	%ymm1, %ymm6, %ymm0
	vpsrlw	$1, %ymm0, %ymm0
	vpaddw	%ymm1, %ymm0, %ymm0
	vpsrlw	$4, %ymm0, %ymm0
	vpsllw	$1, %ymm0, %ymm1
	vpaddw	%ymm0, %ymm1, %ymm1
	vpsllw	$3, %ymm1, %ymm1
	vpsubw	%ymm0, %ymm1, %ymm0
	vpmulhuw	%ymm3, %ymm5, %ymm1
	vpsubw	%ymm0, %ymm6, %ymm6
	vmovdqa	%ymm6, 384(%rsp)
	vmovdqa	%ymm6, 256(%rsp)
	vpsubw	%ymm1, %ymm5, %ymm0
	vpsrlw	$1, %ymm0, %ymm0
	vpaddw	%ymm1, %ymm0, %ymm0
	vpsrlw	$4, %ymm0, %ymm0
	vpsllw	$1, %ymm0, %ymm1
	vpaddw	%ymm0, %ymm1, %ymm1
	vpsllw	$3, %ymm1, %ymm1
	vpsubw	%ymm0, %ymm1, %ymm0
	vpmulhuw	%ymm3, %ymm2, %ymm1
	vpsubw	%ymm0, %ymm5, %ymm5
	vmovdqa	%ymm5, 416(%rsp)
	vmovdqa	%ymm5, 288(%rsp)
	vpsubw	%ymm1, %ymm2, %ymm0
	vpsrlw	$1, %ymm0, %ymm0
	vpaddw	%ymm1, %ymm0, %ymm0
	vpsrlw	$4, %ymm0, %ymm0
	vpsllw	$1, %ymm0, %ymm1
	vpaddw	%ymm0, %ymm1, %ymm1
	vpsllw	$3, %ymm1, %ymm1
	vpsubw	%ymm0, %ymm1, %ymm0
	vpmulhuw	%ymm3, %ymm4, %ymm1
	vpsubw	%ymm0, %ymm2, %ymm2
	vpmulhuw	%ymm3, %ymm7, %ymm3
	vmovdqa	%ymm2, 448(%rsp)
	vmovdqa	%ymm2, 320(%rsp)
	vpsubw	%ymm1, %ymm4, %ymm0
	vpsrlw	$1, %ymm0, %ymm0
	vpaddw	%ymm1, %ymm0, %ymm0
	vpsrlw	$4, %ymm0, %ymm0
	vpsllw	$1, %ymm0, %ymm1
	vpaddw	%ymm0, %ymm1, %ymm1
	vpsllw	$3, %ymm1, %ymm1
	vpsubw	%ymm0, %ymm1, %ymm0
	vpsubw	%ymm0, %ymm4, %ymm4
	vpsubw	%ymm3, %ymm7, %ymm0
	vpsrlw	$1, %ymm0, %ymm0
	vmovdqa	%ymm4, 480(%rsp)
	vpaddw	%ymm3, %ymm0, %ymm0
	vmovdqa	%ymm4, 352(%rsp)
	vpsrlw	$4, %ymm0, %ymm0
	vpsllw	$1, %ymm0, %ymm1
	vpaddw	%ymm0, %ymm1, %ymm1
	vpsllw	$3, %ymm1, %ymm1
	vpsubw	%ymm0, %ymm1, %ymm0
	vpsubw	%ymm0, %ymm7, %ymm7
	vpxor	%xmm0, %xmm0, %xmm0
	vmovdqa	%ymm0, 7040(%rsp)
	vmovdqa	%ymm0, 7072(%rsp)
	vpxor	%xmm0, %xmm0, %xmm0
	vmovdqa	%ymm7, 512(%rsp)
	vmovdqa	%xmm0, 7104(%rsp)
	vzeroupper
	call	shake256_init@PLT
	leaq	138560(%r13), %rsi
	movl	$16, %edx
	leaq	544(%rsp), %rdi
	call	shake_absorb@PLT
	movq	56(%rsp), %rdx
	movq	64(%rsp), %rsi
	leaq	544(%rsp), %rdi
	call	shake_absorb@PLT
	leaq	266(%r12), %rsi
	movl	$16, %edx
	leaq	544(%rsp), %rdi
	call	shake_absorb@PLT
	leaq	544(%rsp), %rdi
	call	shake_finalize@PLT
	leaq	7120(%rsp), %rdi
	leaq	544(%rsp), %rdx
	movl	$80, %esi
	call	shake_squeeze@PLT
	xorl	%edi, %edi
	vmovdqa	352(%rsp), %ymm4
	vmovdqa	320(%rsp), %ymm2
	vmovdqa	256(%rsp), %ymm6
	vmovdqa	288(%rsp), %ymm5
	xorl	%ecx, %ecx
	movabsq	$7218291159277650633, %r8
	cmpq	$45, %rdi
	ja	.L816
.L920:
	movzbl	7121(%rsp,%rdi), %esi
	movzbl	7120(%rsp,%rdi), %eax
	leaq	2(%rdi), %r9
	salq	$8, %rsi
	xorq	%rax, %rsi
	cmpq	$44, %rdi
	je	.L806
	movzbl	7120(%rsp,%r9), %eax
	leaq	4(%rdi), %r9
	salq	$16, %rax
	xorq	%rsi, %rax
	movzbl	7123(%rsp,%rdi), %esi
	salq	$24, %rsi
	xorq	%rax, %rsi
.L806:
	movq	%rsi, %rax
	mulq	%r8
	movq	%rsi, %rax
	subq	%rdx, %rax
	shrq	%rax
	addq	%rax, %rdx
	shrq	$4, %rdx
	imulq	$23, %rdx, %rax
	movq	%rdx, %r10
	subq	%rax, %rsi
	movq	%rdx, %rax
	mulq	%r8
	movq	%r10, %rax
	movb	%sil, 7040(%rsp,%rcx)
	subq	%rdx, %rax
	shrq	%rax
	leaq	(%rdx,%rax), %rsi
	shrq	$4, %rsi
	imulq	$23, %rsi, %rax
	subq	%rax, %r10
	movq	%rsi, %rax
	mulq	%r8
	movq	%rsi, %rax
	movb	%r10b, 7041(%rsp,%rcx)
	subq	%rdx, %rax
	shrq	%rax
	addq	%rax, %rdx
	shrq	$4, %rdx
	imulq	$23, %rdx, %rax
	movq	%rdx, %r10
	subq	%rax, %rsi
	movb	%sil, 7042(%rsp,%rcx)
	cmpq	$77, %rcx
	je	.L807
	movq	%rdx, %rax
	mulq	%r8
	movq	%r10, %rax
	subq	%rdx, %rax
	shrq	%rax
	leaq	(%rdx,%rax), %rsi
	shrq	$4, %rsi
	imulq	$23, %rsi, %rax
	subq	%rax, %r10
	movb	%r10b, 7043(%rsp,%rcx)
	cmpq	$76, %rcx
	je	.L807
	movq	%rsi, %rax
	mulq	%r8
	movq	%rsi, %rax
	subq	%rdx, %rax
	shrq	%rax
	addq	%rax, %rdx
	shrq	$4, %rdx
	imulq	$23, %rdx, %rax
	movq	%rdx, %r10
	subq	%rax, %rsi
	movb	%sil, 7044(%rsp,%rcx)
	cmpq	$75, %rcx
	je	.L807
	movq	%rdx, %rax
	mulq	%r8
	movq	%r10, %rax
	subq	%rdx, %rax
	shrq	%rax
	leaq	(%rdx,%rax), %rsi
	shrq	$4, %rsi
	imulq	$23, %rsi, %rax
	subq	%rax, %r10
	movb	%r10b, 7045(%rsp,%rcx)
	cmpq	$74, %rcx
	je	.L807
	movq	%rsi, %rax
	mulq	%r8
	movq	%rsi, %rax
	subq	%rdx, %rax
	shrq	%rax
	addq	%rdx, %rax
	shrq	$4, %rax
	imulq	$23, %rax, %rax
	subq	%rax, %rsi
	movb	%sil, 7046(%rsp,%rcx)
	addq	$7, %rcx
	cmpq	$80, %rcx
	je	.L807
	cmpq	$45, %rdi
	ja	.L809
	movq	%r9, %rdi
	cmpq	$45, %rdi
	jbe	.L920
.L816:
	movq	%rdi, %r9
	xorl	%esi, %esi
	jmp	.L806
.L818:
	vmovdqa	.LC45(%rip), %ymm1
	vmovdqa	.LC46(%rip), %ymm0
.L810:
	vmovd	%xmm1, %edx
	vmovd	%xmm0, %eax
	jmp	.L811
.L916:
	vmovdqa	.LC43(%rip), %ymm1
	vmovdqa	.LC44(%rip), %ymm0
	jmp	.L810
.L917:
	vzeroupper
	jmp	.L777
.L919:
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE20:
	.size	_snova_24_5_23_4_SNOVA_OPT_verify, .-_snova_24_5_23_4_SNOVA_OPT_verify
	.globl	_snova_24_5_23_4_SNOVA_OPT_Smat
	.data
	.align 32
	.type	_snova_24_5_23_4_SNOVA_OPT_Smat, @object
	.size	_snova_24_5_23_4_SNOVA_OPT_Smat, 128
_snova_24_5_23_4_SNOVA_OPT_Smat:
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
	.value	22
	.value	14
	.value	8
	.value	6
	.value	8
	.value	8
	.value	14
	.value	8
	.value	2
	.value	6
	.value	8
	.value	14
	.value	0
	.value	8
	.value	2
	.value	0
	.value	6
	.value	2
	.value	14
	.value	18
	.value	12
	.value	14
	.value	14
	.value	13
	.value	5
	.value	18
	.value	13
	.value	9
	.value	13
	.value	12
	.value	5
	.value	13
	.value	19
	.section	.rodata.cst32,"aM",@progbits,32
	.align 32
.LC4:
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
	.set	.LC5,.LC4
	.section	.rodata.cst16,"aM",@progbits,16
	.align 16
.LC7:
	.byte	101
	.byte	101
	.byte	101
	.byte	101
	.byte	101
	.byte	101
	.byte	101
	.byte	101
	.byte	101
	.byte	101
	.byte	101
	.byte	101
	.byte	101
	.byte	101
	.byte	101
	.byte	101
	.section	.rodata.cst32
	.align 32
.LC14:
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
.LC15:
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
.LC16:
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
.LC17:
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
.LC19:
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
.LC20:
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
.LC21:
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
.LC22:
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
	.section	.rodata.cst4,"aM",@progbits,4
	.align 4
.LC32:
	.long	-1307163959
	.section	.rodata.cst32
	.align 32
.LC34:
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
.LC35:
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
.LC36:
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
.LC37:
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
.LC38:
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
.LC41:
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
.LC42:
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
.LC43:
	.long	48
	.long	47
	.long	46
	.long	45
	.long	44
	.long	43
	.long	42
	.long	41
	.align 32
.LC44:
	.long	32
	.long	33
	.long	34
	.long	35
	.long	36
	.long	37
	.long	38
	.long	39
	.align 32
.LC45:
	.long	80
	.long	79
	.long	78
	.long	77
	.long	76
	.long	75
	.long	74
	.long	73
	.align 32
.LC46:
	.long	0
	.long	1
	.long	2
	.long	3
	.long	4
	.long	5
	.long	6
	.long	7
	.align 32
.LC47:
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
.LC48:
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
