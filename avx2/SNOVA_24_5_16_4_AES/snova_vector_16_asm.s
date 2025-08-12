	.file	"snova_vector_16.c"
	.text
	.p2align 4
	.type	init_vector_table, @function
init_vector_table:
.LFB7285:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	vpxor	%xmm0, %xmm0, %xmm0
	xorl	%esi, %esi
	movl	$7, %r11d
	movl	$10, %r10d
	movl	$11, %r9d
	movl	$12, %r8d
	movl	$2, %edi
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%r15
	pushq	%r14
	.cfi_offset 15, -24
	.cfi_offset 14, -32
	movl	$9, %r14d
	pushq	%r13
	.cfi_offset 13, -40
	movl	$13, %r13d
	pushq	%r12
	.cfi_offset 12, -48
	movl	$15, %r12d
	pushq	%rbx
	.cfi_offset 3, -56
	movl	$14, %ebx
	andq	$-32, %rsp
	subq	$192, %rsp
	movq	%fs:40, %rax
	movq	%rax, 184(%rsp)
	movabsq	$796017844226884097, %rax
	movb	$0, 16+gf_multtab(%rip)
	movb	$0, 32+gf_multtab(%rip)
	movb	$0, 48+gf_multtab(%rip)
	movb	$0, 64+gf_multtab(%rip)
	movb	$0, 80+gf_multtab(%rip)
	movb	$0, 96+gf_multtab(%rip)
	movq	%rax, 169(%rsp)
	movabsq	$652194073960645899, %rax
	movq	%rax, 176(%rsp)
	leaq	169(%rsp), %rax
	movb	$0, 112+gf_multtab(%rip)
	movb	$0, 128+gf_multtab(%rip)
	movb	$0, 144+gf_multtab(%rip)
	movb	$0, 160+gf_multtab(%rip)
	movb	$0, 176+gf_multtab(%rip)
	movb	$0, 192+gf_multtab(%rip)
	movb	$0, 208+gf_multtab(%rip)
	movb	$0, 224+gf_multtab(%rip)
	movq	%rax, 16(%rsp)
	leaq	gf_multtab(%rip), %rax
	movb	$0, 240+gf_multtab(%rip)
	movb	$5, 26(%rsp)
	movb	$6, 28(%rsp)
	movb	$3, 30(%rsp)
	movb	$8, 27(%rsp)
	movb	$4, 29(%rsp)
	vmovdqa	%xmm0, gf_multtab(%rip)
	jmp	.L4
	.p2align 4,,10
	.p2align 3
.L2:
	leal	14(%rsi), %ecx
	movl	$2290649225, %edi
	movq	%rcx, %rdx
	imulq	%rdi, %rcx
	shrq	$35, %rcx
	movl	%ecx, %edi
	sall	$4, %edi
	subl	%ecx, %edi
	movzbl	27(%rsp), %ecx
	subl	%edi, %edx
	movzbl	29(%rsp), %edi
	movb	%cl, 29(%rsp)
	movzbl	30(%rsp), %ecx
	movslq	%edx, %rdx
	movb	%cl, 27(%rsp)
	movzbl	28(%rsp), %ecx
	movb	%r8b, 28(%rsp)
	movl	%r9d, %r8d
	movzbl	26(%rsp), %r9d
	movb	%cl, 30(%rsp)
	movb	%r10b, 26(%rsp)
	movl	%r11d, %r10d
	movl	%ebx, %r11d
	movl	%r12d, %ebx
	movl	%r13d, %r12d
	movl	%r14d, %r13d
	movzbl	169(%rsp,%rdx), %r14d
.L4:
	movq	16(%rsp), %rcx
	movzbl	27(%rsp), %r15d
	movzbl	(%rcx,%rsi), %edx
	salq	$8, %r15
	incq	%rsi
	movb	%dl, 31(%rsp)
	sall	$4, %edx
	leal	12(%rdx), %ecx
	movslq	%ecx, %rcx
	movb	%r8b, (%rax,%rcx)
	leal	11(%rdx), %ecx
	movslq	%ecx, %rcx
	movb	%r9b, (%rax,%rcx)
	leal	10(%rdx), %ecx
	movslq	%ecx, %rcx
	movb	%r10b, (%rax,%rcx)
	movzbl	%r11b, %ecx
	orq	%r15, %rcx
	movzbl	28(%rsp), %r15d
	salq	$8, %rcx
	orq	%rcx, %r15
	movzbl	26(%rsp), %ecx
	salq	$8, %r15
	orq	%r15, %rcx
	movzbl	29(%rsp), %r15d
	salq	$8, %rcx
	orq	%rcx, %r15
	movzbl	30(%rsp), %ecx
	salq	$8, %r15
	orq	%r15, %rcx
	movzbl	31(%rsp), %r15d
	salq	$8, %rcx
	orq	%rdi, %rcx
	leal	1(%rdx), %edi
	salq	$8, %rcx
	movslq	%edi, %rdi
	orq	%r15, %rcx
	movq	%rcx, (%rax,%rdi)
	leal	14(%rdx), %ecx
	movslq	%ecx, %rcx
	movb	%bl, (%rax,%rcx)
	leal	15(%rdx), %ecx
	movslq	%ecx, %rcx
	movb	%r12b, (%rax,%rcx)
	leal	13(%rdx), %ecx
	addl	$9, %edx
	movslq	%ecx, %rcx
	movslq	%edx, %rdx
	movb	%r13b, (%rax,%rcx)
	movb	%r14b, (%rax,%rdx)
	cmpq	$15, %rsi
	jne	.L2
	leaq	32(%rsp), %rsi
	leaq	160(%rsp), %r9
	movl	$1, %r8d
.L3:
	movl	%r8d, %edi
	xorl	%ecx, %ecx
	sall	$4, %edi
	.p2align 5
	.p2align 4,,10
	.p2align 3
.L5:
	movl	%ecx, %edx
	andl	$15, %edx
	addl	%edi, %edx
	movslq	%edx, %rdx
	movzbl	(%rax,%rdx), %edx
	movb	%dl, (%rsi,%rcx)
	incq	%rcx
	cmpq	$32, %rcx
	jne	.L5
	addq	$32, %rsi
	addl	%r8d, %r8d
	cmpq	%rsi, %r9
	jne	.L3
	vpcmpeqd	%ymm0, %ymm0, %ymm0
	movl	$33686018, %eax
	vpabsb	%ymm0, %ymm0
	vmovdqa	%ymm0, vtl_multmask1(%rip)
	vmovd	%eax, %xmm0
	movl	$67372036, %eax
	vpbroadcastd	%xmm0, %ymm0
	vmovdqa	%ymm0, vtl_multmask2(%rip)
	vmovd	%eax, %xmm0
	movl	$134744072, %eax
	vpbroadcastd	%xmm0, %ymm0
	vmovdqa	%ymm0, vtl_multmask4(%rip)
	vmovd	%eax, %xmm0
	vpbroadcastd	%xmm0, %ymm0
	vmovdqa	%ymm0, vtl_multmask8(%rip)
	vmovdqa	32(%rsp), %ymm0
	vmovdqa	%ymm0, vtl_mult_table1(%rip)
	vmovdqa	64(%rsp), %ymm0
	vmovdqa	%ymm0, vtl_mult_table2(%rip)
	vmovdqa	96(%rsp), %ymm0
	vmovdqa	%ymm0, vtl_mult_table4(%rip)
	vmovdqa	128(%rsp), %ymm0
	vmovdqa	%ymm0, vtl_mult_table8(%rip)
	vmovdqa	.LC4(%rip), %ymm0
	vmovdqa	%ymm0, vector_inv_table(%rip)
	movq	184(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L12
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
.L12:
	.cfi_restore_state
	vzeroupper
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE7285:
	.size	init_vector_table, .-init_vector_table
	.p2align 4
	.type	be_invertible_by_add_aS, @function
be_invertible_by_add_aS:
.LFB7298:
	.cfi_startproc
	pushq	%r15
	.cfi_def_cfa_offset 16
	.cfi_offset 15, -16
	movq	%rdi, %rax
	movq	%rdi, %r11
	subq	%rsi, %rax
	decq	%rax
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
	cmpq	$14, %rax
	jbe	.L14
	vmovdqu	(%rsi), %xmm0
	vmovdqu	%xmm0, (%rdi)
.L15:
	leaq	16(%r11), %rax
	leaq	32+_snova_24_5_16_4_aes_SNOVA_OPT_Smat(%rip), %r13
	cmpq	%rax, %r13
	jnb	.L21
	leaq	32(%r13), %rax
	cmpq	%rax, %r11
	jb	.L25
.L21:
	movl	$2021161080, %eax
	vpcmpeqd	%xmm3, %xmm3, %xmm3
	movb	$1, -16(%rsp)
	leaq	gf_multtab(%rip), %r10
	vmovd	%eax, %xmm6
	vpsrlw	$8, %xmm3, %xmm3
	movl	$1010580540, %eax
	vmovd	%eax, %xmm5
	movl	$505290270, %eax
	vpbroadcastd	%xmm6, %xmm6
	vmovd	%eax, %xmm4
	movl	$252645135, %eax
	vpbroadcastd	%xmm5, %xmm5
	vpbroadcastd	%xmm4, %xmm4
	vmovd	%eax, %xmm7
	jmp	.L16
	.p2align 4,,10
	.p2align 3
.L20:
	movzbl	-16(%rsp), %eax
	vmovd	%eax, %xmm1
	movl	%eax, %ebx
	leaq	_snova_24_5_16_4_aes_SNOVA_OPT_Smat(%rip), %rax
	vpbroadcastw	%xmm1, %xmm1
	incl	%ebx
	vpmullw	32(%rax), %xmm1, %xmm2
	vpmullw	48(%rax), %xmm1, %xmm1
	vpsrlw	$9, %xmm2, %xmm0
	vpsrlw	$9, %xmm1, %xmm8
	vpand	%xmm8, %xmm3, %xmm8
	vpand	%xmm0, %xmm3, %xmm0
	movl	$522133279, %eax
	movb	%bl, -16(%rsp)
	vpackuswb	%xmm8, %xmm0, %xmm0
	vpsrlw	$6, %xmm1, %xmm9
	vpsrlw	$6, %xmm2, %xmm8
	vpand	%xmm9, %xmm3, %xmm9
	vpand	%xmm6, %xmm0, %xmm0
	vpand	%xmm8, %xmm3, %xmm8
	vpackuswb	%xmm9, %xmm8, %xmm8
	vpsrlw	$3, %xmm1, %xmm9
	vpand	%xmm1, %xmm3, %xmm1
	vpand	%xmm5, %xmm8, %xmm8
	vpand	%xmm9, %xmm3, %xmm9
	vpxor	%xmm8, %xmm0, %xmm0
	vpsrlw	$3, %xmm2, %xmm8
	vpand	%xmm2, %xmm3, %xmm2
	vpand	%xmm8, %xmm3, %xmm8
	vpackuswb	%xmm1, %xmm2, %xmm1
	vpbroadcastd	%xmm7, %xmm2
	vpackuswb	%xmm9, %xmm8, %xmm8
	vpand	%xmm2, %xmm1, %xmm1
	vpand	%xmm4, %xmm8, %xmm8
	vpxor	%xmm1, %xmm8, %xmm1
	vpxor	%xmm1, %xmm0, %xmm8
	vmovd	%eax, %xmm0
	vpsrlw	$3, %xmm8, %xmm1
	vpbroadcastd	%xmm0, %xmm0
	vpand	%xmm1, %xmm0, %xmm0
	vpsrlw	$4, %xmm8, %xmm1
	vpand	%xmm2, %xmm1, %xmm1
	vpand	%xmm4, %xmm0, %xmm0
	vpxor	%xmm8, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpand	%xmm2, %xmm0, %xmm0
	vpxor	(%r11), %xmm0, %xmm0
	vmovdqu	%xmm0, (%r11)
.L16:
	movzbl	10(%r11), %eax
	movzbl	(%r11), %ebp
	movzbl	5(%r11), %r9d
	movzbl	1(%r11), %ecx
	movl	%eax, %r15d
	movzbl	2(%r11), %eax
	sall	$4, %ebp
	movzbl	4(%r11), %r13d
	leal	0(%rbp,%r9), %edx
	sall	$4, %ecx
	movzbl	15(%r11), %ebx
	sall	$4, %r15d
	sall	$4, %eax
	movslq	%edx, %rdx
	movzbl	11(%r11), %esi
	movzbl	14(%r11), %r8d
	movl	%eax, %r14d
	movzbl	13(%r11), %eax
	movzbl	(%r10,%rdx), %edx
	sall	$4, %esi
	movzbl	6(%r11), %edi
	movl	%r14d, -32(%rsp)
	movl	%eax, -28(%rsp)
	movzbl	9(%r11), %eax
	leal	(%rsi,%r8), %r12d
	movslq	%r12d, %r12
	sall	$4, %eax
	movl	%eax, -24(%rsp)
	leal	(%rcx,%r13), %eax
	cltq
	xorb	(%r10,%rax), %dl
	leal	(%r15,%rbx), %eax
	cltq
	movzbl	%dl, %edx
	movzbl	(%r10,%rax), %eax
	sall	$4, %edx
	xorb	(%r10,%r12), %al
	leal	0(%r13,%r14), %r12d
	movl	-24(%rsp), %r14d
	movzbl	%al, %eax
	movslq	%r12d, %r12
	addl	%eax, %edx
	leal	0(%rbp,%rdi), %eax
	addl	%ebx, %r14d
	cltq
	movslq	%r14d, %r14
	movslq	%edx, %rdx
	movzbl	(%r10,%rax), %eax
	movzbl	(%r10,%rdx), %edx
	xorb	(%r10,%r12), %al
	movl	-28(%rsp), %r12d
	movzbl	%al, %eax
	addl	%esi, %r12d
	sall	$4, %eax
	movslq	%r12d, %r12
	movzbl	(%r10,%r12), %r12d
	xorb	(%r10,%r14), %r12b
	movzbl	7(%r11), %r14d
	movzbl	%r12b, %r12d
	addl	%r12d, %eax
	movzbl	3(%r11), %r12d
	addl	%r14d, %ebp
	cltq
	movslq	%ebp, %rbp
	sall	$4, %r12d
	xorb	(%r10,%rax), %dl
	movzbl	(%r10,%rbp), %eax
	addl	%r12d, %r13d
	movl	-24(%rsp), %ebp
	movslq	%r13d, %r13
	xorb	(%r10,%r13), %al
	addl	%r8d, %ebp
	movl	%r15d, -20(%rsp)
	movl	-28(%rsp), %r13d
	movslq	%ebp, %rbp
	movzbl	%al, %eax
	movzbl	(%r10,%rbp), %ebp
	sall	$4, %eax
	addl	%r15d, %r13d
	movl	-32(%rsp), %r15d
	movslq	%r13d, %r13
	xorb	(%r10,%r13), %bpl
	addl	%r9d, %r15d
	movzbl	12(%r11), %r13d
	movzbl	%bpl, %ebp
	movslq	%r15d, %r15
	addl	%ebp, %eax
	movzbl	8(%r11), %ebp
	cltq
	xorb	(%r10,%rax), %dl
	leal	(%rcx,%rdi), %eax
	sall	$4, %ebp
	cltq
	addl	%ebp, %ebx
	movzbl	(%r10,%rax), %eax
	movslq	%ebx, %rbx
	movzbl	(%r10,%rbx), %ebx
	xorb	(%r10,%r15), %al
	movl	-20(%rsp), %r15d
	movzbl	%al, %eax
	sall	$4, %eax
	addl	%r13d, %esi
	addl	%r14d, %ecx
	addl	%r12d, %r9d
	movslq	%esi, %rsi
	movslq	%ecx, %rcx
	addl	%ebp, %r8d
	movslq	%r9d, %r9
	xorb	(%r10,%rsi), %bl
	movslq	%r8d, %r8
	addl	%r12d, %edi
	movl	-28(%rsp), %r12d
	movzbl	%bl, %ebx
	movslq	%edi, %rdi
	addl	%ebx, %eax
	cltq
	xorb	(%r10,%rax), %dl
	movzbl	(%r10,%rcx), %eax
	leal	(%r15,%r13), %ecx
	movslq	%ecx, %rcx
	movl	-32(%rsp), %r15d
	movzbl	(%r10,%rcx), %ecx
	xorb	(%r10,%r9), %al
	movzbl	%al, %eax
	xorb	(%r10,%r8), %cl
	sall	$4, %eax
	movzbl	%cl, %ecx
	addl	%ecx, %eax
	leal	(%r12,%rbp), %ecx
	movl	-24(%rsp), %ebp
	cltq
	movslq	%ecx, %rcx
	xorb	(%r10,%rax), %dl
	leal	(%r15,%r14), %eax
	movzbl	(%r10,%rcx), %ecx
	cltq
	movzbl	(%r10,%rax), %eax
	xorb	(%r10,%rdi), %al
	movzbl	%al, %eax
	sall	$4, %eax
	movl	%eax, %esi
	leal	0(%rbp,%r13), %eax
	cltq
	xorb	(%r10,%rax), %cl
	movzbl	%cl, %eax
	addl	%esi, %eax
	cltq
	cmpb	(%r10,%rax), %dl
	je	.L20
.L23:
	popq	%rbx
	.cfi_remember_state
	.cfi_def_cfa_offset 48
	popq	%rbp
	.cfi_def_cfa_offset 40
	popq	%r12
	.cfi_def_cfa_offset 32
	popq	%r13
	.cfi_def_cfa_offset 24
	popq	%r14
	.cfi_def_cfa_offset 16
	popq	%r15
	.cfi_def_cfa_offset 8
	ret
.L14:
	.cfi_restore_state
	movzbl	(%rsi), %eax
	movb	%al, (%rdi)
	movzbl	1(%rsi), %eax
	movb	%al, 1(%rdi)
	movzbl	2(%rsi), %eax
	movb	%al, 2(%rdi)
	movzbl	3(%rsi), %eax
	movb	%al, 3(%rdi)
	movzbl	4(%rsi), %eax
	movb	%al, 4(%rdi)
	movzbl	5(%rsi), %eax
	movb	%al, 5(%rdi)
	movzbl	6(%rsi), %eax
	movb	%al, 6(%rdi)
	movzbl	7(%rsi), %eax
	movb	%al, 7(%rdi)
	movzbl	8(%rsi), %eax
	movb	%al, 8(%rdi)
	movzbl	9(%rsi), %eax
	movb	%al, 9(%rdi)
	movzbl	10(%rsi), %eax
	movb	%al, 10(%rdi)
	movzbl	11(%rsi), %eax
	movb	%al, 11(%rdi)
	movzbl	12(%rsi), %eax
	movb	%al, 12(%rdi)
	movzbl	13(%rsi), %eax
	movb	%al, 13(%rdi)
	movzbl	14(%rsi), %eax
	movb	%al, 14(%rdi)
	movzbl	15(%rsi), %eax
	movb	%al, 15(%rdi)
	jmp	.L15
.L25:
	movb	$1, -9(%rsp)
	leaq	gf_multtab(%rip), %r10
	.p2align 4,,10
	.p2align 3
.L17:
	movzbl	1(%r11), %eax
	movzbl	4(%r11), %r12d
	movzbl	(%r11), %ecx
	movzbl	6(%r11), %r8d
	sall	$4, %eax
	movzbl	15(%r11), %r9d
	movzbl	11(%r11), %esi
	movl	%eax, %r15d
	movzbl	10(%r11), %eax
	sall	$4, %ecx
	movzbl	13(%r11), %edi
	sall	$4, %esi
	movzbl	5(%r11), %ebp
	movzbl	14(%r11), %ebx
	movl	%r15d, -20(%rsp)
	sall	$4, %eax
	movl	%eax, -24(%rsp)
	movzbl	2(%r11), %eax
	movl	%eax, %edx
	movzbl	9(%r11), %eax
	sall	$4, %edx
	movl	%eax, %r14d
	leal	(%rdx,%r12), %eax
	movl	%edx, -28(%rsp)
	leal	(%r8,%rcx), %edx
	cltq
	sall	$4, %r14d
	movslq	%edx, %rdx
	movzbl	(%r10,%rax), %eax
	movl	%r14d, -32(%rsp)
	xorb	(%r10,%rdx), %al
	leal	(%r14,%r9), %edx
	leal	(%rdi,%rsi), %r14d
	movslq	%edx, %rdx
	movslq	%r14d, %r14
	movzbl	%al, %eax
	movzbl	(%r10,%rdx), %edx
	sall	$4, %eax
	xorb	(%r10,%r14), %dl
	leal	0(%rbp,%rcx), %r14d
	movzbl	%dl, %edx
	movslq	%r14d, %r14
	addl	%edx, %eax
	movslq	%eax, %rdx
	leal	(%r12,%r15), %eax
	movl	-24(%rsp), %r15d
	cltq
	movzbl	(%r10,%rdx), %edx
	movzbl	(%r10,%rax), %eax
	addl	%r9d, %r15d
	movslq	%r15d, %r15
	xorb	(%r10,%r14), %al
	leal	(%rbx,%rsi), %r14d
	movslq	%r14d, %r14
	movzbl	%al, %eax
	movzbl	(%r10,%r14), %r14d
	sall	$4, %eax
	xorb	(%r10,%r15), %r14b
	movzbl	%r14b, %r14d
	addl	%r14d, %eax
	movzbl	7(%r11), %r14d
	cltq
	xorb	(%r10,%rax), %dl
	movzbl	3(%r11), %eax
	addl	%r14d, %ecx
	movslq	%ecx, %rcx
	sall	$4, %eax
	movl	%eax, -16(%rsp)
	addl	%r12d, %eax
	cltq
	movzbl	(%r10,%rax), %eax
	xorb	(%r10,%rcx), %al
	movl	-24(%rsp), %ecx
	movl	-32(%rsp), %r12d
	movzbl	%al, %eax
	movl	-20(%rsp), %r15d
	addl	%edi, %ecx
	sall	$4, %eax
	movslq	%ecx, %rcx
	addl	%ebx, %r12d
	addl	%r8d, %r15d
	movzbl	(%r10,%rcx), %ecx
	movslq	%r12d, %r12
	movslq	%r15d, %r15
	xorb	(%r10,%r12), %cl
	movzbl	12(%r11), %r12d
	movzbl	%cl, %ecx
	addl	%ecx, %eax
	movzbl	8(%r11), %ecx
	addl	%r12d, %esi
	cltq
	movslq	%esi, %rsi
	xorb	(%r10,%rax), %dl
	movl	-28(%rsp), %eax
	sall	$4, %ecx
	movzbl	(%r10,%rsi), %esi
	addl	%ebp, %eax
	cltq
	movzbl	(%r10,%rax), %eax
	xorb	(%r10,%r15), %al
	movl	-20(%rsp), %r15d
	movzbl	%al, %eax
	sall	$4, %eax
	addl	%ecx, %r9d
	addl	%ecx, %edi
	addl	%ebx, %ecx
	movslq	%r9d, %r9
	movslq	%edi, %rdi
	movslq	%ecx, %rcx
	xorb	(%r10,%r9), %sil
	movl	-16(%rsp), %r9d
	movzbl	%sil, %esi
	movzbl	(%r10,%rcx), %ecx
	addl	%esi, %eax
	movl	-28(%rsp), %esi
	cltq
	xorb	(%r10,%rax), %dl
	leal	(%r9,%r8), %eax
	addl	%r14d, %esi
	cltq
	movslq	%esi, %rsi
	movzbl	(%r10,%rax), %eax
	xorb	(%r10,%rsi), %al
	movl	-32(%rsp), %esi
	movzbl	%al, %eax
	addl	%r12d, %esi
	sall	$4, %eax
	movslq	%esi, %rsi
	movzbl	(%r10,%rsi), %esi
	xorb	(%r10,%rdi), %sil
	leal	(%r9,%rbp), %edi
	movzbl	%sil, %esi
	movslq	%edi, %rdi
	addl	%esi, %eax
	movzbl	(%r10,%rdi), %edi
	movslq	%eax, %rsi
	leal	(%r14,%r15), %eax
	movl	-24(%rsp), %r15d
	cltq
	xorb	(%r10,%rax), %dil
	movzbl	%dil, %eax
	sall	$4, %eax
	movl	%eax, %edi
	leal	(%r12,%r15), %eax
	cltq
	xorb	(%r10,%rax), %cl
	movzbl	%cl, %eax
	addl	%edi, %eax
	cltq
	xorb	(%r10,%rax), %dl
	cmpb	%dl, (%r10,%rsi)
	jne	.L23
	movzbl	-9(%rsp), %esi
	xorl	%ecx, %ecx
	.p2align 4,,10
	.p2align 3
.L19:
	movzwl	0(%r13,%rcx,2), %edi
	imull	%esi, %edi
	movzwl	%di, %edx
	andl	$15, %edi
	movl	%edx, %eax
	movl	%edx, %r8d
	sarl	$9, %edx
	sarl	$6, %eax
	sarl	$3, %r8d
	andl	$120, %edx
	andl	$60, %eax
	andl	$30, %r8d
	xorl	%r8d, %eax
	xorl	%edi, %eax
	xorl	%edx, %eax
	movl	%eax, %edx
	shrw	$3, %dx
	andl	$14, %edx
	xorl	%eax, %edx
	shrw	$4, %ax
	xorl	%edx, %eax
	andl	$15, %eax
	xorb	%al, (%r11,%rcx)
	incq	%rcx
	cmpq	$16, %rcx
	jne	.L19
	incb	-9(%rsp)
	jmp	.L17
	.cfi_endproc
.LFE7298:
	.size	be_invertible_by_add_aS, .-be_invertible_by_add_aS
	.p2align 4
	.type	expand_T12, @function
expand_T12:
.LFB7297:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movl	$32, %ecx
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%r15
	pushq	%r14
	.cfi_offset 15, -24
	.cfi_offset 14, -32
	movq	%rdi, %r14
	pushq	%r13
	pushq	%r12
	.cfi_offset 13, -40
	.cfi_offset 12, -48
	leaq	_snova_24_5_16_4_aes_SNOVA_OPT_Smat(%rip), %r12
	pushq	%rbx
	andq	$-32, %rsp
	subq	$800, %rsp
	.cfi_offset 3, -56
	movq	%fs:40, %rdx
	movq	%rdx, 792(%rsp)
	movq	%rsi, %rdx
	leaq	32(%rsp), %rdi
	movl	$240, %esi
	leaq	288(%rsp), %r13
	call	shake256@PLT
	movl	$252645135, %eax
	vmovdqa	32(%rsp), %ymm1
	leaq	1920(%r14), %rcx
	vmovd	%eax, %xmm0
	vmovd	%eax, %xmm4
	movl	$1010580540, %eax
	vpbroadcastd	%xmm0, %ymm0
	vpsrlw	$4, %ymm1, %ymm3
	vmovd	%eax, %xmm5
	movl	$2021161080, %eax
	vpand	%ymm3, %ymm0, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vpbroadcastd	%xmm5, %xmm5
	vpunpcklbw	%ymm3, %ymm1, %ymm2
	vpunpckhbw	%ymm3, %ymm1, %ymm1
	vperm2i128	$32, %ymm1, %ymm2, %ymm3
	vperm2i128	$49, %ymm1, %ymm2, %ymm2
	vmovdqa	64(%rsp), %ymm1
	vmovdqa	%ymm3, 288(%rsp)
	vpsrlw	$4, %ymm1, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm2, 320(%rsp)
	vpand	%ymm3, %ymm0, %ymm3
	vpunpcklbw	%ymm3, %ymm1, %ymm2
	vpunpckhbw	%ymm3, %ymm1, %ymm1
	vperm2i128	$32, %ymm1, %ymm2, %ymm3
	vperm2i128	$49, %ymm1, %ymm2, %ymm2
	vmovdqa	96(%rsp), %ymm1
	vmovdqa	%ymm3, 352(%rsp)
	vpsrlw	$4, %ymm1, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm2, 384(%rsp)
	vpand	%ymm3, %ymm0, %ymm3
	vpunpcklbw	%ymm3, %ymm1, %ymm2
	vpunpckhbw	%ymm3, %ymm1, %ymm1
	vperm2i128	$32, %ymm1, %ymm2, %ymm3
	vperm2i128	$49, %ymm1, %ymm2, %ymm2
	vmovdqa	128(%rsp), %ymm1
	vmovdqa	%ymm3, 416(%rsp)
	vpsrlw	$4, %ymm1, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm2, 448(%rsp)
	vpand	%ymm3, %ymm0, %ymm3
	vpunpcklbw	%ymm3, %ymm1, %ymm2
	vpunpckhbw	%ymm3, %ymm1, %ymm1
	vperm2i128	$32, %ymm1, %ymm2, %ymm3
	vperm2i128	$49, %ymm1, %ymm2, %ymm2
	vmovdqa	160(%rsp), %ymm1
	vmovdqa	%ymm3, 480(%rsp)
	vpsrlw	$4, %ymm1, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm2, 512(%rsp)
	vpand	%ymm3, %ymm0, %ymm3
	vpunpcklbw	%ymm3, %ymm1, %ymm2
	vpunpckhbw	%ymm3, %ymm1, %ymm1
	vperm2i128	$32, %ymm1, %ymm2, %ymm3
	vperm2i128	$49, %ymm1, %ymm2, %ymm2
	vmovdqa	192(%rsp), %ymm1
	vmovdqa	%ymm3, 544(%rsp)
	vpsrlw	$4, %ymm1, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm2, 576(%rsp)
	vpand	%ymm3, %ymm0, %ymm3
	vpunpcklbw	%ymm3, %ymm1, %ymm2
	vpunpckhbw	%ymm3, %ymm1, %ymm1
	vperm2i128	$32, %ymm1, %ymm2, %ymm3
	vperm2i128	$49, %ymm1, %ymm2, %ymm2
	vmovdqa	224(%rsp), %ymm1
	vmovdqa	%ymm2, 640(%rsp)
	vpsrlw	$4, %ymm1, %ymm2
	vmovdqa	%ymm3, 608(%rsp)
	vpand	%ymm2, %ymm0, %ymm2
	vpand	%ymm0, %ymm1, %ymm0
	vpunpcklbw	%ymm2, %ymm0, %ymm1
	vpunpckhbw	%ymm2, %ymm0, %ymm0
	vperm2i128	$32, %ymm0, %ymm1, %ymm2
	vperm2i128	$49, %ymm0, %ymm1, %ymm1
	vmovdqa	256(%rsp), %xmm0
	vmovdqa	%ymm2, 672(%rsp)
	vmovdqa	%ymm1, 704(%rsp)
	vpsrlw	$4, %xmm0, %xmm2
	vpbroadcastd	%xmm4, %xmm1
	vmovd	%eax, %xmm4
	vpand	%xmm2, %xmm1, %xmm2
	vpand	%xmm1, %xmm0, %xmm0
	vpbroadcastd	%xmm4, %xmm4
	movl	$505290270, %eax
	vpunpcklbw	%xmm2, %xmm0, %xmm1
	vmovd	%eax, %xmm3
	vpunpckhbw	%xmm2, %xmm0, %xmm0
	vpcmpeqd	%xmm2, %xmm2, %xmm2
	vmovdqa	%xmm1, 736(%rsp)
	vpbroadcastd	%xmm3, %xmm3
	vmovdqa	%xmm0, 752(%rsp)
	vpsrlw	$8, %xmm2, %xmm2
	jmp	.L31
.L33:
	vmovd	%ebx, %xmm6
	vmovd	%r11d, %xmm1
	vmovd	%r9d, %xmm7
	movl	$252645135, %ebx
	vmovd	%edi, %xmm9
	vpbroadcastw	%xmm6, %xmm6
	vpbroadcastw	%xmm1, %xmm1
	addq	$4, %r13
	vpbroadcastw	%xmm7, %xmm7
	vpbroadcastw	%xmm9, %xmm9
	vpmullw	32(%r12), %xmm1, %xmm0
	vpmullw	48(%r12), %xmm1, %xmm1
	vpmullw	(%r12), %xmm7, %xmm8
	vpmullw	96(%r12), %xmm9, %xmm10
	vpxor	%xmm8, %xmm0, %xmm0
	vpmullw	64(%r12), %xmm6, %xmm8
	vpxor	%xmm10, %xmm8, %xmm8
	vpmullw	16(%r12), %xmm7, %xmm7
	vpmullw	112(%r12), %xmm9, %xmm9
	vpxor	%xmm7, %xmm1, %xmm1
	vpxor	%xmm8, %xmm0, %xmm0
	vpmullw	80(%r12), %xmm6, %xmm8
	vpxor	%xmm9, %xmm8, %xmm8
	vpxor	%xmm1, %xmm8, %xmm8
	vpsrlw	$6, %xmm0, %xmm1
	vpsrlw	$6, %xmm8, %xmm6
	vpsrlw	$9, %xmm8, %xmm7
	vpand	%xmm1, %xmm2, %xmm1
	vpand	%xmm6, %xmm2, %xmm6
	vpand	%xmm7, %xmm2, %xmm7
	vpackuswb	%xmm6, %xmm1, %xmm1
	vpsrlw	$9, %xmm0, %xmm6
	vpand	%xmm6, %xmm2, %xmm6
	vpand	%xmm5, %xmm1, %xmm1
	vpackuswb	%xmm7, %xmm6, %xmm6
	vpand	%xmm4, %xmm6, %xmm6
	vpxor	%xmm6, %xmm1, %xmm7
	vpsrlw	$3, %xmm0, %xmm1
	vpand	%xmm0, %xmm2, %xmm0
	vpsrlw	$3, %xmm8, %xmm6
	vpand	%xmm1, %xmm2, %xmm1
	vpand	%xmm8, %xmm2, %xmm8
	vpand	%xmm6, %xmm2, %xmm6
	vpackuswb	%xmm8, %xmm0, %xmm0
	vpackuswb	%xmm6, %xmm1, %xmm1
	vmovd	%ebx, %xmm6
	movl	$522133279, %ebx
	vpbroadcastd	%xmm6, %xmm6
	vpand	%xmm3, %xmm1, %xmm1
	vpand	%xmm6, %xmm0, %xmm0
	vpxor	%xmm0, %xmm1, %xmm0
	vpxor	%xmm0, %xmm7, %xmm1
	vpsrlw	$4, %xmm1, %xmm0
	vpsrlw	$3, %xmm1, %xmm7
	vpand	%xmm6, %xmm0, %xmm0
	vpxor	%xmm1, %xmm0, %xmm0
	vmovd	%ebx, %xmm1
	vpbroadcastd	%xmm1, %xmm1
	vpand	%xmm7, %xmm1, %xmm1
	vpand	%xmm3, %xmm1, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpand	%xmm6, %xmm0, %xmm0
	vmovdqu	%xmm0, (%rax)
	cmpq	%r14, %rcx
	je	.L38
.L31:
	movzbl	0(%r13), %r9d
	movzbl	3(%r13), %eax
	movl	$15, %edx
	movq	%r14, %r10
	movzbl	1(%r13), %r11d
	movzbl	2(%r13), %ebx
	testb	%r9b, %r9b
	setne	%dil
	subl	%r9d, %edx
	addl	%edx, %edi
	cmpb	$1, %al
	sbbl	%edx, %edx
	andl	%edx, %edi
	orl	%eax, %edi
	movq	%r14, %rax
	addq	$16, %r14
	movb	%dil, 3(%r13)
	movzbl	%dil, %edi
	cmpq	%r14, %r12
	jnb	.L33
	leaq	128+_snova_24_5_16_4_aes_SNOVA_OPT_Smat(%rip), %rsi
	cmpq	%rsi, %rax
	jnb	.L33
	movq	%rcx, 24(%rsp)
	leaq	_snova_24_5_16_4_aes_SNOVA_OPT_Smat(%rip), %rsi
	leaq	32(%rsi), %r15
	.p2align 4,,10
	.p2align 3
.L30:
	movzwl	(%rsi), %edx
	movzwl	32(%rsi), %eax
	addq	$2, %rsi
	incq	%r10
	imull	%r11d, %eax
	imull	%r9d, %edx
	xorl	%eax, %edx
	movzwl	62(%rsi), %eax
	imull	%ebx, %eax
	xorl	%eax, %edx
	movzwl	94(%rsi), %eax
	imull	%edi, %eax
	xorl	%eax, %edx
	movzwl	%dx, %ecx
	andl	$15, %edx
	movl	%ecx, %r8d
	movl	%ecx, %eax
	sarl	$9, %ecx
	sarl	$3, %r8d
	sarl	$6, %eax
	andl	$30, %r8d
	andl	$60, %eax
	xorl	%r8d, %eax
	movl	%ecx, %r8d
	xorl	%edx, %eax
	andl	$120, %r8d
	xorl	%r8d, %eax
	movl	%eax, %ecx
	shrw	$3, %ax
	andl	$14, %eax
	xorl	%ecx, %eax
	shrw	$4, %cx
	xorl	%ecx, %eax
	andl	$15, %eax
	movb	%al, -1(%r10)
	cmpq	%rsi, %r15
	jne	.L30
	movq	24(%rsp), %rcx
	addq	$4, %r13
	cmpq	%r14, %rcx
	jne	.L31
.L38:
	movq	792(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L39
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
.L39:
	.cfi_restore_state
	vzeroupper
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE7297:
	.size	expand_T12, .-expand_T12
	.p2align 4
	.globl	_snova_24_5_16_4_aes_SNOVA_OPT_genkeys
	.type	_snova_24_5_16_4_aes_SNOVA_OPT_genkeys, @function
_snova_24_5_16_4_aes_SNOVA_OPT_genkeys:
.LFB7300:
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
	subq	$132992, %rsp
	.cfi_offset 15, -24
	.cfi_offset 14, -32
	.cfi_offset 13, -40
	.cfi_offset 12, -48
	.cfi_offset 3, -56
	movq	%rdi, 56(%rsp)
	movl	first_time(%rip), %eax
	movq	%rsi, 48(%rsp)
	movq	%fs:40, %r13
	movq	%r13, 132984(%rsp)
	movq	%rdx, %r13
	testl	%eax, %eax
	jne	.L76
.L41:
	leaq	27104(%rsp), %r15
	leaq	16(%r13), %rsi
	movq	%r15, %rdi
	leaq	7904(%rsp), %rbx
	leaq	63680(%rsp), %r14
	call	expand_T12
	movl	$16, %edx
	movq	%r13, %rsi
	movq	%rbx, %rdi
	call	snova_pk_expander_init@PLT
	movq	%rbx, %rdx
	movl	$34640, %esi
	leaq	29024(%rsp), %rdi
	call	snova_pk_expander@PLT
	movl	$252645135, %esi
	leaq	29024(%rsp), %rdx
	leaq	132928(%rsp), %rcx
	vmovd	%esi, %xmm1
	movq	%r14, %rax
	vpbroadcastd	%xmm1, %ymm4
.L42:
	vmovdqa	(%rdx), %ymm0
	addq	$64, %rax
	addq	$32, %rdx
	vpsrlw	$4, %ymm0, %ymm3
	vpand	%ymm4, %ymm0, %ymm0
	vpand	%ymm3, %ymm4, %ymm3
	vpunpcklbw	%ymm3, %ymm0, %ymm2
	vpunpckhbw	%ymm3, %ymm0, %ymm0
	vperm2i128	$32, %ymm0, %ymm2, %ymm3
	vperm2i128	$49, %ymm0, %ymm2, %ymm2
	vmovdqa	%ymm3, -64(%rax)
	vmovdqa	%ymm2, -32(%rax)
	cmpq	%rcx, %rax
	jne	.L42
	vmovdqa	63648(%rsp), %xmm0
	vpbroadcastd	%xmm1, %xmm1
	movl	$19200, %edx
	xorl	%esi, %esi
	movq	%rbx, %rdi
	vpsrlw	$4, %xmm0, %xmm2
	vpand	%xmm1, %xmm0, %xmm0
	vpand	%xmm2, %xmm1, %xmm2
	vpunpcklbw	%xmm2, %xmm0, %xmm1
	vpunpckhbw	%xmm2, %xmm0, %xmm0
	vmovdqa	%xmm1, 132928(%rsp)
	vmovdqa	%xmm0, 132944(%rsp)
	vzeroupper
	call	memset@PLT
	movl	$286331153, %edx
	leaq	3904(%rsp), %rdi
	vmovd	%edx, %xmm3
	leaq	64(%rsp), %rax
	vpbroadcastd	%xmm3, %ymm3
.L43:
	vmovdqa	(%r15), %ymm0
	addq	$64, %rax
	addq	$32, %r15
	vpmovzxbw	%xmm0, %ymm2
	vextracti128	$0x1, %ymm0, %xmm0
	vpsllw	$6, %ymm2, %ymm4
	vpsllw	$9, %ymm2, %ymm1
	vpmovzxbw	%xmm0, %ymm0
	vpor	%ymm4, %ymm1, %ymm1
	vpsllw	$3, %ymm2, %ymm4
	vpor	%ymm2, %ymm4, %ymm2
	vpor	%ymm2, %ymm1, %ymm1
	vpsllw	$6, %ymm0, %ymm2
	vpand	%ymm3, %ymm1, %ymm1
	vmovdqa	%ymm1, -64(%rax)
	vpsllw	$9, %ymm0, %ymm1
	vpor	%ymm2, %ymm1, %ymm1
	vpsllw	$3, %ymm0, %ymm2
	vpor	%ymm0, %ymm2, %ymm0
	vpor	%ymm0, %ymm1, %ymm0
	vpand	%ymm3, %ymm0, %ymm0
	vmovdqa	%ymm0, -32(%rax)
	cmpq	%rdi, %rax
	jne	.L43
	movq	%r14, 40(%rsp)
	vmovdqa	.LC24(%rip), %ymm8
	movq	%rbx, %r15
	movq	%rbx, %rdx
	vmovdqa	.LC25(%rip), %ymm7
	vmovdqa	.LC26(%rip), %ymm6
	movq	%r14, %rcx
	xorl	%esi, %esi
	vmovdqa	.LC27(%rip), %ymm5
	vmovdqa	.LC28(%rip), %ymm3
	movl	$576, %r8d
	movq	%rbx, %r11
	vmovdqa	.LC29(%rip), %ymm4
.L44:
	movq	%r15, 32(%rsp)
	leal	-576(%r8), %eax
	movq	%rdx, %r12
	movq	%rcx, %rbx
	movq	%rdx, 24(%rsp)
.L50:
	movl	%eax, 20(%rsp)
	movq	%rdi, %r15
	movq	%r12, %r14
	xorl	%edx, %edx
.L48:
	leaq	-3840(%r15), %rax
	movq	%rbx, %r9
	.p2align 4,,10
	.p2align 3
.L45:
	vmovdqa	(%rax), %ymm2
	vpmovzxbw	(%r9), %ymm1
	addq	$160, %rax
	addq	$16, %r9
	vperm2i128	$0, %ymm2, %ymm2, %ymm9
	vpshufb	%ymm8, %ymm1, %ymm10
	vpshufb	%ymm7, %ymm9, %ymm0
	vpshufb	%ymm5, %ymm9, %ymm9
	vpmullw	%ymm10, %ymm0, %ymm0
	vpshufb	%ymm6, %ymm1, %ymm10
	vpmullw	%ymm10, %ymm9, %ymm9
	vpshufb	%ymm3, %ymm1, %ymm10
	vpshufb	%ymm4, %ymm1, %ymm1
	vpxor	%ymm9, %ymm0, %ymm0
	vpermq	$170, %ymm2, %ymm9
	vpermq	$255, %ymm2, %ymm2
	vpmullw	%ymm10, %ymm9, %ymm9
	vpmullw	%ymm2, %ymm1, %ymm1
	vpxor	(%r14), %ymm0, %ymm0
	vpxor	%ymm1, %ymm9, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, (%r14)
	cmpq	%r15, %rax
	jne	.L45
	incl	%edx
	addq	$32, %r14
	leaq	32(%rax), %r15
	cmpl	$5, %edx
	jne	.L48
	movl	20(%rsp), %eax
	addq	$384, %rbx
	addq	$160, %r12
	addl	$24, %eax
	cmpl	%r8d, %eax
	jne	.L50
	movq	24(%rsp), %rdx
	addq	$24, %rsi
	movq	32(%rsp), %r15
	leal	576(%rax), %r8d
	addq	$9216, %rcx
	addq	$3840, %rdx
	cmpq	$120, %rsi
	jne	.L44
	movl	$7864440, %edx
	movq	40(%rsp), %r14
	vpcmpeqd	%ymm2, %ymm2, %ymm2
	leaq	29024(%rsp), %r12
	vmovd	%edx, %xmm7
	movl	$3932220, %edx
	leaq	19200(%r11), %rcx
	movq	%r11, %rbx
	vmovd	%edx, %xmm6
	leaq	46080(%r14), %rax
	vpbroadcastd	%xmm7, %ymm7
	movl	$1966110, %edx
	vmovd	%edx, %xmm5
	vpsrlw	$12, %ymm2, %ymm2
	vpbroadcastd	%xmm6, %ymm6
	vpbroadcastd	%xmm5, %ymm5
.L51:
	vmovdqa	(%rbx), %ymm1
	vmovdqa	32(%rbx), %ymm0
	addq	$64, %rbx
	addq	$32, %rax
	vpsrlw	$9, %ymm1, %ymm9
	vpsrlw	$6, %ymm1, %ymm8
	vpand	%ymm6, %ymm8, %ymm8
	vpand	%ymm7, %ymm9, %ymm9
	vpxor	%ymm8, %ymm9, %ymm9
	vpsrlw	$3, %ymm1, %ymm8
	vpand	%ymm2, %ymm1, %ymm1
	vpand	%ymm5, %ymm8, %ymm8
	vpxor	%ymm1, %ymm8, %ymm1
	vpsrlw	$6, %ymm0, %ymm8
	vpxor	%ymm1, %ymm9, %ymm9
	vpsrlw	$9, %ymm0, %ymm1
	vpand	%ymm6, %ymm8, %ymm8
	vpand	%ymm7, %ymm1, %ymm1
	vpxor	%ymm8, %ymm1, %ymm1
	vpsrlw	$3, %ymm0, %ymm8
	vpand	%ymm2, %ymm0, %ymm0
	vpand	%ymm5, %ymm8, %ymm8
	vpxor	%ymm0, %ymm8, %ymm0
	vmovdqa	-32(%rax), %ymm8
	vpxor	%ymm0, %ymm1, %ymm1
	vpsrlw	$3, %ymm9, %ymm0
	vpand	%ymm5, %ymm0, %ymm0
	vpxor	%ymm9, %ymm0, %ymm0
	vpsrlw	$4, %ymm9, %ymm9
	vpxor	%ymm9, %ymm0, %ymm0
	vpmovzxbw	%xmm8, %ymm9
	vpand	%ymm2, %ymm0, %ymm0
	vpxor	%ymm9, %ymm0, %ymm0
	vmovdqa	%ymm0, -64(%rbx)
	vpsrlw	$3, %ymm1, %ymm0
	vpand	%ymm5, %ymm0, %ymm0
	vpxor	%ymm1, %ymm0, %ymm0
	vpsrlw	$4, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vextracti128	$0x1, %ymm8, %xmm1
	vpand	%ymm2, %ymm0, %ymm0
	vpmovzxbw	%xmm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, -32(%rbx)
	cmpq	%rbx, %rcx
	jne	.L51
	xorl	%esi, %esi
	movl	$4000, %edx
	vzeroupper
	call	memset@PLT
	vmovdqa	.LC34(%rip), %ymm5
	vmovdqa	.LC35(%rip), %ymm6
	vmovdqa	.LC28(%rip), %ymm3
	vmovdqa	.LC29(%rip), %ymm4
	movq	%rax, %rdi
	movq	%rax, %r9
	movl	$1920, %r8d
.L52:
	leal	-1920(%r8), %esi
	leaq	64(%rsp), %rcx
	movq	%r15, %r10
.L56:
	movq	%r9, %rdx
	movq	%r10, %rbx
	xorl	%r11d, %r11d
.L53:
	vmovdqa	(%rbx), %ymm0
	vmovdqa	(%rcx), %ymm9
	addq	$32, %r11
	addq	$32, %rbx
	addq	$32, %rdx
	vpermq	$0, %ymm0, %ymm8
	vpermq	$85, %ymm0, %ymm7
	vpshufb	%ymm5, %ymm9, %ymm1
	vpshufb	%ymm6, %ymm9, %ymm10
	vpmullw	%ymm8, %ymm1, %ymm1
	vpermq	$170, %ymm0, %ymm2
	vpmullw	%ymm7, %ymm10, %ymm10
	vpermq	$255, %ymm0, %ymm0
	vpxor	%ymm10, %ymm1, %ymm1
	vpshufb	%ymm4, %ymm9, %ymm10
	vpshufb	%ymm3, %ymm9, %ymm9
	vpmullw	%ymm0, %ymm10, %ymm10
	vpmullw	%ymm2, %ymm9, %ymm9
	vpxor	-32(%rdx), %ymm1, %ymm1
	vpxor	%ymm9, %ymm10, %ymm9
	vpxor	%ymm9, %ymm1, %ymm1
	vmovdqa	%ymm1, -32(%rdx)
	vmovdqa	32(%rcx), %ymm9
	vpshufb	%ymm5, %ymm9, %ymm1
	vpshufb	%ymm6, %ymm9, %ymm10
	vpmullw	%ymm7, %ymm10, %ymm10
	vpmullw	%ymm8, %ymm1, %ymm1
	vpxor	%ymm10, %ymm1, %ymm1
	vpshufb	%ymm4, %ymm9, %ymm10
	vpshufb	%ymm3, %ymm9, %ymm9
	vpmullw	%ymm0, %ymm10, %ymm10
	vpmullw	%ymm2, %ymm9, %ymm9
	vpxor	128(%rdx), %ymm1, %ymm1
	vpxor	%ymm9, %ymm10, %ymm9
	vpxor	%ymm9, %ymm1, %ymm1
	vmovdqa	%ymm1, 128(%rdx)
	vmovdqa	64(%rcx), %ymm9
	vpshufb	%ymm5, %ymm9, %ymm1
	vpshufb	%ymm6, %ymm9, %ymm10
	vpmullw	%ymm7, %ymm10, %ymm10
	vpmullw	%ymm8, %ymm1, %ymm1
	vpxor	%ymm10, %ymm1, %ymm1
	vpshufb	%ymm3, %ymm9, %ymm10
	vpshufb	%ymm4, %ymm9, %ymm9
	vpmullw	%ymm2, %ymm10, %ymm10
	vpmullw	%ymm0, %ymm9, %ymm9
	vpxor	288(%rdx), %ymm1, %ymm1
	vpxor	%ymm9, %ymm10, %ymm9
	vpxor	%ymm9, %ymm1, %ymm1
	vmovdqa	%ymm1, 288(%rdx)
	vmovdqa	96(%rcx), %ymm9
	vpshufb	%ymm5, %ymm9, %ymm1
	vpshufb	%ymm6, %ymm9, %ymm10
	vpmullw	%ymm7, %ymm10, %ymm10
	vpmullw	%ymm8, %ymm1, %ymm1
	vpxor	%ymm10, %ymm1, %ymm1
	vpshufb	%ymm3, %ymm9, %ymm10
	vpshufb	%ymm4, %ymm9, %ymm9
	vpmullw	%ymm2, %ymm10, %ymm10
	vpmullw	%ymm0, %ymm9, %ymm9
	vpxor	448(%rdx), %ymm1, %ymm1
	vpxor	%ymm9, %ymm10, %ymm9
	vpxor	%ymm9, %ymm1, %ymm1
	vmovdqa	%ymm1, 448(%rdx)
	vmovdqa	128(%rcx), %ymm9
	vpshufb	%ymm5, %ymm9, %ymm1
	vpmullw	%ymm8, %ymm1, %ymm1
	vpshufb	%ymm6, %ymm9, %ymm8
	vpmullw	%ymm7, %ymm8, %ymm7
	vpxor	%ymm7, %ymm1, %ymm1
	vpshufb	%ymm3, %ymm9, %ymm7
	vpmullw	%ymm2, %ymm7, %ymm7
	vpshufb	%ymm4, %ymm9, %ymm2
	vpxor	608(%rdx), %ymm1, %ymm1
	vpmullw	%ymm0, %ymm2, %ymm0
	vpxor	%ymm0, %ymm7, %ymm0
	vpxor	%ymm0, %ymm1, %ymm0
	vmovdqa	%ymm0, 608(%rdx)
	cmpq	$160, %r11
	jne	.L53
	addl	$80, %esi
	addq	$160, %r10
	addq	$160, %rcx
	cmpl	%r8d, %esi
	jne	.L56
	leal	1920(%rsi), %r8d
	addq	$800, %r9
	addq	$3840, %r15
	cmpl	$9600, %esi
	jne	.L52
	movq	%rdi, %rdx
	xorl	%esi, %esi
	movl	$120, %r8d
.L55:
	leal	-120(%r8), %ecx
	movq	%r14, %r10
	movq	%rdx, %r15
	movq	%rdx, %r11
.L62:
	movq	%rax, 40(%rsp)
	leaq	64(%rsp), %rbx
	movq	%r10, %rdx
	movq	%r10, 32(%rsp)
.L60:
	vpmovzxbw	55680(%rdx), %ymm2
	movq	%r15, %rax
	movq	%rbx, %r10
	xorl	%r9d, %r9d
	vpshufb	%ymm5, %ymm2, %ymm9
	vpshufb	%ymm6, %ymm2, %ymm8
	vpshufb	%ymm3, %ymm2, %ymm7
	vpshufb	%ymm4, %ymm2, %ymm2
.L57:
	vmovdqa	(%r10), %ymm1
	addq	$32, %r9
	addq	$32, %r10
	addq	$32, %rax
	vpermq	$85, %ymm1, %ymm0
	vpermq	$0, %ymm1, %ymm10
	vpmullw	%ymm10, %ymm9, %ymm10
	vpmullw	%ymm0, %ymm8, %ymm0
	vpxor	%ymm10, %ymm0, %ymm0
	vpermq	$255, %ymm1, %ymm10
	vpermq	$170, %ymm1, %ymm1
	vpmullw	%ymm10, %ymm2, %ymm10
	vpmullw	%ymm1, %ymm7, %ymm1
	vpxor	-32(%rax), %ymm0, %ymm0
	vpxor	%ymm1, %ymm10, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, -32(%rax)
	cmpq	$160, %r9
	jne	.L57
	addq	$160, %rbx
	addq	$16, %rdx
	cmpq	%rdi, %rbx
	jne	.L60
	movq	32(%rsp), %r10
	addl	$24, %ecx
	movq	40(%rsp), %rax
	addq	$160, %r15
	addq	$384, %r10
	cmpl	%r8d, %ecx
	jne	.L62
	addq	$5, %rsi
	leal	120(%rcx), %r8d
	leaq	800(%r11), %rdx
	addq	$1920, %r14
	cmpq	$25, %rsi
	jne	.L55
	movl	$505290270, %ebx
	movl	$2021161080, %esi
	movl	$1010580540, %ecx
	movl	$522133279, %edx
	vmovd	%ebx, %xmm3
	movl	$252645135, %ebx
	vpcmpeqd	%ymm1, %ymm1, %ymm1
	movq	%r12, %rdi
	vmovd	%esi, %xmm8
	vmovd	%ecx, %xmm7
	vmovd	%ebx, %xmm4
	vmovd	%edx, %xmm6
	leaq	31008(%rsp), %r8
	vpbroadcastd	%xmm8, %ymm8
	vpsrlw	$8, %ymm1, %ymm1
	vpbroadcastd	%xmm7, %ymm7
	vpbroadcastd	%xmm3, %ymm5
	vpbroadcastd	%xmm4, %ymm2
	vpbroadcastd	%xmm6, %ymm6
.L63:
	vmovdqa	32(%rax), %ymm10
	vmovdqa	(%rax), %ymm0
	addq	$32, %rdi
	addq	$64, %rax
	vpsrlw	$9, %ymm0, %ymm9
	vpsrlw	$9, %ymm10, %ymm11
	vpand	%ymm11, %ymm1, %ymm11
	vpsrlw	$6, %ymm10, %ymm12
	vpand	%ymm9, %ymm1, %ymm9
	vpackuswb	%ymm11, %ymm9, %ymm9
	vpand	%ymm12, %ymm1, %ymm12
	vpermq	$216, %ymm9, %ymm9
	vpand	%ymm9, %ymm8, %ymm11
	vpsrlw	$6, %ymm0, %ymm9
	vpand	%ymm9, %ymm1, %ymm9
	vpackuswb	%ymm12, %ymm9, %ymm9
	vpsrlw	$3, %ymm0, %ymm12
	vpand	%ymm0, %ymm1, %ymm0
	vpermq	$216, %ymm9, %ymm9
	vpand	%ymm12, %ymm1, %ymm12
	vpand	%ymm9, %ymm7, %ymm9
	vpxor	%ymm9, %ymm11, %ymm11
	vpsrlw	$3, %ymm10, %ymm9
	vpand	%ymm9, %ymm1, %ymm9
	vpackuswb	%ymm9, %ymm12, %ymm12
	vpand	%ymm10, %ymm1, %ymm9
	vpackuswb	%ymm9, %ymm0, %ymm0
	vpermq	$216, %ymm12, %ymm12
	vpermq	$216, %ymm0, %ymm0
	vpand	%ymm12, %ymm5, %ymm12
	vpand	%ymm0, %ymm2, %ymm0
	vpxor	%ymm0, %ymm12, %ymm9
	vpxor	%ymm9, %ymm11, %ymm9
	vpsrlw	$3, %ymm9, %ymm0
	vpsrlw	$4, %ymm9, %ymm10
	vpand	%ymm0, %ymm6, %ymm0
	vpand	%ymm2, %ymm10, %ymm10
	vpand	%ymm5, %ymm0, %ymm0
	vpxor	%ymm9, %ymm10, %ymm9
	vpxor	%ymm9, %ymm0, %ymm0
	vpand	%ymm2, %ymm0, %ymm0
	vmovdqa	%ymm0, -32(%rdi)
	cmpq	%rdi, %r8
	jne	.L63
	vmovdqa	7888(%rsp), %xmm7
	vmovdqa	7872(%rsp), %xmm0
	vpcmpeqd	%xmm1, %xmm1, %xmm1
	vmovd	%esi, %xmm6
	vpsrlw	$8, %xmm1, %xmm1
	vpbroadcastd	%xmm3, %xmm3
	vpbroadcastd	%xmm4, %xmm4
	movq	56(%rsp), %rax
	vpsrlw	$9, %xmm0, %xmm2
	vpsrlw	$9, %xmm7, %xmm5
	vpand	%xmm5, %xmm1, %xmm5
	vpand	%xmm2, %xmm1, %xmm2
	addq	$16, %rax
	vpackuswb	%xmm5, %xmm2, %xmm2
	vpbroadcastd	%xmm6, %xmm5
	vpand	%xmm5, %xmm2, %xmm2
	vpsrlw	$6, %xmm0, %xmm6
	vpsrlw	$6, %xmm7, %xmm5
	vpand	%xmm6, %xmm1, %xmm6
	vpand	%xmm5, %xmm1, %xmm5
	vpackuswb	%xmm5, %xmm6, %xmm6
	vmovd	%ecx, %xmm5
	vpbroadcastd	%xmm5, %xmm5
	vpand	%xmm5, %xmm6, %xmm6
	vpxor	%xmm6, %xmm2, %xmm5
	vpsrlw	$3, %xmm0, %xmm2
	vpand	%xmm0, %xmm1, %xmm0
	vpsrlw	$3, %xmm7, %xmm6
	vpand	%xmm2, %xmm1, %xmm2
	vpand	%xmm6, %xmm1, %xmm6
	vpand	%xmm7, %xmm1, %xmm1
	vmovd	%edx, %xmm7
	movl	$-252645136, %edx
	vpackuswb	%xmm1, %xmm0, %xmm0
	vpackuswb	%xmm6, %xmm2, %xmm2
	vpand	%xmm3, %xmm2, %xmm2
	vpand	%xmm4, %xmm0, %xmm0
	vpxor	%xmm0, %xmm2, %xmm0
	vpxor	%xmm0, %xmm5, %xmm2
	vmovd	%edx, %xmm5
	vpsrlw	$4, %xmm2, %xmm0
	vpbroadcastd	%xmm5, %ymm5
	vpand	%xmm4, %xmm0, %xmm0
	vpxor	%xmm2, %xmm0, %xmm1
	vpsrlw	$3, %xmm2, %xmm2
	vpbroadcastd	%xmm7, %xmm0
	vpand	%xmm2, %xmm0, %xmm0
	vpand	%xmm3, %xmm0, %xmm0
	vpcmpeqd	%ymm3, %ymm3, %ymm3
	vpxor	%xmm0, %xmm1, %xmm0
	vmovdqu	0(%r13), %xmm1
	vpsrlw	$8, %ymm3, %ymm3
	vpand	%xmm4, %xmm0, %xmm0
	vmovdqu	%xmm1, -16(%rax)
	vmovdqa	%xmm0, 31008(%rsp)
.L64:
	vmovdqa	(%r12), %ymm2
	vmovdqa	32(%r12), %ymm4
	addq	$64, %r12
	addq	$32, %rax
	vpsrlw	$8, %ymm2, %ymm1
	vpsrlw	$8, %ymm4, %ymm6
	vpand	%ymm2, %ymm3, %ymm2
	vpackuswb	%ymm6, %ymm1, %ymm1
	vpand	%ymm4, %ymm3, %ymm4
	vpermq	$216, %ymm1, %ymm1
	vpackuswb	%ymm4, %ymm2, %ymm2
	vpsllw	$4, %ymm1, %ymm1
	vpermq	$216, %ymm2, %ymm2
	vpand	%ymm1, %ymm5, %ymm1
	vpxor	%ymm2, %ymm1, %ymm1
	vmovdqu	%ymm1, -32(%rax)
	cmpq	%r8, %r12
	jne	.L64
	vmovdqa	%xmm0, %xmm1
	vpsrldq	$8, %xmm0, %xmm0
	vmovdqa	.LC43(%rip), %xmm2
	movq	56(%rsp), %rax
	vpunpcklqdq	%xmm0, %xmm1, %xmm0
	vpshufb	.LC42(%rip), %xmm0, %xmm1
	vpshufb	%xmm2, %xmm0, %xmm0
	vpmovzxbw	%xmm1, %xmm1
	vpsllw	$4, %xmm1, %xmm1
	vpshufb	%xmm2, %xmm1, %xmm1
	vpxor	%xmm0, %xmm1, %xmm1
	vmovq	%xmm1, 1008(%rax)
	movq	48(%rsp), %rax
	vmovdqu	0(%r13), %ymm0
	vmovdqu	%ymm0, (%rax)
	vmovdqu	32(%r13), %xmm0
	vmovdqu	%xmm0, 32(%rax)
	movq	132984(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L77
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
.L76:
	.cfi_restore_state
	movl	$0, first_time(%rip)
	call	init_vector_table
	jmp	.L41
.L77:
	vzeroupper
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE7300:
	.size	_snova_24_5_16_4_aes_SNOVA_OPT_genkeys, .-_snova_24_5_16_4_aes_SNOVA_OPT_genkeys
	.p2align 4
	.globl	_snova_24_5_16_4_aes_SNOVA_OPT_sk_expand
	.type	_snova_24_5_16_4_aes_SNOVA_OPT_sk_expand, @function
_snova_24_5_16_4_aes_SNOVA_OPT_sk_expand:
.LFB7301:
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
	movq	%rdi, %r13
	pushq	%r12
	pushq	%rbx
	andq	$-32, %rsp
	subq	$144544, %rsp
	.cfi_offset 12, -48
	.cfi_offset 3, -56
	movq	%fs:40, %rbx
	movq	%rbx, 144536(%rsp)
	movq	%rsi, %rbx
	movl	first_time(%rip), %eax
	testl	%eax, %eax
	jne	.L112
.L79:
	movl	$191248, %edx
	xorl	%esi, %esi
	leaq	38656(%rsp), %r14
	movq	%r13, %rdi
	call	memset@PLT
	vmovdqu	(%rbx), %ymm0
	leaq	191216(%r13), %rsi
	movq	%r14, %rdi
	vmovdqu	%ymm0, 191200(%r13)
	vmovdqu	32(%rbx), %xmm0
	leaq	40576(%rsp), %rbx
	vmovdqu	%xmm0, 191232(%r13)
	vzeroupper
	call	expand_T12
	movl	$286331153, %ecx
	leaq	134560(%r13), %rdx
	vmovd	%ecx, %xmm3
	movq	%r14, %rax
	vpbroadcastd	%xmm3, %ymm3
.L80:
	vmovdqa	(%rax), %ymm0
	addq	$32, %rax
	addq	$64, %rdx
	vpmovzxbw	%xmm0, %ymm2
	vextracti128	$0x1, %ymm0, %xmm0
	vpsllw	$3, %ymm2, %ymm4
	vpsllw	$9, %ymm2, %ymm1
	vpmovzxbw	%xmm0, %ymm0
	vpor	%ymm4, %ymm1, %ymm1
	vpsllw	$6, %ymm2, %ymm4
	vpor	%ymm2, %ymm4, %ymm2
	vpor	%ymm2, %ymm1, %ymm1
	vpsllw	$3, %ymm0, %ymm2
	vpand	%ymm3, %ymm1, %ymm1
	vmovdqu	%ymm1, -64(%rdx)
	vpsllw	$9, %ymm0, %ymm1
	vpor	%ymm2, %ymm1, %ymm1
	vpsllw	$6, %ymm0, %ymm2
	vpor	%ymm0, %ymm2, %ymm0
	vpor	%ymm0, %ymm1, %ymm0
	vpand	%ymm3, %ymm0, %ymm0
	vmovdqu	%ymm0, -32(%rdx)
	cmpq	%rbx, %rax
	jne	.L80
	leaq	19456(%rsp), %r12
	movl	$16, %edx
	leaq	191200(%r13), %rsi
	vzeroupper
	movq	%r12, %rdi
	call	snova_pk_expander_init@PLT
	movq	%r12, %rdx
	movq	%rbx, %rdi
	movl	$34640, %esi
	call	snova_pk_expander@PLT
	movl	$252645135, %edi
	movq	%rbx, %rdx
	leaq	144480(%rsp), %rcx
	vmovd	%edi, %xmm1
	leaq	75232(%rsp), %rax
	vpbroadcastd	%xmm1, %ymm4
.L81:
	vmovdqa	(%rdx), %ymm0
	addq	$64, %rax
	addq	$32, %rdx
	vpsrlw	$4, %ymm0, %ymm3
	vpand	%ymm4, %ymm0, %ymm0
	vpand	%ymm3, %ymm4, %ymm3
	vpunpcklbw	%ymm3, %ymm0, %ymm2
	vpunpckhbw	%ymm3, %ymm0, %ymm0
	vperm2i128	$32, %ymm0, %ymm2, %ymm3
	vperm2i128	$49, %ymm0, %ymm2, %ymm2
	vmovdqa	%ymm3, -64(%rax)
	vmovdqa	%ymm2, -32(%rax)
	cmpq	%rcx, %rax
	jne	.L81
	vmovdqa	75200(%rsp), %xmm0
	vpbroadcastd	%xmm1, %xmm1
	movq	%r13, %rdx
	leaq	75232(%rsp), %rax
	leaq	121312(%rsp), %rcx
	vpsrlw	$4, %xmm0, %xmm2
	vpand	%xmm1, %xmm0, %xmm0
	vpand	%xmm2, %xmm1, %xmm2
	vpunpcklbw	%xmm2, %xmm0, %xmm1
	vpunpckhbw	%xmm2, %xmm0, %xmm0
	vmovdqa	%xmm1, 144480(%rsp)
	vmovdqa	%xmm0, 144496(%rsp)
.L82:
	vmovdqa	(%rax), %ymm0
	addq	$32, %rax
	addq	$64, %rdx
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqu	%ymm1, -64(%rdx)
	vmovdqu	%ymm0, -32(%rdx)
	cmpq	%rcx, %rax
	jne	.L82
	xorl	%esi, %esi
	leaq	256(%rsp), %rdi
	movl	$19200, %edx
	vzeroupper
	call	memset@PLT
	vmovdqa	.LC35(%rip), %ymm10
	vmovdqa	.LC34(%rip), %ymm9
	vmovdqa	.LC29(%rip), %ymm12
	vmovdqa	.LC28(%rip), %ymm11
	movq	%rax, %rcx
	movq	%rax, %r9
	leaq	18432(%r13), %rdi
	xorl	%eax, %eax
.L83:
	leaq	-18432(%rdi), %r11
	leaq	134560(%r13), %rsi
.L87:
	vmovdqu	(%rsi), %ymm1
	vmovdqu	32(%rsi), %ymm0
	movq	%r9, %rdx
	movq	%r11, %r10
	vmovdqu	64(%rsi), %ymm7
	vmovdqu	96(%rsi), %ymm6
	xorl	%r8d, %r8d
	vpshufb	%ymm12, %ymm1, %ymm4
	vmovdqu	128(%rsi), %ymm5
	vpshufb	%ymm10, %ymm1, %ymm13
	vpshufb	%ymm9, %ymm1, %ymm8
	vmovdqa	%ymm4, 224(%rsp)
	vpshufb	%ymm11, %ymm1, %ymm4
	vmovdqa	%ymm4, 192(%rsp)
	vpshufb	%ymm9, %ymm0, %ymm4
	vmovdqa	%ymm4, 160(%rsp)
	vpshufb	%ymm10, %ymm0, %ymm4
	vmovdqa	%ymm4, 128(%rsp)
	vpshufb	%ymm11, %ymm0, %ymm4
	vmovdqa	%ymm4, 96(%rsp)
	vpshufb	%ymm12, %ymm0, %ymm4
	vmovdqa	%ymm4, 64(%rsp)
	vpshufb	%ymm10, %ymm7, %ymm4
	vmovdqa	%ymm4, 32(%rsp)
	vpshufb	%ymm9, %ymm7, %ymm4
	vmovdqa	%ymm4, (%rsp)
.L84:
	vmovdqu	(%r10), %ymm0
	addq	$32, %r8
	addq	$32, %r10
	addq	$32, %rdx
	vpermq	$0, %ymm0, %ymm4
	vpermq	$85, %ymm0, %ymm3
	vpermq	$170, %ymm0, %ymm2
	vpmullw	%ymm4, %ymm8, %ymm14
	vpmullw	%ymm3, %ymm13, %ymm1
	vpermq	$255, %ymm0, %ymm0
	vpmullw	192(%rsp), %ymm2, %ymm15
	vpxor	%ymm14, %ymm1, %ymm1
	vpmullw	224(%rsp), %ymm0, %ymm14
	vpxor	%ymm15, %ymm14, %ymm14
	vpmullw	64(%rsp), %ymm0, %ymm15
	vpxor	-32(%rdx), %ymm1, %ymm1
	vpxor	%ymm14, %ymm1, %ymm1
	vpmullw	128(%rsp), %ymm3, %ymm14
	vmovdqa	%ymm1, -32(%rdx)
	vpmullw	160(%rsp), %ymm4, %ymm1
	vpxor	%ymm14, %ymm1, %ymm1
	vpmullw	96(%rsp), %ymm2, %ymm14
	vpxor	736(%rdx), %ymm1, %ymm1
	vpxor	%ymm15, %ymm14, %ymm14
	vpshufb	%ymm12, %ymm7, %ymm15
	vpmullw	%ymm0, %ymm15, %ymm15
	vpxor	%ymm14, %ymm1, %ymm1
	vpmullw	(%rsp), %ymm4, %ymm14
	vmovdqa	%ymm1, 736(%rdx)
	vpmullw	32(%rsp), %ymm3, %ymm1
	vpxor	%ymm14, %ymm1, %ymm1
	vpshufb	%ymm11, %ymm7, %ymm14
	vpmullw	%ymm2, %ymm14, %ymm14
	vpxor	1504(%rdx), %ymm1, %ymm1
	vpxor	%ymm15, %ymm14, %ymm14
	vpshufb	%ymm12, %ymm6, %ymm15
	vpxor	%ymm14, %ymm1, %ymm1
	vpmullw	%ymm0, %ymm15, %ymm15
	vpshufb	%ymm10, %ymm6, %ymm14
	vmovdqa	%ymm1, 1504(%rdx)
	vpshufb	%ymm9, %ymm6, %ymm1
	vpmullw	%ymm3, %ymm14, %ymm14
	vpmullw	%ymm4, %ymm1, %ymm1
	vpxor	%ymm14, %ymm1, %ymm1
	vpshufb	%ymm11, %ymm6, %ymm14
	vpmullw	%ymm2, %ymm14, %ymm14
	vpxor	2272(%rdx), %ymm1, %ymm1
	vpxor	%ymm15, %ymm14, %ymm14
	vpxor	%ymm14, %ymm1, %ymm1
	vmovdqa	%ymm1, 2272(%rdx)
	vpshufb	%ymm9, %ymm5, %ymm1
	vpmullw	%ymm4, %ymm1, %ymm1
	vpshufb	%ymm10, %ymm5, %ymm4
	vpmullw	%ymm3, %ymm4, %ymm3
	vpxor	%ymm3, %ymm1, %ymm1
	vpxor	3040(%rdx), %ymm1, %ymm3
	vpshufb	%ymm11, %ymm5, %ymm1
	vpmullw	%ymm2, %ymm1, %ymm1
	vpshufb	%ymm12, %ymm5, %ymm2
	vpmullw	%ymm0, %ymm2, %ymm0
	vpxor	%ymm0, %ymm1, %ymm0
	vpxor	%ymm0, %ymm3, %ymm0
	vmovdqa	%ymm0, 3040(%rdx)
	cmpq	$768, %r8
	jne	.L84
	addq	$768, %r11
	addq	$160, %rsi
	cmpq	%r11, %rdi
	jne	.L87
	addl	$24, %eax
	addq	$18432, %rdi
	addq	$3840, %r9
	cmpl	$120, %eax
	jne	.L83
	vpcmpeqd	%ymm2, %ymm2, %ymm2
	leaq	138400(%r13), %rdx
	leaq	130912(%rsp), %rsi
	movq	%rcx, %rax
	movl	$7864440, %ecx
	vpsrlw	$12, %ymm2, %ymm2
	vmovd	%ecx, %xmm5
	movl	$3932220, %ecx
	vmovd	%ecx, %xmm4
	movl	$1966110, %ecx
	vpbroadcastd	%xmm5, %ymm5
	vmovd	%ecx, %xmm3
	vpbroadcastd	%xmm4, %ymm4
	vpbroadcastd	%xmm3, %ymm3
.L88:
	vmovdqa	(%rax), %ymm1
	vmovdqa	32(%rax), %ymm0
	addq	$64, %rax
	addq	$64, %rdx
	addq	$32, %rsi
	vpsrlw	$9, %ymm1, %ymm7
	vpsrlw	$6, %ymm1, %ymm6
	vpand	%ymm4, %ymm6, %ymm6
	vpand	%ymm5, %ymm7, %ymm7
	vpxor	%ymm6, %ymm7, %ymm7
	vpsrlw	$3, %ymm1, %ymm6
	vpand	%ymm2, %ymm1, %ymm1
	vpand	%ymm3, %ymm6, %ymm6
	vpxor	%ymm1, %ymm6, %ymm1
	vpsrlw	$6, %ymm0, %ymm6
	vpxor	%ymm1, %ymm7, %ymm7
	vpsrlw	$9, %ymm0, %ymm1
	vpand	%ymm4, %ymm6, %ymm6
	vpand	%ymm5, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm1
	vpsrlw	$3, %ymm0, %ymm6
	vpand	%ymm2, %ymm0, %ymm0
	vpand	%ymm3, %ymm6, %ymm6
	vpxor	%ymm0, %ymm6, %ymm0
	vmovdqa	-32(%rsi), %ymm6
	vpxor	%ymm0, %ymm1, %ymm1
	vpsrlw	$3, %ymm7, %ymm0
	vpand	%ymm3, %ymm0, %ymm0
	vpxor	%ymm7, %ymm0, %ymm0
	vpsrlw	$4, %ymm7, %ymm7
	vpxor	%ymm7, %ymm0, %ymm0
	vpmovzxbw	%xmm6, %ymm7
	vpand	%ymm2, %ymm0, %ymm0
	vpxor	%ymm7, %ymm0, %ymm0
	vmovdqu	%ymm0, -64(%rdx)
	vpsrlw	$3, %ymm1, %ymm0
	vpand	%ymm3, %ymm0, %ymm0
	vpxor	%ymm1, %ymm0, %ymm0
	vpsrlw	$4, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vextracti128	$0x1, %ymm6, %xmm1
	vpand	%ymm2, %ymm0, %ymm0
	vpmovzxbw	%xmm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vmovdqu	%ymm0, -32(%rdx)
	cmpq	%r12, %rax
	jne	.L88
	movl	$19200, %edx
	xorl	%esi, %esi
	movq	%r12, %rdi
	vzeroupper
	call	memset@PLT
	vmovdqa	.LC34(%rip), %ymm9
	vmovdqa	.LC35(%rip), %ymm10
	vmovdqa	.LC28(%rip), %ymm11
	vmovdqa	.LC29(%rip), %ymm12
	movq	%r12, %rcx
	movq	%r13, %rdx
	xorl	%eax, %eax
	leaq	3840(%r13), %r11
.L89:
	movq	%rdx, %rdi
	movq	%rcx, %r10
	leaq	120(%rax), %r15
	movq	%rcx, %rsi
.L95:
	movq	%rax, 224(%rsp)
	movq	%rdi, %r8
	movq	%r13, %r9
	movq	%rdi, 192(%rsp)
.L93:
	movq	%r10, %rax
	movq	%r9, %rdi
	xorl	%ecx, %ecx
.L90:
	vmovdqu	134560(%rdi), %ymm2
	vmovdqu	(%r8), %ymm1
	addq	$32, %rcx
	addq	$32, %rdi
	addq	$32, %rax
	vpermq	$0, %ymm2, %ymm3
	vpshufb	%ymm9, %ymm1, %ymm0
	vpermq	$85, %ymm2, %ymm4
	vpmullw	%ymm3, %ymm0, %ymm0
	vpshufb	%ymm10, %ymm1, %ymm3
	vpmullw	%ymm4, %ymm3, %ymm3
	vpshufb	%ymm11, %ymm1, %ymm4
	vpshufb	%ymm12, %ymm1, %ymm1
	vpxor	%ymm3, %ymm0, %ymm0
	vpermq	$170, %ymm2, %ymm3
	vpermq	$255, %ymm2, %ymm2
	vpmullw	%ymm4, %ymm3, %ymm3
	vpmullw	%ymm2, %ymm1, %ymm1
	vpxor	-32(%rax), %ymm0, %ymm0
	vpxor	%ymm1, %ymm3, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, -32(%rax)
	cmpq	$160, %rcx
	jne	.L90
	addq	$160, %r9
	addq	$32, %r8
	cmpq	%r11, %r9
	jne	.L93
	movq	224(%rsp), %rax
	movq	192(%rsp), %rdi
	addq	$160, %r10
	addq	$5, %rax
	addq	$768, %rdi
	cmpq	%r15, %rax
	jne	.L95
	leaq	3840(%rsi), %rcx
	addq	$18432, %rdx
	cmpq	$600, %rax
	jne	.L89
	vpcmpeqd	%ymm1, %ymm1, %ymm1
	leaq	157600(%r13), %rax
	leaq	121312(%rsp), %rdx
	movl	$7864440, %ecx
	vmovd	%ecx, %xmm4
	vpsrlw	$12, %ymm1, %ymm1
	movl	$3932220, %ecx
	vmovd	%ecx, %xmm3
	movl	$1966110, %ecx
	vpbroadcastd	%xmm4, %ymm4
	vmovd	%ecx, %xmm2
	vpbroadcastd	%xmm3, %ymm3
	vpbroadcastd	%xmm2, %ymm2
.L96:
	vmovdqa	(%r12), %ymm5
	vmovdqa	32(%r12), %ymm0
	addq	$64, %r12
	addq	$64, %rax
	addq	$32, %rdx
	vpsrlw	$9, %ymm5, %ymm7
	vpsrlw	$6, %ymm5, %ymm6
	vpand	%ymm3, %ymm6, %ymm6
	vpand	%ymm4, %ymm7, %ymm7
	vpxor	%ymm6, %ymm7, %ymm7
	vpsrlw	$3, %ymm5, %ymm6
	vpand	%ymm1, %ymm5, %ymm5
	vpand	%ymm2, %ymm6, %ymm6
	vpxor	%ymm5, %ymm6, %ymm5
	vpsrlw	$6, %ymm0, %ymm6
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrlw	$9, %ymm0, %ymm5
	vpand	%ymm3, %ymm6, %ymm6
	vpand	%ymm4, %ymm5, %ymm5
	vpxor	%ymm6, %ymm5, %ymm5
	vpsrlw	$3, %ymm0, %ymm6
	vpand	%ymm1, %ymm0, %ymm0
	vpand	%ymm2, %ymm6, %ymm6
	vpxor	%ymm0, %ymm6, %ymm0
	vmovdqa	-32(%rdx), %ymm6
	vpxor	%ymm0, %ymm5, %ymm5
	vpsrlw	$3, %ymm7, %ymm0
	vpand	%ymm2, %ymm0, %ymm0
	vpxor	%ymm7, %ymm0, %ymm0
	vpsrlw	$4, %ymm7, %ymm7
	vpxor	%ymm7, %ymm0, %ymm0
	vpmovzxbw	%xmm6, %ymm7
	vpand	%ymm1, %ymm0, %ymm0
	vpxor	%ymm7, %ymm0, %ymm0
	vmovdqu	%ymm0, -64(%rax)
	vpsrlw	$3, %ymm5, %ymm0
	vpand	%ymm2, %ymm0, %ymm0
	vpxor	%ymm5, %ymm0, %ymm0
	vpsrlw	$4, %ymm5, %ymm5
	vpxor	%ymm5, %ymm0, %ymm0
	vextracti128	$0x1, %ymm6, %xmm5
	vpand	%ymm1, %ymm0, %ymm0
	vpmovzxbw	%xmm5, %ymm5
	vpxor	%ymm5, %ymm0, %ymm0
	vmovdqu	%ymm0, -32(%rax)
	cmpq	%r14, %r12
	jne	.L96
	leaq	42176(%rsp), %rax
	vpcmpeqd	%xmm10, %xmm10, %xmm10
	leaq	140512(%rsp), %r14
	movq	%rbx, %r15
	movq	%rax, 192(%rsp)
	movl	$2021161080, %eax
	leaq	143712(%rsp), %r12
	leaq	_snova_24_5_16_4_aes_SNOVA_OPT_Smat(%rip), %rbx
	vmovd	%eax, %xmm6
	vpsrlw	$8, %xmm10, %xmm10
	movl	$1010580540, %eax
	vpbroadcastd	%xmm6, %xmm7
	vmovd	%eax, %xmm6
	movl	$505290270, %eax
	vmovdqa	%xmm7, 224(%rsp)
	vpbroadcastd	%xmm6, %xmm7
	vmovdqa	%xmm7, 160(%rsp)
	vmovd	%eax, %xmm7
	vpbroadcastd	%xmm7, %xmm15
.L97:
	movq	%r14, %rsi
	movq	%r15, %rdi
	call	be_invertible_by_add_aS
	leaq	1600(%r14), %rsi
	leaq	1600(%r15), %rdi
	call	be_invertible_by_add_aS
	movzbl	(%r12), %edx
	movzbl	3(%r12), %ecx
	movl	$15, %esi
	vmovdqa	32(%rbx), %xmm7
	vmovdqa	(%rbx), %xmm11
	testb	%dl, %dl
	vmovdqa	16(%rbx), %xmm9
	vmovdqa	48(%rbx), %xmm4
	vmovd	%edx, %xmm5
	setne	%al
	subl	%edx, %esi
	vpbroadcastw	%xmm5, %xmm5
	vmovdqa	64(%rbx), %xmm12
	addl	%esi, %eax
	cmpb	$1, %cl
	vmovdqa	96(%rbx), %xmm0
	vmovdqa	112(%rbx), %xmm6
	sbbl	%esi, %esi
	vpmullw	%xmm11, %xmm5, %xmm3
	movzbl	400(%r12), %edx
	andl	%esi, %eax
	movzbl	1(%r12), %esi
	vpmullw	%xmm9, %xmm5, %xmm5
	orl	%ecx, %eax
	movzbl	2(%r12), %ecx
	testb	%dl, %dl
	vmovd	%esi, %xmm2
	movb	%al, 3(%r12)
	movzbl	%al, %eax
	movzbl	403(%r12), %esi
	vpbroadcastw	%xmm2, %xmm2
	vmovd	%ecx, %xmm8
	vmovd	%eax, %xmm1
	movl	$252645135, %eax
	vpmullw	%xmm2, %xmm7, %xmm13
	vpmullw	%xmm2, %xmm4, %xmm2
	vpbroadcastw	%xmm1, %xmm1
	movl	$15, %ecx
	vpbroadcastw	%xmm8, %xmm8
	vpmullw	%xmm8, %xmm12, %xmm14
	vpmullw	80(%rbx), %xmm8, %xmm8
	vpxor	%xmm3, %xmm13, %xmm13
	vpmullw	%xmm0, %xmm1, %xmm3
	vpxor	%xmm5, %xmm2, %xmm5
	vpmullw	%xmm6, %xmm1, %xmm2
	vpxor	%xmm14, %xmm3, %xmm3
	vmovdqa	160(%rsp), %xmm14
	vpxor	%xmm8, %xmm2, %xmm2
	vpxor	%xmm3, %xmm13, %xmm3
	vpxor	%xmm2, %xmm5, %xmm1
	vpsrlw	$9, %xmm3, %xmm2
	vpsrlw	$9, %xmm1, %xmm5
	vpsrlw	$6, %xmm1, %xmm8
	vpand	%xmm2, %xmm10, %xmm2
	vpand	%xmm5, %xmm10, %xmm5
	vpand	%xmm8, %xmm10, %xmm8
	vpackuswb	%xmm5, %xmm2, %xmm2
	vpsrlw	$6, %xmm3, %xmm5
	vpand	%xmm5, %xmm10, %xmm5
	vpand	224(%rsp), %xmm2, %xmm2
	vpackuswb	%xmm8, %xmm5, %xmm5
	vpsrlw	$3, %xmm1, %xmm8
	vpand	%xmm1, %xmm10, %xmm1
	vpand	%xmm14, %xmm5, %xmm5
	vpand	%xmm8, %xmm10, %xmm8
	vpxor	%xmm5, %xmm2, %xmm2
	vpsrlw	$3, %xmm3, %xmm5
	vpand	%xmm3, %xmm10, %xmm3
	vpackuswb	%xmm1, %xmm3, %xmm3
	vpand	%xmm5, %xmm10, %xmm5
	vmovd	%eax, %xmm1
	movl	$522133279, %eax
	vpbroadcastd	%xmm1, %xmm1
	vpackuswb	%xmm8, %xmm5, %xmm5
	vpand	%xmm1, %xmm3, %xmm3
	vpand	%xmm15, %xmm5, %xmm5
	vpxor	%xmm3, %xmm5, %xmm5
	vmovd	%eax, %xmm3
	setne	%al
	subl	%edx, %ecx
	vpxor	%xmm5, %xmm2, %xmm2
	addl	%ecx, %eax
	vpbroadcastd	%xmm3, %xmm3
	cmpb	$1, %sil
	vpsrlw	$4, %xmm2, %xmm5
	sbbl	%ecx, %ecx
	addq	$16, %r15
	addq	$16, %r14
	vpand	%xmm1, %xmm5, %xmm5
	andl	%ecx, %eax
	movzbl	402(%r12), %ecx
	addq	$4, %r12
	vpxor	%xmm2, %xmm5, %xmm5
	vpsrlw	$3, %xmm2, %xmm2
	orl	%esi, %eax
	movzbl	397(%r12), %esi
	vpand	%xmm2, %xmm3, %xmm2
	movb	%al, 399(%r12)
	movzbl	%al, %eax
	vmovd	%ecx, %xmm8
	vpand	%xmm15, %xmm2, %xmm2
	vpbroadcastw	%xmm8, %xmm8
	vmovd	%esi, %xmm13
	vpxor	%xmm2, %xmm5, %xmm2
	vpmullw	%xmm8, %xmm12, %xmm12
	vmovd	%edx, %xmm5
	vpand	%xmm1, %xmm2, %xmm2
	vpbroadcastw	%xmm5, %xmm5
	vpbroadcastw	%xmm13, %xmm13
	vmovdqa	%xmm2, 3184(%r15)
	vpmullw	%xmm5, %xmm11, %xmm11
	vpmullw	%xmm5, %xmm9, %xmm9
	vmovd	%eax, %xmm2
	vpbroadcastw	%xmm2, %xmm2
	vpmullw	%xmm13, %xmm4, %xmm4
	vpmullw	%xmm2, %xmm0, %xmm0
	vpxor	%xmm9, %xmm4, %xmm4
	vpxor	%xmm12, %xmm0, %xmm12
	vpmullw	%xmm13, %xmm7, %xmm0
	vpxor	%xmm11, %xmm0, %xmm0
	vpxor	%xmm0, %xmm12, %xmm7
	vpmullw	%xmm2, %xmm6, %xmm0
	vpmullw	80(%rbx), %xmm8, %xmm2
	vpxor	%xmm2, %xmm0, %xmm0
	vpxor	%xmm0, %xmm4, %xmm2
	vpsrlw	$9, %xmm7, %xmm0
	vpsrlw	$9, %xmm2, %xmm4
	vpsrlw	$6, %xmm2, %xmm5
	vpand	%xmm0, %xmm10, %xmm0
	vpand	%xmm4, %xmm10, %xmm4
	vpand	%xmm5, %xmm10, %xmm5
	vpackuswb	%xmm4, %xmm0, %xmm0
	vpsrlw	$6, %xmm7, %xmm4
	vpand	%xmm4, %xmm10, %xmm4
	vpand	224(%rsp), %xmm0, %xmm0
	vpackuswb	%xmm5, %xmm4, %xmm4
	vpsrlw	$3, %xmm2, %xmm5
	vpand	%xmm2, %xmm10, %xmm2
	vpand	%xmm14, %xmm4, %xmm4
	vpand	%xmm5, %xmm10, %xmm5
	vpxor	%xmm4, %xmm0, %xmm0
	vpsrlw	$3, %xmm7, %xmm4
	vpand	%xmm7, %xmm10, %xmm7
	vpand	%xmm4, %xmm10, %xmm4
	vpackuswb	%xmm2, %xmm7, %xmm2
	vpackuswb	%xmm5, %xmm4, %xmm4
	vpand	%xmm1, %xmm2, %xmm2
	vpand	%xmm15, %xmm4, %xmm4
	vpxor	%xmm2, %xmm4, %xmm2
	vpxor	%xmm2, %xmm0, %xmm0
	vpsrlw	$4, %xmm0, %xmm2
	vpand	%xmm1, %xmm2, %xmm2
	vpxor	%xmm0, %xmm2, %xmm2
	vpsrlw	$3, %xmm0, %xmm0
	vpand	%xmm3, %xmm0, %xmm0
	vpand	%xmm15, %xmm0, %xmm0
	vpxor	%xmm0, %xmm2, %xmm0
	vpand	%xmm1, %xmm0, %xmm0
	vmovdqa	%xmm0, 4784(%r15)
	cmpq	%r15, 192(%rsp)
	jne	.L97
	movl	$286331153, %ecx
	leaq	186400(%r13), %rax
	leaq	45376(%rsp), %rdx
	vmovd	%ecx, %xmm0
	leaq	46976(%rsp), %rsi
	vpbroadcastd	%xmm0, %ymm0
.L98:
	vmovdqa	-4800(%rdx), %ymm1
	addq	$32, %rdx
	addq	$64, %rax
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpsllw	$6, %ymm3, %ymm4
	vpsllw	$9, %ymm3, %ymm2
	vpmovzxbw	%xmm1, %ymm1
	vpor	%ymm4, %ymm2, %ymm2
	vpsllw	$3, %ymm3, %ymm4
	vpor	%ymm3, %ymm4, %ymm3
	vpor	%ymm3, %ymm2, %ymm2
	vpsllw	$6, %ymm1, %ymm3
	vpand	%ymm0, %ymm2, %ymm2
	vmovdqu	%ymm2, -9664(%rax)
	vpsllw	$9, %ymm1, %ymm2
	vpor	%ymm3, %ymm2, %ymm2
	vpsllw	$3, %ymm1, %ymm3
	vpor	%ymm1, %ymm3, %ymm1
	vpor	%ymm1, %ymm2, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqu	%ymm1, -9632(%rax)
	vmovdqa	-3232(%rdx), %ymm1
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpsllw	$6, %ymm3, %ymm4
	vpsllw	$9, %ymm3, %ymm2
	vpmovzxbw	%xmm1, %ymm1
	vpor	%ymm4, %ymm2, %ymm2
	vpsllw	$3, %ymm3, %ymm4
	vpor	%ymm3, %ymm4, %ymm3
	vpor	%ymm3, %ymm2, %ymm2
	vpsllw	$6, %ymm1, %ymm3
	vpand	%ymm0, %ymm2, %ymm2
	vmovdqu	%ymm2, -6464(%rax)
	vpsllw	$9, %ymm1, %ymm2
	vpor	%ymm3, %ymm2, %ymm2
	vpsllw	$3, %ymm1, %ymm3
	vpor	%ymm1, %ymm3, %ymm1
	vpor	%ymm1, %ymm2, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqu	%ymm1, -6432(%rax)
	vmovdqa	-1632(%rdx), %ymm1
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpsllw	$6, %ymm3, %ymm4
	vpsllw	$9, %ymm3, %ymm2
	vpmovzxbw	%xmm1, %ymm1
	vpor	%ymm4, %ymm2, %ymm2
	vpsllw	$3, %ymm3, %ymm4
	vpor	%ymm3, %ymm4, %ymm3
	vpor	%ymm3, %ymm2, %ymm2
	vpsllw	$6, %ymm1, %ymm3
	vpand	%ymm0, %ymm2, %ymm2
	vmovdqu	%ymm2, -3264(%rax)
	vpsllw	$9, %ymm1, %ymm2
	vpor	%ymm3, %ymm2, %ymm2
	vpsllw	$3, %ymm1, %ymm3
	vpor	%ymm1, %ymm3, %ymm1
	vpor	%ymm1, %ymm2, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqu	%ymm1, -3232(%rax)
	vmovdqa	-32(%rdx), %ymm1
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpsllw	$6, %ymm3, %ymm4
	vpsllw	$9, %ymm3, %ymm2
	vpmovzxbw	%xmm1, %ymm1
	vpor	%ymm4, %ymm2, %ymm2
	vpsllw	$3, %ymm3, %ymm4
	vpor	%ymm3, %ymm4, %ymm3
	vpor	%ymm3, %ymm2, %ymm2
	vpsllw	$6, %ymm1, %ymm3
	vpand	%ymm0, %ymm2, %ymm2
	vmovdqu	%ymm2, -64(%rax)
	vpsllw	$9, %ymm1, %ymm2
	vpor	%ymm3, %ymm2, %ymm2
	vpsllw	$3, %ymm1, %ymm3
	vpor	%ymm1, %ymm3, %ymm1
	vpor	%ymm1, %ymm2, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqu	%ymm1, -32(%rax)
	cmpq	%rsi, %rdx
	jne	.L98
	movl	$286331153, %edi
	leaq	190400(%r13), %rax
	leaq	144112(%rsp), %rdx
	vmovd	%edi, %xmm2
	leaq	144496(%rsp), %rcx
	vpbroadcastd	%xmm2, %ymm3
.L99:
	vmovdqa	-400(%rdx), %ymm0
	addq	$32, %rdx
	addq	$64, %rax
	vpmovzxbw	%xmm0, %ymm4
	vextracti128	$0x1, %ymm0, %xmm0
	vpsllw	$6, %ymm4, %ymm5
	vpsllw	$9, %ymm4, %ymm1
	vpmovzxbw	%xmm0, %ymm0
	vpor	%ymm5, %ymm1, %ymm1
	vpsllw	$3, %ymm4, %ymm5
	vpor	%ymm4, %ymm5, %ymm4
	vpor	%ymm4, %ymm1, %ymm1
	vpsllw	$6, %ymm0, %ymm4
	vpand	%ymm3, %ymm1, %ymm1
	vmovdqu	%ymm1, -864(%rax)
	vpsllw	$9, %ymm0, %ymm1
	vpor	%ymm4, %ymm1, %ymm1
	vpsllw	$3, %ymm0, %ymm4
	vpor	%ymm0, %ymm4, %ymm0
	vpor	%ymm0, %ymm1, %ymm0
	vpand	%ymm3, %ymm0, %ymm0
	vmovdqu	%ymm0, -832(%rax)
	vmovdqu	-32(%rdx), %ymm0
	vpmovzxbw	%xmm0, %ymm4
	vextracti128	$0x1, %ymm0, %xmm0
	vpsllw	$6, %ymm4, %ymm5
	vpsllw	$9, %ymm4, %ymm1
	vpmovzxbw	%xmm0, %ymm0
	vpor	%ymm5, %ymm1, %ymm1
	vpsllw	$3, %ymm4, %ymm5
	vpor	%ymm4, %ymm5, %ymm4
	vpor	%ymm4, %ymm1, %ymm1
	vpsllw	$6, %ymm0, %ymm4
	vpand	%ymm3, %ymm1, %ymm1
	vmovdqu	%ymm1, -64(%rax)
	vpsllw	$9, %ymm0, %ymm1
	vpor	%ymm4, %ymm1, %ymm1
	vpsllw	$3, %ymm0, %ymm4
	vpor	%ymm0, %ymm4, %ymm0
	vpor	%ymm0, %ymm1, %ymm0
	vpand	%ymm3, %ymm0, %ymm0
	vmovdqu	%ymm0, -32(%rax)
	cmpq	%rcx, %rdx
	jne	.L99
	vmovdqa	144096(%rsp), %xmm0
	vpbroadcastd	%xmm2, %xmm2
	vpmovzxbw	%xmm0, %xmm3
	vpsrldq	$8, %xmm0, %xmm0
	vpsllw	$6, %xmm3, %xmm4
	vpsllw	$9, %xmm3, %xmm1
	vpmovzxbw	%xmm0, %xmm0
	vpor	%xmm4, %xmm1, %xmm1
	vpsllw	$3, %xmm3, %xmm4
	vpor	%xmm3, %xmm4, %xmm3
	vpor	%xmm3, %xmm1, %xmm1
	vpsllw	$6, %xmm0, %xmm3
	vpand	%xmm2, %xmm1, %xmm1
	vmovdqu	%xmm1, 190368(%r13)
	vpsllw	$9, %xmm0, %xmm1
	vpor	%xmm3, %xmm1, %xmm1
	vpsllw	$3, %xmm0, %xmm3
	vpor	%xmm0, %xmm3, %xmm0
	vpor	%xmm0, %xmm1, %xmm0
	vpand	%xmm2, %xmm0, %xmm0
	vmovdqu	%xmm0, 190384(%r13)
	vmovdqa	144496(%rsp), %xmm0
	vpmovzxbw	%xmm0, %xmm3
	vpsrldq	$8, %xmm0, %xmm0
	vpsllw	$6, %xmm3, %xmm4
	vpsllw	$9, %xmm3, %xmm1
	vpmovzxbw	%xmm0, %xmm0
	vpor	%xmm4, %xmm1, %xmm1
	vpsllw	$3, %xmm3, %xmm4
	vpor	%xmm3, %xmm4, %xmm3
	vpor	%xmm3, %xmm1, %xmm1
	vpsllw	$6, %xmm0, %xmm3
	vpand	%xmm2, %xmm1, %xmm1
	vmovdqu	%xmm1, 191168(%r13)
	vpsllw	$9, %xmm0, %xmm1
	vpor	%xmm3, %xmm1, %xmm1
	vpsllw	$3, %xmm0, %xmm3
	vpor	%xmm0, %xmm3, %xmm0
	vpor	%xmm0, %xmm1, %xmm0
	vpand	%xmm2, %xmm0, %xmm0
	vmovdqu	%xmm0, 191184(%r13)
	movq	144536(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L113
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
.L112:
	.cfi_restore_state
	movl	$0, first_time(%rip)
	call	init_vector_table
	jmp	.L79
.L113:
	vzeroupper
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE7301:
	.size	_snova_24_5_16_4_aes_SNOVA_OPT_sk_expand, .-_snova_24_5_16_4_aes_SNOVA_OPT_sk_expand
	.p2align 4
	.globl	_snova_24_5_16_4_aes_SNOVA_OPT_sign
	.type	_snova_24_5_16_4_aes_SNOVA_OPT_sign, @function
_snova_24_5_16_4_aes_SNOVA_OPT_sign:
.LFB7302:
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
	movq	%rsi, %rbx
	andq	$-32, %rsp
	subq	$52128, %rsp
	movq	%rdi, 200(%rsp)
	movq	%rdx, 104(%rsp)
	movq	%rcx, 96(%rsp)
	movq	%r8, 176(%rsp)
	movq	%fs:40, %rax
	movq	%rax, 52120(%rsp)
	xorl	%eax, %eax
	movl	first_time(%rip), %eax
	testl	%eax, %eax
	je	.L115
	movl	$0, first_time(%rip)
	call	init_vector_table
.L115:
	leaq	35840(%rsp), %r15
	leaq	20480(%rsp), %r14
	xorl	%r12d, %r12d
	movq	%r15, %rdi
	movq	%r15, 112(%rsp)
	call	shake256_init@PLT
	movq	200(%rsp), %rax
	movl	$16, %edx
	movq	%r15, %rdi
	leaq	191200(%rax), %rsi
	call	shake_absorb@PLT
	movq	96(%rsp), %rdx
	movq	104(%rsp), %rsi
	movq	%r15, %rdi
	call	shake_absorb@PLT
	movq	176(%rsp), %rsi
	movl	$16, %edx
	movq	%r15, %rdi
	call	shake_absorb@PLT
	movq	%r15, %rdi
	call	shake_finalize@PLT
	leaq	51200(%rsp), %rdi
	movq	%r15, %rdx
	movl	$40, %esi
	call	shake_squeeze@PLT
	vmovdqa	51200(%rsp), %ymm0
	movl	$252645135, %eax
	movq	%r14, 192(%rsp)
	vmovd	%eax, %xmm1
	movq	%rbx, 88(%rsp)
	vpbroadcastd	%xmm1, %ymm1
	vpsrlw	$4, %ymm0, %ymm2
	vpand	%ymm2, %ymm1, %ymm2
	vpand	%ymm1, %ymm0, %ymm0
	vpunpcklbw	%ymm2, %ymm0, %ymm1
	vpunpckhbw	%ymm2, %ymm0, %ymm0
	vperm2i128	$32, %ymm0, %ymm1, %ymm2
	vperm2i128	$49, %ymm0, %ymm1, %ymm1
	vmovq	51232(%rsp), %xmm0
	vmovdqa	%ymm2, 51264(%rsp)
	vmovq	.LC55(%rip), %xmm2
	vmovdqa	%ymm1, 51296(%rsp)
	vpmovzxbw	%xmm0, %xmm1
	vpsrlw	$4, %xmm1, %xmm1
	vpand	%xmm2, %xmm0, %xmm0
	vpshufb	.LC43(%rip), %xmm1, %xmm1
	vpunpcklbw	%xmm1, %xmm0, %xmm2
	vpunpcklbw	%xmm1, %xmm0, %xmm0
	vpxor	%xmm1, %xmm1, %xmm1
	vpshufd	$78, %xmm0, %xmm0
	vmovq	%xmm2, 51328(%rsp)
	vmovq	%xmm0, 51336(%rsp)
	vpxor	%xmm0, %xmm0, %xmm0
	vmovdqa	%ymm0, 51360(%rsp)
	vmovdqa	%ymm0, 51392(%rsp)
	vmovdqa	%xmm1, 51424(%rsp)
	vmovdqa	%ymm0, 51648(%rsp)
	vmovdqa	%ymm0, 51680(%rsp)
	vmovdqa	%ymm0, 51712(%rsp)
	vmovdqa	%ymm0, 51744(%rsp)
	vmovdqa	%ymm0, 51776(%rsp)
	vmovdqa	%ymm0, 51808(%rsp)
	vmovdqa	%ymm0, 51840(%rsp)
	vmovdqa	%ymm0, 51872(%rsp)
	vmovdqa	%ymm0, 51904(%rsp)
	vmovdqa	%ymm0, 51936(%rsp)
	vmovdqa	%ymm0, 51968(%rsp)
	vmovdqa	%ymm0, 52000(%rsp)
	vmovdqa	%ymm0, 52032(%rsp)
	vmovdqa	%ymm0, 52064(%rsp)
	vmovdqa	%xmm1, 52096(%rsp)
.L185:
	movq	192(%rsp), %rdi
	xorl	%esi, %esi
	movl	$15360, %edx
	vzeroupper
	call	memset@PLT
	leal	1(%r12), %eax
	movb	%al, 223(%rsp)
	cmpb	$-1, %al
	je	.L257
	leaq	544(%rsp), %rdi
	leaq	3328(%rsp), %rbx
	call	shake256_init@PLT
	movq	200(%rsp), %rax
	movl	$32, %edx
	leaq	544(%rsp), %rdi
	leaq	191216(%rax), %rsi
	call	shake_absorb@PLT
	movq	96(%rsp), %rdx
	movq	104(%rsp), %rsi
	leaq	544(%rsp), %rdi
	call	shake_absorb@PLT
	movq	176(%rsp), %rsi
	movl	$16, %edx
	leaq	544(%rsp), %rdi
	call	shake_absorb@PLT
	leaq	223(%rsp), %rsi
	movl	$1, %edx
	leaq	544(%rsp), %rdi
	call	shake_absorb@PLT
	leaq	544(%rsp), %rdi
	call	shake_finalize@PLT
	leaq	51456(%rsp), %rdi
	leaq	544(%rsp), %rdx
	movl	$192, %esi
	call	shake_squeeze@PLT
	vmovdqa	51456(%rsp), %ymm1
	movl	$252645135, %eax
	xorl	%esi, %esi
	vmovd	%eax, %xmm0
	movq	%rbx, %rdi
	movl	$3072, %edx
	vpbroadcastd	%xmm0, %ymm0
	vpsrlw	$4, %ymm1, %ymm3
	vpand	%ymm3, %ymm0, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vpunpcklbw	%ymm3, %ymm1, %ymm2
	vpunpckhbw	%ymm3, %ymm1, %ymm1
	vperm2i128	$32, %ymm1, %ymm2, %ymm3
	vperm2i128	$49, %ymm1, %ymm2, %ymm2
	vmovdqa	51488(%rsp), %ymm1
	vmovdqa	%ymm3, 51648(%rsp)
	vpsrlw	$4, %ymm1, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm2, 51680(%rsp)
	vpand	%ymm3, %ymm0, %ymm3
	vpunpcklbw	%ymm3, %ymm1, %ymm2
	vpunpckhbw	%ymm3, %ymm1, %ymm1
	vperm2i128	$32, %ymm1, %ymm2, %ymm3
	vperm2i128	$49, %ymm1, %ymm2, %ymm2
	vmovdqa	51520(%rsp), %ymm1
	vmovdqa	%ymm3, 51712(%rsp)
	vpsrlw	$4, %ymm1, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm2, 51744(%rsp)
	vpand	%ymm3, %ymm0, %ymm3
	vpunpcklbw	%ymm3, %ymm1, %ymm2
	vpunpckhbw	%ymm3, %ymm1, %ymm1
	vperm2i128	$32, %ymm1, %ymm2, %ymm3
	vperm2i128	$49, %ymm1, %ymm2, %ymm2
	vmovdqa	51552(%rsp), %ymm1
	vmovdqa	%ymm3, 51776(%rsp)
	vpsrlw	$4, %ymm1, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm2, 51808(%rsp)
	vpand	%ymm3, %ymm0, %ymm3
	vpunpcklbw	%ymm3, %ymm1, %ymm2
	vpunpckhbw	%ymm3, %ymm1, %ymm1
	vperm2i128	$32, %ymm1, %ymm2, %ymm3
	vperm2i128	$49, %ymm1, %ymm2, %ymm2
	vmovdqa	51584(%rsp), %ymm1
	vmovdqa	%ymm3, 51840(%rsp)
	vpsrlw	$4, %ymm1, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm2, 51872(%rsp)
	vpand	%ymm3, %ymm0, %ymm3
	vpunpcklbw	%ymm3, %ymm1, %ymm2
	vpunpckhbw	%ymm3, %ymm1, %ymm1
	vperm2i128	$32, %ymm1, %ymm2, %ymm3
	vperm2i128	$49, %ymm1, %ymm2, %ymm2
	vmovdqa	51616(%rsp), %ymm1
	vmovdqa	%ymm2, 51936(%rsp)
	vpsrlw	$4, %ymm1, %ymm2
	vmovdqa	%ymm3, 51904(%rsp)
	vpand	%ymm2, %ymm0, %ymm2
	vpand	%ymm0, %ymm1, %ymm0
	vpunpcklbw	%ymm2, %ymm0, %ymm1
	vpunpckhbw	%ymm2, %ymm0, %ymm0
	vperm2i128	$32, %ymm0, %ymm1, %ymm2
	vperm2i128	$49, %ymm0, %ymm1, %ymm1
	vpxor	%xmm0, %xmm0, %xmm0
	vmovdqa	%ymm2, 51968(%rsp)
	vmovdqa	%ymm1, 52000(%rsp)
	vmovdqa	%ymm0, 224(%rsp)
	vmovdqa	%ymm0, 256(%rsp)
	vmovdqa	%ymm0, 288(%rsp)
	vmovdqa	%ymm0, 320(%rsp)
	vmovdqa	%ymm0, 352(%rsp)
	vzeroupper
	call	memset@PLT
	leaq	52032(%rsp), %rax
	leaq	_snova_24_5_16_4_aes_SNOVA_OPT_Smat(%rip), %rsi
	movq	%rax, 120(%rsp)
	movq	%rbx, %rcx
	xorl	%edi, %edi
.L118:
	vmovdqa	(%rsi), %ymm3
	leaq	51648(%rsp), %r12
	movq	%rcx, %rdx
	movq	%r12, %rax
	vpshufb	.LC34(%rip), %ymm3, %ymm6
	vpshufb	.LC35(%rip), %ymm3, %ymm5
	vpshufb	.LC28(%rip), %ymm3, %ymm4
	vpshufb	.LC29(%rip), %ymm3, %ymm3
.L119:
	vmovdqa	(%rax), %xmm1
	addq	$16, %rax
	addq	$32, %rdx
	vpshufd	$0, %xmm1, %xmm0
	vpshufd	$85, %xmm1, %xmm2
	vpmovzxbw	%xmm0, %ymm0
	vpmovzxbw	%xmm2, %ymm2
	vpmullw	%ymm5, %ymm2, %ymm2
	vpmullw	%ymm6, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpshufd	$170, %xmm1, %xmm2
	vpshufd	$255, %xmm1, %xmm1
	vpmovzxbw	%xmm2, %ymm2
	vpmovzxbw	%xmm1, %ymm1
	vpxor	-32(%rdx), %ymm0, %ymm0
	vpmullw	%ymm4, %ymm2, %ymm2
	vpmullw	%ymm3, %ymm1, %ymm1
	vpxor	%ymm1, %ymm2, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, -32(%rdx)
	cmpq	%rax, 120(%rsp)
	jne	.L119
	addq	$24, %rdi
	addq	$768, %rcx
	addq	$32, %rsi
	cmpq	$96, %rdi
	jne	.L118
	movl	$7864440, %edx
	movq	%rdi, 160(%rsp)
	vpcmpeqd	%ymm2, %ymm2, %ymm2
	leaq	3072(%rbx), %rcx
	vmovd	%edx, %xmm6
	vpsrlw	$12, %ymm2, %ymm2
	movl	$3932220, %edx
	movq	%rbx, %rax
	vmovd	%edx, %xmm5
	movl	$1966110, %edx
	vpbroadcastd	%xmm6, %ymm6
	vmovd	%edx, %xmm3
	movl	$286331153, %edx
	vpbroadcastd	%xmm5, %ymm5
	vmovd	%edx, %xmm4
	vpbroadcastd	%xmm3, %ymm3
	vpbroadcastd	%xmm4, %ymm4
.L121:
	vmovdqa	(%rax), %ymm0
	addq	$32, %rax
	vpsrlw	$9, %ymm0, %ymm1
	vpsrlw	$6, %ymm0, %ymm7
	vpand	%ymm5, %ymm7, %ymm7
	vpand	%ymm6, %ymm1, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpsrlw	$3, %ymm0, %ymm7
	vpand	%ymm2, %ymm0, %ymm0
	vpand	%ymm3, %ymm7, %ymm7
	vpxor	%ymm0, %ymm7, %ymm0
	vpxor	%ymm0, %ymm1, %ymm1
	vpsrlw	$3, %ymm1, %ymm0
	vpand	%ymm3, %ymm0, %ymm0
	vpxor	%ymm1, %ymm0, %ymm0
	vpsrlw	$4, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpand	%ymm2, %ymm0, %ymm0
	vpsllw	$6, %ymm0, %ymm7
	vpsllw	$9, %ymm0, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpsllw	$3, %ymm0, %ymm7
	vpor	%ymm0, %ymm7, %ymm0
	vpor	%ymm0, %ymm1, %ymm0
	vpand	%ymm4, %ymm0, %ymm0
	vmovdqa	%ymm0, -32(%rax)
	cmpq	%rax, %rcx
	jne	.L121
	movq	112(%rsp), %r14
	xorl	%esi, %esi
	movl	$15360, %edx
	vzeroupper
	movq	%r14, %rdi
	call	memset@PLT
	xorl	%esi, %esi
	movl	$2560, %edx
	leaq	768(%rsp), %rdi
	call	memset@PLT
	movq	%r14, %rsi
	xorl	%ecx, %ecx
	movq	%rax, %r8
	movq	200(%rsp), %rax
	movq	%rax, 16(%rsp)
	leaq	18432(%rax), %r10
	movq	%r14, %rax
.L122:
	movq	%rax, 184(%rsp)
	movq	%rax, %r14
	movl	$4, %r15d
	xorl	%edi, %edi
.L128:
	movq	%rbx, %r13
	movq	%r10, %r9
	xorl	%r11d, %r11d
	subq	%rdi, %r13
.L126:
	vmovdqa	0(%r13), %ymm3
	leaq	-18432(%r9), %rdx
	movq	%r14, %rax
	vpermq	$0, %ymm3, %ymm6
	vpermq	$85, %ymm3, %ymm5
	vpermq	$170, %ymm3, %ymm4
	vpermq	$255, %ymm3, %ymm3
.L123:
	vmovdqu	(%rdx), %ymm1
	addq	$768, %rdx
	addq	$32, %rax
	vpshufb	.LC34(%rip), %ymm1, %ymm0
	vpshufb	.LC35(%rip), %ymm1, %ymm2
	vpmullw	%ymm2, %ymm5, %ymm2
	vpmullw	%ymm0, %ymm6, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpshufb	.LC28(%rip), %ymm1, %ymm2
	vpshufb	.LC29(%rip), %ymm1, %ymm1
	vpmullw	%ymm2, %ymm4, %ymm2
	vpmullw	%ymm1, %ymm3, %ymm1
	vpxor	-32(%rax), %ymm0, %ymm0
	vpxor	%ymm1, %ymm2, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, -32(%rax)
	cmpq	%rdx, %r9
	jne	.L123
	incq	%r11
	addq	$32, %r13
	addq	$32, %r9
	cmpq	$24, %r11
	jne	.L126
	addq	$384, %r15
	addq	$768, %r14
	subq	$768, %rdi
	cmpq	$1540, %r15
	jne	.L128
	movq	184(%rsp), %rax
	addq	$24, %rcx
	addq	$18432, %r10
	addq	$3072, %rax
	cmpq	$120, %rcx
	jne	.L122
	movl	$7864440, %edx
	movq	112(%rsp), %rax
	vpcmpeqd	%ymm2, %ymm2, %ymm2
	vmovd	%edx, %xmm5
	vpsrlw	$12, %ymm2, %ymm2
	movl	$3932220, %edx
	vmovd	%edx, %xmm4
	leaq	15360(%rax), %rcx
	vpbroadcastd	%xmm5, %ymm5
	movl	$1966110, %edx
	vmovd	%edx, %xmm3
	vpbroadcastd	%xmm4, %ymm4
	vpbroadcastd	%xmm3, %ymm3
.L129:
	vmovdqa	(%rax), %ymm1
	addq	$32, %rax
	vpsrlw	$9, %ymm1, %ymm0
	vpsrlw	$6, %ymm1, %ymm6
	vpand	%ymm4, %ymm6, %ymm6
	vpand	%ymm5, %ymm0, %ymm0
	vpxor	%ymm6, %ymm0, %ymm0
	vpsrlw	$3, %ymm1, %ymm6
	vpand	%ymm2, %ymm1, %ymm1
	vpand	%ymm3, %ymm6, %ymm6
	vpxor	%ymm1, %ymm6, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpsrlw	$3, %ymm0, %ymm1
	vpand	%ymm3, %ymm1, %ymm1
	vpxor	%ymm0, %ymm1, %ymm1
	vpsrlw	$4, %ymm0, %ymm0
	vpxor	%ymm0, %ymm1, %ymm0
	vpand	%ymm2, %ymm0, %ymm0
	vmovdqa	%ymm0, -32(%rax)
	cmpq	%rax, %rcx
	jne	.L129
	vmovdqa	.LC56(%rip), %ymm0
	movq	%r8, %rax
	xorl	%r10d, %r10d
	movl	$1536, %ecx
.L130:
	leal	-1536(%rcx), %r11d
	movq	%rax, %rdi
	movq	%rsi, %r9
.L134:
	movq	%rbx, %rdx
	movq	%r9, %r14
	xorl	%r13d, %r13d
.L131:
	vmovdqa	(%r14), %ymm2
	vmovq	(%rdx), %xmm8
	vmovq	8(%rdx), %xmm1
	vmovq	16(%rdx), %xmm7
	vperm2i128	$0, %ymm1, %ymm1, %ymm1
	vperm2i128	$0, %ymm8, %ymm8, %ymm8
	vmovq	24(%rdx), %xmm6
	addq	$32, %r13
	vpermq	$0, %ymm2, %ymm5
	vpermq	$85, %ymm2, %ymm4
	vpshufb	%ymm0, %ymm1, %ymm1
	addq	$32, %r14
	vpshufb	%ymm0, %ymm8, %ymm8
	vpmullw	%ymm4, %ymm1, %ymm1
	vperm2i128	$0, %ymm6, %ymm6, %ymm6
	addq	$32, %rdx
	vpmullw	%ymm5, %ymm8, %ymm8
	vperm2i128	$0, %ymm7, %ymm7, %ymm7
	vpermq	$170, %ymm2, %ymm3
	vpshufb	%ymm0, %ymm6, %ymm6
	vpermq	$255, %ymm2, %ymm2
	vpshufb	%ymm0, %ymm7, %ymm7
	vpmullw	%ymm3, %ymm7, %ymm7
	vpmullw	%ymm2, %ymm6, %ymm6
	vpxor	%ymm8, %ymm1, %ymm1
	vpxor	(%rdi), %ymm1, %ymm1
	vpxor	%ymm7, %ymm6, %ymm6
	vpxor	%ymm6, %ymm1, %ymm1
	vmovdqa	%ymm1, (%rdi)
	vmovq	736(%rdx), %xmm8
	vmovq	744(%rdx), %xmm1
	vmovq	752(%rdx), %xmm7
	vperm2i128	$0, %ymm1, %ymm1, %ymm1
	vperm2i128	$0, %ymm8, %ymm8, %ymm8
	vmovq	760(%rdx), %xmm6
	vpshufb	%ymm0, %ymm1, %ymm1
	vpshufb	%ymm0, %ymm8, %ymm8
	vperm2i128	$0, %ymm6, %ymm6, %ymm6
	vpmullw	%ymm5, %ymm8, %ymm8
	vpmullw	%ymm4, %ymm1, %ymm1
	vperm2i128	$0, %ymm7, %ymm7, %ymm7
	vpshufb	%ymm0, %ymm6, %ymm6
	vpshufb	%ymm0, %ymm7, %ymm7
	vpmullw	%ymm3, %ymm7, %ymm7
	vpmullw	%ymm2, %ymm6, %ymm6
	vpxor	%ymm8, %ymm1, %ymm1
	vpxor	128(%rdi), %ymm1, %ymm1
	vpxor	%ymm7, %ymm6, %ymm6
	vpxor	%ymm6, %ymm1, %ymm1
	vmovdqa	%ymm1, 128(%rdi)
	vmovq	1504(%rdx), %xmm8
	vmovq	1512(%rdx), %xmm1
	vmovq	1520(%rdx), %xmm7
	vperm2i128	$0, %ymm1, %ymm1, %ymm1
	vperm2i128	$0, %ymm8, %ymm8, %ymm8
	vmovq	1528(%rdx), %xmm6
	vpshufb	%ymm0, %ymm1, %ymm1
	vpshufb	%ymm0, %ymm8, %ymm8
	vperm2i128	$0, %ymm6, %ymm6, %ymm6
	vpmullw	%ymm5, %ymm8, %ymm8
	vpmullw	%ymm4, %ymm1, %ymm1
	vperm2i128	$0, %ymm7, %ymm7, %ymm7
	vpshufb	%ymm0, %ymm6, %ymm6
	vpshufb	%ymm0, %ymm7, %ymm7
	vpmullw	%ymm3, %ymm7, %ymm7
	vpmullw	%ymm2, %ymm6, %ymm6
	vpxor	%ymm8, %ymm1, %ymm1
	vpxor	256(%rdi), %ymm1, %ymm1
	vpxor	%ymm7, %ymm6, %ymm6
	vpxor	%ymm6, %ymm1, %ymm1
	vmovdqa	%ymm1, 256(%rdi)
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
	vpxor	%ymm4, %ymm1, %ymm1
	vpshufb	%ymm0, %ymm6, %ymm4
	vpmullw	%ymm3, %ymm4, %ymm3
	vpshufb	%ymm0, %ymm7, %ymm4
	vpxor	384(%rdi), %ymm1, %ymm1
	vpmullw	%ymm2, %ymm4, %ymm2
	vpxor	%ymm2, %ymm3, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vmovdqa	%ymm1, 384(%rdi)
	cmpq	$768, %r13
	jne	.L131
	addl	$384, %r11d
	addq	$768, %r9
	addq	$32, %rdi
	cmpl	%r11d, %ecx
	jne	.L134
	addl	$4, %r10d
	addl	$1536, %ecx
	addq	$3072, %rsi
	addq	$512, %rax
	cmpl	$20, %r10d
	jne	.L130
	movl	$7864440, %edx
	vpcmpeqd	%ymm3, %ymm3, %ymm3
	leaq	2560(%r8), %rcx
	movq	%r8, %rax
	vmovd	%edx, %xmm6
	vpsrlw	$12, %ymm3, %ymm3
	movl	$3932220, %edx
	vmovd	%edx, %xmm5
	movl	$1966110, %edx
	vpbroadcastd	%xmm6, %ymm6
	vmovd	%edx, %xmm4
	vpbroadcastd	%xmm5, %ymm5
	vpbroadcastd	%xmm4, %ymm4
.L135:
	vmovdqa	(%rax), %ymm2
	addq	$32, %rax
	vpsrlw	$9, %ymm2, %ymm1
	vpsrlw	$6, %ymm2, %ymm7
	vpand	%ymm5, %ymm7, %ymm7
	vpand	%ymm6, %ymm1, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpsrlw	$3, %ymm2, %ymm7
	vpand	%ymm3, %ymm2, %ymm2
	vpand	%ymm4, %ymm7, %ymm7
	vpxor	%ymm2, %ymm7, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpsrlw	$3, %ymm1, %ymm2
	vpand	%ymm4, %ymm2, %ymm2
	vpxor	%ymm1, %ymm2, %ymm2
	vpsrlw	$4, %ymm1, %ymm1
	vpxor	%ymm1, %ymm2, %ymm1
	vpand	%ymm3, %ymm1, %ymm1
	vmovdqa	%ymm1, -32(%rax)
	cmpq	%rax, %rcx
	jne	.L135
	movq	200(%rsp), %rax
	leaq	51264(%rsp), %rcx
	movl	$80, 152(%rsp)
	vpcmpeqd	%ymm3, %ymm3, %ymm3
	movq	$0, 144(%rsp)
	movq	192(%rsp), %r10
	leaq	224(%rsp), %rdx
	vpsrlw	$12, %ymm3, %ymm3
	leaq	190400(%rax), %rsi
	movq	%rax, 136(%rsp)
	leaq	512(%r8), %rax
	movq	%rax, 8(%rsp)
	movl	$7864440, %eax
	vmovd	%eax, %xmm6
	movl	$3932220, %eax
	movq	%rsi, 168(%rsp)
	vmovd	%eax, %xmm5
	movl	$0, 184(%rsp)
	movl	$1966110, %eax
	vpbroadcastd	%xmm6, %ymm6
	movq	%rcx, 128(%rsp)
	vmovd	%eax, %xmm4
	vpbroadcastd	%xmm5, %ymm5
	vpbroadcastd	%xmm4, %ymm4
.L136:
	movq	128(%rsp), %r14
	movzbl	8(%r14), %r11d
	movzbl	(%r14), %eax
	movzbl	5(%r14), %edi
	movzbl	3(%r14), %esi
	movw	%r11w, 48(%rsp)
	movzbl	9(%r14), %r11d
	movw	%ax, 72(%rsp)
	movzbl	1(%r14), %eax
	movw	%r11w, 40(%rsp)
	movzbl	10(%r14), %r11d
	movw	%di, 56(%rsp)
	movzbl	6(%r14), %edi
	movw	%r11w, 38(%rsp)
	movzbl	11(%r14), %r11d
	movw	%si, 64(%rsp)
	movzbl	2(%r14), %ecx
	movw	%r11w, 36(%rsp)
	movzbl	12(%r14), %r11d
	movw	%di, 52(%rsp)
	movzbl	4(%r14), %esi
	movw	%r11w, 34(%rsp)
	movzbl	13(%r14), %r11d
	movzbl	7(%r14), %edi
	movw	%r11w, 32(%rsp)
	movzbl	14(%r14), %r11d
	movw	%r11w, 30(%rsp)
	movzbl	15(%r14), %r11d
	movl	184(%rsp), %r14d
	movw	%r11w, 28(%rsp)
	movl	144(%rsp), %r11d
	leal	0(,%r11,4), %r13d
	movq	136(%rsp), %r11
	movq	168(%rsp), %r9
	movq	%r10, (%rsp)
	movw	%ax, 26(%rsp)
	addq	$176800, %r11
.L138:
	movl	$3435973837, %r10d
	movl	%r14d, %eax
	movslq	%r13d, %r15
	vpbroadcastw	(%r9), %ymm10
	imulq	%r10, %rax
	vpbroadcastw	2(%r9), %ymm9
	vpbroadcastw	4(%r9), %ymm8
	vpxor	%xmm2, %xmm2, %xmm2
	vpbroadcastw	6(%r9), %ymm7
	shrq	$34, %rax
	leal	(%rax,%rax,4), %r10d
	movl	%r14d, %eax
	subl	%r10d, %eax
	cltq
	salq	$9, %rax
	movq	%rax, %r10
	leaq	(%r8,%rax), %rax
	movq	%rax, 80(%rsp)
	movq	200(%rsp), %rax
	addq	8(%rsp), %r10
	leaq	(%rax,%r15,2), %r15
	movq	80(%rsp), %rax
.L137:
	vpmullw	32(%rax), %ymm9, %ymm11
	vpmullw	64(%rax), %ymm8, %ymm12
	vpmullw	(%rax), %ymm10, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vpmullw	96(%rax), %ymm7, %ymm11
	vpxor	%ymm12, %ymm11, %ymm11
	subq	$-128, %rax
	addq	$2, %r15
	vpxor	%ymm11, %ymm1, %ymm1
	vpsrlw	$9, %ymm1, %ymm11
	vpsrlw	$6, %ymm1, %ymm12
	vpand	%ymm5, %ymm12, %ymm12
	vpand	%ymm6, %ymm11, %ymm11
	vpxor	%ymm12, %ymm11, %ymm11
	vpsrlw	$3, %ymm1, %ymm12
	vpand	%ymm3, %ymm1, %ymm1
	vpand	%ymm4, %ymm12, %ymm12
	vpxor	%ymm1, %ymm12, %ymm1
	vpxor	%ymm1, %ymm11, %ymm11
	vpsrlw	$3, %ymm11, %ymm1
	vpand	%ymm4, %ymm1, %ymm1
	vpxor	%ymm11, %ymm1, %ymm1
	vpsrlw	$4, %ymm11, %ymm11
	vpxor	%ymm11, %ymm1, %ymm1
	vpbroadcastw	189598(%r15), %ymm11
	vpand	%ymm3, %ymm1, %ymm1
	vpmullw	%ymm11, %ymm1, %ymm1
	vpxor	%ymm1, %ymm2, %ymm2
	cmpq	%rax, %r10
	jne	.L137
	vpsrlw	$9, %ymm2, %ymm1
	vpsrlw	$6, %ymm2, %ymm7
	vmovdqu	3200(%r11), %ymm8
	addl	$4, %r13d
	vpand	%ymm5, %ymm7, %ymm7
	vpand	%ymm6, %ymm1, %ymm1
	incl	%r14d
	addq	$32, %r11
	vpxor	%ymm7, %ymm1, %ymm1
	vpsrlw	$3, %ymm2, %ymm7
	vpand	%ymm3, %ymm2, %ymm2
	addq	$8, %r9
	vpand	%ymm4, %ymm7, %ymm7
	vpxor	%ymm2, %ymm7, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpsrlw	$3, %ymm1, %ymm2
	vpand	%ymm4, %ymm2, %ymm2
	vpxor	%ymm1, %ymm2, %ymm2
	vpsrlw	$4, %ymm1, %ymm1
	vpxor	%ymm1, %ymm2, %ymm1
	vpermq	$85, %ymm8, %ymm2
	vpand	%ymm3, %ymm1, %ymm1
	vpshufb	.LC35(%rip), %ymm1, %ymm7
	vpshufb	.LC34(%rip), %ymm1, %ymm9
	vpmullw	%ymm7, %ymm2, %ymm2
	vpermq	$0, %ymm8, %ymm7
	vpmullw	%ymm9, %ymm7, %ymm7
	vpermq	$170, %ymm8, %ymm9
	vpxor	%ymm7, %ymm2, %ymm2
	vpshufb	.LC28(%rip), %ymm1, %ymm7
	vpmullw	%ymm7, %ymm9, %ymm9
	vpshufb	.LC29(%rip), %ymm1, %ymm7
	vpermq	$255, %ymm8, %ymm1
	vpmullw	%ymm7, %ymm1, %ymm1
	vpxor	%ymm1, %ymm9, %ymm1
	vpxor	%ymm1, %ymm2, %ymm1
	vpsrlw	$9, %ymm1, %ymm2
	vpsrlw	$6, %ymm1, %ymm7
	vpand	%ymm5, %ymm7, %ymm7
	vpand	%ymm6, %ymm2, %ymm2
	vpxor	%ymm7, %ymm2, %ymm2
	vpsrlw	$3, %ymm1, %ymm7
	vpand	%ymm3, %ymm1, %ymm1
	vpand	%ymm4, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm1
	vmovdqu	-32(%r11), %ymm7
	vpxor	%ymm1, %ymm2, %ymm1
	vpsrlw	$3, %ymm1, %ymm2
	vpshufb	.LC34(%rip), %ymm7, %ymm8
	vpshufb	.LC35(%rip), %ymm7, %ymm9
	vpand	%ymm4, %ymm2, %ymm2
	vpxor	%ymm1, %ymm2, %ymm2
	vpsrlw	$4, %ymm1, %ymm1
	vpxor	%ymm1, %ymm2, %ymm1
	vpand	%ymm3, %ymm1, %ymm1
	vpermq	$0, %ymm1, %ymm2
	vpmullw	%ymm8, %ymm2, %ymm2
	vpermq	$85, %ymm1, %ymm8
	vpmullw	%ymm9, %ymm8, %ymm8
	vpshufb	.LC28(%rip), %ymm7, %ymm9
	vpshufb	.LC29(%rip), %ymm7, %ymm7
	vpxor	%ymm8, %ymm2, %ymm2
	vpermq	$170, %ymm1, %ymm8
	vpermq	$255, %ymm1, %ymm1
	vpmullw	%ymm9, %ymm8, %ymm8
	vpmullw	%ymm7, %ymm1, %ymm1
	vpxor	(%rdx), %ymm2, %ymm2
	vpxor	%ymm1, %ymm8, %ymm1
	vpxor	%ymm1, %ymm2, %ymm1
	vmovdqa	%ymm1, (%rdx)
	cmpl	%r13d, 152(%rsp)
	jne	.L138
	xorw	8(%rdx), %si
	movzwl	64(%rsp), %r14d
	addq	$32, %rdx
	movl	%esi, %r13d
	movzwl	40(%rsp), %esi
	movzwl	56(%rsp), %r11d
	movzwl	52(%rsp), %r9d
	xorw	-28(%rdx), %cx
	xorw	-14(%rdx), %si
	movl	%ecx, %r15d
	movzwl	48(%rsp), %ecx
	movzwl	26(%rsp), %eax
	movq	(%rsp), %r10
	movw	%si, 80(%rsp)
	movzwl	38(%rsp), %esi
	xorw	-26(%rdx), %r14w
	xorw	-30(%rdx), %ax
	xorw	-22(%rdx), %r11w
	addq	$3072, %r10
	xorw	-12(%rdx), %si
	xorw	-20(%rdx), %r9w
	xorw	-18(%rdx), %di
	xorw	-16(%rdx), %cx
	movw	%si, 64(%rsp)
	movzwl	36(%rsp), %esi
	xorw	-10(%rdx), %si
	movw	%si, 56(%rsp)
	movzwl	34(%rsp), %esi
	xorw	-8(%rdx), %si
	movw	%si, 52(%rsp)
	movzwl	32(%rsp), %esi
	xorw	-6(%rdx), %si
	movw	%si, 48(%rsp)
	movzwl	30(%rsp), %esi
	xorw	-4(%rdx), %si
	movw	%si, 40(%rsp)
	movzwl	28(%rsp), %esi
	incl	184(%rsp)
	xorw	-2(%rdx), %si
	movw	%ax, -2720(%r10)
	movw	%si, -32(%r10)
	vpextrw	$0, %xmm1, %esi
	xorw	72(%rsp), %si
	movw	%r15w, -2528(%r10)
	movw	%si, -2912(%r10)
	movzwl	80(%rsp), %esi
	movl	184(%rsp), %eax
	movw	%r14w, -2336(%r10)
	movw	%si, -1184(%r10)
	movzwl	64(%rsp), %esi
	movw	%r13w, -2144(%r10)
	movw	%si, -992(%r10)
	movzwl	56(%rsp), %esi
	movw	%r11w, -1952(%r10)
	movw	%si, -800(%r10)
	movzwl	52(%rsp), %esi
	movw	%r9w, -1760(%r10)
	movw	%si, -608(%r10)
	movzwl	48(%rsp), %esi
	movw	%di, -1568(%r10)
	movw	%si, -416(%r10)
	movzwl	40(%rsp), %esi
	movw	%cx, -1376(%r10)
	movw	%si, -224(%r10)
	addq	$16, 128(%rsp)
	addq	$640, 136(%rsp)
	addq	$20, 144(%rsp)
	addl	$80, 152(%rsp)
	addq	$160, 168(%rsp)
	cmpl	$5, %eax
	jne	.L136
	movl	$3200, %edx
	xorl	%esi, %esi
	leaq	6400(%rsp), %rdi
	vzeroupper
	call	memset@PLT
	xorl	%r13d, %r13d
	xorl	%r10d, %r10d
	movq	%rax, %rcx
	movq	%rax, %rdx
.L140:
	movq	%rdx, 168(%rsp)
	movq	%rdx, %rdi
	movq	%r10, %r8
	xorl	%r15d, %r15d
	movq	%rax, %r11
.L146:
	movq	200(%rsp), %rax
	movq	%r8, %rsi
	movq	%rcx, 152(%rsp)
	movq	%rbx, %rdx
	salq	$5, %rsi
	addq	%rsi, %rax
	movq	%rdi, %rsi
	movq	%rax, 184(%rsp)
	xorl	%eax, %eax
.L144:
	movq	184(%rsp), %r14
	movq	%rdx, %r9
	xorl	%ecx, %ecx
.L141:
	vmovdqa	(%r9), %ymm2
	vmovdqu	138400(%r14), %ymm3
	addq	$64, %rcx
	addq	$64, %r9
	vmovdqa	-32(%r9), %ymm4
	addq	$64, %r14
	vpermq	$0, %ymm2, %ymm5
	vpshufb	.LC34(%rip), %ymm3, %ymm1
	vpermq	$85, %ymm2, %ymm6
	vpmullw	%ymm5, %ymm1, %ymm1
	vpshufb	.LC35(%rip), %ymm3, %ymm5
	vpmullw	%ymm6, %ymm5, %ymm5
	vpermq	$170, %ymm2, %ymm6
	vpermq	$255, %ymm2, %ymm2
	vpxor	%ymm5, %ymm1, %ymm1
	vpshufb	.LC28(%rip), %ymm3, %ymm5
	vpshufb	.LC29(%rip), %ymm3, %ymm3
	vpmullw	%ymm6, %ymm5, %ymm5
	vpmullw	%ymm3, %ymm2, %ymm2
	vpxor	(%rsi), %ymm1, %ymm1
	vpermq	$85, %ymm4, %ymm6
	vpxor	%ymm2, %ymm5, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpermq	$0, %ymm4, %ymm2
	vmovdqa	%ymm1, (%rsi)
	vmovdqu	138368(%r14), %ymm3
	vpshufb	.LC34(%rip), %ymm3, %ymm5
	vpmullw	%ymm5, %ymm2, %ymm2
	vpshufb	.LC35(%rip), %ymm3, %ymm5
	vpmullw	%ymm6, %ymm5, %ymm5
	vpxor	%ymm5, %ymm2, %ymm2
	vpshufb	.LC28(%rip), %ymm3, %ymm5
	vpxor	%ymm1, %ymm2, %ymm1
	vpermq	$170, %ymm4, %ymm2
	vpermq	$255, %ymm4, %ymm4
	vpmullw	%ymm5, %ymm2, %ymm5
	vpshufb	.LC29(%rip), %ymm3, %ymm2
	vpmullw	%ymm4, %ymm2, %ymm2
	vpxor	%ymm2, %ymm5, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vmovdqa	%ymm1, (%rsi)
	cmpq	$768, %rcx
	jne	.L141
	addl	$24, %eax
	addq	$768, %rdx
	addq	$160, %rsi
	cmpl	$96, %eax
	jne	.L144
	incq	%r15
	movq	152(%rsp), %rcx
	addq	$24, %r8
	addq	$32, %rdi
	cmpq	$5, %r15
	jne	.L146
	movq	168(%rsp), %rdx
	addq	$5, %r13
	movq	%r11, %rax
	addq	$120, %r10
	addq	$640, %rdx
	cmpq	$25, %r13
	jne	.L140
	movl	$7864440, %edx
	vpcmpeqd	%ymm3, %ymm3, %ymm3
	addq	$3200, %rcx
	vmovd	%edx, %xmm6
	vpsrlw	$12, %ymm3, %ymm3
	movl	$3932220, %edx
	vmovd	%edx, %xmm5
	movl	$1966110, %edx
	vpbroadcastd	%xmm6, %ymm6
	vmovd	%edx, %xmm4
	vpbroadcastd	%xmm5, %ymm5
	vpbroadcastd	%xmm4, %ymm4
.L147:
	vmovdqa	(%rax), %ymm2
	addq	$32, %rax
	vpsrlw	$9, %ymm2, %ymm1
	vpsrlw	$6, %ymm2, %ymm7
	vpand	%ymm5, %ymm7, %ymm7
	vpand	%ymm6, %ymm1, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpsrlw	$3, %ymm2, %ymm7
	vpand	%ymm3, %ymm2, %ymm2
	vpand	%ymm4, %ymm7, %ymm7
	vpxor	%ymm2, %ymm7, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vpsrlw	$3, %ymm1, %ymm2
	vpand	%ymm4, %ymm2, %ymm2
	vpxor	%ymm1, %ymm2, %ymm2
	vpsrlw	$4, %ymm1, %ymm1
	vpxor	%ymm1, %ymm2, %ymm1
	vpand	%ymm3, %ymm1, %ymm1
	vmovdqa	%ymm1, -32(%rax)
	cmpq	%rcx, %rax
	jne	.L147
	leaq	9600(%rsp), %r15
	xorl	%esi, %esi
	movl	$3200, %edx
	movq	%r15, %rdi
	vzeroupper
	call	memset@PLT
	movq	200(%rsp), %rcx
	vmovdqa	.LC56(%rip), %ymm0
	movq	%r15, %rsi
	xorl	%eax, %eax
.L148:
	movq	%rsi, %rdi
	movq	%rbx, %r9
	xorl	%r8d, %r8d
.L152:
	movq	%rcx, %rdx
	movq	%r9, %r11
	xorl	%r10d, %r10d
.L149:
	vmovdqa	(%r11), %ymm2
	vmovq	157600(%rdx), %xmm1
	vmovq	157608(%rdx), %xmm8
	vmovq	157616(%rdx), %xmm6
	vperm2i128	$0, %ymm1, %ymm1, %ymm1
	vperm2i128	$0, %ymm8, %ymm8, %ymm8
	vmovq	157624(%rdx), %xmm7
	addq	$32, %r10
	vpermq	$0, %ymm2, %ymm5
	vpermq	$85, %ymm2, %ymm4
	vpshufb	%ymm0, %ymm1, %ymm1
	addq	$32, %r11
	vpshufb	%ymm0, %ymm8, %ymm8
	vpmullw	%ymm5, %ymm1, %ymm1
	vperm2i128	$0, %ymm6, %ymm6, %ymm6
	addq	$160, %rdx
	vpmullw	%ymm4, %ymm8, %ymm8
	vperm2i128	$0, %ymm7, %ymm7, %ymm7
	vpermq	$170, %ymm2, %ymm3
	vpshufb	%ymm0, %ymm6, %ymm6
	vpermq	$255, %ymm2, %ymm2
	vpshufb	%ymm0, %ymm7, %ymm7
	vpmullw	%ymm2, %ymm7, %ymm7
	vpmullw	%ymm3, %ymm6, %ymm6
	vpxor	%ymm8, %ymm1, %ymm1
	vpxor	(%rdi), %ymm1, %ymm1
	vpxor	%ymm7, %ymm6, %ymm6
	vpxor	%ymm6, %ymm1, %ymm1
	vmovdqa	%ymm1, (%rdi)
	vmovq	157472(%rdx), %xmm1
	vmovq	157480(%rdx), %xmm8
	vmovq	157488(%rdx), %xmm7
	vperm2i128	$0, %ymm1, %ymm1, %ymm1
	vperm2i128	$0, %ymm8, %ymm8, %ymm8
	vmovq	157496(%rdx), %xmm6
	vpshufb	%ymm0, %ymm1, %ymm1
	vpshufb	%ymm0, %ymm8, %ymm8
	vperm2i128	$0, %ymm6, %ymm6, %ymm6
	vpmullw	%ymm4, %ymm8, %ymm8
	vpmullw	%ymm5, %ymm1, %ymm1
	vperm2i128	$0, %ymm7, %ymm7, %ymm7
	vpshufb	%ymm0, %ymm6, %ymm6
	vpshufb	%ymm0, %ymm7, %ymm7
	vpmullw	%ymm3, %ymm7, %ymm7
	vpmullw	%ymm2, %ymm6, %ymm6
	vpxor	%ymm8, %ymm1, %ymm1
	vpxor	32(%rdi), %ymm1, %ymm1
	vpxor	%ymm7, %ymm6, %ymm6
	vpxor	%ymm6, %ymm1, %ymm1
	vmovdqa	%ymm1, 32(%rdi)
	vmovq	157504(%rdx), %xmm8
	vmovq	157512(%rdx), %xmm1
	vmovq	157520(%rdx), %xmm7
	vperm2i128	$0, %ymm1, %ymm1, %ymm1
	vperm2i128	$0, %ymm8, %ymm8, %ymm8
	vmovq	157528(%rdx), %xmm6
	vpshufb	%ymm0, %ymm1, %ymm1
	vpshufb	%ymm0, %ymm8, %ymm8
	vperm2i128	$0, %ymm6, %ymm6, %ymm6
	vpmullw	%ymm5, %ymm8, %ymm8
	vpmullw	%ymm4, %ymm1, %ymm1
	vperm2i128	$0, %ymm7, %ymm7, %ymm7
	vpshufb	%ymm0, %ymm6, %ymm6
	vpshufb	%ymm0, %ymm7, %ymm7
	vpmullw	%ymm3, %ymm7, %ymm7
	vpmullw	%ymm2, %ymm6, %ymm6
	vpxor	%ymm8, %ymm1, %ymm1
	vpxor	64(%rdi), %ymm1, %ymm1
	vpxor	%ymm7, %ymm6, %ymm6
	vpxor	%ymm6, %ymm1, %ymm1
	vmovdqa	%ymm1, 64(%rdi)
	vmovq	157536(%rdx), %xmm8
	vmovq	157544(%rdx), %xmm1
	vmovq	157552(%rdx), %xmm7
	vperm2i128	$0, %ymm1, %ymm1, %ymm1
	vperm2i128	$0, %ymm8, %ymm8, %ymm8
	vmovq	157560(%rdx), %xmm6
	vpshufb	%ymm0, %ymm1, %ymm1
	vpshufb	%ymm0, %ymm8, %ymm8
	vperm2i128	$0, %ymm6, %ymm6, %ymm6
	vpmullw	%ymm5, %ymm8, %ymm8
	vpmullw	%ymm4, %ymm1, %ymm1
	vperm2i128	$0, %ymm7, %ymm7, %ymm7
	vpshufb	%ymm0, %ymm6, %ymm6
	vpshufb	%ymm0, %ymm7, %ymm7
	vpmullw	%ymm3, %ymm7, %ymm7
	vpmullw	%ymm2, %ymm6, %ymm6
	vpxor	%ymm8, %ymm1, %ymm1
	vpxor	96(%rdi), %ymm1, %ymm1
	vpxor	%ymm7, %ymm6, %ymm6
	vpxor	%ymm6, %ymm1, %ymm1
	vmovdqa	%ymm1, 96(%rdi)
	vmovq	157568(%rdx), %xmm1
	vmovq	157576(%rdx), %xmm8
	vmovq	157584(%rdx), %xmm6
	vperm2i128	$0, %ymm1, %ymm1, %ymm1
	vperm2i128	$0, %ymm8, %ymm8, %ymm8
	vmovq	157592(%rdx), %xmm7
	vpshufb	%ymm0, %ymm1, %ymm1
	vperm2i128	$0, %ymm6, %ymm6, %ymm6
	vperm2i128	$0, %ymm7, %ymm7, %ymm7
	vpmullw	%ymm5, %ymm1, %ymm1
	vpshufb	%ymm0, %ymm8, %ymm5
	vpmullw	%ymm4, %ymm5, %ymm4
	vpxor	%ymm4, %ymm1, %ymm1
	vpshufb	%ymm0, %ymm6, %ymm4
	vpmullw	%ymm3, %ymm4, %ymm3
	vpshufb	%ymm0, %ymm7, %ymm4
	vpxor	128(%rdi), %ymm1, %ymm1
	vpmullw	%ymm2, %ymm4, %ymm2
	vpxor	%ymm2, %ymm3, %ymm2
	vpxor	%ymm2, %ymm1, %ymm1
	vmovdqa	%ymm1, 128(%rdi)
	cmpq	$768, %r10
	jne	.L149
	addl	$24, %r8d
	addq	$768, %r9
	addq	$160, %rdi
	cmpl	$96, %r8d
	jne	.L152
	addq	$4, %rax
	addq	$3840, %rcx
	addq	$640, %rsi
	cmpq	$20, %rax
	jne	.L148
	movl	$7864440, %edx
	vpcmpeqd	%ymm2, %ymm2, %ymm2
	leaq	3200(%r15), %rcx
	movq	%r15, %rax
	vmovd	%edx, %xmm5
	vpsrlw	$12, %ymm2, %ymm2
	movl	$3932220, %edx
	vmovd	%edx, %xmm4
	movl	$1966110, %edx
	vpbroadcastd	%xmm5, %ymm5
	vmovd	%edx, %xmm3
	vpbroadcastd	%xmm4, %ymm4
	vpbroadcastd	%xmm3, %ymm3
.L153:
	vmovdqa	(%rax), %ymm1
	addq	$32, %rax
	vpsrlw	$9, %ymm1, %ymm0
	vpsrlw	$6, %ymm1, %ymm6
	vpand	%ymm4, %ymm6, %ymm6
	vpand	%ymm5, %ymm0, %ymm0
	vpxor	%ymm6, %ymm0, %ymm0
	vpsrlw	$3, %ymm1, %ymm6
	vpand	%ymm2, %ymm1, %ymm1
	vpand	%ymm3, %ymm6, %ymm6
	vpxor	%ymm1, %ymm6, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpsrlw	$3, %ymm0, %ymm1
	vpand	%ymm3, %ymm1, %ymm1
	vpxor	%ymm0, %ymm1, %ymm1
	vpsrlw	$4, %ymm0, %ymm0
	vpxor	%ymm0, %ymm1, %ymm0
	vpand	%ymm2, %ymm0, %ymm0
	vmovdqa	%ymm0, -32(%rax)
	cmpq	%rax, %rcx
	jne	.L153
	movq	192(%rsp), %rax
	movq	200(%rsp), %rbx
	movq	%r15, 56(%rsp)
	vpcmpeqd	%ymm1, %ymm1, %ymm1
	vpsrlw	$12, %ymm1, %ymm1
	xorl	%edx, %edx
	xorl	%r8d, %r8d
	movq	%rax, 136(%rsp)
	movl	$7864440, %eax
	movq	%rbx, %r14
	vmovd	%eax, %xmm4
	movl	$3932220, %eax
	vmovd	%eax, %xmm3
	movl	$1966110, %eax
	vpbroadcastd	%xmm4, %ymm4
	vmovd	%eax, %xmm2
	vpbroadcastd	%xmm3, %ymm3
	vpbroadcastd	%xmm2, %ymm2
.L154:
	leaq	2(%r14), %rdi
	movl	%r8d, 52(%rsp)
	leal	1(%r8), %ecx
	movl	%r8d, %r11d
	movq	%rdi, 80(%rsp)
	leaq	4(%r14), %rdi
	leal	2(%r8), %r15d
	movq	%rbx, %rsi
	movq	%rdi, 72(%rsp)
	leaq	6(%r14), %rdi
	leal	3(%r8), %r13d
	movq	%r12, %rax
	movq	%rdi, 64(%rsp)
	movq	$0, 184(%rsp)
.L158:
	movq	184(%rsp), %rdi
	movl	$3435973837, %r9d
	leal	(%rdx,%rdi), %r12d
	vpbroadcastw	190400(%r14,%rdi,8), %ymm11
	movq	%r12, %r10
	imulq	%r9, %r12
	movq	80(%rsp), %r9
	vpbroadcastw	190400(%r9,%rdi,8), %ymm0
	movq	72(%rsp), %r9
	shrq	$34, %r12
	leal	(%r12,%r12,4), %r12d
	vpbroadcastw	190400(%r9,%rdi,8), %ymm10
	movq	64(%rsp), %r9
	subl	%r12d, %r10d
	movslq	%r10d, %r10
	vpbroadcastw	190400(%r9,%rdi,8), %ymm5
	leaq	0(,%r10,4), %r12
	addq	%r12, %r10
	leaq	10(%r12,%r12,4), %r12
	salq	$7, %r10
	salq	$5, %r12
	vpmullw	6560(%rsp,%r12), %ymm5, %ymm6
	vpmullw	6400(%rsp,%r12), %ymm10, %ymm7
	vpmullw	6400(%rsp,%r10), %ymm11, %ymm8
	vpxor	%ymm6, %ymm8, %ymm8
	vpmullw	6560(%rsp,%r10), %ymm0, %ymm6
	vpxor	%ymm7, %ymm6, %ymm6
	vpmullw	6592(%rsp,%r12), %ymm5, %ymm9
	vpmullw	6592(%rsp,%r10), %ymm0, %ymm7
	vpxor	%ymm6, %ymm8, %ymm8
	vpmullw	6432(%rsp,%r10), %ymm11, %ymm6
	vpxor	%ymm6, %ymm7, %ymm7
	vpmullw	6432(%rsp,%r12), %ymm10, %ymm6
	vpxor	%ymm9, %ymm6, %ymm6
	vpmullw	6624(%rsp,%r12), %ymm5, %ymm12
	vpmullw	6464(%rsp,%r10), %ymm11, %ymm9
	vpmullw	6656(%rsp,%r12), %ymm5, %ymm13
	vpxor	%ymm6, %ymm7, %ymm7
	vpmullw	6624(%rsp,%r10), %ymm0, %ymm6
	vpxor	%ymm9, %ymm6, %ymm6
	vpmullw	6464(%rsp,%r12), %ymm10, %ymm9
	vpxor	%ymm12, %ymm9, %ymm9
	vpmullw	6688(%rsp,%r12), %ymm5, %ymm5
	vpmullw	6496(%rsp,%r10), %ymm11, %ymm12
	vpmullw	6528(%rsp,%r10), %ymm11, %ymm11
	vpxor	%ymm9, %ymm6, %ymm6
	vpmullw	6656(%rsp,%r10), %ymm0, %ymm9
	vpmullw	6688(%rsp,%r10), %ymm0, %ymm0
	vpxor	%ymm12, %ymm9, %ymm9
	vpxor	%ymm11, %ymm0, %ymm0
	vpmullw	6496(%rsp,%r12), %ymm10, %ymm12
	vpmullw	6528(%rsp,%r12), %ymm10, %ymm10
	vpxor	%ymm10, %ymm5, %ymm5
	vpxor	%ymm5, %ymm0, %ymm0
	vpsrlw	$6, %ymm8, %ymm10
	vpxor	%ymm13, %ymm12, %ymm12
	movslq	%r11d, %r10
	vpsrlw	$9, %ymm8, %ymm5
	vpand	%ymm3, %ymm10, %ymm10
	vpxor	%ymm12, %ymm9, %ymm9
	vpand	%ymm4, %ymm5, %ymm5
	leaq	12800(%rsp), %r12
	vpxor	%ymm10, %ymm5, %ymm5
	vpsrlw	$3, %ymm8, %ymm10
	vpand	%ymm1, %ymm8, %ymm8
	vpand	%ymm2, %ymm10, %ymm10
	vpxor	%ymm8, %ymm10, %ymm8
	vpsrlw	$6, %ymm7, %ymm10
	vpxor	%ymm8, %ymm5, %ymm5
	vpand	%ymm3, %ymm10, %ymm10
	vpsrlw	$3, %ymm5, %ymm8
	vpand	%ymm2, %ymm8, %ymm8
	vpxor	%ymm5, %ymm8, %ymm8
	vpsrlw	$4, %ymm5, %ymm5
	vpxor	%ymm5, %ymm8, %ymm8
	vpsrlw	$9, %ymm7, %ymm5
	vpand	%ymm4, %ymm5, %ymm5
	vpand	%ymm1, %ymm8, %ymm8
	vpxor	%ymm10, %ymm5, %ymm5
	vpsrlw	$3, %ymm7, %ymm10
	vpand	%ymm1, %ymm7, %ymm7
	vpand	%ymm2, %ymm10, %ymm10
	vpshufb	.LC28(%rip), %ymm8, %ymm15
	vpshufb	.LC29(%rip), %ymm8, %ymm13
	vpxor	%ymm7, %ymm10, %ymm7
	vpsrlw	$9, %ymm6, %ymm10
	vpshufb	.LC34(%rip), %ymm8, %ymm14
	vpxor	%ymm7, %ymm5, %ymm5
	vpand	%ymm4, %ymm10, %ymm10
	vpsrlw	$3, %ymm5, %ymm7
	vpand	%ymm2, %ymm7, %ymm7
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrlw	$4, %ymm5, %ymm5
	vpxor	%ymm5, %ymm7, %ymm7
	vpsrlw	$6, %ymm6, %ymm5
	vpand	%ymm3, %ymm5, %ymm5
	vpand	%ymm1, %ymm7, %ymm7
	vpxor	%ymm10, %ymm5, %ymm5
	vpsrlw	$3, %ymm6, %ymm10
	vpand	%ymm1, %ymm6, %ymm6
	vpand	%ymm2, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm6
	vpsrlw	$6, %ymm9, %ymm10
	vpxor	%ymm6, %ymm5, %ymm5
	vpand	%ymm3, %ymm10, %ymm10
	vpsrlw	$3, %ymm5, %ymm6
	vpand	%ymm2, %ymm6, %ymm6
	vpxor	%ymm5, %ymm6, %ymm6
	vpsrlw	$4, %ymm5, %ymm5
	vpxor	%ymm5, %ymm6, %ymm6
	vpsrlw	$9, %ymm9, %ymm5
	vpand	%ymm4, %ymm5, %ymm5
	vpand	%ymm1, %ymm6, %ymm6
	vpxor	%ymm10, %ymm5, %ymm5
	vpsrlw	$3, %ymm9, %ymm10
	vpand	%ymm1, %ymm9, %ymm9
	vpand	%ymm2, %ymm10, %ymm10
	vpxor	%ymm9, %ymm10, %ymm9
	vpsrlw	$6, %ymm0, %ymm10
	vpxor	%ymm9, %ymm5, %ymm5
	vpand	%ymm3, %ymm10, %ymm10
	vpsrlw	$3, %ymm5, %ymm9
	vpand	%ymm2, %ymm9, %ymm9
	vpxor	%ymm5, %ymm9, %ymm9
	vpsrlw	$4, %ymm5, %ymm5
	vpxor	%ymm5, %ymm9, %ymm5
	vpsrlw	$9, %ymm0, %ymm9
	vpand	%ymm4, %ymm9, %ymm9
	vpand	%ymm1, %ymm5, %ymm5
	vpxor	%ymm10, %ymm9, %ymm9
	vpsrlw	$3, %ymm0, %ymm10
	vpand	%ymm1, %ymm0, %ymm0
	vpand	%ymm2, %ymm10, %ymm10
	vpxor	%ymm0, %ymm10, %ymm0
	vpxor	%ymm0, %ymm9, %ymm0
	vpsrlw	$3, %ymm0, %ymm9
	vpand	%ymm2, %ymm9, %ymm9
	vpxor	%ymm0, %ymm9, %ymm9
	vpsrlw	$4, %ymm0, %ymm0
	vpxor	%ymm0, %ymm9, %ymm0
	vmovdqu	180000(%rsi), %ymm9
	vpshufb	.LC35(%rip), %ymm8, %ymm8
	movq	200(%rsp), %rdi
	vpand	%ymm1, %ymm0, %ymm0
	vpermq	$0, %ymm9, %ymm12
	vpermq	$85, %ymm9, %ymm11
	vpermq	$170, %ymm9, %ymm10
	vpermq	$255, %ymm9, %ymm9
	vpmullw	%ymm10, %ymm15, %ymm15
	leaq	(%rdi,%r10,2), %r9
	movslq	%ecx, %r10
	vpmullw	%ymm9, %ymm13, %ymm13
	vpmullw	%ymm12, %ymm14, %ymm14
	movq	%r9, 168(%rsp)
	leaq	(%rdi,%r10,2), %r9
	movslq	%r15d, %r10
	movq	%r9, 144(%rsp)
	leaq	(%rdi,%r10,2), %r9
	movslq	%r13d, %r10
	leaq	(%rdi,%r10,2), %rdi
	movq	%r9, 152(%rsp)
	movq	%rdi, 128(%rsp)
	xorl	%edi, %edi
	vpxor	%ymm13, %ymm15, %ymm15
	vpmullw	%ymm11, %ymm8, %ymm13
	vpxor	%ymm13, %ymm14, %ymm14
	vpshufb	.LC35(%rip), %ymm7, %ymm13
	vpxor	%ymm14, %ymm15, %ymm8
	vpshufb	.LC34(%rip), %ymm7, %ymm15
	vpshufb	.LC28(%rip), %ymm7, %ymm14
	vpmullw	%ymm11, %ymm13, %ymm13
	vpmullw	%ymm12, %ymm15, %ymm15
	vpshufb	.LC29(%rip), %ymm7, %ymm7
	vpmullw	%ymm10, %ymm14, %ymm14
	vpxor	%ymm13, %ymm15, %ymm15
	vpmullw	%ymm9, %ymm7, %ymm13
	vpxor	%ymm13, %ymm14, %ymm14
	vpshufb	.LC35(%rip), %ymm6, %ymm13
	vpxor	%ymm14, %ymm15, %ymm7
	vpshufb	.LC34(%rip), %ymm6, %ymm15
	vpshufb	.LC28(%rip), %ymm6, %ymm14
	vpmullw	%ymm11, %ymm13, %ymm13
	vpmullw	%ymm12, %ymm15, %ymm15
	vpshufb	.LC29(%rip), %ymm6, %ymm6
	vpmullw	%ymm10, %ymm14, %ymm14
	vpxor	%ymm13, %ymm15, %ymm15
	vpmullw	%ymm9, %ymm6, %ymm13
	vpxor	%ymm13, %ymm14, %ymm14
	vpshufb	.LC35(%rip), %ymm5, %ymm13
	vpxor	%ymm14, %ymm15, %ymm6
	vpshufb	.LC34(%rip), %ymm5, %ymm15
	vpshufb	.LC28(%rip), %ymm5, %ymm14
	vpmullw	%ymm11, %ymm13, %ymm13
	vpmullw	%ymm12, %ymm15, %ymm15
	vpshufb	.LC29(%rip), %ymm5, %ymm5
	vpmullw	%ymm10, %ymm14, %ymm14
	vpxor	%ymm13, %ymm15, %ymm15
	vpmullw	%ymm9, %ymm5, %ymm13
	vpxor	%ymm13, %ymm14, %ymm14
	vpshufb	.LC34(%rip), %ymm0, %ymm13
	vpmullw	%ymm12, %ymm13, %ymm13
	vpshufb	.LC35(%rip), %ymm0, %ymm12
	vpxor	%ymm14, %ymm15, %ymm5
	vpmullw	%ymm11, %ymm12, %ymm12
	vpxor	%ymm12, %ymm13, %ymm11
	vpshufb	.LC28(%rip), %ymm0, %ymm12
	vpshufb	.LC29(%rip), %ymm0, %ymm0
	vpmullw	%ymm10, %ymm12, %ymm10
	vpmullw	%ymm9, %ymm0, %ymm9
	vpxor	%ymm9, %ymm10, %ymm9
	vpsrlw	$6, %ymm8, %ymm10
	vpxor	%ymm9, %ymm11, %ymm0
	vpsrlw	$9, %ymm8, %ymm9
	vpand	%ymm3, %ymm10, %ymm10
	vpand	%ymm4, %ymm9, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpsrlw	$3, %ymm8, %ymm10
	vpand	%ymm1, %ymm8, %ymm8
	vpand	%ymm2, %ymm10, %ymm10
	vpxor	%ymm8, %ymm10, %ymm8
	vpsrlw	$6, %ymm7, %ymm10
	vpxor	%ymm8, %ymm9, %ymm8
	vpand	%ymm3, %ymm10, %ymm10
	vpsrlw	$3, %ymm8, %ymm9
	vpand	%ymm2, %ymm9, %ymm9
	vpxor	%ymm8, %ymm9, %ymm9
	vpsrlw	$4, %ymm8, %ymm8
	vpxor	%ymm8, %ymm9, %ymm8
	vpsrlw	$9, %ymm7, %ymm9
	vpand	%ymm4, %ymm9, %ymm9
	vpand	%ymm1, %ymm8, %ymm8
	vpxor	%ymm10, %ymm9, %ymm9
	vpsrlw	$3, %ymm7, %ymm10
	vpand	%ymm1, %ymm7, %ymm7
	vpand	%ymm2, %ymm10, %ymm10
	vpermq	$0, %ymm8, %ymm15
	vpermq	$85, %ymm8, %ymm13
	vpxor	%ymm7, %ymm10, %ymm7
	vpsrlw	$6, %ymm6, %ymm10
	vpermq	$255, %ymm8, %ymm14
	vpxor	%ymm7, %ymm9, %ymm7
	vpand	%ymm3, %ymm10, %ymm10
	vpermq	$170, %ymm8, %ymm8
	vpsrlw	$3, %ymm7, %ymm9
	vpand	%ymm2, %ymm9, %ymm9
	vpxor	%ymm7, %ymm9, %ymm9
	vpsrlw	$4, %ymm7, %ymm7
	vpxor	%ymm7, %ymm9, %ymm7
	vpsrlw	$9, %ymm6, %ymm9
	vpand	%ymm4, %ymm9, %ymm9
	vpand	%ymm1, %ymm7, %ymm7
	vpxor	%ymm10, %ymm9, %ymm9
	vpsrlw	$3, %ymm6, %ymm10
	vpand	%ymm1, %ymm6, %ymm6
	vpand	%ymm2, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm6
	vpsrlw	$9, %ymm5, %ymm10
	vpxor	%ymm6, %ymm9, %ymm6
	vpand	%ymm4, %ymm10, %ymm10
	vpsrlw	$3, %ymm6, %ymm9
	vpand	%ymm2, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpsrlw	$4, %ymm6, %ymm6
	vpxor	%ymm6, %ymm9, %ymm6
	vpsrlw	$6, %ymm5, %ymm9
	vpand	%ymm3, %ymm9, %ymm9
	vpand	%ymm1, %ymm6, %ymm6
	vpxor	%ymm10, %ymm9, %ymm9
	vpsrlw	$3, %ymm5, %ymm10
	vpand	%ymm1, %ymm5, %ymm5
	vpand	%ymm2, %ymm10, %ymm10
	vpxor	%ymm5, %ymm10, %ymm5
	vpsrlw	$6, %ymm0, %ymm10
	vpxor	%ymm5, %ymm9, %ymm5
	vpand	%ymm3, %ymm10, %ymm10
	vpsrlw	$3, %ymm5, %ymm9
	vpand	%ymm2, %ymm9, %ymm9
	vpxor	%ymm5, %ymm9, %ymm9
	vpsrlw	$4, %ymm5, %ymm5
	vpxor	%ymm5, %ymm9, %ymm5
	vpsrlw	$9, %ymm0, %ymm9
	vpand	%ymm4, %ymm9, %ymm9
	vpand	%ymm1, %ymm5, %ymm5
	vpxor	%ymm10, %ymm9, %ymm9
	vpsrlw	$3, %ymm0, %ymm10
	vpand	%ymm1, %ymm0, %ymm0
	vpand	%ymm2, %ymm10, %ymm10
	vpxor	%ymm0, %ymm10, %ymm0
	vpxor	%ymm0, %ymm9, %ymm0
	vpsrlw	$3, %ymm0, %ymm9
	vpand	%ymm2, %ymm9, %ymm9
	vpxor	%ymm0, %ymm9, %ymm9
	vpsrlw	$4, %ymm0, %ymm0
	vpxor	%ymm0, %ymm9, %ymm0
	vmovdqu	183200(%rsi), %ymm9
	vpand	%ymm1, %ymm0, %ymm0
	vpshufb	.LC34(%rip), %ymm9, %ymm12
	vpshufb	.LC35(%rip), %ymm9, %ymm11
	vpshufb	.LC28(%rip), %ymm9, %ymm10
	vpmullw	%ymm11, %ymm13, %ymm13
	vpmullw	%ymm12, %ymm15, %ymm15
	vpshufb	.LC29(%rip), %ymm9, %ymm9
	vpmullw	%ymm9, %ymm14, %ymm14
	vpxor	%ymm13, %ymm15, %ymm15
	vpmullw	%ymm10, %ymm8, %ymm13
	vpxor	%ymm13, %ymm14, %ymm14
	vpermq	$255, %ymm7, %ymm13
	vpxor	%ymm14, %ymm15, %ymm8
	vpermq	$170, %ymm7, %ymm15
	vpermq	$0, %ymm7, %ymm14
	vpmullw	%ymm9, %ymm13, %ymm13
	vpmullw	%ymm10, %ymm15, %ymm15
	vpermq	$85, %ymm7, %ymm7
	vpmullw	%ymm12, %ymm14, %ymm14
	vpxor	%ymm13, %ymm15, %ymm15
	vpmullw	%ymm11, %ymm7, %ymm13
	vpxor	%ymm13, %ymm14, %ymm14
	vpermq	$255, %ymm6, %ymm13
	vpxor	%ymm14, %ymm15, %ymm7
	vpermq	$170, %ymm6, %ymm15
	vpermq	$0, %ymm6, %ymm14
	vpmullw	%ymm9, %ymm13, %ymm13
	vpmullw	%ymm10, %ymm15, %ymm15
	vpermq	$85, %ymm6, %ymm6
	vpmullw	%ymm12, %ymm14, %ymm14
	vpxor	%ymm13, %ymm15, %ymm15
	vpmullw	%ymm11, %ymm6, %ymm13
	vpxor	%ymm13, %ymm14, %ymm14
	vpermq	$255, %ymm5, %ymm13
	vpxor	%ymm14, %ymm15, %ymm6
	vpermq	$170, %ymm5, %ymm15
	vpermq	$0, %ymm5, %ymm14
	vpmullw	%ymm9, %ymm13, %ymm13
	vpmullw	%ymm10, %ymm15, %ymm15
	vpermq	$85, %ymm5, %ymm5
	vpmullw	%ymm12, %ymm14, %ymm14
	vpxor	%ymm13, %ymm15, %ymm15
	vpmullw	%ymm11, %ymm5, %ymm13
	vpxor	%ymm13, %ymm14, %ymm14
	vpermq	$0, %ymm0, %ymm13
	vpmullw	%ymm12, %ymm13, %ymm13
	vpermq	$85, %ymm0, %ymm12
	vpxor	%ymm14, %ymm15, %ymm5
	vpmullw	%ymm11, %ymm12, %ymm12
	vpxor	%ymm12, %ymm13, %ymm11
	vpermq	$170, %ymm0, %ymm12
	vpermq	$255, %ymm0, %ymm0
	vpmullw	%ymm10, %ymm12, %ymm10
	vpmullw	%ymm9, %ymm0, %ymm9
	vpxor	%ymm9, %ymm10, %ymm9
	vpsrlw	$6, %ymm8, %ymm10
	vpxor	%ymm9, %ymm11, %ymm0
	vpsrlw	$9, %ymm8, %ymm9
	vpand	%ymm3, %ymm10, %ymm10
	vpand	%ymm4, %ymm9, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpsrlw	$3, %ymm8, %ymm10
	vpand	%ymm1, %ymm8, %ymm8
	vpand	%ymm2, %ymm10, %ymm10
	vpxor	%ymm8, %ymm10, %ymm8
	vpxor	%ymm8, %ymm9, %ymm8
	vpsrlw	$3, %ymm8, %ymm9
	vpand	%ymm2, %ymm9, %ymm9
	vpxor	%ymm8, %ymm9, %ymm9
	vpsrlw	$4, %ymm8, %ymm8
	vpxor	%ymm8, %ymm9, %ymm8
	vpsrlw	$6, %ymm7, %ymm9
	vpand	%ymm1, %ymm8, %ymm8
	vpand	%ymm3, %ymm9, %ymm9
	vmovdqa	%ymm8, 12800(%rsp)
	vpsrlw	$9, %ymm7, %ymm8
	vpand	%ymm4, %ymm8, %ymm8
	vpxor	%ymm9, %ymm8, %ymm8
	vpsrlw	$3, %ymm7, %ymm9
	vpand	%ymm1, %ymm7, %ymm7
	vpand	%ymm2, %ymm9, %ymm9
	vpxor	%ymm7, %ymm9, %ymm7
	vpxor	%ymm7, %ymm8, %ymm7
	vpsrlw	$3, %ymm7, %ymm8
	vpand	%ymm2, %ymm8, %ymm8
	vpxor	%ymm7, %ymm8, %ymm8
	vpsrlw	$4, %ymm7, %ymm7
	vpxor	%ymm7, %ymm8, %ymm7
	vpsrlw	$6, %ymm6, %ymm8
	vpand	%ymm1, %ymm7, %ymm7
	vpand	%ymm3, %ymm8, %ymm8
	vmovdqa	%ymm7, 12832(%rsp)
	vpsrlw	$9, %ymm6, %ymm7
	vpand	%ymm4, %ymm7, %ymm7
	vpxor	%ymm8, %ymm7, %ymm7
	vpsrlw	$3, %ymm6, %ymm8
	vpand	%ymm1, %ymm6, %ymm6
	vpand	%ymm2, %ymm8, %ymm8
	vpxor	%ymm6, %ymm8, %ymm6
	vpxor	%ymm6, %ymm7, %ymm6
	vpsrlw	$3, %ymm6, %ymm7
	vpand	%ymm2, %ymm7, %ymm7
	vpxor	%ymm6, %ymm7, %ymm7
	vpsrlw	$4, %ymm6, %ymm6
	vpxor	%ymm6, %ymm7, %ymm6
	vpsrlw	$6, %ymm5, %ymm7
	vpand	%ymm1, %ymm6, %ymm6
	vpand	%ymm3, %ymm7, %ymm7
	vmovdqa	%ymm6, 12864(%rsp)
	vpsrlw	$9, %ymm5, %ymm6
	vpand	%ymm4, %ymm6, %ymm6
	vpxor	%ymm7, %ymm6, %ymm6
	vpsrlw	$3, %ymm5, %ymm7
	vpand	%ymm1, %ymm5, %ymm5
	vpand	%ymm2, %ymm7, %ymm7
	vpxor	%ymm5, %ymm7, %ymm5
	vpxor	%ymm5, %ymm6, %ymm5
	vpsrlw	$3, %ymm5, %ymm6
	vpand	%ymm2, %ymm6, %ymm6
	vpxor	%ymm5, %ymm6, %ymm6
	vpsrlw	$4, %ymm5, %ymm5
	vpxor	%ymm5, %ymm6, %ymm5
	vpsrlw	$6, %ymm0, %ymm6
	vpand	%ymm1, %ymm5, %ymm5
	vpand	%ymm3, %ymm6, %ymm6
	vmovdqa	%ymm5, 12896(%rsp)
	vpsrlw	$9, %ymm0, %ymm5
	vpand	%ymm4, %ymm5, %ymm5
	vpxor	%ymm6, %ymm5, %ymm5
	vpsrlw	$3, %ymm0, %ymm6
	vpand	%ymm1, %ymm0, %ymm0
	vpand	%ymm2, %ymm6, %ymm6
	vpxor	%ymm0, %ymm6, %ymm0
	vpxor	%ymm0, %ymm5, %ymm0
	vpsrlw	$3, %ymm0, %ymm5
	vpand	%ymm2, %ymm5, %ymm5
	vpxor	%ymm0, %ymm5, %ymm5
	vpsrlw	$4, %ymm0, %ymm0
	vpxor	%ymm0, %ymm5, %ymm0
	vpand	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 12928(%rsp)
	movq	136(%rsp), %r8
	movl	%edx, 48(%rsp)
.L155:
	movq	%rbx, 40(%rsp)
	movq	%r8, %r9
	xorl	%r10d, %r10d
.L156:
	movq	168(%rsp), %rbx
	movq	152(%rsp), %rdx
	addq	$768, %r9
	movzwl	176800(%rbx,%r10), %ebx
	movzwl	176800(%rdx,%r10), %edx
	vmovd	%ebx, %xmm0
	movq	144(%rsp), %rbx
	vmovd	%edx, %xmm5
	vpinsrw	$1, 176800(%rbx,%r10), %xmm0, %xmm0
	movq	128(%rsp), %rbx
	vpinsrw	$1, 176800(%rbx,%r10), %xmm5, %xmm5
	addq	$8, %r10
	vpunpckldq	%xmm5, %xmm0, %xmm0
	vmovdqa	(%r12), %ymm5
	vpunpcklqdq	%xmm0, %xmm0, %xmm0
	vinserti128	$1, %xmm0, %ymm0, %ymm0
	vpshufb	.LC34(%rip), %ymm5, %ymm5
	vpmullw	%ymm5, %ymm0, %ymm5
	vpxor	-768(%r9), %ymm5, %ymm5
	vmovdqa	%ymm5, -768(%r9)
	vmovdqa	(%r12), %ymm5
	vpshufb	.LC35(%rip), %ymm5, %ymm5
	vpmullw	%ymm5, %ymm0, %ymm5
	vpxor	-576(%r9), %ymm5, %ymm5
	vmovdqa	%ymm5, -576(%r9)
	vmovdqa	(%r12), %ymm5
	vpshufb	.LC28(%rip), %ymm5, %ymm5
	vpmullw	%ymm5, %ymm0, %ymm5
	vpxor	-384(%r9), %ymm5, %ymm5
	vmovdqa	%ymm5, -384(%r9)
	vmovdqa	(%r12), %ymm5
	vpshufb	.LC29(%rip), %ymm5, %ymm5
	vpmullw	%ymm5, %ymm0, %ymm0
	vpxor	-192(%r9), %ymm0, %ymm0
	vmovdqa	%ymm0, -192(%r9)
	cmpq	$32, %r10
	jne	.L156
	addq	$16, %rdi
	movq	40(%rsp), %rbx
	addq	$32, %r8
	addq	$32, %r12
	cmpq	$80, %rdi
	jne	.L155
	incq	184(%rsp)
	addq	$32, %rsi
	addl	$16, %r11d
	addl	$16, %ecx
	addl	$16, %r15d
	addl	$16, %r13d
	movl	48(%rsp), %edx
	cmpq	$20, 184(%rsp)
	jne	.L158
	movl	52(%rsp), %r8d
	incl	%edx
	addq	$3072, 136(%rsp)
	movq	%rax, %r12
	addq	$640, %rbx
	addq	$160, %r14
	addl	$320, %r8d
	cmpl	$5, %edx
	jne	.L154
	movl	$7864440, %eax
	movq	200(%rsp), %r13
	vpcmpeqd	%ymm0, %ymm0, %ymm0
	movq	56(%rsp), %r15
	vmovd	%eax, %xmm8
	movl	$3932220, %eax
	movq	192(%rsp), %rbx
	xorl	%ecx, %ecx
	vmovd	%eax, %xmm7
	movl	$1966110, %eax
	vpbroadcastd	%xmm8, %ymm8
	movq	%r13, %r9
	vmovd	%eax, %xmm1
	vpsrlw	$12, %ymm0, %ymm0
	vpbroadcastd	%xmm7, %ymm7
	vpbroadcastd	%xmm1, %ymm1
.L159:
	leaq	6(%r13), %rdi
	movl	%ecx, %esi
	leaq	176800(%r9), %rax
	xorl	%edx, %edx
	movq	%rdi, 184(%rsp)
	leal	20(%rcx), %edi
	leaq	2(%r13), %r11
	movl	%edi, 168(%rsp)
	leaq	4(%r13), %r14
	movl	%ecx, %edi
	movq	%r12, %rcx
.L164:
	movl	$3435973837, %r12d
	movl	%esi, %r8d
	movq	%rax, 152(%rsp)
	vpxor	%xmm4, %xmm4, %xmm4
	imulq	%r12, %r8
	vmovdqa	%ymm4, 384(%rsp)
	leaq	384(%rsp), %r10
	vmovdqa	%ymm4, 416(%rsp)
	vmovdqa	%ymm4, 448(%rsp)
	shrq	$34, %r8
	vmovdqa	%ymm4, 480(%rsp)
	leal	(%r8,%r8,4), %r12d
	movl	%esi, %r8d
	vmovdqa	%ymm4, 512(%rsp)
	subl	%r12d, %r8d
	xorl	%r12d, %r12d
	movslq	%r8d, %r8
	leaq	(%r8,%r8,4), %r8
	salq	$7, %r8
	addq	%r15, %r8
.L160:
	vpbroadcastw	189600(%rdx,%r11), %ymm2
	vpbroadcastw	189600(%rdx,%r13), %ymm3
	addq	$32, %r12
	addq	$32, %r10
	movq	184(%rsp), %rax
	vpbroadcastw	189600(%rdx,%r14), %ymm4
	addq	$32, %r8
	vpmullw	-32(%r8), %ymm3, %ymm3
	vpmullw	128(%r8), %ymm2, %ymm2
	vpxor	%ymm3, %ymm2, %ymm2
	vpbroadcastw	189600(%rdx,%rax), %ymm3
	vpxor	-32(%r10), %ymm2, %ymm2
	vpmullw	288(%r8), %ymm4, %ymm4
	vpmullw	448(%r8), %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpxor	%ymm3, %ymm2, %ymm2
	vmovdqa	%ymm2, -32(%r10)
	cmpq	$160, %r12
	jne	.L160
	vmovdqa	384(%rsp), %ymm3
	movq	152(%rsp), %rax
	leaq	12800(%rsp), %r8
	movq	%rbx, %r10
	xorl	%r12d, %r12d
	vpsrlw	$9, %ymm3, %ymm2
	vpsrlw	$6, %ymm3, %ymm4
	vpand	%ymm7, %ymm4, %ymm4
	vpand	%ymm8, %ymm2, %ymm2
	vpxor	%ymm4, %ymm2, %ymm2
	vpsrlw	$3, %ymm3, %ymm4
	vpand	%ymm0, %ymm3, %ymm3
	vpand	%ymm1, %ymm4, %ymm4
	vpxor	%ymm3, %ymm4, %ymm3
	vpxor	%ymm3, %ymm2, %ymm2
	vmovdqa	416(%rsp), %ymm3
	vpsrlw	$3, %ymm2, %ymm6
	vpand	%ymm1, %ymm6, %ymm6
	vpsrlw	$6, %ymm3, %ymm4
	vpxor	%ymm2, %ymm6, %ymm6
	vpsrlw	$4, %ymm2, %ymm2
	vpand	%ymm7, %ymm4, %ymm4
	vpxor	%ymm2, %ymm6, %ymm6
	vpsrlw	$9, %ymm3, %ymm2
	vpand	%ymm8, %ymm2, %ymm2
	vpand	%ymm0, %ymm6, %ymm6
	vpxor	%ymm4, %ymm2, %ymm2
	vpsrlw	$3, %ymm3, %ymm4
	vpand	%ymm0, %ymm3, %ymm3
	vpand	%ymm1, %ymm4, %ymm4
	vpshufb	.LC57(%rip), %ymm6, %ymm13
	vpxor	%ymm3, %ymm4, %ymm3
	vpermq	$78, %ymm13, %ymm14
	vpxor	%ymm3, %ymm2, %ymm2
	vmovdqa	448(%rsp), %ymm3
	vpor	%ymm14, %ymm13, %ymm14
	vpshufb	.LC58(%rip), %ymm6, %ymm13
	vpsrlw	$3, %ymm2, %ymm5
	vpermq	$78, %ymm13, %ymm15
	vpand	%ymm1, %ymm5, %ymm5
	vpsrlw	$6, %ymm3, %ymm4
	vpor	%ymm15, %ymm13, %ymm13
	vpxor	%ymm2, %ymm5, %ymm5
	vpsrlw	$4, %ymm2, %ymm2
	vpand	%ymm7, %ymm4, %ymm4
	vpxor	%ymm2, %ymm5, %ymm5
	vpsrlw	$9, %ymm3, %ymm2
	vpand	%ymm8, %ymm2, %ymm2
	vpand	%ymm0, %ymm5, %ymm5
	vpxor	%ymm4, %ymm2, %ymm2
	vpsrlw	$3, %ymm3, %ymm4
	vpand	%ymm0, %ymm3, %ymm3
	vpand	%ymm1, %ymm4, %ymm4
	vpxor	%ymm3, %ymm4, %ymm3
	vpxor	%ymm3, %ymm2, %ymm2
	vmovdqa	480(%rsp), %ymm3
	vpsrlw	$3, %ymm2, %ymm4
	vpand	%ymm1, %ymm4, %ymm4
	vpsrlw	$9, %ymm3, %ymm9
	vpxor	%ymm2, %ymm4, %ymm4
	vpsrlw	$4, %ymm2, %ymm2
	vpand	%ymm8, %ymm9, %ymm9
	vpxor	%ymm2, %ymm4, %ymm4
	vpsrlw	$6, %ymm3, %ymm2
	vpand	%ymm7, %ymm2, %ymm2
	vpand	%ymm0, %ymm4, %ymm4
	vpxor	%ymm9, %ymm2, %ymm2
	vpsrlw	$3, %ymm3, %ymm9
	vpand	%ymm0, %ymm3, %ymm3
	vpand	%ymm1, %ymm9, %ymm9
	vpxor	%ymm3, %ymm9, %ymm3
	vmovdqa	512(%rsp), %ymm9
	vpxor	%ymm3, %ymm2, %ymm2
	vpsrlw	$3, %ymm2, %ymm3
	vpsrlw	$6, %ymm9, %ymm10
	vpand	%ymm1, %ymm3, %ymm3
	vpand	%ymm7, %ymm10, %ymm10
	vpxor	%ymm2, %ymm3, %ymm3
	vpsrlw	$4, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm3
	vpsrlw	$9, %ymm9, %ymm2
	vpand	%ymm8, %ymm2, %ymm2
	vpand	%ymm0, %ymm3, %ymm3
	vpxor	%ymm10, %ymm2, %ymm2
	vpsrlw	$3, %ymm9, %ymm10
	vpand	%ymm0, %ymm9, %ymm9
	vpand	%ymm1, %ymm10, %ymm10
	vpxor	%ymm9, %ymm10, %ymm9
	vpxor	%ymm9, %ymm2, %ymm2
	vpsrlw	$3, %ymm2, %ymm9
	vpand	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpsrlw	$4, %ymm2, %ymm2
	vpxor	%ymm2, %ymm9, %ymm2
	vmovdqu	(%rax), %ymm9
	vpand	%ymm0, %ymm2, %ymm2
	vpshufb	.LC35(%rip), %ymm9, %ymm10
	vpshufb	.LC34(%rip), %ymm9, %ymm11
	vpshufb	.LC28(%rip), %ymm9, %ymm12
	vpmullw	%ymm11, %ymm13, %ymm13
	vpmullw	%ymm10, %ymm14, %ymm14
	vpshufb	.LC29(%rip), %ymm9, %ymm9
	vpxor	%ymm13, %ymm14, %ymm14
	vpshufb	.LC59(%rip), %ymm6, %ymm13
	vpshufb	.LC60(%rip), %ymm6, %ymm6
	vpermq	$78, %ymm13, %ymm15
	vpor	%ymm15, %ymm13, %ymm13
	vpermq	$78, %ymm6, %ymm15
	vpor	%ymm15, %ymm6, %ymm6
	vpmullw	%ymm9, %ymm13, %ymm13
	vpmullw	%ymm12, %ymm6, %ymm6
	vpxor	%ymm6, %ymm13, %ymm13
	vpxor	%ymm13, %ymm14, %ymm6
	vpshufb	.LC60(%rip), %ymm5, %ymm13
	vpermq	$78, %ymm13, %ymm14
	vpor	%ymm14, %ymm13, %ymm14
	vpshufb	.LC59(%rip), %ymm5, %ymm13
	vpermq	$78, %ymm13, %ymm15
	vpmullw	%ymm12, %ymm14, %ymm14
	vpor	%ymm15, %ymm13, %ymm13
	vpmullw	%ymm9, %ymm13, %ymm13
	vpxor	%ymm13, %ymm14, %ymm14
	vpshufb	.LC58(%rip), %ymm5, %ymm13
	vpshufb	.LC57(%rip), %ymm5, %ymm5
	vpermq	$78, %ymm13, %ymm15
	vpor	%ymm15, %ymm13, %ymm13
	vpermq	$78, %ymm5, %ymm15
	vpor	%ymm15, %ymm5, %ymm5
	vpmullw	%ymm11, %ymm13, %ymm13
	vpmullw	%ymm10, %ymm5, %ymm5
	vpxor	%ymm5, %ymm13, %ymm13
	vpxor	%ymm13, %ymm14, %ymm5
	vpshufb	.LC60(%rip), %ymm4, %ymm13
	vpermq	$78, %ymm13, %ymm14
	vpor	%ymm14, %ymm13, %ymm14
	vpshufb	.LC59(%rip), %ymm4, %ymm13
	vpermq	$78, %ymm13, %ymm15
	vpmullw	%ymm12, %ymm14, %ymm14
	vpor	%ymm15, %ymm13, %ymm13
	vpmullw	%ymm9, %ymm13, %ymm13
	vpxor	%ymm13, %ymm14, %ymm14
	vpshufb	.LC58(%rip), %ymm4, %ymm13
	vpshufb	.LC57(%rip), %ymm4, %ymm4
	vpermq	$78, %ymm13, %ymm15
	vpor	%ymm15, %ymm13, %ymm13
	vpermq	$78, %ymm4, %ymm15
	vpor	%ymm15, %ymm4, %ymm4
	vpmullw	%ymm11, %ymm13, %ymm13
	vpmullw	%ymm10, %ymm4, %ymm4
	vpxor	%ymm4, %ymm13, %ymm13
	vpxor	%ymm13, %ymm14, %ymm4
	vpshufb	.LC59(%rip), %ymm3, %ymm13
	vpermq	$78, %ymm13, %ymm14
	vpor	%ymm14, %ymm13, %ymm14
	vpshufb	.LC60(%rip), %ymm3, %ymm13
	vpermq	$78, %ymm13, %ymm15
	vpmullw	%ymm9, %ymm14, %ymm14
	vpor	%ymm15, %ymm13, %ymm13
	vpmullw	%ymm12, %ymm13, %ymm13
	vpxor	%ymm13, %ymm14, %ymm14
	vpshufb	.LC58(%rip), %ymm3, %ymm13
	vpshufb	.LC57(%rip), %ymm3, %ymm3
	vpermq	$78, %ymm13, %ymm15
	vpor	%ymm15, %ymm13, %ymm13
	vpermq	$78, %ymm3, %ymm15
	vpor	%ymm15, %ymm3, %ymm3
	vpmullw	%ymm11, %ymm13, %ymm13
	vpmullw	%ymm10, %ymm3, %ymm3
	vpxor	%ymm3, %ymm13, %ymm13
	vpxor	%ymm13, %ymm14, %ymm3
	vpshufb	.LC60(%rip), %ymm2, %ymm13
	vpermq	$78, %ymm13, %ymm14
	vpor	%ymm14, %ymm13, %ymm13
	vpmullw	%ymm12, %ymm13, %ymm12
	vpshufb	.LC59(%rip), %ymm2, %ymm13
	vpermq	$78, %ymm13, %ymm14
	vpor	%ymm14, %ymm13, %ymm13
	vpmullw	%ymm9, %ymm13, %ymm9
	vpxor	%ymm9, %ymm12, %ymm12
	vpshufb	.LC58(%rip), %ymm2, %ymm9
	vpshufb	.LC57(%rip), %ymm2, %ymm2
	vpermq	$78, %ymm9, %ymm13
	vpor	%ymm13, %ymm9, %ymm9
	vpmullw	%ymm11, %ymm9, %ymm11
	vpermq	$78, %ymm2, %ymm9
	vpor	%ymm9, %ymm2, %ymm2
	vpmullw	%ymm10, %ymm2, %ymm9
	vpsrlw	$6, %ymm6, %ymm10
	vpand	%ymm7, %ymm10, %ymm10
	vpxor	%ymm9, %ymm11, %ymm2
	vpsrlw	$9, %ymm6, %ymm9
	vpand	%ymm8, %ymm9, %ymm9
	vpxor	%ymm2, %ymm12, %ymm2
	vpxor	%ymm10, %ymm9, %ymm9
	vpsrlw	$3, %ymm6, %ymm10
	vpand	%ymm0, %ymm6, %ymm6
	vpand	%ymm1, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm6
	vpsrlw	$9, %ymm5, %ymm10
	vpxor	%ymm6, %ymm9, %ymm6
	vpand	%ymm8, %ymm10, %ymm10
	vpsrlw	$3, %ymm6, %ymm9
	vpand	%ymm1, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpsrlw	$4, %ymm6, %ymm6
	vpxor	%ymm6, %ymm9, %ymm6
	vpsrlw	$6, %ymm5, %ymm9
	vpand	%ymm7, %ymm9, %ymm9
	vpand	%ymm0, %ymm6, %ymm6
	vpxor	%ymm10, %ymm9, %ymm9
	vpsrlw	$3, %ymm5, %ymm10
	vpand	%ymm0, %ymm5, %ymm5
	vpand	%ymm1, %ymm10, %ymm10
	vpxor	%ymm5, %ymm10, %ymm5
	vpsrlw	$9, %ymm4, %ymm10
	vpxor	%ymm5, %ymm9, %ymm5
	vpand	%ymm8, %ymm10, %ymm10
	vpsrlw	$3, %ymm5, %ymm9
	vpand	%ymm1, %ymm9, %ymm9
	vpxor	%ymm5, %ymm9, %ymm9
	vpsrlw	$4, %ymm5, %ymm5
	vpxor	%ymm5, %ymm9, %ymm5
	vpsrlw	$6, %ymm4, %ymm9
	vpand	%ymm7, %ymm9, %ymm9
	vpand	%ymm0, %ymm5, %ymm5
	vpxor	%ymm10, %ymm9, %ymm9
	vpsrlw	$3, %ymm4, %ymm10
	vpand	%ymm0, %ymm4, %ymm4
	vpand	%ymm1, %ymm10, %ymm10
	vpxor	%ymm4, %ymm10, %ymm4
	vpsrlw	$6, %ymm3, %ymm10
	vpxor	%ymm4, %ymm9, %ymm4
	vpand	%ymm7, %ymm10, %ymm10
	vpsrlw	$3, %ymm4, %ymm9
	vpand	%ymm1, %ymm9, %ymm9
	vpxor	%ymm4, %ymm9, %ymm9
	vpsrlw	$4, %ymm4, %ymm4
	vpxor	%ymm4, %ymm9, %ymm4
	vpsrlw	$9, %ymm3, %ymm9
	vpand	%ymm8, %ymm9, %ymm9
	vpand	%ymm0, %ymm4, %ymm4
	vpxor	%ymm10, %ymm9, %ymm9
	vpsrlw	$3, %ymm3, %ymm10
	vpand	%ymm0, %ymm3, %ymm3
	vpand	%ymm1, %ymm10, %ymm10
	vpxor	%ymm3, %ymm10, %ymm3
	vpsrlw	$6, %ymm2, %ymm10
	vpxor	%ymm3, %ymm9, %ymm3
	vpand	%ymm7, %ymm10, %ymm10
	vpsrlw	$3, %ymm3, %ymm9
	vpand	%ymm1, %ymm9, %ymm9
	vpxor	%ymm3, %ymm9, %ymm9
	vpsrlw	$4, %ymm3, %ymm3
	vpxor	%ymm3, %ymm9, %ymm3
	vpsrlw	$9, %ymm2, %ymm9
	vpand	%ymm8, %ymm9, %ymm9
	vpand	%ymm0, %ymm3, %ymm3
	vpxor	%ymm10, %ymm9, %ymm9
	vpsrlw	$3, %ymm2, %ymm10
	vpand	%ymm0, %ymm2, %ymm2
	vpand	%ymm1, %ymm10, %ymm10
	vpxor	%ymm2, %ymm10, %ymm2
	vpxor	%ymm2, %ymm9, %ymm2
	vpsrlw	$3, %ymm2, %ymm9
	vpand	%ymm1, %ymm9, %ymm9
	vpxor	%ymm2, %ymm9, %ymm9
	vpsrlw	$4, %ymm2, %ymm2
	vpxor	%ymm2, %ymm9, %ymm2
	vmovdqu	9600(%rax), %ymm9
	vpshufb	.LC28(%rip), %ymm6, %ymm15
	vpshufb	.LC29(%rip), %ymm6, %ymm13
	vpshufb	.LC34(%rip), %ymm6, %ymm14
	vpshufb	.LC35(%rip), %ymm6, %ymm6
	vpand	%ymm0, %ymm2, %ymm2
	movl	%edi, 152(%rsp)
	vpermq	$85, %ymm9, %ymm10
	vpermq	$0, %ymm9, %ymm11
	vpermq	$170, %ymm9, %ymm12
	movq	%rcx, 144(%rsp)
	vpmullw	%ymm12, %ymm15, %ymm15
	vpmullw	%ymm11, %ymm14, %ymm14
	vpermq	$255, %ymm9, %ymm9
	movq	%rax, %rdi
	vpmullw	%ymm9, %ymm13, %ymm13
	vpxor	%ymm13, %ymm15, %ymm15
	vpmullw	%ymm10, %ymm6, %ymm13
	vpxor	%ymm13, %ymm14, %ymm14
	vpshufb	.LC28(%rip), %ymm5, %ymm13
	vpxor	%ymm14, %ymm15, %ymm6
	vpshufb	.LC29(%rip), %ymm5, %ymm15
	vpshufb	.LC34(%rip), %ymm5, %ymm14
	vpmullw	%ymm12, %ymm13, %ymm13
	vpmullw	%ymm9, %ymm15, %ymm15
	vpshufb	.LC35(%rip), %ymm5, %ymm5
	vpmullw	%ymm11, %ymm14, %ymm14
	vpxor	%ymm13, %ymm15, %ymm15
	vpmullw	%ymm10, %ymm5, %ymm13
	vpxor	%ymm13, %ymm14, %ymm14
	vpshufb	.LC29(%rip), %ymm4, %ymm13
	vpxor	%ymm14, %ymm15, %ymm5
	vpshufb	.LC28(%rip), %ymm4, %ymm15
	vpshufb	.LC34(%rip), %ymm4, %ymm14
	vpmullw	%ymm9, %ymm13, %ymm13
	vpmullw	%ymm12, %ymm15, %ymm15
	vpshufb	.LC35(%rip), %ymm4, %ymm4
	vpmullw	%ymm11, %ymm14, %ymm14
	vpxor	%ymm13, %ymm15, %ymm15
	vpmullw	%ymm10, %ymm4, %ymm13
	vpxor	%ymm13, %ymm14, %ymm14
	vpshufb	.LC29(%rip), %ymm3, %ymm13
	vpxor	%ymm14, %ymm15, %ymm4
	vpshufb	.LC28(%rip), %ymm3, %ymm15
	vpshufb	.LC34(%rip), %ymm3, %ymm14
	vpmullw	%ymm9, %ymm13, %ymm13
	vpmullw	%ymm12, %ymm15, %ymm15
	vpshufb	.LC35(%rip), %ymm3, %ymm3
	vpmullw	%ymm11, %ymm14, %ymm14
	vpxor	%ymm13, %ymm15, %ymm15
	vpmullw	%ymm10, %ymm3, %ymm13
	vpxor	%ymm13, %ymm14, %ymm14
	vpshufb	.LC28(%rip), %ymm2, %ymm13
	vpmullw	%ymm12, %ymm13, %ymm12
	vpshufb	.LC29(%rip), %ymm2, %ymm13
	vpxor	%ymm14, %ymm15, %ymm3
	vpmullw	%ymm9, %ymm13, %ymm9
	vpxor	%ymm9, %ymm12, %ymm12
	vpshufb	.LC34(%rip), %ymm2, %ymm9
	vpmullw	%ymm11, %ymm9, %ymm11
	vpshufb	.LC35(%rip), %ymm2, %ymm9
	vpmullw	%ymm10, %ymm9, %ymm9
	vpsrlw	$6, %ymm6, %ymm10
	vpand	%ymm7, %ymm10, %ymm10
	vpxor	%ymm9, %ymm11, %ymm9
	vpxor	%ymm9, %ymm12, %ymm2
	vpsrlw	$9, %ymm6, %ymm9
	vpand	%ymm8, %ymm9, %ymm9
	vpxor	%ymm10, %ymm9, %ymm9
	vpsrlw	$3, %ymm6, %ymm10
	vpand	%ymm0, %ymm6, %ymm6
	vpand	%ymm1, %ymm10, %ymm10
	vpxor	%ymm6, %ymm10, %ymm6
	vpxor	%ymm6, %ymm9, %ymm6
	vpsrlw	$3, %ymm6, %ymm9
	vpand	%ymm1, %ymm9, %ymm9
	vpxor	%ymm6, %ymm9, %ymm9
	vpsrlw	$4, %ymm6, %ymm6
	vpxor	%ymm6, %ymm9, %ymm6
	vpsrlw	$9, %ymm5, %ymm9
	vpand	%ymm0, %ymm6, %ymm6
	vpand	%ymm8, %ymm9, %ymm9
	vmovdqa	%ymm6, 12800(%rsp)
	vpsrlw	$6, %ymm5, %ymm6
	vpand	%ymm7, %ymm6, %ymm6
	vpxor	%ymm9, %ymm6, %ymm6
	vpsrlw	$3, %ymm5, %ymm9
	vpand	%ymm0, %ymm5, %ymm5
	vpand	%ymm1, %ymm9, %ymm9
	vpxor	%ymm5, %ymm9, %ymm5
	vpxor	%ymm5, %ymm6, %ymm5
	vpsrlw	$3, %ymm5, %ymm6
	vpand	%ymm1, %ymm6, %ymm6
	vpxor	%ymm5, %ymm6, %ymm6
	vpsrlw	$4, %ymm5, %ymm5
	vpxor	%ymm5, %ymm6, %ymm5
	vpsrlw	$6, %ymm4, %ymm6
	vpand	%ymm0, %ymm5, %ymm5
	vpand	%ymm7, %ymm6, %ymm6
	vmovdqa	%ymm5, 12832(%rsp)
	vpsrlw	$9, %ymm4, %ymm5
	vpand	%ymm8, %ymm5, %ymm5
	vpxor	%ymm6, %ymm5, %ymm5
	vpsrlw	$3, %ymm4, %ymm6
	vpand	%ymm0, %ymm4, %ymm4
	vpand	%ymm1, %ymm6, %ymm6
	vpxor	%ymm4, %ymm6, %ymm4
	vpxor	%ymm4, %ymm5, %ymm4
	vpsrlw	$3, %ymm4, %ymm5
	vpand	%ymm1, %ymm5, %ymm5
	vpxor	%ymm4, %ymm5, %ymm5
	vpsrlw	$4, %ymm4, %ymm4
	vpxor	%ymm4, %ymm5, %ymm4
	vpsrlw	$9, %ymm3, %ymm5
	vpand	%ymm0, %ymm4, %ymm4
	vpand	%ymm8, %ymm5, %ymm5
	vmovdqa	%ymm4, 12864(%rsp)
	vpsrlw	$6, %ymm3, %ymm4
	vpand	%ymm7, %ymm4, %ymm4
	vpxor	%ymm5, %ymm4, %ymm4
	vpsrlw	$3, %ymm3, %ymm5
	vpand	%ymm0, %ymm3, %ymm3
	vpand	%ymm1, %ymm5, %ymm5
	vpxor	%ymm3, %ymm5, %ymm3
	vpxor	%ymm3, %ymm4, %ymm3
	vpsrlw	$3, %ymm3, %ymm4
	vpand	%ymm1, %ymm4, %ymm4
	vpxor	%ymm3, %ymm4, %ymm4
	vpsrlw	$4, %ymm3, %ymm3
	vpxor	%ymm3, %ymm4, %ymm3
	vpsrlw	$6, %ymm2, %ymm4
	vpand	%ymm0, %ymm3, %ymm3
	vpand	%ymm7, %ymm4, %ymm4
	vmovdqa	%ymm3, 12896(%rsp)
	vpsrlw	$9, %ymm2, %ymm3
	vpand	%ymm8, %ymm3, %ymm3
	vpxor	%ymm4, %ymm3, %ymm3
	vpsrlw	$3, %ymm2, %ymm4
	vpand	%ymm0, %ymm2, %ymm2
	vpand	%ymm1, %ymm4, %ymm4
	vpxor	%ymm2, %ymm4, %ymm2
	vpxor	%ymm2, %ymm3, %ymm2
	vpsrlw	$3, %ymm2, %ymm3
	vpand	%ymm1, %ymm3, %ymm3
	vpxor	%ymm2, %ymm3, %ymm3
	vpsrlw	$4, %ymm2, %ymm2
	vpxor	%ymm2, %ymm3, %ymm2
	vpand	%ymm0, %ymm2, %ymm2
	vmovdqa	%ymm2, 12928(%rsp)
	vmovdqu	3200(%rax), %ymm2
	vpshufb	.LC58(%rip), %ymm2, %ymm9
	vpshufb	.LC57(%rip), %ymm2, %ymm6
	vpshufb	.LC60(%rip), %ymm2, %ymm5
	vpermq	$78, %ymm9, %ymm3
	vpshufb	.LC59(%rip), %ymm2, %ymm2
	movq	%rdx, 136(%rsp)
	vpor	%ymm3, %ymm9, %ymm9
	vpermq	$78, %ymm6, %ymm3
	movq	%rbx, 128(%rsp)
	vpor	%ymm3, %ymm6, %ymm6
	movq	%r13, 80(%rsp)
	vpermq	$78, %ymm5, %ymm3
	movq	%r9, 72(%rsp)
	vpor	%ymm3, %ymm5, %ymm5
	vpermq	$78, %ymm2, %ymm3
	movl	%esi, 64(%rsp)
	vpor	%ymm3, %ymm2, %ymm4
	movq	%r15, %rsi
.L161:
	movq	%r10, 56(%rsp)
	movq	%r10, %rax
	xorl	%edx, %edx
	leaq	2(%r8), %r15
	movl	%r12d, 52(%rsp)
	leaq	4(%r8), %r13
	leaq	6(%r8), %rbx
.L162:
	movzwl	(%r8,%rdx), %r12d
	movzwl	(%r15,%rdx), %r10d
	addq	$768, %rax
	movzwl	0(%r13,%rdx), %r9d
	movzwl	(%rbx,%rdx), %ecx
	addq	$8, %rdx
	vmovd	%r12d, %xmm3
	vmovd	%r10d, %xmm10
	vpinsrw	$1, %r12d, %xmm3, %xmm2
	vpinsrw	$1, %r10d, %xmm10, %xmm3
	vmovd	%ecx, %xmm11
	vpunpckldq	%xmm3, %xmm3, %xmm3
	vmovd	%r9d, %xmm10
	vpunpckldq	%xmm2, %xmm2, %xmm2
	vpunpcklqdq	%xmm3, %xmm2, %xmm2
	vpinsrw	$1, %r9d, %xmm10, %xmm3
	vpinsrw	$1, %ecx, %xmm11, %xmm10
	vpunpckldq	%xmm3, %xmm3, %xmm3
	vpunpckldq	%xmm10, %xmm10, %xmm10
	vpunpcklqdq	%xmm10, %xmm3, %xmm3
	vinserti128	$0x1, %xmm3, %ymm2, %ymm2
	vpmullw	%ymm9, %ymm2, %ymm3
	vpxor	-768(%rax), %ymm3, %ymm3
	vmovdqa	%ymm3, -768(%rax)
	vpmullw	%ymm6, %ymm2, %ymm3
	vpxor	-576(%rax), %ymm3, %ymm3
	vmovdqa	%ymm3, -576(%rax)
	vpmullw	%ymm5, %ymm2, %ymm3
	vpmullw	%ymm4, %ymm2, %ymm2
	vpxor	-384(%rax), %ymm3, %ymm3
	vpxor	-192(%rax), %ymm2, %ymm2
	vmovdqa	%ymm3, -384(%rax)
	vmovdqa	%ymm2, -192(%rax)
	cmpq	$32, %rdx
	jne	.L162
	movl	52(%rsp), %r12d
	movq	56(%rsp), %r10
	addq	$32, %r8
	addl	$4, %r12d
	addq	$32, %r10
	cmpl	$20, %r12d
	jne	.L161
	movq	%rsi, %r15
	movl	64(%rsp), %esi
	movq	136(%rsp), %rdx
	leaq	32(%rdi), %rax
	movq	144(%rsp), %rcx
	movq	128(%rsp), %rbx
	incl	%esi
	movq	80(%rsp), %r13
	movq	72(%rsp), %r9
	addq	$8, %rdx
	movl	152(%rsp), %edi
	cmpl	%esi, 168(%rsp)
	jne	.L164
	movq	%rcx, %r12
	leal	1(%rdi), %ecx
	addq	$3072, %rbx
	addq	$160, %r13
	addq	$640, %r9
	cmpl	$5, %ecx
	jne	.L159
	movl	$2021161080, %edi
	movq	192(%rsp), %rax
	leaq	12800(%rsp), %rdx
	vpcmpeqd	%ymm0, %ymm0, %ymm0
	vmovd	%edi, %xmm6
	vpsrlw	$8, %ymm0, %ymm0
	movl	$1010580540, %edi
	movq	%rdx, %rcx
	vmovd	%edi, %xmm5
	leaq	15360(%rax), %rsi
	vpbroadcastd	%xmm6, %ymm6
	movl	$505290270, %edi
	vmovd	%edi, %xmm3
	movl	$252645135, %edi
	vpbroadcastd	%xmm5, %ymm5
	vmovd	%edi, %xmm2
	movl	$522133279, %edi
	vpbroadcastd	%xmm3, %ymm3
	vmovd	%edi, %xmm4
	vpbroadcastd	%xmm2, %ymm2
	vpbroadcastd	%xmm4, %ymm4
.L165:
	vmovdqa	(%rax), %ymm1
	vmovdqa	32(%rax), %ymm9
	addq	$192, %rax
	addq	$96, %rcx
	vpsrlw	$9, %ymm1, %ymm7
	vpsrlw	$9, %ymm9, %ymm8
	vpand	%ymm8, %ymm0, %ymm8
	vpsrlw	$6, %ymm9, %ymm10
	vpand	%ymm7, %ymm0, %ymm7
	vpackuswb	%ymm8, %ymm7, %ymm7
	vpsrlw	$6, %ymm1, %ymm8
	vpand	%ymm10, %ymm0, %ymm10
	vpand	%ymm8, %ymm0, %ymm8
	vpermq	$216, %ymm7, %ymm7
	vpackuswb	%ymm10, %ymm8, %ymm8
	vpsrlw	$3, %ymm9, %ymm10
	vpand	%ymm7, %ymm6, %ymm7
	vpermq	$216, %ymm8, %ymm8
	vpand	%ymm10, %ymm0, %ymm10
	vpand	%ymm9, %ymm0, %ymm9
	vpand	%ymm8, %ymm5, %ymm8
	vpxor	%ymm8, %ymm7, %ymm7
	vpsrlw	$3, %ymm1, %ymm8
	vpand	%ymm1, %ymm0, %ymm1
	vpand	%ymm8, %ymm0, %ymm8
	vpackuswb	%ymm9, %ymm1, %ymm1
	vpackuswb	%ymm10, %ymm8, %ymm8
	vpermq	$216, %ymm1, %ymm1
	vpermq	$216, %ymm8, %ymm8
	vpand	%ymm1, %ymm2, %ymm1
	vpand	%ymm8, %ymm3, %ymm8
	vpxor	%ymm1, %ymm8, %ymm1
	vpxor	%ymm1, %ymm7, %ymm1
	vpsrlw	$4, %ymm1, %ymm7
	vpand	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpsrlw	$3, %ymm1, %ymm1
	vpand	%ymm1, %ymm4, %ymm1
	vpand	%ymm3, %ymm1, %ymm1
	vpxor	%ymm1, %ymm7, %ymm1
	vpand	%ymm2, %ymm1, %ymm1
	vmovdqa	%ymm1, -96(%rcx)
	vmovdqa	-128(%rax), %ymm1
	vmovdqa	-96(%rax), %ymm9
	vpsrlw	$9, %ymm1, %ymm7
	vpsrlw	$9, %ymm9, %ymm8
	vpand	%ymm8, %ymm0, %ymm8
	vpsrlw	$6, %ymm9, %ymm10
	vpand	%ymm7, %ymm0, %ymm7
	vpackuswb	%ymm8, %ymm7, %ymm7
	vpsrlw	$6, %ymm1, %ymm8
	vpand	%ymm10, %ymm0, %ymm10
	vpand	%ymm8, %ymm0, %ymm8
	vpermq	$216, %ymm7, %ymm7
	vpackuswb	%ymm10, %ymm8, %ymm8
	vpsrlw	$3, %ymm9, %ymm10
	vpand	%ymm6, %ymm7, %ymm7
	vpermq	$216, %ymm8, %ymm8
	vpand	%ymm10, %ymm0, %ymm10
	vpand	%ymm9, %ymm0, %ymm9
	vpand	%ymm5, %ymm8, %ymm8
	vpxor	%ymm8, %ymm7, %ymm7
	vpsrlw	$3, %ymm1, %ymm8
	vpand	%ymm1, %ymm0, %ymm1
	vpand	%ymm8, %ymm0, %ymm8
	vpackuswb	%ymm9, %ymm1, %ymm1
	vpackuswb	%ymm10, %ymm8, %ymm8
	vpermq	$216, %ymm1, %ymm1
	vpermq	$216, %ymm8, %ymm8
	vpand	%ymm2, %ymm1, %ymm1
	vpand	%ymm3, %ymm8, %ymm8
	vpxor	%ymm1, %ymm8, %ymm1
	vpxor	%ymm1, %ymm7, %ymm1
	vpsrlw	$4, %ymm1, %ymm7
	vpand	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpsrlw	$3, %ymm1, %ymm1
	vpand	%ymm4, %ymm1, %ymm1
	vpand	%ymm3, %ymm1, %ymm1
	vpxor	%ymm1, %ymm7, %ymm1
	vpand	%ymm2, %ymm1, %ymm1
	vmovdqa	%ymm1, -64(%rcx)
	vmovdqa	-64(%rax), %ymm1
	vmovdqa	-32(%rax), %ymm9
	vpsrlw	$9, %ymm1, %ymm7
	vpsrlw	$9, %ymm9, %ymm8
	vpand	%ymm8, %ymm0, %ymm8
	vpsrlw	$6, %ymm9, %ymm10
	vpand	%ymm7, %ymm0, %ymm7
	vpackuswb	%ymm8, %ymm7, %ymm7
	vpsrlw	$6, %ymm1, %ymm8
	vpand	%ymm10, %ymm0, %ymm10
	vpand	%ymm8, %ymm0, %ymm8
	vpermq	$216, %ymm7, %ymm7
	vpackuswb	%ymm10, %ymm8, %ymm8
	vpsrlw	$3, %ymm9, %ymm10
	vpand	%ymm6, %ymm7, %ymm7
	vpermq	$216, %ymm8, %ymm8
	vpand	%ymm10, %ymm0, %ymm10
	vpand	%ymm9, %ymm0, %ymm9
	vpand	%ymm5, %ymm8, %ymm8
	vpxor	%ymm8, %ymm7, %ymm7
	vpsrlw	$3, %ymm1, %ymm8
	vpand	%ymm1, %ymm0, %ymm1
	vpand	%ymm8, %ymm0, %ymm8
	vpackuswb	%ymm9, %ymm1, %ymm1
	vpackuswb	%ymm10, %ymm8, %ymm8
	vpermq	$216, %ymm1, %ymm1
	vpermq	$216, %ymm8, %ymm8
	vpand	%ymm2, %ymm1, %ymm1
	vpand	%ymm3, %ymm8, %ymm8
	vpxor	%ymm1, %ymm8, %ymm1
	vpxor	%ymm1, %ymm7, %ymm1
	vpsrlw	$4, %ymm1, %ymm7
	vpand	%ymm2, %ymm7, %ymm7
	vpxor	%ymm1, %ymm7, %ymm7
	vpsrlw	$3, %ymm1, %ymm1
	vpand	%ymm4, %ymm1, %ymm1
	vpand	%ymm3, %ymm1, %ymm1
	vpxor	%ymm1, %ymm7, %ymm1
	vpand	%ymm2, %ymm1, %ymm1
	vmovdqa	%ymm1, -32(%rcx)
	cmpq	%rax, %rsi
	jne	.L165
	leaq	12800(%rsp), %rax
	movq	%rsi, 80(%rsp)
	vmovdqa	vector_inv_table(%rip), %ymm10
	movl	$78, %ebx
	leaq	192(%rax), %rdi
	movq	%rdx, 72(%rsp)
	vmovdqa	vtl_mult_table1(%rip), %ymm9
	movq	%rax, %r9
	movq	%rdi, 168(%rsp)
	vmovdqa	vtl_multmask1(%rip), %ymm8
	xorl	%r10d, %r10d
	xorl	%r15d, %r15d
	vmovdqa	vtl_mult_table2(%rip), %ymm7
	vmovdqa	vtl_multmask2(%rip), %ymm6
	xorl	%ecx, %ecx
	xorl	%r13d, %r13d
	vmovdqa	vtl_mult_table4(%rip), %ymm5
	vmovdqa	vtl_multmask4(%rip), %ymm4
	leaq	96(%rax), %r11
	vpxor	%xmm1, %xmm1, %xmm1
	vmovdqa	vtl_mult_table8(%rip), %ymm3
	vmovdqa	vtl_multmask8(%rip), %ymm2
.L173:
	movzbl	(%r9), %edi
	leal	1(%rcx), %esi
	movl	%esi, 184(%rsp)
	cmpb	$1, %dil
	sbbl	%r8d, %r8d
	cmpl	$79, %ecx
	je	.L166
	movl	%ebx, %edi
	movq	168(%rsp), %rsi
	vmovdqa	(%rax), %ymm13
	leaq	96(%rax), %r14
	addq	%r15, %rdi
	vmovdqa	32(%rax), %ymm12
	vmovdqa	64(%rax), %ymm11
	leaq	(%rdi,%rdi,2), %rdi
	salq	$5, %rdi
	leaq	(%rdi,%rsi), %rdx
.L167:
	vmovd	%r8d, %xmm0
	vpbroadcastb	%xmm0, %ymm0
	vpand	(%r14), %ymm0, %ymm14
	vpxor	%ymm14, %ymm13, %ymm13
	vmovdqa	%ymm13, (%rax)
	vpand	32(%r14), %ymm0, %ymm14
	vpxor	%ymm14, %ymm12, %ymm12
	vmovdqa	%ymm12, 32(%rax)
	vpand	64(%r14), %ymm0, %ymm0
	vpxor	%ymm0, %ymm11, %ymm11
	vmovdqa	%ymm11, 64(%rax)
	movzbl	(%r9), %edi
	cmpb	$1, %dil
	sbbl	%r8d, %r8d
	addq	$96, %r14
	cmpq	%r14, %rdx
	jne	.L167
.L166:
	vmovd	%edi, %xmm0
	movl	%ecx, %esi
	andl	$-32, %ecx
	orl	%r8d, %r13d
	vpbroadcastb	%xmm0, %ymm0
	movslq	%ecx, %r14
	sarl	$5, %esi
	leal	32(%rcx), %edx
	vpshufb	%ymm0, %ymm10, %ymm0
	addq	%rax, %r14
	vpbroadcastb	%xmm0, %ymm0
	vpand	%ymm0, %ymm4, %ymm11
	vpand	%ymm0, %ymm2, %ymm12
	vpcmpgtd	%ymm1, %ymm11, %ymm11
	vpcmpgtd	%ymm1, %ymm12, %ymm12
	vpand	%ymm11, %ymm5, %ymm11
	vpand	%ymm12, %ymm3, %ymm12
	vpxor	%ymm12, %ymm11, %ymm11
	vpand	%ymm0, %ymm8, %ymm12
	vpand	%ymm0, %ymm6, %ymm0
	vpcmpgtd	%ymm1, %ymm12, %ymm12
	vpcmpgtd	%ymm1, %ymm0, %ymm0
	vpand	%ymm12, %ymm9, %ymm12
	vpand	%ymm0, %ymm7, %ymm0
	vpxor	%ymm0, %ymm12, %ymm0
	vpxor	%ymm0, %ymm11, %ymm0
	vpshufb	(%r14), %ymm0, %ymm11
	vmovdqa	%ymm11, (%r14)
	cmpl	$64, %ecx
	je	.L168
	movslq	%edx, %rcx
	vpshufb	(%rcx,%rax), %ymm0, %ymm11
	vmovdqa	%ymm11, (%rcx,%rax)
	testl	%esi, %esi
	jne	.L186
	vpshufb	64(%rax), %ymm0, %ymm0
	vmovdqa	%ymm0, 64(%rax)
.L186:
	movl	%ebx, %r8d
	movslq	%esi, %rdi
	leaq	(%r15,%r15,2), %rcx
	addq	%r15, %r8
	addq	%rdi, %rcx
	leaq	(%r8,%r8,2), %r8
	salq	$5, %rcx
	addq	%rdi, %r8
	addq	%r11, %rcx
	negq	%rdi
	salq	$5, %r8
	movq	%rcx, 144(%rsp)
	salq	$5, %rdi
	addq	168(%rsp), %r8
	movq	%r8, 136(%rsp)
	movq	%rdi, %r8
	leaq	(%rdi,%r10), %rdi
	movq	%rdi, 152(%rsp)
	movslq	%edx, %rdi
	movq	144(%rsp), %rcx
	movq	%rdi, 128(%rsp)
	movl	%edx, 144(%rsp)
.L172:
	movq	152(%rsp), %rdi
	movq	160(%rsp), %rdx
	addq	%rcx, %rdi
	cmpl	$96, 144(%rsp)
	vpbroadcastb	-96(%rdx,%rdi), %ymm0
	vpand	%ymm0, %ymm8, %ymm11
	vpand	%ymm0, %ymm6, %ymm12
	vpcmpgtd	%ymm1, %ymm11, %ymm11
	vpcmpgtd	%ymm1, %ymm12, %ymm12
	vpand	%ymm11, %ymm9, %ymm11
	vpand	%ymm12, %ymm7, %ymm12
	vpxor	%ymm12, %ymm11, %ymm11
	vpand	%ymm0, %ymm4, %ymm12
	vpand	%ymm0, %ymm2, %ymm0
	vpcmpgtd	%ymm1, %ymm12, %ymm12
	vpcmpgtd	%ymm1, %ymm0, %ymm0
	vpand	%ymm12, %ymm5, %ymm12
	vpand	%ymm0, %ymm3, %ymm0
	vpxor	%ymm0, %ymm12, %ymm0
	vpxor	%ymm0, %ymm11, %ymm0
	vpshufb	(%r14), %ymm0, %ymm11
	vpxor	(%rcx), %ymm11, %ymm11
	vmovdqa	%ymm11, (%rcx)
	je	.L171
	movq	128(%rsp), %rdi
	vpshufb	(%rax,%rdi), %ymm0, %ymm11
	vpxor	32(%rcx), %ymm11, %ymm11
	vmovdqa	%ymm11, 32(%rcx)
	cmpl	$1, %esi
	je	.L171
	vpshufb	64(%rax), %ymm0, %ymm0
	vpxor	64(%rcx,%r8), %ymm0, %ymm0
	vmovdqa	%ymm0, 64(%rcx,%r8)
.L171:
	addq	$96, %rcx
	cmpq	136(%rsp), %rcx
	jne	.L172
	addq	$96, 160(%rsp)
	movl	184(%rsp), %ecx
	incq	%r15
	addq	$97, %r9
	addq	$96, %rax
	subq	$95, %r10
	decl	%ebx
	jmp	.L173
.L257:
	movq	88(%rsp), %rbx
	vpxor	%xmm0, %xmm0, %xmm0
	movl	$-1, %r13d
	vmovdqu	%ymm0, 192(%rbx)
	vmovdqu	%ymm0, (%rbx)
	vmovdqu	%ymm0, 32(%rbx)
	vmovdqu	%ymm0, 64(%rbx)
	vmovdqu	%ymm0, 96(%rbx)
	vmovdqu	%ymm0, 128(%rbx)
	vmovdqu	%ymm0, 160(%rbx)
	vmovdqu	%ymm0, 216(%rbx)
.L114:
	movq	52120(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L258
	vzeroupper
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
.L168:
	.cfi_restore_state
	cmpl	$80, 184(%rsp)
	jne	.L186
	movq	80(%rsp), %rsi
	movq	72(%rsp), %rdx
	movq	192(%rsp), %rax
	jmp	.L170
.L259:
	addq	$96, %r11
.L170:
	vmovdqa	(%rdx), %ymm0
	addq	$192, %rax
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqa	%ymm1, -192(%rax)
	vmovdqa	%ymm0, -160(%rax)
	vmovdqa	32(%rdx), %ymm0
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqa	%ymm1, -128(%rax)
	vmovdqa	%ymm0, -96(%rax)
	vmovdqa	64(%rdx), %ymm0
	movq	%r11, %rdx
	vpmovzxbw	%xmm0, %ymm1
	vextracti128	$0x1, %ymm0, %xmm0
	vpmovzxbw	%xmm0, %ymm0
	vmovdqa	%ymm1, -64(%rax)
	vmovdqa	%ymm0, -32(%rax)
	cmpq	%rax, %rsi
	jne	.L259
	testl	%r13d, %r13d
	je	.L260
	movzbl	223(%rsp), %r12d
	jmp	.L185
.L260:
	movq	192(%rsp), %r14
	vpxor	%xmm0, %xmm0, %xmm0
	movq	%r12, 200(%rsp)
	leaq	542(%rsp), %rsi
	movq	88(%rsp), %rbx
	vmovdqa	%ymm0, 384(%rsp)
	movl	$79, %r8d
	xorl	%r10d, %r10d
	leaq	15328(%r14), %r11
	vmovdqa	%ymm0, 416(%rsp)
	movl	$7663, %r14d
	movl	$80, %edi
	vmovdqa	%ymm0, 448(%rsp)
	movq	%r11, %r9
	vmovdqa	%ymm0, 480(%rsp)
	vmovdqa	%ymm0, 512(%rsp)
	jmp	.L181
.L262:
	leal	-64(%r8), %eax
	movl	%r8d, %r12d
	movl	%edi, %edx
	cmpl	$14, %eax
	jbe	.L191
	vmovdqu	2(%rsi), %ymm0
	movl	%r10d, %eax
	shrl	$4, %eax
	vpmullw	(%r9), %ymm0, %ymm0
	cmpl	$1, %eax
	je	.L177
	vmovdqu	34(%rsi), %ymm1
	vpmullw	32(%r9), %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	cmpl	$2, %eax
	je	.L177
	vmovdqu	66(%rsi), %ymm1
	vpmullw	64(%r9), %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	cmpl	$4, %eax
	jne	.L177
	vmovdqu	96(%r9), %ymm1
	vpmullw	98(%rsi), %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
.L177:
	vextracti128	$0x1, %ymm0, %xmm1
	vpxor	%xmm0, %xmm1, %xmm1
	vpsrldq	$8, %xmm1, %xmm0
	vpxor	%xmm0, %xmm1, %xmm0
	vpsrldq	$4, %xmm0, %xmm2
	vpxor	%xmm2, %xmm0, %xmm0
	vpsrldq	$2, %xmm0, %xmm2
	vpxor	%xmm2, %xmm0, %xmm0
	vpextrw	$0, %xmm0, %eax
	testb	$15, %r10b
	je	.L175
	movl	%r10d, %ecx
	andl	$-16, %ecx
	leal	(%rdi,%rcx), %edx
.L176:
	addl	%ecx, %r12d
	leal	-72(%r12), %r15d
	cmpl	$6, %r15d
	jbe	.L179
	leaq	1(%r8,%rcx), %rax
	leaq	1(%r14,%rcx), %rcx
	movl	$79, %r15d
	vmovdqu	20480(%rsp,%rcx,2), %xmm0
	subl	%r12d, %r15d
	vpmullw	384(%rsp,%rax,2), %xmm0, %xmm0
	vpxor	%xmm1, %xmm0, %xmm0
	vpsrldq	$8, %xmm0, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpsrldq	$4, %xmm0, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpsrldq	$2, %xmm0, %xmm1
	vpxor	%xmm1, %xmm0, %xmm0
	vpextrw	$0, %xmm0, %eax
	testb	$7, %r15b
	je	.L175
	andl	$-8, %r15d
	addl	%r15d, %edx
.L179:
	movslq	%r8d, %rcx
	movslq	%edx, %r12
	leaq	(%rcx,%rcx,2), %rcx
	salq	$5, %rcx
	leaq	(%rcx,%r12), %r15
	movzwl	20480(%rsp,%r15,2), %r15d
	imulw	384(%rsp,%r12,2), %r15w
	leal	1(%rdx), %r12d
	xorl	%r15d, %eax
	cmpl	$79, %edx
	je	.L175
	movslq	%r12d, %r12
	leaq	(%rcx,%r12), %r15
	movzwl	20480(%rsp,%r15,2), %r15d
	imulw	384(%rsp,%r12,2), %r15w
	leal	2(%rdx), %r12d
	xorl	%r15d, %eax
	cmpl	$78, %edx
	je	.L175
	movslq	%r12d, %r12
	leaq	(%rcx,%r12), %r15
	movzwl	20480(%rsp,%r15,2), %r15d
	imulw	384(%rsp,%r12,2), %r15w
	leal	3(%rdx), %r12d
	xorl	%r15d, %eax
	cmpl	$77, %edx
	je	.L175
	movslq	%r12d, %r12
	leaq	(%rcx,%r12), %r15
	movzwl	20480(%rsp,%r15,2), %r15d
	imulw	384(%rsp,%r12,2), %r15w
	leal	4(%rdx), %r12d
	xorl	%r15d, %eax
	cmpl	$76, %edx
	je	.L175
	movslq	%r12d, %r12
	leaq	(%rcx,%r12), %r15
	movzwl	20480(%rsp,%r15,2), %r15d
	imulw	384(%rsp,%r12,2), %r15w
	leal	5(%rdx), %r12d
	xorl	%r15d, %eax
	cmpl	$75, %edx
	je	.L175
	movslq	%r12d, %r12
	leaq	(%rcx,%r12), %r15
	movzwl	20480(%rsp,%r15,2), %r15d
	imulw	384(%rsp,%r12,2), %r15w
	leal	6(%rdx), %r12d
	xorl	%r15d, %eax
	cmpl	$74, %edx
	je	.L175
	movslq	%r12d, %rdx
	addq	%rdx, %rcx
	movzwl	384(%rsp,%rdx,2), %edx
	imulw	20480(%rsp,%rcx,2), %dx
	xorl	%edx, %eax
.L175:
	movzbl	(%r11), %ecx
	incl	%r10d
	decq	%r8
	subq	$192, %r11
	movl	%ecx, %r12d
	leal	0(,%rcx,8), %edx
	sall	$6, %r12d
	orl	%r12d, %edx
	orl	%ecx, %edx
	sall	$9, %ecx
	orl	%ecx, %edx
	andw	$4369, %dx
	movl	%edx, %ecx
	xorl	%eax, %ecx
	movzwl	%cx, %edx
	andl	$15, %ecx
	movl	%edx, %eax
	movl	%edx, %r12d
	sarl	$9, %edx
	sarl	$3, %eax
	sarl	$6, %r12d
	andl	$120, %edx
	andl	$30, %eax
	andl	$60, %r12d
	xorl	%r12d, %eax
	xorl	%ecx, %eax
	xorl	%edx, %eax
	movl	%eax, %edx
	shrw	$3, %dx
	andl	$14, %edx
	xorl	%eax, %edx
	shrw	$4, %ax
	xorl	%edx, %eax
	andl	$15, %eax
	movl	%eax, %ecx
	leal	0(,%rax,8), %edx
	sall	$6, %ecx
	orl	%ecx, %edx
	orl	%eax, %edx
	sall	$9, %eax
	orl	%edx, %eax
	andw	$4369, %ax
	subq	$2, %rsi
	movw	%ax, 2(%rsi)
	subq	$194, %r9
	subq	$97, %r14
	decl	%edi
	je	.L261
.L181:
	cmpl	$80, %edi
	jne	.L262
	xorl	%eax, %eax
	jmp	.L175
.L191:
	vpxor	%xmm1, %xmm1, %xmm1
	xorl	%ecx, %ecx
	xorl	%eax, %eax
	jmp	.L176
.L261:
	vmovdqa	384(%rsp), %ymm1
	vmovdqa	416(%rsp), %ymm5
	vpcmpeqd	%ymm7, %ymm7, %ymm7
	movl	$2021161080, %eax
	vpsrlw	$8, %ymm7, %ymm7
	vmovd	%eax, %xmm11
	movl	$1010580540, %eax
	vmovdqa	480(%rsp), %ymm14
	vpsrlw	$9, %ymm1, %ymm3
	vpsrlw	$9, %ymm5, %ymm0
	vmovd	%eax, %xmm10
	movl	$505290270, %eax
	vpand	%ymm0, %ymm7, %ymm0
	vpand	%ymm3, %ymm7, %ymm3
	vpbroadcastd	%xmm11, %ymm2
	movq	200(%rsp), %r15
	vpackuswb	%ymm0, %ymm3, %ymm3
	vpsrlw	$6, %ymm5, %ymm4
	vpbroadcastd	%xmm10, %ymm13
	movq	16(%rsp), %rsi
	vpsrlw	$6, %ymm1, %ymm0
	vpand	%ymm4, %ymm7, %ymm4
	vpermq	$216, %ymm3, %ymm3
	vpand	%ymm0, %ymm7, %ymm0
	vpand	%ymm3, %ymm2, %ymm3
	vmovd	%eax, %xmm6
	movl	$252645135, %eax
	vpackuswb	%ymm4, %ymm0, %ymm0
	vpsrlw	$3, %ymm5, %ymm4
	vpand	%ymm5, %ymm7, %ymm5
	vpermq	$216, %ymm0, %ymm0
	vpand	%ymm4, %ymm7, %ymm4
	vpbroadcastd	%xmm11, %xmm11
	vpand	%ymm0, %ymm13, %ymm0
	vpsrlw	$9, %ymm14, %ymm12
	vpbroadcastd	%xmm10, %xmm10
	vpxor	%ymm0, %ymm3, %ymm0
	vpsrlw	$3, %ymm1, %ymm3
	vpand	%ymm1, %ymm7, %ymm1
	vpand	%ymm3, %ymm7, %ymm3
	vpackuswb	%ymm5, %ymm1, %ymm1
	vpand	%ymm12, %ymm7, %ymm12
	vpackuswb	%ymm4, %ymm3, %ymm3
	vpbroadcastd	%xmm6, %ymm4
	vpermq	$216, %ymm1, %ymm1
	vpermq	$216, %ymm3, %ymm3
	vpsrlw	$6, %ymm14, %ymm15
	vpbroadcastd	%xmm6, %xmm6
	vpand	%ymm3, %ymm4, %ymm8
	vmovd	%eax, %xmm3
	vpand	%ymm15, %ymm7, %ymm15
	movl	$522133279, %eax
	vpbroadcastd	%xmm3, %ymm5
	vmovd	%eax, %xmm9
	vpbroadcastd	%xmm3, %xmm3
	vpand	%ymm1, %ymm5, %ymm1
	leaq	51440(%rsp), %rcx
	vpxor	%ymm1, %ymm8, %ymm1
	vpbroadcastd	%xmm9, %ymm8
	vpbroadcastd	%xmm9, %xmm9
	vpxor	%ymm1, %ymm0, %ymm1
	vpsrlw	$4, %ymm1, %ymm0
	vpand	%ymm5, %ymm0, %ymm0
	vpxor	%ymm1, %ymm0, %ymm0
	vpsrlw	$3, %ymm1, %ymm1
	vpand	%ymm1, %ymm8, %ymm1
	vpand	%ymm4, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vmovdqa	448(%rsp), %ymm1
	vpand	%ymm5, %ymm0, %ymm0
	vmovdqa	%ymm0, 51360(%rsp)
	vpsrlw	$9, %ymm1, %ymm0
	vpand	%ymm0, %ymm7, %ymm0
	vpackuswb	%ymm12, %ymm0, %ymm0
	vpsrlw	$6, %ymm1, %ymm12
	vpand	%ymm12, %ymm7, %ymm12
	vpermq	$216, %ymm0, %ymm0
	vpackuswb	%ymm15, %ymm12, %ymm12
	vpand	%ymm2, %ymm0, %ymm0
	vmovdqa	.LC61(%rip), %xmm15
	vpermq	$216, %ymm12, %ymm12
	vpand	%ymm13, %ymm12, %ymm12
	vpxor	%ymm12, %ymm0, %ymm2
	vpsrlw	$3, %ymm1, %ymm0
	vpand	%ymm1, %ymm7, %ymm1
	vpsrlw	$3, %ymm14, %ymm12
	vpand	%ymm0, %ymm7, %ymm0
	vpand	%ymm12, %ymm7, %ymm12
	vpackuswb	%ymm12, %ymm0, %ymm0
	vpermq	$216, %ymm0, %ymm0
	vpand	%ymm4, %ymm0, %ymm12
	vpand	%ymm14, %ymm7, %ymm0
	vmovdqa	.LC62(%rip), %xmm14
	vpackuswb	%ymm0, %ymm1, %ymm0
	vpermq	$216, %ymm0, %ymm0
	vpand	%ymm5, %ymm0, %ymm0
	vpxor	%ymm0, %ymm12, %ymm0
	vpxor	%ymm0, %ymm2, %ymm0
	vmovdqa	512(%rsp), %xmm2
	vpsrlw	$4, %ymm0, %ymm1
	vpand	%ymm5, %ymm1, %ymm1
	vpxor	%ymm0, %ymm1, %ymm1
	vpsrlw	$3, %ymm0, %ymm0
	vpand	%ymm8, %ymm0, %ymm0
	vpand	%ymm4, %ymm0, %ymm0
	vpsrlw	$9, %xmm2, %xmm4
	vpxor	%ymm0, %ymm1, %ymm0
	vpand	%ymm5, %ymm0, %ymm0
	vmovdqa	528(%rsp), %xmm5
	vmovdqa	%ymm0, 51392(%rsp)
	vpcmpeqd	%xmm0, %xmm0, %xmm0
	vpsrlw	$8, %xmm0, %xmm0
	vpsrlw	$9, %xmm5, %xmm1
	vpand	%xmm1, %xmm0, %xmm1
	vpsrlw	$6, %xmm5, %xmm7
	vpand	%xmm4, %xmm0, %xmm4
	vpackuswb	%xmm1, %xmm4, %xmm4
	vpsrlw	$6, %xmm2, %xmm1
	vpand	%xmm7, %xmm0, %xmm7
	vpand	%xmm1, %xmm0, %xmm1
	vpand	%xmm11, %xmm4, %xmm4
	vpackuswb	%xmm7, %xmm1, %xmm1
	vpsrlw	$3, %xmm5, %xmm7
	vpand	%xmm5, %xmm0, %xmm5
	vpand	%xmm10, %xmm1, %xmm1
	vpand	%xmm7, %xmm0, %xmm7
	vpxor	%xmm1, %xmm4, %xmm1
	vpsrlw	$3, %xmm2, %xmm4
	vpand	%xmm2, %xmm0, %xmm2
	vpand	%xmm4, %xmm0, %xmm4
	vpackuswb	%xmm5, %xmm2, %xmm2
	vpackuswb	%xmm7, %xmm4, %xmm4
	vpand	%xmm3, %xmm2, %xmm2
	vpand	%xmm6, %xmm4, %xmm4
	vpxor	%xmm2, %xmm4, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpsrlw	$4, %xmm1, %xmm2
	vpand	%xmm3, %xmm2, %xmm2
	vpxor	%xmm1, %xmm2, %xmm2
	vpsrlw	$3, %xmm1, %xmm1
	vpand	%xmm1, %xmm9, %xmm1
	vpand	%xmm6, %xmm1, %xmm1
	vpxor	%xmm1, %xmm2, %xmm1
	vpand	%xmm3, %xmm1, %xmm1
	vmovdqa	%xmm1, 51424(%rsp)
.L182:
	leaq	51360(%rsp), %rax
	movq	%rsi, %rdx
.L183:
	vmovq	(%rax), %xmm1
	vmovq	8(%rax), %xmm2
	addq	$16, %rax
	addq	$32, %rdx
	vmovdqu	134528(%rdx), %xmm7
	vmovdqu	134544(%rdx), %xmm8
	vpshufd	$224, %xmm1, %xmm12
	vpshufd	$224, %xmm2, %xmm5
	vpshufd	$229, %xmm1, %xmm1
	vpshufd	$229, %xmm2, %xmm2
	vpmovzxbw	%xmm12, %xmm12
	vpmovzxbw	%xmm1, %xmm1
	vpmovzxbw	%xmm2, %xmm4
	vpshufb	%xmm14, %xmm7, %xmm13
	vpshufb	%xmm15, %xmm7, %xmm2
	vpmullw	%xmm13, %xmm12, %xmm13
	vpmullw	%xmm2, %xmm1, %xmm2
	vpmovzxbw	%xmm5, %xmm5
	vpxor	%xmm13, %xmm2, %xmm2
	vpshufb	.LC63(%rip), %xmm7, %xmm13
	vpshufb	.LC64(%rip), %xmm7, %xmm7
	vpmullw	%xmm7, %xmm4, %xmm7
	vpmullw	%xmm13, %xmm5, %xmm13
	vpxor	%xmm7, %xmm13, %xmm13
	vpshufb	%xmm15, %xmm8, %xmm7
	vpmullw	%xmm7, %xmm1, %xmm1
	vpshufb	%xmm14, %xmm8, %xmm7
	vpxor	%xmm13, %xmm2, %xmm2
	vpmullw	%xmm7, %xmm12, %xmm12
	vpshufb	.LC63(%rip), %xmm8, %xmm7
	vpshufb	.LC64(%rip), %xmm8, %xmm8
	vpmullw	%xmm7, %xmm5, %xmm5
	vpmullw	%xmm8, %xmm4, %xmm4
	vpxor	%xmm12, %xmm1, %xmm1
	vpxor	%xmm4, %xmm5, %xmm4
	vpxor	%xmm4, %xmm1, %xmm1
	vpsrlw	$9, %xmm2, %xmm4
	vpsrlw	$9, %xmm1, %xmm5
	vpsrlw	$6, %xmm1, %xmm7
	vpand	%xmm4, %xmm0, %xmm4
	vpand	%xmm5, %xmm0, %xmm5
	vpand	%xmm7, %xmm0, %xmm7
	vpackuswb	%xmm5, %xmm4, %xmm4
	vpsrlw	$6, %xmm2, %xmm5
	vpand	%xmm5, %xmm0, %xmm5
	vpand	%xmm11, %xmm4, %xmm4
	vpackuswb	%xmm7, %xmm5, %xmm5
	vpsrlw	$3, %xmm1, %xmm7
	vpand	%xmm1, %xmm0, %xmm1
	vpand	%xmm10, %xmm5, %xmm5
	vpand	%xmm7, %xmm0, %xmm7
	vpxor	%xmm5, %xmm4, %xmm4
	vpsrlw	$3, %xmm2, %xmm5
	vpand	%xmm2, %xmm0, %xmm2
	vpand	%xmm5, %xmm0, %xmm5
	vpackuswb	%xmm1, %xmm2, %xmm1
	vpackuswb	%xmm7, %xmm5, %xmm5
	vpand	%xmm3, %xmm1, %xmm1
	vpand	%xmm6, %xmm5, %xmm5
	vpxor	%xmm1, %xmm5, %xmm1
	vpxor	%xmm1, %xmm4, %xmm2
	vpsrlw	$4, %xmm2, %xmm1
	vpand	%xmm3, %xmm1, %xmm1
	vpxor	%xmm2, %xmm1, %xmm1
	vpsrlw	$3, %xmm2, %xmm2
	vpand	%xmm2, %xmm9, %xmm2
	vpand	%xmm6, %xmm2, %xmm2
	vpxor	%xmm2, %xmm1, %xmm1
	vpand	%xmm3, %xmm1, %xmm1
	vpxor	(%r15), %xmm1, %xmm1
	vmovdqa	%xmm1, (%r15)
	cmpq	%rcx, %rax
	jne	.L183
	addq	$16, %r15
	addq	$160, %rsi
	cmpq	%r15, 120(%rsp)
	jne	.L182
	vmovdqa	51424(%rsp), %xmm0
	vmovdqa	51648(%rsp), %ymm6
	movl	$-252645136, %eax
	vmovdqa	51680(%rsp), %ymm7
	vmovd	%eax, %xmm4
	vmovdqa	51360(%rsp), %ymm2
	vmovdqa	%xmm0, 52096(%rsp)
	vmovdqa	%xmm0, %xmm5
	vpsrlw	$8, %ymm6, %ymm1
	vpbroadcastd	%xmm4, %ymm4
	vpsrlw	$8, %ymm7, %ymm0
	vmovdqa	51392(%rsp), %ymm3
	vmovdqa	%ymm2, 52032(%rsp)
	movq	176(%rsp), %rax
	vpackuswb	%ymm0, %ymm1, %ymm1
	vpcmpeqd	%ymm0, %ymm0, %ymm0
	vpsrlw	$8, %ymm0, %ymm0
	vpermq	$216, %ymm1, %ymm1
	vmovdqa	%ymm3, 52064(%rsp)
	vpand	%ymm7, %ymm0, %ymm7
	vpsllw	$4, %ymm1, %ymm1
	vpand	%ymm6, %ymm0, %ymm6
	vpackuswb	%ymm7, %ymm6, %ymm6
	vpand	%ymm1, %ymm4, %ymm1
	vmovdqa	51744(%rsp), %ymm7
	vpermq	$216, %ymm6, %ymm6
	vpxor	%ymm6, %ymm1, %ymm1
	vmovdqa	51712(%rsp), %ymm6
	vpsrlw	$8, %ymm7, %ymm8
	vpand	%ymm7, %ymm0, %ymm7
	vmovdqu	%ymm1, (%rbx)
	vpsrlw	$8, %ymm6, %ymm1
	vpand	%ymm6, %ymm0, %ymm6
	vpackuswb	%ymm8, %ymm1, %ymm1
	vpackuswb	%ymm7, %ymm6, %ymm6
	vmovdqa	51808(%rsp), %ymm7
	vpermq	$216, %ymm1, %ymm1
	vpermq	$216, %ymm6, %ymm6
	vpsllw	$4, %ymm1, %ymm1
	vpsrlw	$8, %ymm7, %ymm8
	vpand	%ymm7, %ymm0, %ymm7
	vpand	%ymm4, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm1
	vmovdqa	51776(%rsp), %ymm6
	vmovdqu	%ymm1, 32(%rbx)
	vpsrlw	$8, %ymm6, %ymm1
	vpand	%ymm6, %ymm0, %ymm6
	vpackuswb	%ymm8, %ymm1, %ymm1
	vpackuswb	%ymm7, %ymm6, %ymm6
	vmovdqa	51872(%rsp), %ymm7
	vpermq	$216, %ymm1, %ymm1
	vpermq	$216, %ymm6, %ymm6
	vpsllw	$4, %ymm1, %ymm1
	vpsrlw	$8, %ymm7, %ymm8
	vpand	%ymm7, %ymm0, %ymm7
	vpand	%ymm4, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm1
	vmovdqa	51840(%rsp), %ymm6
	vmovdqu	%ymm1, 64(%rbx)
	vpsrlw	$8, %ymm6, %ymm1
	vpand	%ymm6, %ymm0, %ymm6
	vpackuswb	%ymm8, %ymm1, %ymm1
	vpackuswb	%ymm7, %ymm6, %ymm6
	vmovdqa	51936(%rsp), %ymm7
	vpermq	$216, %ymm1, %ymm1
	vpermq	$216, %ymm6, %ymm6
	vpsllw	$4, %ymm1, %ymm1
	vpsrlw	$8, %ymm7, %ymm8
	vpand	%ymm7, %ymm0, %ymm7
	vpand	%ymm4, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm1
	vmovdqa	51904(%rsp), %ymm6
	vmovdqu	%ymm1, 96(%rbx)
	vpsrlw	$8, %ymm6, %ymm1
	vpand	%ymm6, %ymm0, %ymm6
	vpackuswb	%ymm8, %ymm1, %ymm1
	vpackuswb	%ymm7, %ymm6, %ymm6
	vmovdqa	52000(%rsp), %ymm7
	vpermq	$216, %ymm1, %ymm1
	vpermq	$216, %ymm6, %ymm6
	vpsllw	$4, %ymm1, %ymm1
	vpsrlw	$8, %ymm7, %ymm8
	vpand	%ymm7, %ymm0, %ymm7
	vpand	%ymm4, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm1
	vmovdqa	51968(%rsp), %ymm6
	vmovdqu	%ymm1, 128(%rbx)
	vpsrlw	$8, %ymm6, %ymm1
	vpand	%ymm6, %ymm0, %ymm6
	vpackuswb	%ymm8, %ymm1, %ymm1
	vpackuswb	%ymm7, %ymm6, %ymm6
	vpermq	$216, %ymm1, %ymm1
	vpermq	$216, %ymm6, %ymm6
	vpsllw	$4, %ymm1, %ymm1
	vpand	%ymm4, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm1
	vpsrlw	$8, %ymm3, %ymm6
	vmovdqu	%ymm1, 160(%rbx)
	vpsrlw	$8, %ymm2, %ymm1
	vpand	%ymm2, %ymm0, %ymm2
	vpand	%ymm3, %ymm0, %ymm0
	vpackuswb	%ymm6, %ymm1, %ymm1
	vpackuswb	%ymm0, %ymm2, %ymm0
	vpermq	$216, %ymm1, %ymm1
	vpermq	$216, %ymm0, %ymm0
	vpsllw	$4, %ymm1, %ymm1
	vpand	%ymm4, %ymm1, %ymm1
	vpxor	%ymm0, %ymm1, %ymm0
	vmovhps	52104(%rsp), %xmm5, %xmm1
	vmovdqu	%ymm0, 192(%rbx)
	vpshufb	.LC42(%rip), %xmm1, %xmm0
	vpshufb	.LC43(%rip), %xmm1, %xmm1
	vpmovzxbw	%xmm0, %xmm0
	vpsllw	$4, %xmm0, %xmm0
	vpshufb	.LC43(%rip), %xmm0, %xmm0
	vpxor	%xmm1, %xmm0, %xmm0
	vmovq	%xmm0, 224(%rbx)
	vmovdqu	(%rax), %xmm0
	vmovdqu	%xmm0, 232(%rbx)
	jmp	.L114
.L258:
	vzeroupper
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE7302:
	.size	_snova_24_5_16_4_aes_SNOVA_OPT_sign, .-_snova_24_5_16_4_aes_SNOVA_OPT_sign
	.p2align 4
	.globl	_snova_24_5_16_4_aes_SNOVA_OPT_pk_expand
	.type	_snova_24_5_16_4_aes_SNOVA_OPT_pk_expand, @function
_snova_24_5_16_4_aes_SNOVA_OPT_pk_expand:
.LFB7303:
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
	subq	$107648, %rsp
	movq	%fs:40, %r12
	movq	%r12, 107640(%rsp)
	movq	%rsi, %r12
	movl	first_time(%rip), %eax
	testl	%eax, %eax
	jne	.L293
.L264:
	movl	$138576, %edx
	xorl	%esi, %esi
	movq	%rbx, %rdi
	call	memset@PLT
	vmovdqu	(%r12), %xmm0
	movl	$252645135, %edx
	leaq	16(%r12), %rcx
	vmovd	%edx, %xmm1
	leaq	1664(%rsp), %rax
	leaq	3648(%rsp), %rsi
	vmovdqu	%xmm0, 138560(%rbx)
	vpbroadcastd	%xmm1, %ymm1
.L265:
	vmovdqu	(%rcx), %ymm0
	addq	$64, %rax
	addq	$32, %rcx
	vpsrlw	$4, %ymm0, %ymm3
	vpand	%ymm1, %ymm0, %ymm0
	vpand	%ymm3, %ymm1, %ymm3
	vpunpcklbw	%ymm3, %ymm0, %ymm2
	vpunpckhbw	%ymm3, %ymm0, %ymm0
	vperm2i128	$32, %ymm0, %ymm2, %ymm3
	vperm2i128	$49, %ymm0, %ymm2, %ymm2
	vmovdqa	%ymm3, -64(%rax)
	vmovdqa	%ymm2, -32(%rax)
	cmpq	%rsi, %rax
	jne	.L265
	vmovq	1008(%r12), %xmm0
	vmovq	.LC55(%rip), %xmm2
	movl	$16, %edx
	movq	%r12, %rsi
	leaq	16(%rsp), %rdi
	vpmovzxbw	%xmm0, %xmm1
	vpand	%xmm2, %xmm0, %xmm0
	vpsrlw	$4, %xmm1, %xmm1
	vpshufb	.LC43(%rip), %xmm1, %xmm1
	vpunpcklbw	%xmm1, %xmm0, %xmm2
	vpunpcklbw	%xmm1, %xmm0, %xmm0
	vpshufd	$78, %xmm0, %xmm0
	vmovq	%xmm2, 3648(%rsp)
	vmovq	%xmm0, 3656(%rsp)
	vzeroupper
	call	snova_pk_expander_init@PLT
	leaq	16(%rsp), %rdx
	leaq	3680(%rsp), %rdi
	movl	$34640, %esi
	call	snova_pk_expander@PLT
	movl	$252645135, %edi
	leaq	3680(%rsp), %rax
	leaq	107584(%rsp), %rcx
	vmovd	%edi, %xmm1
	leaq	38336(%rsp), %rdx
	vpbroadcastd	%xmm1, %ymm4
.L266:
	vmovdqa	(%rax), %ymm0
	addq	$64, %rdx
	addq	$32, %rax
	vpsrlw	$4, %ymm0, %ymm3
	vpand	%ymm4, %ymm0, %ymm0
	vpand	%ymm3, %ymm4, %ymm3
	vpunpcklbw	%ymm3, %ymm0, %ymm2
	vpunpckhbw	%ymm3, %ymm0, %ymm0
	vperm2i128	$32, %ymm0, %ymm2, %ymm3
	vperm2i128	$49, %ymm0, %ymm2, %ymm2
	vmovdqa	%ymm3, -64(%rdx)
	vmovdqa	%ymm2, -32(%rdx)
	cmpq	%rcx, %rdx
	jne	.L266
	vmovdqa	38304(%rsp), %xmm0
	vpbroadcastd	%xmm1, %xmm1
	movq	$0, 8(%rsp)
	leaq	1664(%rsp), %r14
	leaq	22288(%rbx), %r12
	leaq	38720(%rsp), %r15
	xorl	%r10d, %r10d
	xorl	%eax, %eax
	vpsrlw	$4, %xmm0, %xmm2
	vpand	%xmm1, %xmm0, %xmm0
	leaq	38336(%rsp), %r11
	vpand	%xmm2, %xmm1, %xmm2
	vpunpcklbw	%xmm2, %xmm0, %xmm1
	vpunpckhbw	%xmm2, %xmm0, %xmm0
	vmovdqa	%xmm1, 107584(%rsp)
	vmovdqa	%xmm0, 107600(%rsp)
.L267:
	movq	%rax, %rdx
	movq	%r14, (%rsp)
	incq	%rax
	movq	8(%rsp), %r9
	leaq	(%rax,%rax,8), %r13
	leaq	-22272(%r12), %rdi
	movq	%r15, %rsi
	movq	%r11, %r8
	salq	$6, %r13
.L268:
	leaq	-384(%rsi), %rcx
	movq	%rdi, %r14
	.p2align 6
	.p2align 4,,10
	.p2align 3
.L270:
	vmovdqa	(%rcx), %xmm0
	addq	$16, %rcx
	addq	$32, %r14
	vpmovzxbw	%xmm0, %xmm1
	vpsrldq	$8, %xmm0, %xmm0
	vpmovzxbw	%xmm0, %xmm0
	vmovdqu	%xmm1, -48(%r14)
	vmovdqu	%xmm0, -32(%r14)
	cmpq	%rsi, %rcx
	jne	.L270
	vmovdqa	46080(%r8), %xmm0
	addq	$24, %r9
	addq	$80, %r8
	addq	$928, %rdi
	leaq	384(%rcx), %rsi
	vpmovzxbw	%xmm0, %xmm1
	vpsrldq	$8, %xmm0, %xmm0
	vpmovzxbw	%xmm0, %xmm0
	vmovdqu	%xmm1, -176(%rdi)
	vmovdqu	%xmm0, -160(%rdi)
	vmovdqa	46016(%r8), %xmm0
	vpmovzxbw	%xmm0, %xmm1
	vpsrldq	$8, %xmm0, %xmm0
	vpmovzxbw	%xmm0, %xmm0
	vmovdqu	%xmm1, -144(%rdi)
	vmovdqu	%xmm0, -128(%rdi)
	vmovdqa	46032(%r8), %xmm0
	vpmovzxbw	%xmm0, %xmm1
	vpsrldq	$8, %xmm0, %xmm0
	vpmovzxbw	%xmm0, %xmm0
	vmovdqu	%xmm1, -112(%rdi)
	vmovdqu	%xmm0, -96(%rdi)
	vmovdqa	46048(%r8), %xmm0
	vpmovzxbw	%xmm0, %xmm1
	vpsrldq	$8, %xmm0, %xmm0
	vpmovzxbw	%xmm0, %xmm0
	vmovdqu	%xmm1, -80(%rdi)
	vmovdqu	%xmm0, -64(%rdi)
	vmovdqa	46064(%r8), %xmm0
	vpmovzxbw	%xmm0, %xmm1
	vpsrldq	$8, %xmm0, %xmm0
	vpmovzxbw	%xmm0, %xmm0
	vmovdqu	%xmm1, -48(%rdi)
	vmovdqu	%xmm0, -32(%rdi)
	cmpq	%r13, %r9
	jne	.L268
	imulq	$120, %rdx, %r13
	movq	(%rsp), %r14
	leaq	576(%r10,%r10,4), %r9
	movq	%r12, %rdi
	leaq	56064(%r11), %rsi
	movq	%r14, %r8
	addq	$696, %r13
.L272:
	leaq	-384(%rsi), %rcx
	movq	%rdi, %rdx
	.p2align 6
	.p2align 4,,10
	.p2align 3
.L274:
	vmovdqa	(%rcx), %xmm0
	addq	$16, %rcx
	addq	$32, %rdx
	vpmovzxbw	%xmm0, %xmm1
	vpsrldq	$8, %xmm0, %xmm0
	vpmovzxbw	%xmm0, %xmm0
	vmovdqu	%xmm1, -48(%rdx)
	vmovdqu	%xmm0, -32(%rdx)
	cmpq	%rcx, %rsi
	jne	.L274
	vmovdqa	(%r8), %xmm0
	addq	$24, %r9
	addq	$80, %r8
	addq	$928, %rdi
	addq	$384, %rsi
	vpmovzxbw	%xmm0, %xmm1
	vpsrldq	$8, %xmm0, %xmm0
	vpmovzxbw	%xmm0, %xmm0
	vmovdqu	%xmm1, -176(%rdi)
	vmovdqu	%xmm0, -160(%rdi)
	vmovdqa	-64(%r8), %xmm0
	vpmovzxbw	%xmm0, %xmm1
	vpsrldq	$8, %xmm0, %xmm0
	vpmovzxbw	%xmm0, %xmm0
	vmovdqu	%xmm1, -144(%rdi)
	vmovdqu	%xmm0, -128(%rdi)
	vmovdqa	-48(%r8), %xmm0
	vpmovzxbw	%xmm0, %xmm1
	vpsrldq	$8, %xmm0, %xmm0
	vpmovzxbw	%xmm0, %xmm0
	vmovdqu	%xmm1, -112(%rdi)
	vmovdqu	%xmm0, -96(%rdi)
	vmovdqa	-32(%r8), %xmm0
	vpmovzxbw	%xmm0, %xmm1
	vpsrldq	$8, %xmm0, %xmm0
	vpmovzxbw	%xmm0, %xmm0
	vmovdqu	%xmm1, -80(%rdi)
	vmovdqu	%xmm0, -64(%rdi)
	vmovdqa	-16(%r8), %xmm0
	vpmovzxbw	%xmm0, %xmm1
	vpsrldq	$8, %xmm0, %xmm0
	vpmovzxbw	%xmm0, %xmm0
	vmovdqu	%xmm1, -48(%rdi)
	vmovdqu	%xmm0, -32(%rdi)
	cmpq	%r13, %r9
	jne	.L272
	addq	$576, 8(%rsp)
	addq	$400, %r14
	addq	$26912, %r12
	addq	$1920, %r11
	addq	$24, %r10
	addq	$9216, %r15
	cmpq	$5, %rax
	jne	.L267
	leaq	134560(%rbx), %r14
	leaq	103616(%rsp), %r13
	leaq	106816(%rsp), %r12
	leaq	107216(%rsp), %r15
.L279:
	movq	%r13, %rsi
	movq	%r14, %rdi
	call	be_invertible_by_add_aS
	leaq	1600(%r13), %rsi
	leaq	1600(%r14), %rdi
	call	be_invertible_by_add_aS
	cmpb	$0, 3(%r12)
	jne	.L277
	movzbl	(%r12), %edx
	movl	$16, %eax
	subl	%edx, %eax
	cmpb	$1, %dl
	sbbb	$0, %al
	movb	%al, 3(%r12)
.L277:
	cmpb	$0, 403(%r12)
	jne	.L278
	movzbl	400(%r12), %edx
	movl	$16, %eax
	subl	%edx, %eax
	cmpb	$1, %dl
	sbbb	$0, %al
	movb	%al, 403(%r12)
.L278:
	addq	$4, %r12
	addq	$16, %r14
	addq	$16, %r13
	cmpq	%r12, %r15
	jne	.L279
	vmovdqa	106816(%rsp), %ymm0
	vmovdqu	%ymm0, 137760(%rbx)
	vmovdqa	106848(%rsp), %ymm0
	vmovdqu	%ymm0, 137792(%rbx)
	vmovdqa	106880(%rsp), %ymm0
	vmovdqu	%ymm0, 137824(%rbx)
	vmovdqa	106912(%rsp), %ymm0
	vmovdqu	%ymm0, 137856(%rbx)
	vmovdqa	106944(%rsp), %ymm0
	vmovdqu	%ymm0, 137888(%rbx)
	vmovdqa	106976(%rsp), %ymm0
	vmovdqu	%ymm0, 137920(%rbx)
	vmovdqa	107008(%rsp), %ymm0
	vmovdqu	%ymm0, 137952(%rbx)
	vmovdqa	107040(%rsp), %ymm0
	vmovdqu	%ymm0, 137984(%rbx)
	vmovdqa	107072(%rsp), %ymm0
	vmovdqu	%ymm0, 138016(%rbx)
	vmovdqa	107104(%rsp), %ymm0
	vmovdqu	%ymm0, 138048(%rbx)
	vmovdqa	107136(%rsp), %ymm0
	vmovdqu	%ymm0, 138080(%rbx)
	vmovdqa	107168(%rsp), %ymm0
	vmovdqu	%ymm0, 138112(%rbx)
	vmovdqa	107200(%rsp), %xmm0
	vmovdqu	%xmm0, 138144(%rbx)
	vmovdqu	107216(%rsp), %ymm0
	vmovdqu	%ymm0, 138160(%rbx)
	vmovdqu	107248(%rsp), %ymm0
	vmovdqu	%ymm0, 138192(%rbx)
	vmovdqu	107280(%rsp), %ymm0
	vmovdqu	%ymm0, 138224(%rbx)
	vmovdqu	107312(%rsp), %ymm0
	vmovdqu	%ymm0, 138256(%rbx)
	vmovdqu	107344(%rsp), %ymm0
	vmovdqu	%ymm0, 138288(%rbx)
	vmovdqu	107376(%rsp), %ymm0
	vmovdqu	%ymm0, 138320(%rbx)
	vmovdqu	107408(%rsp), %ymm0
	vmovdqu	%ymm0, 138352(%rbx)
	vmovdqu	107440(%rsp), %ymm0
	vmovdqu	%ymm0, 138384(%rbx)
	vmovdqu	107472(%rsp), %ymm0
	vmovdqu	%ymm0, 138416(%rbx)
	vmovdqu	107504(%rsp), %ymm0
	vmovdqu	%ymm0, 138448(%rbx)
	vmovdqu	107536(%rsp), %ymm0
	vmovdqu	%ymm0, 138480(%rbx)
	vmovdqu	107568(%rsp), %ymm0
	vmovdqu	%ymm0, 138512(%rbx)
	vmovdqa	107600(%rsp), %xmm0
	vmovdqu	%xmm0, 138544(%rbx)
	movq	107640(%rsp), %rax
	subq	%fs:40, %rax
	jne	.L294
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
.L293:
	.cfi_restore_state
	movl	$0, first_time(%rip)
	call	init_vector_table
	jmp	.L264
.L294:
	vzeroupper
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE7303:
	.size	_snova_24_5_16_4_aes_SNOVA_OPT_pk_expand, .-_snova_24_5_16_4_aes_SNOVA_OPT_pk_expand
	.p2align 4
	.globl	_snova_24_5_16_4_aes_SNOVA_OPT_verify
	.type	_snova_24_5_16_4_aes_SNOVA_OPT_verify, @function
_snova_24_5_16_4_aes_SNOVA_OPT_verify:
.LFB7304:
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
	movq	%rsi, %r12
	pushq	%rbx
	.cfi_offset 3, -56
	movq	%rdi, %rbx
	andq	$-64, %rsp
	subq	$15744, %rsp
	movq	%rdx, 80(%rsp)
	movl	first_time(%rip), %r13d
	movq	%rcx, 72(%rsp)
	movq	%fs:40, %rax
	movq	%rax, 15736(%rsp)
	xorl	%eax, %eax
	testl	%r13d, %r13d
	jne	.L335
.L296:
	vmovdqu	(%r12), %ymm1
	movl	$252645135, %eax
	vmovq	.LC55(%rip), %xmm7
	leaq	11392(%rsp), %r13
	vmovd	%eax, %xmm0
	xorl	%esi, %esi
	movq	%r13, %rdi
	movl	$3712, %edx
	vpbroadcastd	%xmm0, %ymm0
	vpsrlw	$4, %ymm1, %ymm3
	vpand	%ymm3, %ymm0, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vpunpcklbw	%ymm3, %ymm1, %ymm2
	vpunpckhbw	%ymm3, %ymm1, %ymm1
	vperm2i128	$32, %ymm1, %ymm2, %ymm3
	vperm2i128	$49, %ymm1, %ymm2, %ymm2
	vmovdqu	32(%r12), %ymm1
	vmovdqa	%ymm3, 15264(%rsp)
	vpsrlw	$4, %ymm1, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm2, 15296(%rsp)
	vpand	%ymm3, %ymm0, %ymm3
	vpunpcklbw	%ymm3, %ymm1, %ymm2
	vpunpckhbw	%ymm3, %ymm1, %ymm1
	vperm2i128	$32, %ymm1, %ymm2, %ymm3
	vperm2i128	$49, %ymm1, %ymm2, %ymm2
	vmovdqu	64(%r12), %ymm1
	vmovdqa	%ymm3, 15328(%rsp)
	vpsrlw	$4, %ymm1, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm2, 15360(%rsp)
	vpand	%ymm3, %ymm0, %ymm3
	vpunpcklbw	%ymm3, %ymm1, %ymm2
	vpunpckhbw	%ymm3, %ymm1, %ymm1
	vperm2i128	$32, %ymm1, %ymm2, %ymm3
	vperm2i128	$49, %ymm1, %ymm2, %ymm2
	vmovdqu	96(%r12), %ymm1
	vmovdqa	%ymm3, 15392(%rsp)
	vpsrlw	$4, %ymm1, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm2, 15424(%rsp)
	vpand	%ymm3, %ymm0, %ymm3
	vpunpcklbw	%ymm3, %ymm1, %ymm2
	vpunpckhbw	%ymm3, %ymm1, %ymm1
	vperm2i128	$32, %ymm1, %ymm2, %ymm3
	vperm2i128	$49, %ymm1, %ymm2, %ymm2
	vmovdqu	128(%r12), %ymm1
	vmovdqa	%ymm3, 15456(%rsp)
	vpsrlw	$4, %ymm1, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm2, 15488(%rsp)
	vpand	%ymm3, %ymm0, %ymm3
	vpunpcklbw	%ymm3, %ymm1, %ymm2
	vpunpckhbw	%ymm3, %ymm1, %ymm1
	vperm2i128	$32, %ymm1, %ymm2, %ymm3
	vperm2i128	$49, %ymm1, %ymm2, %ymm2
	vmovdqu	160(%r12), %ymm1
	vmovdqa	%ymm3, 15520(%rsp)
	vpsrlw	$4, %ymm1, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm2, 15552(%rsp)
	vpand	%ymm3, %ymm0, %ymm3
	vpunpcklbw	%ymm3, %ymm1, %ymm2
	vpunpckhbw	%ymm3, %ymm1, %ymm1
	vperm2i128	$32, %ymm1, %ymm2, %ymm3
	vperm2i128	$49, %ymm1, %ymm2, %ymm2
	vmovdqu	192(%r12), %ymm1
	vmovdqa	%ymm2, 15616(%rsp)
	vpsrlw	$4, %ymm1, %ymm2
	vmovdqa	%ymm3, 15584(%rsp)
	vpand	%ymm2, %ymm0, %ymm2
	vpand	%ymm0, %ymm1, %ymm0
	vpunpcklbw	%ymm2, %ymm0, %ymm1
	vpunpckhbw	%ymm2, %ymm0, %ymm0
	vperm2i128	$32, %ymm0, %ymm1, %ymm2
	vperm2i128	$49, %ymm0, %ymm1, %ymm1
	vmovq	224(%r12), %xmm0
	vmovdqa	%ymm1, 15680(%rsp)
	vpmovzxbw	%xmm0, %xmm1
	vpand	%xmm7, %xmm0, %xmm0
	vmovdqa	%ymm2, 15648(%rsp)
	vpsrlw	$4, %xmm1, %xmm1
	vpshufb	.LC43(%rip), %xmm1, %xmm1
	vpunpcklbw	%xmm1, %xmm0, %xmm2
	vpunpcklbw	%xmm1, %xmm0, %xmm0
	vpshufd	$78, %xmm0, %xmm0
	vmovq	%xmm2, 15712(%rsp)
	vmovq	%xmm0, 15720(%rsp)
	vzeroupper
	call	memset@PLT
	leaq	_snova_24_5_16_4_aes_SNOVA_OPT_Smat(%rip), %rdi
	movq	%r13, %rsi
	xorl	%ecx, %ecx
	leaq	15728(%rsp), %r8
.L297:
	vmovdqa	(%rdi), %ymm3
	leaq	15264(%rsp), %rdx
	movq	%rsi, %rax
	vpshufb	.LC34(%rip), %ymm3, %ymm6
	vpshufb	.LC35(%rip), %ymm3, %ymm5
	vpshufb	.LC28(%rip), %ymm3, %ymm4
	vpshufb	.LC29(%rip), %ymm3, %ymm3
.L298:
	vmovdqa	(%rdx), %xmm1
	addq	$16, %rdx
	subq	$-128, %rax
	vpshufd	$0, %xmm1, %xmm0
	vpshufd	$85, %xmm1, %xmm2
	vpmovzxbw	%xmm0, %ymm0
	vpmovzxbw	%xmm2, %ymm2
	vpmullw	%ymm5, %ymm2, %ymm2
	vpmullw	%ymm6, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpshufd	$170, %xmm1, %xmm2
	vpshufd	$255, %xmm1, %xmm1
	vpmovzxbw	%xmm2, %ymm2
	vpmovzxbw	%xmm1, %ymm1
	vpxor	-128(%rax), %ymm0, %ymm0
	vpmullw	%ymm4, %ymm2, %ymm2
	vpmullw	%ymm3, %ymm1, %ymm1
	vpxor	%ymm1, %ymm2, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, -128(%rax)
	cmpq	%rdx, %r8
	jne	.L298
	incq	%rcx
	addq	$32, %rsi
	addq	$32, %rdi
	cmpq	$4, %rcx
	jne	.L297
	movl	$7864440, %eax
	vpcmpeqd	%ymm2, %ymm2, %ymm2
	movq	%r13, %rdx
	xorl	%ecx, %ecx
	vmovd	%eax, %xmm6
	vpsrlw	$12, %ymm2, %ymm2
	movl	$3932220, %eax
	vmovd	%eax, %xmm5
	movl	$1966110, %eax
	vpbroadcastd	%xmm6, %ymm6
	vmovd	%eax, %xmm3
	movl	$286331153, %eax
	vpbroadcastd	%xmm5, %ymm5
	vmovd	%eax, %xmm4
	vpbroadcastd	%xmm3, %ymm3
	vpbroadcastd	%xmm4, %ymm4
.L299:
	movq	%rdx, %rax
	leaq	3712(%rdx), %rsi
.L300:
	vmovdqa	(%rax), %ymm0
	subq	$-128, %rax
	vpsrlw	$9, %ymm0, %ymm1
	vpsrlw	$6, %ymm0, %ymm7
	vpand	%ymm5, %ymm7, %ymm7
	vpand	%ymm6, %ymm1, %ymm1
	vpxor	%ymm7, %ymm1, %ymm1
	vpsrlw	$3, %ymm0, %ymm7
	vpand	%ymm2, %ymm0, %ymm0
	vpand	%ymm3, %ymm7, %ymm7
	vpxor	%ymm0, %ymm7, %ymm0
	vpxor	%ymm0, %ymm1, %ymm1
	vpsrlw	$3, %ymm1, %ymm0
	vpand	%ymm3, %ymm0, %ymm0
	vpxor	%ymm1, %ymm0, %ymm0
	vpsrlw	$4, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpand	%ymm2, %ymm0, %ymm0
	vpsllw	$6, %ymm0, %ymm7
	vpsllw	$9, %ymm0, %ymm1
	vpor	%ymm7, %ymm1, %ymm1
	vpsllw	$3, %ymm0, %ymm7
	vpor	%ymm0, %ymm7, %ymm0
	vpor	%ymm0, %ymm1, %ymm0
	vpand	%ymm4, %ymm0, %ymm0
	vmovdqa	%ymm0, -128(%rax)
	cmpq	%rax, %rsi
	jne	.L300
	incq	%rcx
	addq	$32, %rdx
	cmpq	$4, %rcx
	jne	.L299
	leaq	2432(%rsp), %r14
	vpxor	%xmm0, %xmm0, %xmm0
	xorl	%esi, %esi
	movl	$2560, %edx
	movq	%r14, 112(%rsp)
	movq	%r14, %rdi
	vmovdqa	%ymm0, 448(%rsp)
	vmovdqa	%ymm0, 480(%rsp)
	vmovdqa	%ymm0, 512(%rsp)
	vmovdqa	%ymm0, 544(%rsp)
	vmovdqa	%ymm0, 576(%rsp)
	vzeroupper
	call	memset@PLT
	movl	$3932220, %ecx
	vpcmpeqd	%ymm0, %ymm0, %ymm0
	vmovd	%ecx, %xmm7
	movl	$7864440, %ecx
	leaq	134560(%rbx), %rsi
	movq	%rbx, %rax
	vmovd	%ecx, %xmm13
	movl	$1966110, %ecx
	vpbroadcastd	%xmm7, %ymm7
	movq	%r14, %rdx
	vmovd	%ecx, %xmm12
	leaq	3712(%r13), %rdi
	vmovdqa	%ymm7, 416(%rsp)
	vpbroadcastd	%xmm13, %ymm13
	vpbroadcastd	%xmm12, %ymm12
	vpsrlw	$12, %ymm0, %ymm11
.L302:
	movq	%rax, %r10
	movq	%r13, %r9
.L305:
	vpxor	%xmm3, %xmm3, %xmm3
	movq	%r13, %rcx
	movq	%r10, %r8
	vmovdqa	%ymm3, %ymm4
	vmovdqa	%ymm3, %ymm5
	vmovdqa	%ymm3, %ymm6
.L303:
	vmovdqu	(%r8), %ymm0
	vpbroadcastq	8(%rcx), %ymm8
	subq	$-128, %rcx
	addq	$32, %r8
	vpbroadcastq	-128(%rcx), %ymm10
	vpshufb	.LC34(%rip), %ymm0, %ymm7
	vpshufb	.LC35(%rip), %ymm0, %ymm1
	vpshufb	.LC28(%rip), %ymm0, %ymm2
	vpmullw	%ymm8, %ymm1, %ymm8
	vpmullw	%ymm10, %ymm7, %ymm10
	vpshufb	.LC29(%rip), %ymm0, %ymm0
	vpxor	%ymm10, %ymm8, %ymm9
	vpbroadcastq	-112(%rcx), %ymm8
	vpbroadcastq	-104(%rcx), %ymm10
	vpmullw	%ymm8, %ymm2, %ymm8
	vpmullw	%ymm10, %ymm0, %ymm10
	vpxor	%ymm10, %ymm8, %ymm8
	vpbroadcastq	-96(%rcx), %ymm10
	vpxor	%ymm8, %ymm9, %ymm8
	vpxor	%ymm8, %ymm6, %ymm6
	vpbroadcastq	-88(%rcx), %ymm8
	vpmullw	%ymm10, %ymm7, %ymm10
	vpmullw	%ymm8, %ymm1, %ymm8
	vpxor	%ymm10, %ymm8, %ymm9
	vpbroadcastq	-80(%rcx), %ymm8
	vpbroadcastq	-72(%rcx), %ymm10
	vpmullw	%ymm8, %ymm2, %ymm8
	vpmullw	%ymm10, %ymm0, %ymm10
	vpxor	%ymm10, %ymm8, %ymm8
	vpbroadcastq	-64(%rcx), %ymm10
	vpxor	%ymm8, %ymm9, %ymm8
	vpxor	%ymm8, %ymm5, %ymm5
	vpbroadcastq	-56(%rcx), %ymm8
	vpmullw	%ymm10, %ymm7, %ymm10
	vpmullw	%ymm8, %ymm1, %ymm8
	vpxor	%ymm10, %ymm8, %ymm9
	vpbroadcastq	-48(%rcx), %ymm8
	vpbroadcastq	-40(%rcx), %ymm10
	vpmullw	%ymm8, %ymm2, %ymm8
	vpmullw	%ymm10, %ymm0, %ymm10
	vpxor	%ymm10, %ymm8, %ymm8
	vpxor	%ymm8, %ymm9, %ymm8
	vpxor	%ymm8, %ymm4, %ymm4
	vpbroadcastq	-24(%rcx), %ymm8
	vpmullw	%ymm8, %ymm1, %ymm1
	vpbroadcastq	-32(%rcx), %ymm8
	vpmullw	%ymm8, %ymm7, %ymm7
	vpxor	%ymm7, %ymm1, %ymm1
	vpbroadcastq	-16(%rcx), %ymm7
	vpmullw	%ymm7, %ymm2, %ymm2
	vpbroadcastq	-8(%rcx), %ymm7
	vpmullw	%ymm7, %ymm0, %ymm0
	vpxor	%ymm0, %ymm2, %ymm0
	vpxor	%ymm0, %ymm1, %ymm0
	vpxor	%ymm0, %ymm3, %ymm3
	cmpq	%rcx, %rdi
	jne	.L303
	vmovdqa	416(%rsp), %ymm7
	vpsrlw	$6, %ymm6, %ymm0
	vpsrlw	$9, %ymm6, %ymm1
	movq	%rdx, %rcx
	vpand	%ymm13, %ymm1, %ymm1
	vpsrlw	$6, %ymm3, %ymm2
	movq	%r9, %r8
	xorl	%r11d, %r11d
	vpand	%ymm7, %ymm0, %ymm0
	vpand	%ymm7, %ymm2, %ymm2
	vpxor	%ymm1, %ymm0, %ymm0
	vpsrlw	$3, %ymm6, %ymm1
	vpand	%ymm11, %ymm6, %ymm6
	vpand	%ymm12, %ymm1, %ymm1
	vpxor	%ymm6, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpsrlw	$6, %ymm5, %ymm1
	vpsrlw	$3, %ymm0, %ymm6
	vpand	%ymm7, %ymm1, %ymm1
	vpand	%ymm12, %ymm6, %ymm6
	vpxor	%ymm0, %ymm6, %ymm6
	vpsrlw	$4, %ymm0, %ymm0
	vpxor	%ymm0, %ymm6, %ymm6
	vpsrlw	$9, %ymm5, %ymm0
	vpand	%ymm13, %ymm0, %ymm0
	vpand	%ymm11, %ymm6, %ymm6
	vpxor	%ymm1, %ymm0, %ymm0
	vpsrlw	$3, %ymm5, %ymm1
	vpand	%ymm11, %ymm5, %ymm5
	vpand	%ymm12, %ymm1, %ymm1
	vpbroadcastq	%xmm6, %ymm10
	vpxor	%ymm5, %ymm1, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpsrlw	$9, %ymm4, %ymm1
	vpsrlw	$3, %ymm0, %ymm5
	vpand	%ymm13, %ymm1, %ymm1
	vpand	%ymm12, %ymm5, %ymm5
	vpxor	%ymm0, %ymm5, %ymm5
	vpsrlw	$4, %ymm0, %ymm0
	vpxor	%ymm0, %ymm5, %ymm5
	vpsrlw	$6, %ymm4, %ymm0
	vpand	%ymm7, %ymm0, %ymm0
	vpand	%ymm11, %ymm5, %ymm5
	vpxor	%ymm1, %ymm0, %ymm0
	vpsrlw	$3, %ymm4, %ymm1
	vpand	%ymm11, %ymm4, %ymm4
	vpand	%ymm12, %ymm1, %ymm1
	vpbroadcastq	%xmm5, %ymm9
	vpxor	%ymm4, %ymm1, %ymm1
	vpsrldq	$8, %xmm6, %xmm4
	vextracti128	$0x1, %ymm6, %xmm6
	vpxor	%ymm1, %ymm0, %ymm0
	vpbroadcastq	%xmm4, %ymm4
	vpsrlw	$3, %ymm0, %ymm1
	vpand	%ymm12, %ymm1, %ymm1
	vpxor	%ymm0, %ymm1, %ymm1
	vpsrlw	$4, %ymm0, %ymm0
	vpxor	%ymm0, %ymm1, %ymm1
	vpsrlw	$9, %ymm3, %ymm0
	vpand	%ymm13, %ymm0, %ymm0
	vpand	%ymm11, %ymm1, %ymm1
	vpxor	%ymm2, %ymm0, %ymm0
	vpsrlw	$3, %ymm3, %ymm2
	vpand	%ymm11, %ymm3, %ymm3
	vpand	%ymm12, %ymm2, %ymm2
	vpbroadcastq	%xmm1, %ymm8
	vpxor	%ymm3, %ymm2, %ymm2
	vpsrldq	$8, %xmm5, %xmm3
	vextracti128	$0x1, %ymm5, %xmm5
	vpxor	%ymm2, %ymm0, %ymm0
	vpbroadcastq	%xmm3, %ymm3
	vpsrlw	$3, %ymm0, %ymm2
	vpand	%ymm12, %ymm2, %ymm2
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlw	$4, %ymm0, %ymm0
	vpxor	%ymm0, %ymm2, %ymm0
	vpsrldq	$8, %xmm1, %xmm2
	vextracti128	$0x1, %ymm1, %xmm1
	vpand	%ymm11, %ymm0, %ymm0
	vpbroadcastq	%xmm2, %ymm2
	vpsrldq	$8, %xmm0, %xmm14
	vpbroadcastq	%xmm0, %ymm7
	vextracti128	$0x1, %ymm0, %xmm0
	vpbroadcastq	%xmm14, %ymm15
	vpbroadcastq	%xmm5, %ymm14
	vpsrldq	$8, %xmm5, %xmm5
	vmovdqa	%ymm15, 192(%rsp)
	vpbroadcastq	%xmm6, %ymm15
	vpsrldq	$8, %xmm6, %xmm6
	vpbroadcastq	%xmm6, %ymm6
	vmovdqa	%ymm15, 224(%rsp)
	vpbroadcastq	%xmm1, %ymm15
	vpsrldq	$8, %xmm1, %xmm1
	vmovdqa	%ymm6, 160(%rsp)
	vpbroadcastq	%xmm5, %ymm6
	vmovdqa	%ymm14, 256(%rsp)
	vpbroadcastq	%xmm0, %ymm14
	vpsrldq	$8, %xmm0, %xmm0
	vmovdqa	%ymm6, 384(%rsp)
	vpbroadcastq	%xmm1, %ymm6
	vmovdqa	%ymm6, 352(%rsp)
	vpbroadcastq	%xmm0, %ymm6
	vmovdqa	%ymm15, 288(%rsp)
	vmovdqa	%ymm14, 320(%rsp)
	vmovdqa	%ymm6, 128(%rsp)
.L304:
	vmovdqa	(%r8), %ymm0
	addq	$32, %r11
	addq	$32, %r8
	subq	$-128, %rcx
	vperm2i128	$0, %ymm0, %ymm0, %ymm0
	vpshufb	.LC56(%rip), %ymm0, %ymm0
	vpmullw	%ymm0, %ymm10, %ymm6
	vpmullw	%ymm0, %ymm9, %ymm5
	vpmullw	%ymm0, %ymm8, %ymm15
	vpmullw	%ymm0, %ymm7, %ymm0
	vpxor	-128(%rcx), %ymm6, %ymm6
	vpxor	-96(%rcx), %ymm5, %ymm5
	vpxor	-64(%rcx), %ymm15, %ymm15
	vpxor	-32(%rcx), %ymm0, %ymm0
	vmovdqa	%ymm6, -128(%rcx)
	vmovdqa	%ymm5, -96(%rcx)
	vmovdqa	%ymm15, -64(%rcx)
	vmovdqa	%ymm0, -32(%rcx)
	vmovdqa	-32(%r8), %ymm1
	vperm2i128	$0, %ymm1, %ymm1, %ymm1
	vpshufb	.LC71(%rip), %ymm1, %ymm1
	vpmullw	%ymm1, %ymm4, %ymm14
	vpxor	%ymm6, %ymm14, %ymm14
	vpmullw	%ymm1, %ymm3, %ymm6
	vmovdqa	%ymm14, -128(%rcx)
	vpxor	%ymm5, %ymm6, %ymm6
	vpmullw	%ymm1, %ymm2, %ymm5
	vpmullw	192(%rsp), %ymm1, %ymm1
	vpxor	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm6, -96(%rcx)
	vmovdqa	%ymm1, -32(%rcx)
	vpxor	%ymm15, %ymm5, %ymm5
	vmovdqa	%ymm5, -64(%rcx)
	vmovdqa	-32(%r8), %ymm0
	vperm2i128	$17, %ymm0, %ymm0, %ymm0
	vpshufb	.LC56(%rip), %ymm0, %ymm0
	vpmullw	224(%rsp), %ymm0, %ymm15
	vpxor	%ymm14, %ymm15, %ymm14
	vpmullw	256(%rsp), %ymm0, %ymm15
	vpxor	%ymm6, %ymm15, %ymm6
	vpmullw	288(%rsp), %ymm0, %ymm15
	vpmullw	320(%rsp), %ymm0, %ymm0
	vpxor	%ymm5, %ymm15, %ymm5
	vpxor	%ymm1, %ymm0, %ymm1
	vmovdqa	%ymm14, -128(%rcx)
	vmovdqa	%ymm6, -96(%rcx)
	vmovdqa	%ymm5, -64(%rcx)
	vmovdqa	%ymm1, -32(%rcx)
	vmovdqa	-32(%r8), %ymm0
	vperm2i128	$17, %ymm0, %ymm0, %ymm0
	vpshufb	.LC71(%rip), %ymm0, %ymm0
	vpmullw	160(%rsp), %ymm0, %ymm15
	vpxor	%ymm14, %ymm15, %ymm14
	vmovdqa	%ymm14, -128(%rcx)
	vpmullw	384(%rsp), %ymm0, %ymm14
	vpxor	%ymm6, %ymm14, %ymm6
	vmovdqa	%ymm6, -96(%rcx)
	vpmullw	352(%rsp), %ymm0, %ymm6
	vpmullw	128(%rsp), %ymm0, %ymm0
	vpxor	%ymm5, %ymm6, %ymm5
	vpxor	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm5, -64(%rcx)
	vmovdqa	%ymm0, -32(%rcx)
	cmpq	$128, %r11
	jne	.L304
	subq	$-128, %r9
	addq	$928, %r10
	cmpq	%rdi, %r9
	jne	.L305
	leaq	512(%rdx), %rcx
.L306:
	vmovdqa	(%rdx), %ymm1
	addq	$32, %rdx
	vpsrlw	$6, %ymm1, %ymm2
	vpsrlw	$9, %ymm1, %ymm0
	vpand	416(%rsp), %ymm2, %ymm2
	vpand	%ymm13, %ymm0, %ymm0
	vpxor	%ymm2, %ymm0, %ymm0
	vpsrlw	$3, %ymm1, %ymm2
	vpand	%ymm11, %ymm1, %ymm1
	vpand	%ymm12, %ymm2, %ymm2
	vpxor	%ymm1, %ymm2, %ymm1
	vpxor	%ymm1, %ymm0, %ymm0
	vpsrlw	$3, %ymm0, %ymm1
	vpand	%ymm12, %ymm1, %ymm1
	vpxor	%ymm0, %ymm1, %ymm1
	vpsrlw	$4, %ymm0, %ymm0
	vpxor	%ymm0, %ymm1, %ymm0
	vpand	%ymm11, %ymm0, %ymm0
	vmovdqa	%ymm0, -32(%rdx)
	cmpq	%rdx, %rcx
	jne	.L306
	addq	$26912, %rax
	cmpq	%rax, %rsi
	je	.L307
	movq	%rcx, %rdx
	jmp	.L302
.L307:
	movl	$286331153, %ecx
	leaq	4992(%rsp), %rax
	leaq	8192(%rsp), %rdi
	vmovd	%ecx, %xmm3
	movq	%rax, %rdx
	vpbroadcastd	%xmm3, %ymm3
.L308:
	vmovdqu	(%rsi), %ymm0
	addq	$64, %rdx
	addq	$32, %rsi
	vpmovzxbw	%xmm0, %ymm2
	vextracti128	$0x1, %ymm0, %xmm0
	vpsllw	$6, %ymm2, %ymm4
	vpsllw	$9, %ymm2, %ymm1
	vpmovzxbw	%xmm0, %ymm0
	vpor	%ymm4, %ymm1, %ymm1
	vpsllw	$3, %ymm2, %ymm4
	vpor	%ymm2, %ymm4, %ymm2
	vpor	%ymm2, %ymm1, %ymm1
	vpsllw	$6, %ymm0, %ymm2
	vpand	%ymm3, %ymm1, %ymm1
	vmovdqa	%ymm1, -64(%rdx)
	vpsllw	$9, %ymm0, %ymm1
	vpor	%ymm2, %ymm1, %ymm1
	vpsllw	$3, %ymm0, %ymm2
	vpor	%ymm0, %ymm2, %ymm0
	vpor	%ymm0, %ymm1, %ymm0
	vpand	%ymm3, %ymm0, %ymm0
	vmovdqa	%ymm0, -32(%rdx)
	cmpq	%rdi, %rdx
	jne	.L308
	movl	$286331153, %edi
	leaq	136160(%rbx), %rsi
	movq	%rdx, %rcx
	vmovd	%edi, %xmm2
	vpbroadcastd	%xmm2, %ymm0
.L309:
	vmovdqu	(%rsi), %ymm1
	addq	$64, %rcx
	addq	$32, %rsi
	vpmovzxbw	%xmm1, %ymm4
	vextracti128	$0x1, %ymm1, %xmm1
	vpsllw	$6, %ymm4, %ymm5
	vpsllw	$9, %ymm4, %ymm3
	vpmovzxbw	%xmm1, %ymm1
	vpor	%ymm5, %ymm3, %ymm3
	vpsllw	$3, %ymm4, %ymm5
	vpor	%ymm4, %ymm5, %ymm4
	vpor	%ymm4, %ymm3, %ymm3
	vpsllw	$6, %ymm1, %ymm4
	vpand	%ymm0, %ymm3, %ymm3
	vmovdqa	%ymm3, -64(%rcx)
	vpsllw	$9, %ymm1, %ymm3
	vpor	%ymm4, %ymm3, %ymm3
	vpsllw	$3, %ymm1, %ymm4
	vpor	%ymm1, %ymm4, %ymm1
	vpor	%ymm1, %ymm3, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, -32(%rcx)
	cmpq	%rcx, %r13
	jne	.L309
	vmovdqu	137760(%rbx), %ymm1
	vpbroadcastd	%xmm2, %xmm2
	leaq	832(%rsp), %rdi
	movl	$7864440, %ecx
	leaq	448(%rsp), %r15
	leaq	1632(%rsp), %r13
	xorl	%r14d, %r14d
	xorl	%r11d, %r11d
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm1, %ymm4
	vpsllw	$9, %ymm3, %ymm5
	vpsllw	$6, %ymm3, %ymm1
	vpor	%ymm5, %ymm1, %ymm1
	vpsllw	$3, %ymm3, %ymm5
	vpor	%ymm3, %ymm5, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$9, %ymm4, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 832(%rsp)
	vpsllw	$6, %ymm4, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$3, %ymm4, %ymm3
	vpor	%ymm4, %ymm3, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 864(%rsp)
	vmovdqu	137792(%rbx), %ymm1
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm1, %ymm4
	vpsllw	$9, %ymm3, %ymm5
	vpsllw	$6, %ymm3, %ymm1
	vpor	%ymm5, %ymm1, %ymm1
	vpsllw	$3, %ymm3, %ymm5
	vpor	%ymm3, %ymm5, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$9, %ymm4, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 896(%rsp)
	vpsllw	$6, %ymm4, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$3, %ymm4, %ymm3
	vpor	%ymm4, %ymm3, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 928(%rsp)
	vmovdqu	137824(%rbx), %ymm1
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm1, %ymm4
	vpsllw	$6, %ymm3, %ymm5
	vpsllw	$9, %ymm3, %ymm1
	vpor	%ymm5, %ymm1, %ymm1
	vpsllw	$3, %ymm3, %ymm5
	vpor	%ymm3, %ymm5, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$6, %ymm4, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 960(%rsp)
	vpsllw	$9, %ymm4, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$3, %ymm4, %ymm3
	vpor	%ymm4, %ymm3, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 992(%rsp)
	vmovdqu	137856(%rbx), %ymm1
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm1, %ymm4
	vpsllw	$6, %ymm3, %ymm5
	vpsllw	$9, %ymm3, %ymm1
	vpor	%ymm5, %ymm1, %ymm1
	vpsllw	$3, %ymm3, %ymm5
	vpor	%ymm3, %ymm5, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$6, %ymm4, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1024(%rsp)
	vpsllw	$9, %ymm4, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$3, %ymm4, %ymm3
	vpor	%ymm4, %ymm3, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1056(%rsp)
	vmovdqu	137888(%rbx), %ymm1
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm1, %ymm4
	vpsllw	$6, %ymm3, %ymm5
	vpsllw	$9, %ymm3, %ymm1
	vpor	%ymm5, %ymm1, %ymm1
	vpsllw	$3, %ymm3, %ymm5
	vpor	%ymm3, %ymm5, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$6, %ymm4, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1088(%rsp)
	vpsllw	$9, %ymm4, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$3, %ymm4, %ymm3
	vpor	%ymm4, %ymm3, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1120(%rsp)
	vmovdqu	137920(%rbx), %ymm1
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm1, %ymm4
	vpsllw	$9, %ymm3, %ymm5
	vpsllw	$6, %ymm3, %ymm1
	vpor	%ymm5, %ymm1, %ymm1
	vpsllw	$3, %ymm3, %ymm5
	vpor	%ymm3, %ymm5, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$6, %ymm4, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1152(%rsp)
	vpsllw	$9, %ymm4, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$3, %ymm4, %ymm3
	vpor	%ymm4, %ymm3, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1184(%rsp)
	vmovdqu	137952(%rbx), %ymm1
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm1, %ymm4
	vpsllw	$9, %ymm3, %ymm5
	vpsllw	$6, %ymm3, %ymm1
	vpor	%ymm5, %ymm1, %ymm1
	vpsllw	$3, %ymm3, %ymm5
	vpor	%ymm3, %ymm5, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$6, %ymm4, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1216(%rsp)
	vpsllw	$9, %ymm4, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$3, %ymm4, %ymm3
	vpor	%ymm4, %ymm3, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1248(%rsp)
	vmovdqu	137984(%rbx), %ymm1
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm1, %ymm4
	vpsllw	$6, %ymm3, %ymm5
	vpsllw	$9, %ymm3, %ymm1
	vpor	%ymm5, %ymm1, %ymm1
	vpsllw	$3, %ymm3, %ymm5
	vpor	%ymm3, %ymm5, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$9, %ymm4, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1280(%rsp)
	vpsllw	$6, %ymm4, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$3, %ymm4, %ymm3
	vpor	%ymm4, %ymm3, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1312(%rsp)
	vmovdqu	138016(%rbx), %ymm1
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm1, %ymm4
	vpsllw	$6, %ymm3, %ymm5
	vpsllw	$9, %ymm3, %ymm1
	vpor	%ymm5, %ymm1, %ymm1
	vpsllw	$3, %ymm3, %ymm5
	vpor	%ymm3, %ymm5, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$6, %ymm4, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1344(%rsp)
	vpsllw	$9, %ymm4, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$3, %ymm4, %ymm3
	vpor	%ymm4, %ymm3, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1376(%rsp)
	vmovdqu	138048(%rbx), %ymm1
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm1, %ymm4
	vpsllw	$6, %ymm3, %ymm5
	vpsllw	$9, %ymm3, %ymm1
	vpor	%ymm5, %ymm1, %ymm1
	vpsllw	$3, %ymm3, %ymm5
	vpor	%ymm3, %ymm5, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$6, %ymm4, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1408(%rsp)
	vpsllw	$9, %ymm4, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$3, %ymm4, %ymm3
	vpor	%ymm4, %ymm3, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1440(%rsp)
	vmovdqu	138080(%rbx), %ymm1
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm1, %ymm4
	vpsllw	$6, %ymm3, %ymm5
	vpsllw	$9, %ymm3, %ymm1
	vpor	%ymm5, %ymm1, %ymm1
	vpsllw	$3, %ymm3, %ymm5
	vpor	%ymm3, %ymm5, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$6, %ymm4, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1472(%rsp)
	vpsllw	$9, %ymm4, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$3, %ymm4, %ymm3
	vpor	%ymm4, %ymm3, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1504(%rsp)
	vmovdqu	138112(%rbx), %ymm1
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm1, %ymm4
	vpsllw	$6, %ymm3, %ymm5
	vpsllw	$9, %ymm3, %ymm1
	vpor	%ymm5, %ymm1, %ymm1
	vpsllw	$3, %ymm3, %ymm5
	vpor	%ymm3, %ymm5, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$6, %ymm4, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1536(%rsp)
	vpsllw	$9, %ymm4, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$3, %ymm4, %ymm3
	vpor	%ymm4, %ymm3, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1568(%rsp)
	vmovdqu	138144(%rbx), %xmm1
	vpmovzxbw	%xmm1, %xmm4
	vpsrldq	$8, %xmm1, %xmm1
	vpmovzxbw	%xmm1, %xmm3
	vpsllw	$6, %xmm4, %xmm5
	vpsllw	$9, %xmm4, %xmm1
	vpor	%xmm5, %xmm1, %xmm1
	vpsllw	$3, %xmm4, %xmm5
	vpor	%xmm4, %xmm5, %xmm4
	vpor	%xmm4, %xmm1, %xmm1
	vpsllw	$6, %xmm3, %xmm4
	vpand	%xmm2, %xmm1, %xmm1
	vmovdqa	%xmm1, 1600(%rsp)
	vpsllw	$9, %xmm3, %xmm1
	vpor	%xmm4, %xmm1, %xmm1
	vpsllw	$3, %xmm3, %xmm4
	vpor	%xmm3, %xmm4, %xmm3
	vpor	%xmm3, %xmm1, %xmm1
	vpand	%xmm2, %xmm1, %xmm1
	vmovdqa	%xmm1, 1616(%rsp)
	vmovdqu	138160(%rbx), %ymm1
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm1, %ymm4
	vpsllw	$6, %ymm3, %ymm5
	vpsllw	$9, %ymm3, %ymm1
	vpor	%ymm5, %ymm1, %ymm1
	vpsllw	$3, %ymm3, %ymm5
	vpor	%ymm3, %ymm5, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$6, %ymm4, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1632(%rsp)
	vpsllw	$9, %ymm4, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$3, %ymm4, %ymm3
	vpor	%ymm4, %ymm3, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1664(%rsp)
	vmovdqu	138192(%rbx), %ymm1
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm1, %ymm4
	vpsllw	$6, %ymm3, %ymm5
	vpsllw	$9, %ymm3, %ymm1
	vpor	%ymm5, %ymm1, %ymm1
	vpsllw	$3, %ymm3, %ymm5
	vpor	%ymm3, %ymm5, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$6, %ymm4, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1696(%rsp)
	vpsllw	$9, %ymm4, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$3, %ymm4, %ymm3
	vpor	%ymm4, %ymm3, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1728(%rsp)
	vmovdqu	138224(%rbx), %ymm1
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm1, %ymm4
	vpsllw	$6, %ymm3, %ymm5
	vpsllw	$9, %ymm3, %ymm1
	vpor	%ymm5, %ymm1, %ymm1
	vpsllw	$3, %ymm3, %ymm5
	vpor	%ymm3, %ymm5, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$6, %ymm4, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1760(%rsp)
	vpsllw	$9, %ymm4, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$3, %ymm4, %ymm3
	vpor	%ymm4, %ymm3, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1792(%rsp)
	vmovdqu	138256(%rbx), %ymm1
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm1, %ymm4
	vpsllw	$6, %ymm3, %ymm5
	vpsllw	$9, %ymm3, %ymm1
	vpor	%ymm5, %ymm1, %ymm1
	vpsllw	$3, %ymm3, %ymm5
	vpor	%ymm3, %ymm5, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$6, %ymm4, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1824(%rsp)
	vpsllw	$9, %ymm4, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$3, %ymm4, %ymm3
	vpor	%ymm4, %ymm3, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1856(%rsp)
	vmovdqu	138288(%rbx), %ymm1
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm1, %ymm4
	vpsllw	$6, %ymm3, %ymm5
	vpsllw	$9, %ymm3, %ymm1
	vpor	%ymm5, %ymm1, %ymm1
	vpsllw	$3, %ymm3, %ymm5
	vpor	%ymm3, %ymm5, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$9, %ymm4, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1888(%rsp)
	vpsllw	$6, %ymm4, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$3, %ymm4, %ymm3
	vpor	%ymm4, %ymm3, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1920(%rsp)
	vmovdqu	138320(%rbx), %ymm1
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm1, %ymm4
	vpsllw	$6, %ymm3, %ymm5
	vpsllw	$9, %ymm3, %ymm1
	vpor	%ymm5, %ymm1, %ymm1
	vpsllw	$3, %ymm3, %ymm5
	vpor	%ymm3, %ymm5, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$6, %ymm4, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1952(%rsp)
	vpsllw	$9, %ymm4, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$3, %ymm4, %ymm3
	vpor	%ymm4, %ymm3, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 1984(%rsp)
	vmovdqu	138352(%rbx), %ymm1
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm1, %ymm4
	vpsllw	$6, %ymm3, %ymm5
	vpsllw	$9, %ymm3, %ymm1
	vpor	%ymm5, %ymm1, %ymm1
	vpsllw	$3, %ymm3, %ymm5
	vpor	%ymm3, %ymm5, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$6, %ymm4, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 2016(%rsp)
	vpsllw	$9, %ymm4, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$3, %ymm4, %ymm3
	vpor	%ymm4, %ymm3, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 2048(%rsp)
	vmovdqu	138384(%rbx), %ymm1
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm1, %ymm4
	vpsllw	$6, %ymm3, %ymm5
	vpsllw	$9, %ymm3, %ymm1
	vpor	%ymm5, %ymm1, %ymm1
	vpsllw	$3, %ymm3, %ymm5
	vpor	%ymm3, %ymm5, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$6, %ymm4, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 2080(%rsp)
	vpsllw	$9, %ymm4, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$3, %ymm4, %ymm3
	vpor	%ymm4, %ymm3, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 2112(%rsp)
	vmovdqu	138416(%rbx), %ymm1
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm1, %ymm4
	vpsllw	$9, %ymm3, %ymm5
	vpsllw	$6, %ymm3, %ymm1
	vpor	%ymm5, %ymm1, %ymm1
	vpsllw	$3, %ymm3, %ymm5
	vpor	%ymm3, %ymm5, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$6, %ymm4, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 2144(%rsp)
	vpsllw	$9, %ymm4, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$3, %ymm4, %ymm3
	vpor	%ymm4, %ymm3, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 2176(%rsp)
	vmovdqu	138448(%rbx), %ymm1
	movq	%rdi, 88(%rsp)
	movq	112(%rsp), %rdi
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	movl	$80, 120(%rsp)
	vpmovzxbw	%xmm1, %ymm4
	vpsllw	$6, %ymm3, %ymm5
	addq	$512, %rdi
	vpsllw	$9, %ymm3, %ymm1
	movq	%rdi, 96(%rsp)
	vpor	%ymm5, %ymm1, %ymm1
	vpsllw	$3, %ymm3, %ymm5
	vpor	%ymm3, %ymm5, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$6, %ymm4, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 2208(%rsp)
	vpsllw	$9, %ymm4, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$3, %ymm4, %ymm3
	vpor	%ymm4, %ymm3, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 2240(%rsp)
	vmovdqu	138480(%rbx), %ymm1
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm1, %ymm4
	vpsllw	$6, %ymm3, %ymm5
	vpsllw	$9, %ymm3, %ymm1
	vpor	%ymm5, %ymm1, %ymm1
	vpsllw	$3, %ymm3, %ymm5
	vpor	%ymm3, %ymm5, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$6, %ymm4, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 2272(%rsp)
	vpsllw	$9, %ymm4, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$3, %ymm4, %ymm3
	vpor	%ymm4, %ymm3, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 2304(%rsp)
	vmovdqu	138512(%rbx), %ymm1
	vpmovzxbw	%xmm1, %ymm3
	vextracti128	$0x1, %ymm1, %xmm1
	vpmovzxbw	%xmm1, %ymm4
	vpsllw	$6, %ymm3, %ymm5
	vpsllw	$9, %ymm3, %ymm1
	vpor	%ymm5, %ymm1, %ymm1
	vpsllw	$3, %ymm3, %ymm5
	vpor	%ymm3, %ymm5, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$6, %ymm4, %ymm3
	vpand	%ymm0, %ymm1, %ymm1
	vmovdqa	%ymm1, 2336(%rsp)
	vpsllw	$9, %ymm4, %ymm1
	vpor	%ymm3, %ymm1, %ymm1
	vpsllw	$3, %ymm4, %ymm3
	vpor	%ymm4, %ymm3, %ymm3
	vpor	%ymm3, %ymm1, %ymm1
	vpand	%ymm0, %ymm1, %ymm0
	vmovdqa	%ymm0, 2368(%rsp)
	vmovdqu	138544(%rbx), %xmm0
	vpmovzxbw	%xmm0, %xmm3
	vpsrldq	$8, %xmm0, %xmm0
	vpsllw	$6, %xmm3, %xmm4
	vpsllw	$9, %xmm3, %xmm1
	vpmovzxbw	%xmm0, %xmm0
	vpor	%xmm4, %xmm1, %xmm1
	vpsllw	$3, %xmm3, %xmm4
	vpor	%xmm3, %xmm4, %xmm3
	vmovd	%ecx, %xmm4
	movl	$3932220, %ecx
	vpor	%xmm3, %xmm1, %xmm1
	vpsllw	$6, %xmm0, %xmm3
	vpbroadcastd	%xmm4, %ymm4
	vpand	%xmm2, %xmm1, %xmm1
	vmovdqa	%xmm1, 2400(%rsp)
	vpsllw	$9, %xmm0, %xmm1
	vpor	%xmm3, %xmm1, %xmm1
	vpsllw	$3, %xmm0, %xmm3
	vpor	%xmm0, %xmm3, %xmm0
	vmovd	%ecx, %xmm3
	movl	$1966110, %ecx
	vpor	%xmm0, %xmm1, %xmm0
	vpcmpeqd	%ymm1, %ymm1, %ymm1
	vpbroadcastd	%xmm3, %ymm3
	vpand	%xmm2, %xmm0, %xmm0
	vpsrlw	$12, %ymm1, %ymm1
	vmovd	%ecx, %xmm2
	vmovdqa	%xmm0, 2416(%rsp)
	vpbroadcastd	%xmm2, %ymm2
.L310:
	movl	%r11d, 416(%rsp)
	leal	0(,%r14,4), %r10d
	movq	%r13, %r9
	movq	%rax, %r8
	movl	%r11d, 68(%rsp)
	movq	%rdx, %rdi
	movq	%r13, 56(%rsp)
	movq	%rdx, 48(%rsp)
	movq	%r14, 40(%rsp)
	movq	%rbx, 32(%rsp)
	movq	%r12, 24(%rsp)
.L312:
	movl	416(%rsp), %ecx
	movl	$3435973837, %esi
	movq	88(%rsp), %rdx
	movl	%r10d, 64(%rsp)
	vpbroadcastw	(%r9), %ymm9
	vpbroadcastw	2(%r9), %ymm8
	xorl	%r12d, %r12d
	xorl	%r13d, %r13d
	movq	%rcx, %rbx
	imulq	%rsi, %rcx
	vpbroadcastw	4(%r9), %ymm7
	vpbroadcastw	6(%r9), %ymm6
	xorl	%r14d, %r14d
	shrq	$34, %rcx
	leal	(%rcx,%rcx,4), %esi
	subl	%esi, %ebx
	movq	112(%rsp), %rsi
	movslq	%ebx, %rcx
	xorl	%ebx, %ebx
	salq	$9, %rcx
	movq	%rcx, %r11
	leaq	(%rsi,%rcx), %rcx
	movslq	%r10d, %rsi
	leaq	(%rdx,%rsi,2), %rsi
	movq	96(%rsp), %rdx
	addq	%r11, %rdx
	xorl	%r11d, %r11d
	movw	%r11w, 320(%rsp)
	xorl	%r11d, %r11d
	movw	%r11w, 352(%rsp)
	xorl	%r11d, %r11d
	movw	%r11w, 384(%rsp)
	xorl	%r11d, %r11d
	movw	%r11w, 124(%rsp)
	xorl	%r11d, %r11d
	movw	%r11w, 126(%rsp)
	xorl	%r11d, %r11d
	movw	%r11w, 128(%rsp)
	xorl	%r11d, %r11d
	movw	%r11w, 160(%rsp)
	xorl	%r11d, %r11d
	movw	%r11w, 192(%rsp)
	xorl	%r11d, %r11d
	movw	%r11w, 224(%rsp)
	xorl	%r11d, %r11d
	movw	%r11w, 256(%rsp)
	xorl	%r11d, %r11d
	movw	%r11w, 288(%rsp)
	movq	%rdx, 104(%rsp)
	xorl	%edx, %edx
.L311:
	vpmullw	96(%rcx), %ymm6, %ymm5
	vpmullw	32(%rcx), %ymm8, %ymm10
	vpmullw	64(%rcx), %ymm7, %ymm0
	vpxor	%ymm5, %ymm0, %ymm0
	vpmullw	(%rcx), %ymm9, %ymm5
	vpxor	%ymm10, %ymm5, %ymm5
	movzwl	(%rsi), %r10d
	vpxor	%ymm5, %ymm0, %ymm0
	vpsrlw	$9, %ymm0, %ymm5
	vpsrlw	$6, %ymm0, %ymm10
	vpand	%ymm3, %ymm10, %ymm10
	vpand	%ymm4, %ymm5, %ymm5
	vpxor	%ymm10, %ymm5, %ymm5
	vpsrlw	$3, %ymm0, %ymm10
	vpand	%ymm1, %ymm0, %ymm0
	vpand	%ymm2, %ymm10, %ymm10
	vpxor	%ymm0, %ymm10, %ymm0
	vpxor	%ymm0, %ymm5, %ymm5
	vpsrlw	$3, %ymm5, %ymm0
	vpand	%ymm2, %ymm0, %ymm0
	vpxor	%ymm5, %ymm0, %ymm0
	vpsrlw	$4, %ymm5, %ymm5
	vpxor	%ymm5, %ymm0, %ymm0
	vpand	%ymm1, %ymm0, %ymm0
	vpextrw	$0, %xmm0, %r11d
	imull	%r10d, %r11d
	xorw	%r11w, 288(%rsp)
	vpextrw	$1, %xmm0, %r11d
	imull	%r10d, %r11d
	xorw	%r11w, 256(%rsp)
	vpextrw	$2, %xmm0, %r11d
	imull	%r10d, %r11d
	xorw	%r11w, 224(%rsp)
	vpextrw	$3, %xmm0, %r11d
	imull	%r10d, %r11d
	xorw	%r11w, 192(%rsp)
	vpextrw	$4, %xmm0, %r11d
	imull	%r10d, %r11d
	xorw	%r11w, 160(%rsp)
	vpextrw	$5, %xmm0, %r11d
	imull	%r10d, %r11d
	xorw	%r11w, 128(%rsp)
	vpextrw	$6, %xmm0, %r11d
	imull	%r10d, %r11d
	xorw	%r11w, 126(%rsp)
	vpextrw	$7, %xmm0, %r11d
	vextracti128	$0x1, %ymm0, %xmm0
	imull	%r10d, %r11d
	xorw	%r11w, 124(%rsp)
	vpextrw	$0, %xmm0, %r11d
	imull	%r10d, %r11d
	xorw	%r11w, 384(%rsp)
	vpextrw	$1, %xmm0, %r11d
	imull	%r10d, %r11d
	xorw	%r11w, 352(%rsp)
	vpextrw	$2, %xmm0, %r11d
	imull	%r10d, %r11d
	xorw	%r11w, 320(%rsp)
	vpextrw	$3, %xmm0, %r11d
	imull	%r10d, %r11d
	xorl	%r11d, %r14d
	vpextrw	$4, %xmm0, %r11d
	imull	%r10d, %r11d
	xorl	%r11d, %r13d
	vpextrw	$5, %xmm0, %r11d
	imull	%r10d, %r11d
	xorl	%r11d, %r12d
	vpextrw	$6, %xmm0, %r11d
	imull	%r10d, %r11d
	xorl	%r11d, %ebx
	vpextrw	$7, %xmm0, %r11d
	imull	%r11d, %r10d
	xorl	%r10d, %edx
	subq	$-128, %rcx
	addq	$2, %rsi
	cmpq	%rcx, 104(%rsp)
	jne	.L311
	movzwl	288(%rsp), %esi
	movw	%r14w, 630(%rsp)
	addq	$32, %rdi
	addq	$32, %r8
	movw	%r13w, 632(%rsp)
	movl	64(%rsp), %r10d
	addq	$8, %r9
	movw	%si, 608(%rsp)
	movzwl	256(%rsp), %esi
	movw	%r12w, 634(%rsp)
	addl	$4, %r10d
	movw	%si, 610(%rsp)
	movzwl	224(%rsp), %esi
	movw	%bx, 636(%rsp)
	movw	%si, 612(%rsp)
	movzwl	192(%rsp), %esi
	movw	%dx, 638(%rsp)
	movw	%si, 614(%rsp)
	movzwl	160(%rsp), %esi
	movw	%si, 616(%rsp)
	movzwl	128(%rsp), %esi
	movw	%si, 618(%rsp)
	movzwl	126(%rsp), %esi
	movw	%si, 620(%rsp)
	movzwl	124(%rsp), %esi
	movw	%si, 622(%rsp)
	movzwl	384(%rsp), %esi
	movw	%si, 624(%rsp)
	movzwl	352(%rsp), %esi
	movw	%si, 626(%rsp)
	movzwl	320(%rsp), %esi
	movw	%si, 628(%rsp)
	vmovdqa	608(%rsp), %ymm0
	vpsrlw	$9, %ymm0, %ymm5
	vpsrlw	$6, %ymm0, %ymm6
	vpand	%ymm3, %ymm6, %ymm6
	vpand	%ymm4, %ymm5, %ymm5
	vpxor	%ymm6, %ymm5, %ymm5
	vpsrlw	$3, %ymm0, %ymm6
	vpand	%ymm1, %ymm0, %ymm0
	vpand	%ymm2, %ymm6, %ymm6
	vpxor	%ymm0, %ymm6, %ymm0
	vmovdqa	-32(%rdi), %ymm6
	vpxor	%ymm0, %ymm5, %ymm5
	vpsrlw	$3, %ymm5, %ymm0
	vpermq	$170, %ymm6, %ymm7
	vpermq	$255, %ymm6, %ymm8
	vpand	%ymm2, %ymm0, %ymm0
	vpxor	%ymm5, %ymm0, %ymm0
	vpsrlw	$4, %ymm5, %ymm5
	vpxor	%ymm5, %ymm0, %ymm0
	vpand	%ymm1, %ymm0, %ymm0
	vpshufb	.LC28(%rip), %ymm0, %ymm5
	vpmullw	%ymm7, %ymm5, %ymm5
	vpshufb	.LC29(%rip), %ymm0, %ymm7
	vpmullw	%ymm8, %ymm7, %ymm7
	vpermq	$0, %ymm6, %ymm8
	vpermq	$85, %ymm6, %ymm6
	vpxor	%ymm7, %ymm5, %ymm5
	vpshufb	.LC34(%rip), %ymm0, %ymm7
	vpshufb	.LC35(%rip), %ymm0, %ymm0
	incl	416(%rsp)
	vpmullw	%ymm8, %ymm7, %ymm7
	vpmullw	%ymm0, %ymm6, %ymm0
	vpxor	%ymm0, %ymm7, %ymm0
	vmovdqa	-32(%r8), %ymm7
	vpxor	%ymm0, %ymm5, %ymm0
	vpsrlw	$9, %ymm0, %ymm5
	vpsrlw	$6, %ymm0, %ymm6
	vpand	%ymm3, %ymm6, %ymm6
	vpand	%ymm4, %ymm5, %ymm5
	vpxor	%ymm6, %ymm5, %ymm5
	vpsrlw	$3, %ymm0, %ymm6
	vpand	%ymm1, %ymm0, %ymm0
	vpand	%ymm2, %ymm6, %ymm6
	vpxor	%ymm0, %ymm6, %ymm0
	vpxor	%ymm0, %ymm5, %ymm0
	vpsrlw	$3, %ymm0, %ymm5
	vpand	%ymm2, %ymm5, %ymm5
	vpxor	%ymm0, %ymm5, %ymm5
	vpsrlw	$4, %ymm0, %ymm0
	vpxor	%ymm0, %ymm5, %ymm0
	vpshufb	.LC34(%rip), %ymm7, %ymm5
	vpand	%ymm1, %ymm0, %ymm0
	vpermq	$0, %ymm0, %ymm6
	vpermq	$85, %ymm0, %ymm8
	vpmullw	%ymm6, %ymm5, %ymm5
	vpshufb	.LC35(%rip), %ymm7, %ymm6
	vpmullw	%ymm8, %ymm6, %ymm6
	vpshufb	.LC28(%rip), %ymm7, %ymm8
	vpxor	%ymm6, %ymm5, %ymm5
	vpermq	$170, %ymm0, %ymm6
	vpmullw	%ymm6, %ymm8, %ymm8
	vpermq	$255, %ymm0, %ymm6
	vpshufb	.LC29(%rip), %ymm7, %ymm0
	vpmullw	%ymm6, %ymm0, %ymm0
	vpxor	(%r15), %ymm5, %ymm5
	vpxor	%ymm0, %ymm8, %ymm0
	vpxor	%ymm0, %ymm5, %ymm0
	vmovdqa	%ymm0, (%r15)
	cmpl	120(%rsp), %r10d
	jne	.L312
	movl	68(%rsp), %r11d
	movq	56(%rsp), %r13
	leal	80(%r10), %edi
	addq	$32, %r15
	movq	48(%rsp), %rdx
	movq	40(%rsp), %r14
	movl	%edi, 120(%rsp)
	addq	$640, %rax
	incl	%r11d
	movq	32(%rsp), %rbx
	movq	24(%rsp), %r12
	addq	$160, %r13
	addq	$20, %r14
	addq	$640, %rdx
	cmpl	$5, %r11d
	jne	.L310
	vmovdqa	448(%rsp), %ymm5
	leaq	608(%rsp), %rdi
	vpsrlw	$9, %ymm5, %ymm0
	vpsrlw	$6, %ymm5, %ymm6
	vpand	%ymm3, %ymm6, %ymm6
	vpand	%ymm4, %ymm0, %ymm0
	vpxor	%ymm6, %ymm0, %ymm0
	vpsrlw	$3, %ymm5, %ymm6
	vpand	%ymm1, %ymm5, %ymm5
	vpand	%ymm2, %ymm6, %ymm6
	vpxor	%ymm5, %ymm6, %ymm5
	vpxor	%ymm5, %ymm0, %ymm0
	vmovdqa	480(%rsp), %ymm5
	vpsrlw	$3, %ymm0, %ymm7
	vpand	%ymm2, %ymm7, %ymm7
	vpsrlw	$6, %ymm5, %ymm6
	vpxor	%ymm0, %ymm7, %ymm7
	vpsrlw	$4, %ymm0, %ymm0
	vpand	%ymm3, %ymm6, %ymm6
	vpxor	%ymm0, %ymm7, %ymm7
	vpsrlw	$9, %ymm5, %ymm0
	vpand	%ymm4, %ymm0, %ymm0
	vpand	%ymm1, %ymm7, %ymm7
	vpxor	%ymm6, %ymm0, %ymm0
	vpsrlw	$3, %ymm5, %ymm6
	vpand	%ymm1, %ymm5, %ymm5
	vmovdqa	%ymm7, 448(%rsp)
	vpand	%ymm2, %ymm6, %ymm6
	vmovdqa	%ymm7, 320(%rsp)
	vpxor	%ymm5, %ymm6, %ymm5
	vpxor	%ymm5, %ymm0, %ymm0
	vmovdqa	512(%rsp), %ymm5
	vpsrlw	$3, %ymm0, %ymm8
	vpand	%ymm2, %ymm8, %ymm8
	vpsrlw	$6, %ymm5, %ymm6
	vpxor	%ymm0, %ymm8, %ymm8
	vpsrlw	$4, %ymm0, %ymm0
	vpand	%ymm3, %ymm6, %ymm6
	vpxor	%ymm0, %ymm8, %ymm8
	vpsrlw	$9, %ymm5, %ymm0
	vpand	%ymm4, %ymm0, %ymm0
	vpand	%ymm1, %ymm8, %ymm8
	vpxor	%ymm6, %ymm0, %ymm0
	vpsrlw	$3, %ymm5, %ymm6
	vpand	%ymm1, %ymm5, %ymm5
	vmovdqa	%ymm8, 480(%rsp)
	vpand	%ymm2, %ymm6, %ymm6
	vmovdqa	%ymm8, 352(%rsp)
	vpxor	%ymm5, %ymm6, %ymm5
	vmovdqa	544(%rsp), %ymm6
	vpxor	%ymm5, %ymm0, %ymm0
	vpsrlw	$3, %ymm0, %ymm5
	vpsrlw	$6, %ymm6, %ymm9
	vpand	%ymm2, %ymm5, %ymm5
	vpand	%ymm3, %ymm9, %ymm9
	vpxor	%ymm0, %ymm5, %ymm5
	vpsrlw	$4, %ymm0, %ymm0
	vpxor	%ymm0, %ymm5, %ymm5
	vpsrlw	$9, %ymm6, %ymm0
	vpand	%ymm4, %ymm0, %ymm0
	vpand	%ymm1, %ymm5, %ymm5
	vpxor	%ymm9, %ymm0, %ymm0
	vpsrlw	$3, %ymm6, %ymm9
	vpand	%ymm1, %ymm6, %ymm6
	vmovdqa	%ymm5, 512(%rsp)
	vpand	%ymm2, %ymm9, %ymm9
	vmovdqa	%ymm5, 384(%rsp)
	vpxor	%ymm6, %ymm9, %ymm6
	vmovdqa	576(%rsp), %ymm9
	vpxor	%ymm6, %ymm0, %ymm0
	vpsrlw	$3, %ymm0, %ymm6
	vpand	%ymm2, %ymm6, %ymm6
	vpxor	%ymm0, %ymm6, %ymm6
	vpsrlw	$4, %ymm0, %ymm0
	vpxor	%ymm0, %ymm6, %ymm6
	vpsrlw	$9, %ymm9, %ymm0
	vpand	%ymm4, %ymm0, %ymm0
	vpsrlw	$6, %ymm9, %ymm4
	vpand	%ymm1, %ymm6, %ymm6
	vpand	%ymm3, %ymm4, %ymm3
	vmovdqa	%ymm6, 544(%rsp)
	vpxor	%ymm3, %ymm0, %ymm0
	vpsrlw	$3, %ymm9, %ymm3
	vpand	%ymm1, %ymm9, %ymm9
	vmovdqa	%ymm6, 416(%rsp)
	vpand	%ymm2, %ymm3, %ymm3
	vpxor	%ymm9, %ymm3, %ymm3
	vpxor	%ymm3, %ymm0, %ymm0
	vpsrlw	$3, %ymm0, %ymm3
	vpand	%ymm2, %ymm3, %ymm2
	vpxor	%ymm0, %ymm2, %ymm2
	vpsrlw	$4, %ymm0, %ymm0
	vpxor	%ymm0, %ymm2, %ymm0
	vpand	%ymm1, %ymm0, %ymm0
	vmovdqa	%ymm0, 576(%rsp)
	vzeroupper
	call	shake256_init@PLT
	leaq	138560(%rbx), %rsi
	movl	$16, %edx
	leaq	608(%rsp), %rdi
	call	shake_absorb@PLT
	movq	72(%rsp), %rdx
	movq	80(%rsp), %rsi
	leaq	608(%rsp), %rdi
	call	shake_absorb@PLT
	leaq	232(%r12), %rsi
	movl	$16, %edx
	leaq	608(%rsp), %rdi
	call	shake_absorb@PLT
	leaq	608(%rsp), %rdi
	call	shake_finalize@PLT
	leaq	15104(%rsp), %rdi
	leaq	608(%rsp), %rdx
	movl	$40, %esi
	call	shake_squeeze@PLT
	vmovdqa	15104(%rsp), %ymm2
	movl	$252645135, %eax
	vmovq	.LC55(%rip), %xmm7
	vmovd	%eax, %xmm0
	vpbroadcastd	%xmm0, %ymm0
	vpsrlw	$4, %ymm2, %ymm1
	vpand	%ymm1, %ymm0, %ymm1
	vpand	%ymm0, %ymm2, %ymm2
	vpunpcklbw	%ymm1, %ymm2, %ymm0
	vpunpckhbw	%ymm1, %ymm2, %ymm2
	vperm2i128	$32, %ymm2, %ymm0, %ymm1
	vperm2i128	$49, %ymm2, %ymm0, %ymm0
	vmovq	15136(%rsp), %xmm2
	vmovdqa	%ymm1, 15168(%rsp)
	vpmovzxbw	%xmm2, %xmm3
	vpand	%xmm7, %xmm2, %xmm2
	vmovdqa	%ymm0, 15200(%rsp)
	vpsrlw	$4, %xmm3, %xmm3
	vpshufb	.LC43(%rip), %xmm3, %xmm3
	vpunpcklbw	%xmm3, %xmm2, %xmm4
	vpunpcklbw	%xmm3, %xmm2, %xmm2
	vextracti128	$0x1, %ymm1, %xmm3
	vpmovzxbw	%xmm3, %ymm3
	vpmovzxbw	%xmm1, %ymm1
	vpshufd	$78, %xmm2, %xmm2
	vmovq	%xmm4, 15232(%rsp)
	vpcmpeqw	352(%rsp), %ymm3, %ymm3
	vpcmpeqw	320(%rsp), %ymm1, %ymm1
	vmovq	%xmm2, 15240(%rsp)
	vpxor	%xmm2, %xmm2, %xmm2
	vpcmpeqw	%ymm2, %ymm3, %ymm3
	vpcmpeqw	%ymm2, %ymm1, %ymm1
	vpor	%ymm1, %ymm3, %ymm1
	vptest	%ymm1, %ymm1
	jne	.L320
	vextracti128	$0x1, %ymm0, %xmm1
	vpmovzxbw	%xmm0, %ymm0
	movl	$16, %edx
	movl	$64, %eax
	vpmovzxbw	%xmm1, %ymm1
	vpcmpeqw	384(%rsp), %ymm0, %ymm0
	vpcmpeqw	416(%rsp), %ymm1, %ymm1
	vpcmpeqw	%ymm2, %ymm0, %ymm0
	vpcmpeqw	%ymm2, %ymm1, %ymm1
	vpor	%ymm0, %ymm1, %ymm0
	vptest	%ymm0, %ymm0
	jne	.L336
.L315:
	cltq
	leal	-1(%rdx), %esi
	xorl	%edx, %edx
	leaq	448(%rsp,%rax,2), %rcx
	leaq	15168(%rsp,%rax), %rax
	jmp	.L317
.L338:
	cmpq	%rdx, %rsi
	je	.L337
	incq	%rdx
.L317:
	movzbl	(%rax,%rdx), %edi
	cmpw	(%rcx,%rdx,2), %di
	je	.L338
	movl	$-1, %eax
.L295:
	movq	15736(%rsp), %rdx
	subq	%fs:40, %rdx
	jne	.L339
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
.L335:
	.cfi_restore_state
	movl	$0, first_time(%rip)
	call	init_vector_table
	jmp	.L296
.L320:
	vmovdqa	.LC69(%rip), %ymm1
	vmovdqa	.LC70(%rip), %ymm0
.L314:
	vmovd	%xmm1, %edx
	vmovd	%xmm0, %eax
	jmp	.L315
.L336:
	vmovdqa	.LC67(%rip), %ymm1
	vmovdqa	.LC68(%rip), %ymm0
	jmp	.L314
.L337:
	xorl	%eax, %eax
	jmp	.L295
.L339:
	vzeroupper
	call	__stack_chk_fail@PLT
	.cfi_endproc
.LFE7304:
	.size	_snova_24_5_16_4_aes_SNOVA_OPT_verify, .-_snova_24_5_16_4_aes_SNOVA_OPT_verify
	.data
	.align 4
	.type	first_time, @object
	.size	first_time, 4
first_time:
	.long	1
	.globl	_snova_24_5_16_4_aes_SNOVA_OPT_Smat
	.align 32
	.type	_snova_24_5_16_4_aes_SNOVA_OPT_Smat, @object
	.size	_snova_24_5_16_4_aes_SNOVA_OPT_Smat, 128
_snova_24_5_16_4_aes_SNOVA_OPT_Smat:
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
	.value	4096
	.value	273
	.value	272
	.value	257
	.value	273
	.value	272
	.value	257
	.value	256
	.value	272
	.value	257
	.value	256
	.value	17
	.value	257
	.value	256
	.value	17
	.value	16
	.value	4369
	.value	272
	.value	4097
	.value	1
	.value	272
	.value	0
	.value	273
	.value	256
	.value	4097
	.value	273
	.value	17
	.value	0
	.value	1
	.value	256
	.value	0
	.value	0
	.value	272
	.value	17
	.value	4096
	.value	273
	.value	17
	.value	4112
	.value	256
	.value	4352
	.value	4096
	.value	256
	.value	273
	.value	1
	.value	273
	.value	4352
	.value	1
	.value	272
	.local	vtl_mult_table8
	.comm	vtl_mult_table8,32,32
	.local	vtl_mult_table4
	.comm	vtl_mult_table4,32,32
	.local	vtl_mult_table2
	.comm	vtl_mult_table2,32,32
	.local	vtl_mult_table1
	.comm	vtl_mult_table1,32,32
	.local	vtl_multmask8
	.comm	vtl_multmask8,32,32
	.local	vtl_multmask4
	.comm	vtl_multmask4,32,32
	.local	vtl_multmask2
	.comm	vtl_multmask2,32,32
	.local	vtl_multmask1
	.comm	vtl_multmask1,32,32
	.local	vector_inv_table
	.comm	vector_inv_table,32,32
	.local	gf_multtab
	.comm	gf_multtab,256,32
	.section	.rodata.cst32,"aM",@progbits,32
	.align 32
.LC4:
	.quad	434328039762493696
	.quad	577309618314412559
	.quad	434328039762493696
	.quad	577309618314412559
	.align 32
.LC24:
	.byte	0
	.byte	1
	.byte	2
	.byte	3
	.byte	2
	.byte	3
	.byte	2
	.byte	3
	.byte	8
	.byte	9
	.byte	10
	.byte	11
	.byte	10
	.byte	11
	.byte	10
	.byte	11
	.byte	0
	.byte	1
	.byte	2
	.byte	3
	.byte	2
	.byte	3
	.byte	2
	.byte	3
	.byte	8
	.byte	9
	.byte	10
	.byte	11
	.byte	10
	.byte	11
	.byte	10
	.byte	11
	.align 32
.LC25:
	.byte	0
	.byte	1
	.byte	10
	.byte	11
	.byte	12
	.byte	13
	.byte	14
	.byte	15
	.byte	0
	.byte	1
	.byte	10
	.byte	11
	.byte	12
	.byte	13
	.byte	14
	.byte	15
	.byte	0
	.byte	1
	.byte	10
	.byte	11
	.byte	12
	.byte	13
	.byte	14
	.byte	15
	.byte	0
	.byte	1
	.byte	10
	.byte	11
	.byte	12
	.byte	13
	.byte	14
	.byte	15
	.align 32
.LC26:
	.byte	2
	.byte	3
	.byte	0
	.byte	1
	.byte	0
	.byte	1
	.byte	0
	.byte	1
	.byte	10
	.byte	11
	.byte	8
	.byte	9
	.byte	8
	.byte	9
	.byte	8
	.byte	9
	.byte	2
	.byte	3
	.byte	0
	.byte	1
	.byte	0
	.byte	1
	.byte	0
	.byte	1
	.byte	10
	.byte	11
	.byte	8
	.byte	9
	.byte	8
	.byte	9
	.byte	8
	.byte	9
	.align 32
.LC27:
	.byte	8
	.byte	9
	.byte	2
	.byte	3
	.byte	4
	.byte	5
	.byte	6
	.byte	7
	.byte	8
	.byte	9
	.byte	2
	.byte	3
	.byte	4
	.byte	5
	.byte	6
	.byte	7
	.byte	8
	.byte	9
	.byte	2
	.byte	3
	.byte	4
	.byte	5
	.byte	6
	.byte	7
	.byte	8
	.byte	9
	.byte	2
	.byte	3
	.byte	4
	.byte	5
	.byte	6
	.byte	7
	.align 32
.LC28:
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
.LC29:
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
.LC35:
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
	.section	.rodata.cst16,"aM",@progbits,16
	.align 16
.LC42:
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
.LC43:
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
	.section	.rodata.cst8,"aM",@progbits,8
	.align 8
.LC55:
	.byte	15
	.byte	15
	.byte	15
	.byte	15
	.byte	15
	.byte	15
	.byte	15
	.byte	15
	.section	.rodata.cst32
	.align 32
.LC56:
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
.LC57:
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
.LC58:
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
.LC59:
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
.LC60:
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
	.set	.LC61,.LC35
	.set	.LC62,.LC34
	.set	.LC63,.LC28
	.set	.LC64,.LC29
	.align 32
.LC67:
	.long	48
	.long	47
	.long	46
	.long	45
	.long	44
	.long	43
	.long	42
	.long	41
	.align 32
.LC68:
	.long	32
	.long	33
	.long	34
	.long	35
	.long	36
	.long	37
	.long	38
	.long	39
	.align 32
.LC69:
	.long	80
	.long	79
	.long	78
	.long	77
	.long	76
	.long	75
	.long	74
	.long	73
	.align 32
.LC70:
	.long	0
	.long	1
	.long	2
	.long	3
	.long	4
	.long	5
	.long	6
	.long	7
	.align 32
.LC71:
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
	.ident	"GCC: (GNU) 15.1.1 20250729"
	.section	.note.GNU-stack,"",@progbits
