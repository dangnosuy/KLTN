.intel_syntax noprefix
.global sys_direct_call
.global sys_indirect_call

.text

/*
   sys_direct_call(DWORD ssn, PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4, PVOID arg5, PVOID arg6)
   Windows x64 ABI:
     RCX = ssn
     RDX = arg1
     R8  = arg2
     R9  = arg3
     [RSP+40] = arg4
     [RSP+48] = arg5
     [RSP+56] = arg6
*/
sys_direct_call:
    mov eax, ecx            /* EAX = SSN */
    mov r10, rdx            /* R10 = first syscall argument (RCX in kernel) */
    mov rdx, r8             /* RDX = second argument */
    mov r8, r9              /* R8  = third argument */
    mov r9, [rsp + 40]      /* R9  = fourth argument */
    /* Stack arguments 5 and 6 remain above the shadow space */
    syscall
    ret

/*
   sys_indirect_call(DWORD ssn, void* jmp_gadget, PVOID arg1, PVOID arg2, PVOID arg3, PVOID arg4, PVOID arg5)
   Windows x64 ABI:
     RCX = ssn
     RDX = jmp_gadget
     R8  = arg1
     R9  = arg2
     [RSP+40] = arg3
     [RSP+48] = arg4
     [RSP+56] = arg5
     [RSP+64] = arg6
*/
sys_indirect_call:
    mov eax, ecx            /* EAX = SSN */
    mov r11, rdx            /* R11 = address of 'syscall; ret' inside ntdll */
    mov r10, r8             /* R10 = first syscall argument */
    mov rdx, r9             /* RDX = second syscall argument */
    mov r8, [rsp + 40]      /* R8  = third syscall argument */
    mov r9, [rsp + 48]      /* R9  = fourth syscall argument */
    /* If there are 5th/6th arguments on stack: */
    mov rax, [rsp + 56]
    mov [rsp + 40], rax
    mov rax, [rsp + 64]
    mov [rsp + 48], rax
    mov eax, ecx            /* Restore EAX = SSN */
    jmp r11                 /* Jump into ntdll gadget (syscall; ret) */
