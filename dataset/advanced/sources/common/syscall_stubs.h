#ifndef SYSCALL_STUBS_H
#define SYSCALL_STUBS_H

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
   Invokes direct syscall instruction with provided SSN and arguments.
*/
extern NTSTATUS sys_direct_call(
    DWORD ssn,
    PVOID a1, PVOID a2, PVOID a3, PVOID a4, PVOID a5, PVOID a6
);

/*
   Jumps into ntdll's 'syscall; ret' gadget to avoid direct syscall signatures.
*/
extern NTSTATUS sys_indirect_call(
    DWORD ssn,
    void* jmp_gadget,
    PVOID a1, PVOID a2, PVOID a3, PVOID a4, PVOID a5, PVOID a6
);

#ifdef __cplusplus
}
#endif

#endif /* SYSCALL_STUBS_H */
