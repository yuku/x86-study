BITS 32
    org 0x7c00
    sub esp, 16
    xor esp, 0xffff
    mov ebp, esp
    mov eax, 2
    add eax, 16
    or eax, 16
    or esp, dword [ebp+4]
    or dword [ebp+4], esp
    mov dword [ebp+4], 5
    add dword [ebp+4], eax
    add eax, dword [ebp+4]
    mov esi, [ebp+4]
    inc dword [ebp+4]
    mov edi, [ebp+4]
    jmp 0
