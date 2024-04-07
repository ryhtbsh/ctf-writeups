from pwn import *

def what(s):
    fornamen = b64d(s)
    recursive = b''
    final = bytearray(b'SGF2ZSB5b3UgZXZlciB1c2VkIEZyaWRhPw==')
    kent = 0
    xor = len(final)-1
    while kent < xor:
        glaf = final[kent]
        final[kent] = final[xor]
        final[xor] = glaf
        kent += 1
        xor -= 1

    every = 0
    while every < len(fornamen):
        recursive += p8(fornamen[every] - 1)
        every += 1
    print(recursive)


what(b'cmpkdjNjYzE6MzUuU1R8aHY0dHR6YGd2b2R1MnBvfi46MTI0M3M6amcz')
