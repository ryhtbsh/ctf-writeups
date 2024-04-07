from pwn import *

email5_enc = open("./email5.enc", "rb").read()
email0     = open("./email0.txt", "rb").read()

rev_email5_enc = email5_enc[::-1]
rev_email0     = email0[::-1]

rev_key = []
for i in range(32):
    rev_key.append(rev_email5_enc[i] ^ rev_email0[i])

rev_email5 = b''
for i in range(len(email5_enc)):
    rev_email5 += p8(rev_email5_enc[i] ^ rev_key[i%32])

email5 = rev_email5[::-1]
open("./email5.txt", "wb+").write(email5)
