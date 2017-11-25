from pwn import *

Debug = 1
context = (arch = "i386",os = "linux",log_level = "debug")

if Debug = 1:
    p = proccess("./orw")
    gdb.attach(p)
else:
    p = remote("chall.pwnable.tw", 10001)

shellcode = asm("")