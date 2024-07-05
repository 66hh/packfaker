import os
import lief
import struct

path = input("请输入要伪装的exe文件路径: ")
if path[len(path) - 4:].lower() != ".exe":
    print("文件后缀错误")
    exit()
binary = lief.parse(path)

# 经过修改的CodeCrypt入口点代码
asm = b"\xE9\x10\x00\x00\x00\xEB\x02\x83\x3D\x58\xEB\x02\xFF\x1D\x5B\xEB\x02\x0F\xC7\x5F\x00\x90"

# 新建区段
code_sec = lief.PE.Section()
code_sec.name = ".vlizer"
code_sec.content = bytearray(asm + b'\x00\x00\x00\x00\x00')
code_sec.size = 1000

# 加入区段
code_sec = binary.add_section(code_sec, lief.PE.SECTION_TYPES.TEXT)

# jmp到oep
jmp_addr = binary.optional_header.addressof_entrypoint - code_sec.virtual_address - code_sec.virtual_size
code_sec.content = bytearray(asm + b'\xE9' + struct.pack("i", jmp_addr))

# 修改oep
binary.optional_header.addressof_entrypoint = code_sec.virtual_address

# 加入伪装区段
fake_sec = lief.PE.Section()
fake_sec.name = ".vmp0"
fake_sec.content = bytearray(os.urandom(256))
fake_sec.size = 1000
binary.add_section(fake_sec, lief.PE.SECTION_TYPES.TEXT)

fake_sec = lief.PE.Section()
fake_sec.name = ".vmp1"
fake_sec.content = bytearray(os.urandom(256))
fake_sec.size = 1000
binary.add_section(fake_sec, lief.PE.SECTION_TYPES.TEXT)

binary.write(path[:len(path) - 4] + ".fake.exe")

print("伪装成功")