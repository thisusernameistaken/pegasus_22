prev = current_function.get_instruction_containing_address(here-1)
tok = next(bv.disassembly_tokens(prev))[0]
val = int(str(tok[-1]),16)
dest = here + val
br = BinaryReader(bv)
br.seek(dest)
string = b""
c = br.read8()
while c != 0x0a:
    string += bytes([c&0x7f])
    c = br.read8()
print(string)