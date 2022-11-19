from binaryninja import (
    InstructionTextToken,
    InstructionTextTokenType
)
import struct

class EARdisassembler:

    def __init__(self):
        _xc=_tf=_em = self.default_prefix

        self.opcodes = {
            0:self._add,
            1:self._sub,
            2:self._mlu,
            3:self._mls,
            4:self._dvu,
            5:self._dvs,
            6:self._xor,
            7:self._and,
            8:self._or,
            9:self._shl,
            0xa:self._sru,
            0xb:self._srs,
            0xc:self._mov,
            0xd:self._cmp,
            0x17:self._fcr
        }
        self.instr_prefix = {
            0xc0:_xc,
            0xc1:_tf,
            0xc2:_em,
            0xd0:self._dr,
        }
    

    def decode_cond(self,data):
        cond = data >> 5
        opcode = data & 0x1f
        return cond, opcode

    def get_cond_tokens(self,cond):
        tokens = []
        if cond == 7:
            tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken,"ALWAYS "))
        return tokens   
    
    def disasm(self,data,addr,prefix=None):
        if prefix is None and data[0] in self.instr_prefix.keys():
            return self.instr_prefix[data[0]](data,addr)
        elif prefix is None  and(data[0] >> 4) == 0xd:
            return self.instr_prefix[0xd0](data,addr)

        cond,opcode = self.decode_cond(data[0])

        cond_tokens = self.get_cond_tokens(cond)

        if opcode in self.opcodes.keys():
            size,tokens = self.opcodes[opcode](data,addr)
            cond_tokens.extend(tokens)
            tokens = cond_tokens
            return size,tokens
         
        return self.default_bad()

    def default_prefix(self,data,addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,"UNIMPL PREFIX")]
        size, _tokens = self.disasm(data[1:],addr+1,prefix=1)
        tokens.extend(_tokens)
        return size+1,tokens

    def default_bad(self):
        return 2,[InstructionTextToken(InstructionTextTokenType.TextToken,"BAD")]
    
    def default(self,data,addr):
        return 2,[InstructionTextToken(InstructionTextTokenType.TextToken,"UNIMPL")]

    #PREFIXES
    def _dr(self,data,addr):
        dest_reg_val = data[0] & 0xf
        dest_reg = f"R{dest_reg_val}"
        dr_tokens = [InstructionTextToken(InstructionTextTokenType.RegisterToken,dest_reg)]
        dr_tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken,", "))
        size, _tokens = self.disasm(data[1:],addr+1,prefix=1)
        _tokens[2:2]=dr_tokens
        return size+1,_tokens

    # INSTRUCTIONS
    def _standard(self,data,addr,name):
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,name)]
        reg_pair = data[1]
        length = 2
        rx = reg_pair >> 4
        ry = reg_pair & 0xf
        vy = None
        if ry == 15:
            vy = struct.unpack("<H",data[2:4])[0]
            length += 2
        dest_reg = f"R{rx}"
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,dest_reg))
        tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken,", "))
        if vy is None:
            source_reg = f"R{ry}"
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,source_reg))
        else:
            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken,hex(vy),vy))
        return length, tokens
    
    def _add(self,data,addr):
        return self._standard(data,addr,"ADD ")

    def _sub(self,data,addr):
        return self._standard(data,addr,"SUB ")
    
    def _mlu(self,data,addr):
        return self._standard(data,addr,"MLU ")

    def _mls(self,data,addr):
        return self._standard(data,addr,"MLS ")

    def _dvu(self,data,addr):
        return self._standard(data,addr,"DVU ")

    def _dvs(self,data,addr):
        return self._standard(data,addr,"DVS ")

    def _xor(self,data,addr):
        return self._standard(data,addr,"xor ")

    def _and(self,data,addr):
        return self._standard(data,addr,"AND ")
    
    def _or(self,data,addr):
        return self._standard(data,addr,"ORR ")

    def _shl(self,data,addr):
        return self._standard(data,addr,"SHL ")

    def _sru(self,data,addr):
        return self._standard(data,addr,"SHR ")

    def _srs(self,data,addr):
        return self._standard(data,addr,"SRS ")

    def _mov(self,data,addr):
       return self._standard(data,addr,"MOV ")

    def _cmp(self,data,addr):
       return self._standard(data,addr,"CMP ")

    def _fcr(self,data,addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,"FCR ")]
        data = data[1:]
        vy = struct.unpack("<H",data[:2])[0]
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken,hex(vy),vy))
        length = 3
        return length, tokens