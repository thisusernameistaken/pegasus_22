from selectors import EpollSelector
from binaryninja import (
    InstructionTextToken,
    InstructionTextTokenType,
    BranchType
)
# from binaryninjaui import UIContext
import struct
import ctypes

class EARdisassembler:

    def __init__(self,skip):
        _xc=_tf=_em = self.default_prefix
        self.SKIP_VAL = skip
        self.bv = None
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
            0x12:self._ldb,
            0x14:self._bra,
            0x15:self._brr,
            0x17:self._fcr,
            0x18:self._rdb,
            0x19:self._wrb,
            0x1c:self._inc,
            0x1d:self._bpt,
            0x1e:self._hlt,
            0x1f:self._nop
        }
        self.instr_prefix = {
            0xc0:_xc,
            0xc1:_tf,
            0xc2:_em,
            0xd0:self._dr,
        }
    
        self.cond_val = ["EQ ","NE ","GT ","LE ","LT ","GE ","SP ","A ","NG ","PS ","BG ","SE ","SM ","BE ","OD ","EV "]

    def decode_cond(self,data):
        cond = data >> 5
        opcode = data & 0x1f
        return cond, opcode

    def get_cond_tokens(self,cond):
        tokens = [InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken,".")]
        tokens.append(InstructionTextToken(InstructionTextTokenType.KeywordToken,self.cond_val[cond]))
        if cond != 7:
            cond = True
        else:
            cond = False
        return tokens, cond
    
    def disasm(self,data,addr,prefix=None):
        # if prefix is None and data[0] in self.instr_prefix.keys():
        #     return self.instr_prefix[data[0]](data,addr)
        # elif prefix is None  and(data[0] >> 4) == 0xd:
        #     return self.instr_prefix[0xd0](data,addr)

        # cond,opcode = self.decode_cond(data[0])

        # cond_tokens,more_cond = self.get_cond_tokens(cond)

        # if opcode in self.opcodes.keys():
        #     size,tokens, branch_info = self.opcodes[opcode](data,addr)
        #     tokens[1:1] = cond_tokens
        #     if more_cond and len(branch_info)>0:
        #         branch_info.append((BranchType.FalseBranch,addr+(size*self.SKIP_VAL)))
        #     return size,tokens,branch_info
         
        return self.default_bad()

    def default_prefix(self,data,addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,"UNIMPL PREFIX")]
        size, _tokens, cond = self.disasm(data[1:],addr+1,prefix=1)
        tokens.extend(_tokens)
        return size+1,tokens, cond

    def default_bad(self):
        return 2,[InstructionTextToken(InstructionTextTokenType.TextToken,"BAD")], []
    
    def default(self,data,addr):
        return 2,[InstructionTextToken(InstructionTextTokenType.TextToken,"UNIMPL")], []

    #PREFIXES
    def _dr(self,data,addr):
        dest_reg_val = data[0] & 0xf
        dest_reg = f"R{dest_reg_val}"
        dr_tokens = [InstructionTextToken(InstructionTextTokenType.RegisterToken,dest_reg)]
        dr_tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken,", "))
        size, _tokens, cond = self.disasm(data[1:],addr+1,prefix=1)
        _tokens[3:3]=dr_tokens
        return size+1,_tokens, cond

    # INSTRUCTIONS
    def _single(self,data,addr,name):
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,name)]
        return 1,tokens,[]

    def _standard(self,data,addr,name):
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,name)]
        reg_pair = data[1]
        length = 2
        rx = reg_pair >> 4
        ry = reg_pair & 0xf
        vy = None
        if ry == 15:
            # print("heers data",data)
            vy = struct.unpack("<h",data[2:4])[0]
            length += 2
        dest_reg = f"R{rx}"
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,dest_reg))
        tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken,", "))
        if vy is None:
            source_reg = f"R{ry}"
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,source_reg))
        else:
            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken,hex(vy),vy))
        return length, tokens, []
    
    def _add(self,data,addr):
        return self._standard(data,addr,"ADD")

    def _sub(self,data,addr):
        return self._standard(data,addr,"SUB")
    
    def _mlu(self,data,addr):
        return self._standard(data,addr,"MLU")

    def _mls(self,data,addr):
        return self._standard(data,addr,"MLS")

    def _dvu(self,data,addr):
        return self._standard(data,addr,"DVU")

    def _dvs(self,data,addr):
        return self._standard(data,addr,"DVS")

    def _xor(self,data,addr):
        return self._standard(data,addr,"XOR")

    def _and(self,data,addr):
        return self._standard(data,addr,"AND")
    
    def _or(self,data,addr):
        return self._standard(data,addr,"ORR")

    def _shl(self,data,addr):
        return self._standard(data,addr,"SHL")

    def _sru(self,data,addr):
        return self._standard(data,addr,"SHR")

    def _srs(self,data,addr):
        return self._standard(data,addr,"SRS")

    def _mov(self,data,addr):
       return self._standard(data,addr,"MOV")

    def _cmp(self,data,addr):
       return self._standard(data,addr,"CMP")

    def _ldb(self,data,addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,"LDB")]
        reg_pair = data[1]
        length = 2
        rx = reg_pair >> 4
        ry = reg_pair & 0xf
        vy = None
        if ry == 15:
            vy = struct.unpack("<h",data[2:4])[0]
            length += 2
        dest_reg = f"R{rx}"
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,dest_reg))
        tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken,", "))
        tokens.append(InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken,"["))
        if vy is None:
            source_reg = f"R{ry}"
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,source_reg))
        else:
            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken,hex(vy),vy))
        tokens.append(InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken,"]"))
        return length, tokens, []

    def _bra(self,data,addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,"BRA")]
        reg_pair = data[1]
        length = 2
        rx = reg_pair >> 4
        ry = reg_pair & 0xf
        vy = None
        if ry == 15:
            vy = struct.unpack("<h",data[2:4])[0]
            length += 2
        dest_reg = f"R{rx}"
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,dest_reg))
        tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken,", "))
        if vy is None:
            source_reg = f"R{ry}"
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,source_reg))
            true_branch = (BranchType.IndirectBranch,None)
            # false_branch = (BranchType.FalseBranch,addr+length)
            cond = [true_branch]
        else:
            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken,hex(vy),vy))
            true_branch = (BranchType.TrueBranch,vy)
            # false_branch = (BranchType.FalseBranch,addr+length)
            cond = [true_branch]
        return length, tokens, cond

    def _brr(self,data,addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,"BRR")]
        length = 1
        vy = struct.unpack("<h",data[1:3])[0]
        length += 2
        tokens.append(InstructionTextToken(InstructionTextTokenType.CodeRelativeAddressToken,hex(addr+vy+(length*self.SKIP_VAL)),addr+vy+(length*self.SKIP_VAL)))
        true_branch = (BranchType.TrueBranch,addr+vy+(length*self.SKIP_VAL))
        # false_branch = (BranchType.FalseBranch,addr+length)
        cond = [true_branch]
        return length, tokens, cond

    def _fcr(self,data,addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,"FCR")]
        data = data[1:]
        val = struct.unpack("<h",data[:2])[0]
        dest = addr+3+val
        tokens.append(InstructionTextToken(InstructionTextTokenType.CodeRelativeAddressToken,hex(dest),dest))
        length = 3
        branch = BranchType.CallDestination
        return length, tokens, [(branch,dest)]

    def _rdb(self,data,addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,"RDB")]
        reg_pair = data[1]
        length = 2
        rx = reg_pair>>4
        ry = reg_pair & 0xf
        val = ctypes.c_int8(ry).value
        dest_reg = f"R{rx}"
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,dest_reg))
        tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken,", "))
        tokens.append(InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken,"("))
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken,str(val),val))
        tokens.append(InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken,")"))
        return length, tokens, []

    def _wrb(self,data,addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,"WRB")]
        reg_pair = data[1]
        length = 2
        val = reg_pair>>4
        ry = reg_pair & 0xf
        vy = None
        if ry == 15:
            vy = data[2]
            length += 1
        tokens.append(InstructionTextToken(InstructionTextTokenType.BeginMemoryOperandToken,"("))
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken,str(val),val))
        tokens.append(InstructionTextToken(InstructionTextTokenType.EndMemoryOperandToken,")"))
        tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken,", "))
        if vy is None:
            source_reg = f"R{ry}"
            tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,source_reg))
        else:
            tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken,hex(vy),vy))
        return length,tokens,[]

    def _inc(self,data,addr):
        tokens = [InstructionTextToken(InstructionTextTokenType.TextToken,"INC")]
        reg_pair = data[1]
        length = 2
        rx = reg_pair >> 4
        ry = reg_pair & 0xf
        val = ctypes.c_int8(ry).value
        if val >=0:
            val +=1
        dest_reg = f"R{rx}"
        tokens.append(InstructionTextToken(InstructionTextTokenType.RegisterToken,dest_reg))
        tokens.append(InstructionTextToken(InstructionTextTokenType.OperandSeparatorToken,", "))
        tokens.append(InstructionTextToken(InstructionTextTokenType.IntegerToken,str(val),val))
        return length, tokens, []

    def _bpt(self,data,addr):
        return self._single(data,addr,"BPT")
    
    def _hlt(self,data,addr):
        length,tokens,_= self._single(data,addr,"HLT")
        cond = [(BranchType.FunctionReturn,None)]
        return length, tokens, cond

    def _nop(self,data,addr):
        return self._single(data,addr,"NOP")

    # def update_bv(self):
    #     if self.bv == None:
    #         ac = UIContext.activeContext()
    #         cv=ac.getCurrentViewFrame()
    #         if cv != None:
    #             self.bv = cv.getCurrentBinaryView()
    #             if self.bv != None:
    #                 return True
    #             return False
    #         return False
    #     return True