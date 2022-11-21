from binaryninja import (
    Architecture,
    RegisterInfo,
    InstructionInfo,
)
from binaryninja.enums import (
    FlagRole,
    Endianness
)
from .disassembly import EARdisassembler
import struct
with open("/home/chris/ctfs/sunshine22/peg/skip","rb") as f:
    SKIP_VAL = struct.unpack("<h",f.read().ljust(2,b"\x00"))[0]

# SKIP_VAL = 0x40

class EAR(Architecture):
    name = "ear"

    default_int_size = 2
    address_size = 2
    max_instr_length = 256

    endianness = Endianness.LittleEndian
    stack_pointer = "SP"

    regs = {
        'R0' : RegisterInfo("R0",2),
        'R1' : RegisterInfo("R0",2),
        'R2' : RegisterInfo("R2",2),
        'R3' : RegisterInfo("R3",2),
        'R4' : RegisterInfo("R4",2),
        'R5' : RegisterInfo("R5",2),
        'R6' : RegisterInfo("R6",2),
        'R7' : RegisterInfo("R7",2),
        'R8' : RegisterInfo("R8",2),
        'R9' : RegisterInfo("R9",2),
        'FP' : RegisterInfo("FP",2),
        'SP' : RegisterInfo("SP",2),
        'RA' : RegisterInfo("RA",2),
        'RD' : RegisterInfo("RD",2),
        'PC' : RegisterInfo("PC",2),
        'DPC' : RegisterInfo("DPC",2),
    }

    flags = ['zf','sf','pf','cf','vf','mf']
    flag_roles = {
        'zf' : FlagRole.ZeroFlagRole,
        'sf' : FlagRole.NegativeSignFlagRole,
        'pf' : FlagRole.EvenParityFlagRole,
        'cf' : FlagRole.CarryFlagRole,
        'vf' : FlagRole.OverflowFlagRole,
        'mf' : FlagRole.SpecialFlagRole
    }

    def get_bytes(self):
        if SKIP_VAL == 0x64:
            file_data = open("/home/chris/ctfs/sunshine22/peg/binary_2.peg","rb").read()
        elif SKIP_VAL == 0x40:
            file_data = open("/home/chris/ctfs/sunshine22/peg/binary_1.peg","rb").read()
        else:
            file_data = open("/home/chris/ctfs/sunshine22/peg/binary_0.peg","rb").read()
        return file_data
    #     while not self.disassembler.update_bv():
    #         pass
    #     return self.disassembler.bv.read(addr,SKIP_VAL*4)    

    def __init__(self):
        super().__init__()
        self.disassembler = EARdisassembler(SKIP_VAL)

    def get_instruction_info(self,data,addr):
        # data = self.get_bytes(addr)
        # print("fd",self.file_data)
        # print("d",data)
        # i = self.file_data.index(data)
        # data = self.file_data[i:]
        data = data[::SKIP_VAL]
        result = InstructionInfo()
        size, _, cond = self.disassembler.disasm(data,addr)
        result.length = size*SKIP_VAL
        for c in cond:
            if c[1] is not None:
                result.add_branch(c[0],c[1])
            else:
                result.add_branch(c[0])
        return result
    
    def get_instruction_text(self, data, addr):
        # data = self.get_bytes(addr)
        # i = self.file_data.index(data)
        # data = self.file_data[i:]
        data = data[::SKIP_VAL]
        try:
            size, tokens, cond = self.disassembler.disasm(data,addr)
        except:
            tokens = []
            size = 2
        return tokens,size*SKIP_VAL

    def get_instruction_low_level_il(self,data,addr,il):
        return il.unimplemented()
