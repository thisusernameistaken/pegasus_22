from binaryninja import (
    Architecture,
    RegisterInfo,
    InstructionInfo,
    InstructionTextToken,
    InstructionTextTokenType
)
from binaryninja.enums import (
    FlagRole,
    Endianness
)

class EAR(Architecture):
    name = "ear"

    default_int_size = 2
    address_size = 2
    max_instr_length = 6

    endianness = Endianness.LittleEndian
    stack_pointer = "SP"
    
    regs = {
        'R0' : RegisterInfo("R0",2),
        'R1' : RegisterInfo("R1",2),
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

    def __init__(self):
        super().__init__()

    def get_instruction_info(self,data,addr):
        return InstructionInfo(1)
    
    def get_instruction_text(self, data, addr):
        return InstructionTextToken(InstructionTextTokenType.TextToken,"HI"),1
