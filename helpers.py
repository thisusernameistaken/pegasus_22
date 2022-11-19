from enum import Enum
from binaryninja import (
    DataRenderer, InstructionTextToken, InstructionTextTokenType,
    DisassemblyTextLine
)

peg_header_struct = """
struct Pegasus_Header __packed{
    char magic[8];
    uint32_t arch;
    uint16_t cmd_count;
};
"""

peg_type_struct = """
enum PEG_TYPE : uint16_t
{
    PEG_SEGMENT = 1,
    PEG_ENTRY = 2,
    PEG_SYMTAB = 3,
    PEG_RELTAB = 4,
};
"""

lestring_def = """
typedef char lestring;
"""

class PEG_TYPE(Enum):
    PEG_SEGMENT = 1
    PEG_ENTRY = 2
    PEG_SYMTAB = 3
    PEG_RELTAB = 4

def get_lestring(data):
    done = False
    i = 0
    string = b""
    while not done:
        b = data[i]
        c = b&127
        string += bytes([c])
        i+=1
        cont = (b&128)>>7
        if cont != 1:
            done = True
    return string

class lestring_renderer(DataRenderer):
    def __init__(self):
        DataRenderer.__init__(self)
    def perform_is_valid_for_data(self, ctxt, view, addr, type, context):
        return "lestring" in str(type)

    def perform_get_lines_for_data(self, ctxt, view, addr, type, prefix, width, context):
        if addr in view.session_data['strings'].keys():
            string = view.session_data['strings'][addr]
            prefix.append(InstructionTextToken(InstructionTextTokenType.StringToken,"\""))
            prefix.append(InstructionTextToken(InstructionTextTokenType.StringToken,string))
            prefix.append(InstructionTextToken(InstructionTextTokenType.StringToken,"\""))
        print("DID I HIT")
        return [DisassemblyTextLine(prefix, addr)]        