from optparse import Values
from binaryninja import (
    BinaryView, 
    BinaryReader,
    Architecture,
    Type,
    IntegerType,
    StructureBuilder,
    Symbol,
)
from binaryninja.enums import(
    SegmentFlag,
    SectionSemantics,
    SymbolType
)

from .helpers import (
    PEG_TYPE, 
    get_lestring, 
    peg_header_struct,
    peg_type_struct,
    lestring_def
)

class PEGASUS(BinaryView):
    name = "PEGASUS"
    long_name = "PEGASUS File Format"

    def __init__(self,data):
        BinaryView.__init__(self,file_metadata=data.file,parent_view=data)
        self.raw = data
        self.br = BinaryReader(data)

    @classmethod
    def is_valid_for_data(cls,data):
        magic = BinaryReader(data).read(8)
        if magic == b"\x7fPEGASUS":
            return True
        return False

    def init(self):
        self.platform = Architecture['ear'].standalone_platform
        self.arch = Architecture['ear']

        self.init_vals = {}
       
        # define header struct and enums
        header_t , header_name = self.parse_type_string(peg_header_struct)
        self.define_type(Type.generate_auto_type_id("pegasus",str(header_name)),header_name,header_t)
        self.define_data_var(0,header_t,str(header_name))
        
        cmd_enum_t , cmd_enum = self.parse_type_string(peg_type_struct)
        self.define_type(Type.generate_auto_type_id("pegasus",str(cmd_enum)),cmd_enum,cmd_enum_t)

        lestring_t , lestring_name = self.parse_type_string(lestring_def)
        self.define_type(Type.generate_auto_type_id("pegasus",str(lestring_name)),lestring_name,lestring_t)

        # global string tracking
        self.session_data['strings'] = {}

        magic = self.br.read(8)
        arch = self.br.read32()
        cmd_count = self.br.read16()
        #do pegasus cmd
        for _ in range(cmd_count):
            data_start = self.br.offset
            cmd_type = self.br.read16()
            cmd_size = self.br.read16()
            sz = cmd_size-4
            cmd_data = self.br.read(sz)
            self.br.seek_relative(-sz)
            if PEG_TYPE(cmd_type) == PEG_TYPE.PEG_SEGMENT:
                name = get_lestring(cmd_data)
                self.session_data['strings'][self.br.offset] = name
                self.br.read(len(name))
                mem_vppn = self.br.read8()
                mem_start = mem_vppn*0x100
                mem_vpage_count = self.br.read8()
                mem_length = mem_vpage_count*0x100
                mem_foff = self.br.read16()
                mem_fsize = self.br.read16()
                mem_prot = self.br.read8()
                perms = 0
                sem = 0
                if mem_prot & 1 != 0:
                    perms |= SegmentFlag.SegmentReadable
                if mem_prot & 2 != 0:
                    perms |= SegmentFlag.SegmentWritable
                if mem_prot & 4 != 0:
                    perms |= SegmentFlag.SegmentExecutable
                if name == b"@TEXT":
                    perms |= SegmentFlag.SegmentContainsCode
                    sem = SectionSemantics.ReadOnlyCodeSectionSemantics
                    #i guess we know where header ends
                    self.add_auto_segment(0,mem_foff,0,mem_foff,SegmentFlag.SegmentReadable)
                    self.add_auto_section("@HEAD",0,mem_foff,SectionSemantics.ReadOnlyDataSectionSemantics)
                self.add_auto_segment(mem_start,mem_length,mem_foff,mem_fsize,perms)
                self.add_auto_section(name,mem_start,mem_length,sem)
                struct = f"""
                    struct __packed{{
                        PEG_TYPE cmd_type;
                        uint16_t cmd_size;
                        lestring name[{len(name)}];
                        uint8_t memvppn;
                        uint8_t mem_vpage_count;
                        uint16_t mem_foff;
                        uint16_t mem_fsize;
                        uint8_t mem_prot;
                    }}
                """
                data_t, data_name = self.parse_type_string(struct)
                self.define_type(Type.generate_auto_type_id("pegasus",str(data_name)),data_name,data_t)
                self.define_data_var(data_start,data_t)
            elif PEG_TYPE(cmd_type) == PEG_TYPE.PEG_ENTRY:
                entry_start = self.br.offset-4
                entry_struct = StructureBuilder.create()
                entry_struct.packed = True
                entry_struct.append(cmd_enum_t,"cmd_type")
                entry_struct.append(IntegerType.create(2),"cmd_size")
                regs = ['rv','r3','r4','r5','r6','r7','pc','dpc']
                self.init_vals = {}
                for reg in regs:
                    self.init_vals[reg] = self.br.read16()
                    entry_struct.append(IntegerType.create(2,False),reg)
                self.entry = self.init_vals['pc']
                self.add_entry_point(self.entry)
                self.add_function(self.entry)
                self.define_data_var(entry_start,entry_struct)
            elif PEG_TYPE(cmd_type) == PEG_TYPE.PEG_SYMTAB:
                sym_start = self.br.offset-4
                sym_table_struct = StructureBuilder.create()
                sym_table_struct.packed = True
                sym_table_struct.append(cmd_enum_t,"cmd_type")
                sym_table_struct.append(IntegerType.create(2),"cmd_size")
                sym_table_struct.append(IntegerType.create(2),"sym_count")
                sym_count = self.br.read16()
                cmd_data = cmd_data[2:]
                for _ in range(sym_count):
                    name = get_lestring(cmd_data)
                    self.session_data['strings'][self.br.offset] = name
                    self.br.read(len(name))
                    val = self.br.read16()
                    self.add_function(val)
                    f_sym = Symbol(SymbolType.FunctionSymbol,val,name)
                    self.define_auto_symbol(f_sym)
                    sym_struct = f"""
                        struct __packed {{
                            lestring name[{len(name)}];
                            uint16_t val;
                        }};
                    """
                    sym_t, sym_name = self.parse_type_string(sym_struct)
                    self.define_type(Type.generate_auto_type_id("pegasus",str(sym_name)),sym_name,sym_t)
                    sym_table_struct.append(sym_t)
                    cmd_data = cmd_data[len(name)+2:]
                self.define_data_var(sym_start,sym_table_struct)
            elif PEG_TYPE(cmd_type) == PEG_TYPE.PEG_RELTAB:
                reloc_count = self.br.read16()
                #TODO
        self.entry_addr = 0
        

        return True