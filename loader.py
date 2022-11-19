from optparse import Values
from binaryninja import (
    BinaryView, 
    BinaryReader,
    Architecture,
    Type
)
from binaryninja.enums import(
    SegmentFlag,
    SectionSemantics
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


        magic = self.br.read(8)
        arch = self.br.read32()
        cmd_count = self.br.read16()
        print("CMD_COUNT",cmd_count)
        #do pegasus cmd
        for _ in range(cmd_count):
            data_start = self.br.offset
            cmd_type = self.br.read16()
            cmd_size = self.br.read16()
            print("st",hex(data_start))
            sz = cmd_size-4
            cmd_data = self.br.read(sz)
            self.br.seek_relative(-sz)
            print("CMD_TYPE", cmd_type)
            if PEG_TYPE(cmd_type) == PEG_TYPE.PEG_SEGMENT:
                name = get_lestring(cmd_data)
                print(name)
                self.br.read(len(name))
                mem_vppn = self.br.read8()
                print(mem_vppn)
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
                print("ADDING SEG")
                print("start",hex(mem_start))
                print("len",hex(mem_length))
                print("mem_off",hex(mem_foff))
                print("mem lenb",hex(mem_fsize))
                print("arch",self.arch)
                print("plat",self.platform)
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
                regs = ['rv','r3','r4','r5','r6','r7','pc','dpc']
                self.init_vals = {}
                for reg in regs:
                    self.init_vals[reg] = self.br.read16()
                self.entry_point = self.init_vals['pc']
                self.add_entry_point(self.entry_point)
                self.add_function(self.entry_point)
            elif PEG_TYPE(cmd_type) == PEG_TYPE.PEG_SYMTAB:
                sym_count = self.br.read16()
                for _ in range(sym_count):
                    sym_start = self.br.offset
                    name = get_lestring(cmd_data)
                    print(name)
                    self.br.read(len(name))
                    val = self.br.read16()
                    sym_struct = f"""
                        struct {{
                            lestring name[{len(name)}];
                            uint16_t val;
                        }};
                    """
                    sym_t, sym_name = self.parse_type_string(sym_struct)
                    self.define_type(Type.generate_auto_type_id("pegasus",str(sym_name)),sym_name,sym_t)
                    self.define_data_var(sym_start,sym_t)
                return True
            elif PEG_TYPE(cmd_type) == PEG_TYPE.PEG_RELTAB:
                reloc_count = self.br.read16()

        self.entry_addr = 0
        

        return True