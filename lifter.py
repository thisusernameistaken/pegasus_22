from binaryninja import ILRegister, Architecture, InstructionTextTokenType, LowLevelILLabel
from .disassembly import *

# Add from rondo vmmod
def add(data, addr, il, disas):
    tokens = disas[0]
    dest = tokens[2]
    source = tokens[4]
    if source.type == InstructionTextTokenType.RegisterToken:
        expr = il.add(2,il.reg(2,dest.text),il.reg(2,source.text))
    else:
        expr = il.add(2,il.reg(2,dest.text),il.const(2,source.value))
    il.append(il.set_reg(2,dest.text,expr))
    return disas[1]   

def sub(data, addr, il, disas):
    pass

def mlu(data, addr, il, disas):
    pass

def mls(data, addr, il, disas):
    pass

def dvu(data, addr, il, disas):
    pass

def dvs(data, addr, il, disas):
    pass

def xor(data, addr, il, disas):
    pass

def f_and(data, addr, il, disas):
    pass

def orr(data, addr, il, disas):
    pass

def shl(data, addr, il, disas):
    pass

def sru(data, addr, il, disas):
    pass

def srs(data, addr, il, disas):
    pass

def mov(data, addr, il, disas):
    pass

def cmp(data, addr, il, disas):
    pass

def ldw(data, addr, il, disas):
    pass

def stw(data, addr, il, disas):
    pass

def ldb(data, addr, il, disas):
    pass

def stb(data, addr, il, disas):
    pass

def bra(data, addr, il, disas):
    pass

def brr(data, addr, il, disas):
    pass

def fca(data, addr, il, disas):
    pass

def fcr(data, addr, il, disas):
    pass

def rdb(data, addr, il, disas):
    pass

def wrb(data, addr, il, disas):
    pass

def psh(data, addr, il, disas):
    pass

def pop(data, addr, il, disas):
    pass

def inc(data, addr, il, disas):
    pass

def bpt(data, addr, il, disas):
    pass

def hlt(data, addr, il, disas):
    pass

def nop(data, addr, il, disas):
    il.append(il.nop)

class PEGASUSlifter:
    opcodes = {
        0 : add,
        1 : sub,
        2 : mlu,
        3 : mls,
        4 : dvu,
        5 : dvs,
        6 : xor,
        7 : f_and,
        8 : orr,
        9 : shl,
        0xa: sru,
        0xb: srs,
        0xc: mov,
        0xd: cmp,
        0xe: None,
        0xf: None,
        0x10: ldw,
        0x11: stw,
        0x12: ldb,
        0x13: stb,
        0x14: bra,
        0x15: brr,
        0x16: fca,
        0x17: fcr,
        0x18: rdb,
        0x19: wrb,
        0x1a: psh,
        0x1b: pop,
        0x1c: inc,
        0x1d: bpt,
        0x1e: hlt,
        0x1f: nop
    }