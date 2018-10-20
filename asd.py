#!/usr/bin/python
#
# below dependencies are required:
# https://github.com/williballenthin/python-idb
# sudo apt-get install libcapstone3
# sudo apt-get install libcapstone-dev
#
import idb
import sys
import os
import re
from capstone import *

BCC = ["je", "jne", "js", "jns", "jp", "jnp", "jo", "jno", "jl", "jle", "jg",
       "jge", "jb", "jbe", "ja", "jae", "jcxz", "jecxz", "jrcxz", "loop", "loopne",
       "loope", "call", "lcall"]
END = ["ret", "retn", "retf", "iret", "int3"]
BNC = ["jmp", "jmpf", "ljmp"]

def GetTextBase(file_name):
    os.system('readelf -S ' + file_name + ' | grep .text > ' + file_name + '.temp')
    with open(file_name + '.temp') as f:
        tmp = f.read()
    text_base = int(re.findall('\ [0-9a-fA-F]+', tmp)[0], 16)
    tmp = int(re.findall('\ [0-9a-fA-F]+', tmp)[1], 16)
    os.system('rm ' + file_name + '.temp')
    return text_base - tmp

def GetFunctions(file_name):
    functions = []
    with idb.from_file(file_name + '.idb') as db:
        api = idb.IDAPython(db)
    for entry_point in api.idautils.Functions():
        exit_point = idb.analysis.Functions(db).functions[entry_point].endEA
        functions.append((entry_point, exit_point, api.idc.GetFunctionName(entry_point)))
    return functions

def ConvertAddrtoOffset(functions, text_base):
    offsets = []
    for entry_point, exit_point, function_name in functions:
        offsets.append((entry_point - text_base, exit_point - text_base, function_name))
    return offsets

def ViewFunctions(functions):
    for entry_point, exit_point, function_name in functions:
        print '%x-%x: %s()' % (entry_point, exit_point, function_name)

def GetAddrofMemroyAccess(file_name):
    with open(file_name, "rb") as f:
        file_data = f.read()
    memory_access = []
    for entry_point, exit_point, function_name in functions:
        code = file_data[entry_point:exit_point]
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for i in md.disasm(code, entry_point):
            tmp = re.findall('\[.+\]', i.op_str)
            if len(tmp) != 0:
                if ('rip' not in tmp[0]):
                    memory_access.append((i.address, exit_point))
    return memory_access

def Disassemble(file_name, entry_point, exit_point):
    with open(file_name, "rb") as f:
        file_data = f.read()
    end = entry_point + 5
    if (end > exit_point):
        end = exit_point
    code = file_data[entry_point:exit_point]
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in md.disasm(code, entry_point):
        #tmp = re.findall('\[.+\]', i.op_str)
        #if len(tmp) != 0:
        #    if ('rip' not in tmp[0]):
        print "0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str)
        if (i.address > end):
            break

if __name__ == '__main__':
    file_name = sys.argv[1]
    text_base = GetTextBase(file_name)
    print 'text_base: ' + hex(text_base)
    functions = GetFunctions(file_name)
    functions = ConvertAddrtoOffset(functions, text_base)
    ViewFunctions(functions)
    memory_access = GetAddrofMemroyAccess(file_name)
    for entry_point, exit_point in memory_access:
        print 'entry_point: ' + hex(entry_point)
        Disassemble(file_name, entry_point, exit_point)
        print ''
