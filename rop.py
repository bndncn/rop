from capstone import *
import sys

md = Cs(CS_ARCH_X86, CS_MODE_32)

seen_instructions = set()

class Gadget:
    def __init__(self, mnemonic, op_str, start_addr, end_addr):
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.start_addr = start_addr
        self.end_addr = end_addr

def get_gadgets(binaries):
    for binary in binaries:
        print('Processing file: ' + binary)
        with open(binary, 'rb') as f:
            instructions = b''
            address = 0x0
            while True:
                curr_byte = f.read(1)
                if not curr_byte:
                    break
                instructions += curr_byte
                if curr_byte == b'\xc3':  
                    for i in md.disasm(instructions, address):
                        print ('0x%x:\t%s\t%s' %(i.address, i.mnemonic, i.op_str))
                        address = i.address + 1
                    instructions = b''

get_gadgets(sys.argv[1:])