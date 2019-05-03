from capstone import *
import sys

md = Cs(CS_ARCH_X86, CS_MODE_32)

class Gadget:
    def __init__(self, mnemonic, op_str, start_addr, end_addr):
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.start_addr = start_addr
        self.end_addr = end_addr

    def __str__(self):
        return '0x%x:\t0x%x:\t%s\t%s' % (self.start_addr, self.end_addr, self.mnemonic, self.op_str)

def get_gadgets(binaries):
    seen_instructions = set() # Avoid duplicated instructions
    mnemonic_to_gadget = {}
    address_to_gadget = {}

    for binary in binaries:
        print('Processing file: ' + binary)
        with open(binary, 'rb') as f:
            instructions = b''
            start_addr = 0x0
            end_addr = 0x0
            while True:
                curr_byte = f.read(1)
                if not curr_byte:
                    break
                instructions += curr_byte
                end_addr += 1
                if curr_byte == b'\xc3':  
                    for i in md.disasm(instructions, start_addr):
                        if (i.mnemonic + ' ' + i.op_str) not in seen_instructions:
                            gadget = Gadget(i.mnemonic, i.op_str, start_addr, end_addr)
                            seen_instructions.add(i.mnemonic + ' ' + i.op_str)
                            
                            if i.mnemonic not in mnemonic_to_gadget:
                                mnemonic_to_gadget[i.mnemonic] = []

                            mnemonic_to_gadget[i.mnemonic].append(gadget)

                            address_to_gadget[start_addr] = gadget              
                    
                        start_addr = i.address + 1
                    instructions = b''
    
    return mnemonic_to_gadget, address_to_gadget # Return 2 dictionaries

mnemonic_to_gadget, address_to_gadget = get_gadgets(sys.argv[1:])

for k, v in address_to_gadget.items():
    print(str(hex(k)), end=' ')
    print(v)