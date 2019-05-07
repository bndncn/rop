from capstone import *
from elftools.elf.elffile import ELFFile
from unicorn import *
from unicorn.x86_const import *

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
    def __init__(self, gadget, parent):
        self.gadget = gadget
        self.children = {}
        self.parent = parent


def insert(root, gadget):
    gadget_node = TrieNode(gadget, root)

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


def print_trie(root, gadgets, depth):
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
                print_trie(node, gadgets, depth + 1)
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
            build_from(root, code, pos, text_section_start_addr + pos)


def build_from(parent_insn, code, pos, parent_instr_addr):
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

            gadget_node = insert(parent_insn, gadget)
            # recurse building gadgets from this node backwards, similar to how building gadgets from ret works
            build_from(gadget_node, code, start_index, instruction.address)


def test_trie():
    ret_gadget = Gadget('ret', '', -1, -1, b'\xc3')
    root = TrieNode(ret_gadget, None)

    # code = b'\x55\x48\x8b\x05\xb8\x13\xc3\x90\x92\x27\xa3'
    # code = b"\x04\x04\x02\x02\xc3"
    # code = b"\x04\x04\x02\x02\xc3"
    # code = b"\x04\x04\x02\x02\xC3\x87\x12\xAA\xC3"
    # code = b"\x31\xC0\xC3\x40\xC3\xCD\x80\x58\x83\xC3\x15\xC3\x5B\x59\xC3\x5A\xB8\x0B\x00\x00\x00\xC3"
    code = b"\x53\x83\xEC\x08\xE8\xD3\xFC\xFF\xFF\x81\xC3\xB3\x2B\x00\x00\x83\xC4\x08\x5B\xC3"
    populate_trie(root, code, 0)
    print_trie(root, [], 0)


def get_gadgets(binaries):
    ret_gadget = Gadget('ret', '', -1, -1, b'\xc3')
    root = TrieNode(ret_gadget, None)

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
            populate_trie(root, code, text_section_start_addr)

    return root

# Need to set:
# eax = 0x7D (125)
# ebx = Address of Memory to change (Must align to page boundary)
# ecx = Length of memory to change
# edx = 0x07
registers = {'eax': 0x7B, 'ebx': 0xbffdf000, 'ecx': 0x00021000, 'edx': 0x7}
EIP_ADDRESS = 0x400000
STACK_ADDRESS = 0x0

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

def regs_done(curr_state):
    return registers

# Do a BFS on root to find useful gadgets
def create_payload(root, registers_state, base_addr):
    queue = collections.deque()
    queue.append(root)

    payload = ''
    temp = '' # In case the remaining gadgets are bad
    curr_state = {'eax': 0x7B, 'ebx': 0xbffdf000, 'ecx': 0x00021000, 'edx': 0x7} # In case the remaining gadgets are bad

    mu = Uc(UC_ARCH_X86, UC_MODE_32)
    mu.mem_map(EIP_ADDRESS, 2 * 1024 * 1024)
    mu.mem_map(STACK_ADDRESS, 1024 * 1024)
    
    #mu.reg_write(UC_X86_REG_EBX, 0x0)
    #mu.reg_write(UC_X86_REG_RSP, STACK_ADDRESS + 1024 * 1024 - 1)

    while queue:
        if registers == registers_state:
            return payload

        node = queue.popleft()

        gadget_addr = node.gadget.start_addr

        instruction = node.gadget.mnemonic + ' ' + node.gadget.op_str

        bad = False

        print(node.gadget.mnemonic)
        try:
            # Process node
            if node.gadget.mnemonic == 'pop':
                temp += struct.pack("<I", gadget_addr)  
                print(temp)
                # Pop one of eax, ebx, ecx, or edx
                if node.gadget.op_str in registers:
                    print(temp)
                    temp += struct.pack("<I", registers[node.gadget.op_str])
                    curr_state[node.gadget.op_str] = registers[node.gadget.op_str]
                else:
                    temp += struct.pack("<I", 0x12341234) # Add random junk for useless pop
            
            elif node.gadget.mnemonic == 'xor' and re.search('xor (e\S+), (e\S+)', instruction):
                reg1, reg2 = re.search('xor (e\S+), (e\S+)', instruction).groups()
                
                # Zero out one of eax, ebx, ecx, or edx
                if reg1 == reg2 and reg1 in registers:
                    pass
                else:
                    pass
                
            # Add the current node's children into the queue
            for mnemonic in node.children:
                for child in node.children[mnemonic]:
                    queue.append(child)
            
            # Process all of the parent nodes before the lower levels    
            if node.parent is not None and not bad:
                queue.appendleft(node.parent)
                continue
            else:
                # We've reached ret or hit a bad instruction
                payload += temp
                registers_state = curr_state
                temp = ''
        
        except UcError as e:
            # For invalid memory operations
            temp = ''
            curr_state = registers_state 
        
            #mu.emu_start(EIP_ADDRESS, EIP_ADDRESS + len(node.gadget.code))

            
            #r_ebx = mu.reg_read(UC_X86_REG_EBX)
            #print(">>> EBX = 0x%x" %r_ebx)
        
        return payload


if (len(sys.argv) > 1):
    registers_state = {'eax': 0x11112222, 'ebx': 0x11112222, 'ecx': 0x11112222, 'edx': 0x11112222}
    print(create_payload(get_gadgets(sys.argv[1:]), registers_state, 0x0))
    #root = get_gadgets(sys.argv[1:])
    #print_trie(root, [], 0)
else:
    test_trie()
