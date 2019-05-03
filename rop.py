from capstone import *
import sys

md = Cs(CS_ARCH_X86, CS_MODE_32)

with open(sys.argv[1], 'rb') as f:
   instructions = ''
   while True:
      curr_byte = f.read(1)
      if not curr_byte:
         break
      instructions += curr_byte
      if curr_byte == '\xc3':          
         for i in md.disasm(curr, 0x1000):           
            print "0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str)
         instructions = ''
