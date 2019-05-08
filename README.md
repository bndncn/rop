# rop.py - Return Oriented Programming Payload Generator

Setup: 
This tool requires 'captstone' and 'pyelftools' to be installed, which can be done with:
pip install capstone pyelftools
This tool is also written using python 3.7.

pyelftools is used to retrieve the .text sections of provided binaries, and capstone is used for disassembling the retrieved bytes. 

Usage:
To use rop.py, please run 'python3 rop.py' with at least the --binary option, with arguments for space delimited binaries you wish to pool gadgets from, so long as they are used together with the exploitable binary. 

rop.py may also be run with --gadgets option, which will print out the gadgets found along with their offset in memory. To create a payload with precalculated addresses that will be plug and play, use the --offset option with a hex value so the base address need not be added to each gadget offset manually. 

This payload's goal is to bypass NX stacks by using the mprotect() syscall to set the stack as executable, allowing stack-resident shellcode to be directly jumped into as if compiled with -z execstack option.

It aims to set up:
eax with 0x7d, the syscall # for mprotect()
ebx with 0xbffdf000: the start address of the stack
ecx with 0x00021000: the length of the stack
edx with 0x7 for RWX option to set stack readable, writable, and most importantly executable.

As buffer overflow exploits are often a product of unbounded strcpy(), null bytes are attempted to be avoided with the rop payload.

For instance:
ebx = 0xbffdf000 and the bottom byte is '\x00', so we attempt to pass in 0xbffdf000 - 1 = 0xbffde111 and then look for a gadget that contains 'inc ebx' to fix the stack address to 0xbffdf000, its intended, 4KB page aligned value.

In addition, the stack length as ecx = 0x00021000 contains multiple null bytes, so its bitwise NOT is pushed onto the stack and 'not ecx' gadget is searched for to fix it. 

After the payload executes the stack is now executable and typical shellcode can be directly jumped into.
