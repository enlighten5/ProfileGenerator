import read_mem as rm
from program import *
import struct

class KernelSymbol(rm.AddressSpace):
    def __init__(self, image_path):
        rm.AddressSpace.__init__(self, image_path, 0)

    def find_symtable(self, start_addr = 0x100000):
        self.log("find symtable")
        for step in range(0, self.mem.size() - start_addr, 8):
            # read the full pml4
            value = self.read_memory(start_addr+step, 8)
            if not value:
                continue
            if "init_tas" in value:
                print "found init_task at", hex(start_addr + step), value
                return start_addr + step

    
            



def main():
    content = struct.unpack('<9c', "init_task")
    print content
    ks = KernelSymbol(sys.argv[1])
    ks.find_symtable()

if __name__ == "__main__":
    main()

