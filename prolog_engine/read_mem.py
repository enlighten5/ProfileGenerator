import mmap, struct, os, sys
from time import gmtime, strftime
import LinuxMemory as linux

offset = [
    (0, 1208, 655360),
    (655360, 656568, 65536),
    (786432, 722104, 536084480),
    (786432, 722104, 536084480),
    (4294705152, 553583800, 262144)
]

def log(message):
    print('%s\t%s' %(strftime("%Y-%m-%d %H:%M:%S", gmtime()), message))
    sys.stdout.flush()

class AddressSpace(linux.AMD64PagedMemory):
    def __init__(self, mem_path, dtb = 0):
        try:
            f = os.open(mem_path, os.O_RDONLY)
        except:
            print "Error: open image failed.\n"
            sys.exit(1)

        try:
            self.mem = mmap.mmap(f, 0, mmap.MAP_PRIVATE, mmap.PROT_READ)
        except:
            print "Error mmap\m"
            sys.exit(1)

        self.offset = offset
        self.mem.seek(0)
        if "ELF" in self.mem.read(6):
            self.has_elf_header = True
        else:
            self.has_elf_header = False

        vdtb_idx = self.mem.find("SYMBOL(swapper_pg_dir)=") + len("SYMBOL(swapper_pg_dir)=")
        self.mem.seek(vdtb_idx)
        dtb_vaddr = "0x" + self.mem.read(16)
        
        self.dtb_vaddr = dtb_vaddr
        self.dtb = dtb
        if dtb:
            self.dtb = dtb
        else:
            self.find_dtb(0x1000000)

    def translate(self, addr):
        for input_addr, output_addr, length in self.offset:
            if addr >= input_addr and addr < input_addr + length:
                return output_addr + (addr - input_addr)
            if addr < input_addr:
                return None

        return None
    def read_memory(self, paddr, length):
        if self.has_elf_header :
            paddr = self.translate(paddr)
            if not paddr:
                #print "Error: translate failed.\n"
                return None
                #sys.exit(1)
        if self.mem.size() - paddr < length:
            print "Error: read out of bound memory.\n"
            sys.exit(1)

        self.mem.seek(paddr)
        value = self.mem.read(length)
        if not value:
            print "Error: fail to read memory at", hex(paddr)
            sys.exit(1)
        return value

    def find_dtb(self, start_addr = 0x3809000):
        '''
        This method generates a list of pages that are
        available within the address space. The entries in
        are composed of the virtual address of the page
        and the size of the particular page (address, size).
        It walks the 0x1000/0x8 (0x200) entries in each Page Map,
        Page Directory, and Page Table to determine which pages
        are accessible.
        '''
        log("find dtb")
        for step in range(0, self.mem.size() - start_addr, 4096):
            # read the full pml4
            pml4 = self.read_memory(start_addr+step & 0xffffffffff000, 0x200 * 8)
            #print "read pml4", hex(start_addr+step)
            if pml4 is None:
                continue

            # unpack all entries
            pml4_entries = struct.unpack('<512Q', pml4)
            for key in pml4_entries:
                if key == 0:
                    continue
                if not bin(key & 0b111111111111) == '0b1100111':
                    continue
                if len(bin(key)) > 32 or len(bin(key)) < 25:
                    continue
                #print bin(key), hex(key), hex(start_addr+step)
            
            for pml4e in range(0, 0x200):
                pml4e_value = pml4_entries[pml4e]
                if not self.entry_present(pml4e_value):
                    continue
                if not bin(pml4e_value & 0b111111111111) == '0b1100111':
                    continue
                if len(bin(pml4e_value)) > 32 or len(bin(pml4e_value)) < 25:
                    continue

                pdpt_base = (pml4e_value & 0xffffffffff000)
                #print "read pdpt_base", pdpt_base
                pdpt = self.read_memory(pdpt_base, 0x200 * 8)
                if pdpt is None:
                    continue
                pdpt_entries = struct.unpack('<512Q', pdpt)
                for pdpte in range(0, 0x200):
                    vaddr = (pml4e << 39) | (pdpte << 30)
                    pdpte_value = pdpt_entries[pdpte]
                    if not self.entry_present(pdpte_value):
                        continue

                    if self.page_size_flag(pdpte_value):
                        if self.maybe_vtop(self.dtb_vaddr, start_addr+step):
                            log("found dtb " + hex(start_addr+step))
                            self.dtb = start_addr + step
                            return start_addr + step
                        continue
                    #print "pdpte_value", hex(pdpte_value)
                    pd_base = self.pdba_base(pdpte_value)
                    #print "read pd_base", pd_base
                    pd = self.read_memory(pd_base, 0x200 * 8)
                    if pd is None:
                        continue
                    pd_entries = struct.unpack('<512Q', pd)
                    for key in pd_entries:
                        if key == 0:
                            continue
                        #print bin(key), hex(key)
                    prev_pd_entry = None
                    for j in range(0, 0x200):
                        soffset = (j * 0x200 * 0x200 * 8)

                        entry = pd_entries[j]
                        
                        if self.skip_duplicate_entries and entry == prev_pd_entry:
                            continue
                        prev_pd_entry = entry
                        if self.entry_present(entry) and self.page_size_flag(entry):
                            if self.maybe_vtop(self.dtb_vaddr, start_addr+step):
                                log("found dtb " + hex(start_addr+step))
                                self.dtb = start_addr + step
                                return start_addr + step

                        elif self.entry_present(entry):
                            pt_base = entry & 0xFFFFFFFFFF000
                            pt = self.read_memory(pt_base, 0x200 * 8)
                            if pt is None:
                                continue
                            pt_entries = struct.unpack('<512Q', pt)
                            prev_pt_entry = None
                            for k in range(0, 0x200):
                                pt_entry = pt_entries[k]
                                if self.skip_duplicate_entries and pt_entry == prev_pt_entry:
                                    continue
                                prev_pt_entry = pt_entry

                                if self.entry_present(pt_entry):
                                    if self.maybe_vtop(self.dtb_vaddr, start_addr+step):
                                        log("found dtb " + hex(start_addr+step))
                                        self.dtb = start_addr + step
                                        return start_addr + step
        if self.dtb == 0:
            print "fail to find dtb.\n"
        return 0

    
def test():
    try:
        f = os.open(sys.argv[1], os.O_RDONLY)
    except:
        print "Error: fopen.\n"
        sys.exit(1)

    try:
        mem = mmap.mmap(f, 0, mmap.MAP_PRIVATE, mmap.PROT_READ)
    except:
        print "Error mmap\m"
        sys.exit(1)
    
    for addr in range(0, mem.size(), 4096):
        mem.seek(addr)
        content = mem.read(8)
        value = struct.unpack("<Q", content)[0]
        #print hex(value)

    mem.seek(0x160d3b8)
    content = mem.read(4096)
    value = struct.unpack("<4096c", content)

    for idx in range(0, len(value), 8):
        pass
#        print value[idx: idx+8]
    mem.seek(0)
    content = mem.read(6)
    print content
    for addr in range(0, mem.size(), 4096):
        mem.seek(addr)
        content = mem.read(4096)
        if len(content) < 4096:
            break
        value = struct.unpack("<512Q", content)
        for item in value:
            if value == 536084480:
                print addr

    mem.close()   
def main():

    if len(sys.argv) < 2:
        print "Error: please specify memory path and dtb_vaddr.\n"
        sys.exit(1)
    mem_path = sys.argv[1]
    addr_space = AddressSpace(mem_path)
    print addr_space.vtop(0xffffffffacc09000)
    
    

    pass

if __name__ == "__main__":
    main()