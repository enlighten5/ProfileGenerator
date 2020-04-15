import mmap, struct, os, sys
from time import gmtime, strftime
import LinuxMemory as linux

offset = [
    (0, 1208, 655360),
    (655360, 656568, 65536),
    (786432, 722104, 536084480),
    (4244635648, 536806584, 16777216),
    (4294705152, 553583800, 262144)
]

offset2 = [ 
    (0, 400, 816),
    (0, 1216, 655360),
    (655360, 656576, 65536),
    (786432, 722112, 536084480),
    (4244635648, 536806592, 16777216),
    (4294705152, 553583808, 262144)
]

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
            print "Error mmap\n"
            sys.exit(1)
        self.verbose = 0
        self.offset = offset2
        self.mem_path = mem_path
        self.mem.seek(0)
        
        if "ELF" in self.mem.read(6):
            #print "ELF headers"
            self.has_elf_header = True
        else:
            #print "not elf headers"
            self.has_elf_header = False

        vdtb_idx = self.mem.find("SYMBOL(swapper_pg_dir)=") + len("SYMBOL(swapper_pg_dir)=")
        if vdtb_idx:
            self.mem.seek(vdtb_idx)
            dtb_vaddr = "0x" + self.mem.read(16)
            #print "dtb_vaddr", dtb_vaddr
        else:
            dtb_vaddr = 0

        image_name = os.path.basename(mem_path)
        store_dtb = "./" + image_name + "_dtb"
        try: 
            with open(store_dtb, 'r') as fd:
                g_dtb = fd.readline()
                #print "--", g_dtb
                if g_dtb:
                    g_dtb = int(g_dtb)
                else:
                    g_dtb = None
        except IOError:
            g_dtb = None
        self.dtb_vaddr = dtb_vaddr
        self.dtb = dtb
        if dtb:
            self.dtb = dtb
        elif g_dtb:
            #print "get dtb", g_dtb
            self.dtb = g_dtb
        else:
            #self.find_dtb(0x1a000000)
            self.find_dtb(0x1000000)
            # There is another page table when searchingfrom 0x0. but not complete.
            #self.find_dtb(0x0)
            with open(store_dtb, 'w') as fd:
                fd.write(str(self.dtb))

    def parse_system_map(self, path):
        with open(path, 'r') as system_map:
            sysmap = system_map.read()
            init_task_idx = sysmap.find(" init_task")
            init_task_from_system_map = "0x" + sysmap[init_task_idx-18:init_task_idx-2]

            init_top_pgt_idx = sysmap.find(" init_top_pgt")
            if init_top_pgt_idx < 0:
                init_top_pgt_idx = sysmap.find(" init_level4_pgt")
            if init_top_pgt_idx < 0:
                print "[-] Error: cannot find init_pgt form System.map"
            init_top_pgt_from_system_map = "0x" + sysmap[init_top_pgt_idx-18:init_top_pgt_idx-2]

        self.init_task_from_system_map = init_task_from_system_map
        self.init_top_pgt_from_system_map = init_top_pgt_from_system_map
        
        #print "[-] init_task_from_system_map: {}, init_top_pgt_from_system_map: {}".format(init_task_from_system_map, init_top_pgt_from_system_map)


    def log(self, message):
        print('%s\t%s' %(strftime("%Y-%m-%d %H:%M:%S", gmtime()), message))
        sys.stdout.flush()

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
        self.log("find dtb")
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
                        #self.log("found dtb " + hex(start_addr+step))
                        if self.maybe_vtop(self.dtb_vaddr, start_addr+step) == start_addr+step:
                            self.log("found dtb " + hex(start_addr+step))
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
                            #self.log("found dtb " + hex(start_addr+step))
                            if self.maybe_vtop(self.dtb_vaddr, start_addr+step) == start_addr+step:
                                self.log("found dtb " + hex(start_addr+step))
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
                                    #self.log("found dtb " + hex(start_addr+step))
                                    if self.maybe_vtop(self.dtb_vaddr, start_addr+step) == start_addr+step:
                                        self.log("found dtb " + hex(start_addr+step))
                                        self.dtb = start_addr + step
                                        return start_addr + step
        if self.dtb == 0:
            print "fail to find dtb.\n"
        return 0

    def extract_info(self, paddr, output, size = 4096):
        valid_pointer = {}
        valid_long = {}
        valid_int = {}
        valid_stirng = {}
        content = self.read_memory(paddr, size)
        value = struct.unpack("<512Q", content)
        # There may be some potential issues about identifying long and int
        for item in range(len(value)):
            number = value[item]
            phys_addr = self.vtop(number)
            if phys_addr:
                if self.verbose:
                    pass
                    print "[-] ", item*8, hex(paddr+item*8), "pointer", hex(number), hex(self.vtop(number))
                #if phys_addr - item*8 == paddr:
                #    continue
                valid_pointer[item*8] = phys_addr
                pass
            else:
                #number = int(number)
                if number < 0xffff:
                    #print "int: ", hex(number), item*8
                    #valid_int[item*8] = number
                    if number == 0x0:
                        if self.verbose:
                            pass
                            print "[-] ", item*8, hex(paddr+item*8), "pointer", number
                        valid_pointer[item*8] = number
                        #valid_long[item*8] = number
                    else:
                        if self.verbose:
                            print "[-] ", item*8, hex(paddr+item*8), "value", number
                        valid_long[item*8] = number
                elif number < 0xffffffffffff:
                    if self.verbose:
                        pass
                        print "[-] ", item*8, hex(paddr+item*8), "unsigned long: ", hex(number)
                    valid_long[item*8] = number
                elif number == 0xffffffffffffffff:
                    pass
                else:
                    if self.verbose:
                        print "[-] offset", item*8, hex(paddr+item*8), "string: ", hex(number), content[item*8:item*8+8]
                    
                    # add for test randstruct
                    str_content = content[item*8:(item+1)*8]
                    if all( ord(c) >= 47 and ord(c) <= 122 or ord(c)==0 for c in str_content ):
                        if len(str_content.strip('\x00')) > 4:
                            if self.verbose:
                                print "[--] ", str_content
                            valid_stirng[item*8] = number


                    
        value = struct.unpack("<1024I", content)
        for idx in range(len(value)):
            number = value[idx] 
            # This value is very ad hoc
            if number < 0x7fff:
                #print "int: ", hex(number), idx*4
                valid_int[idx*4] = number
        

        
        with open(output, 'a') as output:
            keys = valid_pointer.keys()
            keys.sort()
            for key in keys:
                fact = "ispointer(" + hex(paddr) + "," + str(key) + "," + str(valid_pointer[key]) + ")." + "\n"
                output.write(fact)
            keys = valid_long.keys()
            keys.sort()
            for key in keys:
                fact = "islong(" + hex(paddr) + "," + str(key) + "," + str(valid_long[key]) + ")." + "\n"
                output.write(fact)
            keys = valid_int.keys()
            keys.sort()
            for key in keys:
                fact = "isint(" + hex(paddr) + "," + str(key) + "," + str(valid_int[key]) + ")." + "\n"
                output.write(fact)
            keys = valid_stirng.keys()
            keys.sort()
            for key in keys:
                fact = "isstring(" + hex(paddr) + "," + str(key) + "," + str(valid_stirng[key]) + ")." + "\n"
                output.write(fact)
        
        return valid_pointer

    
    def pslist(self):
        init_addr = 0x3810500
        while True:
            content = self.read_memory(init_addr + 1928, 8)
            value = struct.unpack("<Q", content)[0]
            p_next_task = self.vtop(value)
            pname = self.read_memory(p_next_task + 680, 8)
            init_addr = p_next_task - 1928
            pid = self.read_memory(init_addr + 2184, 4)
            pid = struct.unpack("<I", pid)[0]
            print "next process", pname, "at", hex(init_addr), "with pid", pid
            if init_addr == 0x3810500:
                break

    def find_comm(self):
        # This function want to find whether the shuffled offsets in task structure 
        # follow the same pattern for all task structure.
        # it goes ahead and search all pointers and save the strings it finds.

        # start from init_task
        paddr = self.vtop(0xffffffffac413740)
        valid_paddr = self.extract_info(paddr, "./tmp")
        keys = valid_paddr.keys()
        keys.sort()
        for p in keys:
            if valid_paddr[p] == 0:
                continue
            possible_comm = self.read_memory(valid_paddr[p] + 368, 8)
            content = struct.unpack("<Q", possible_comm)
            #str_content = struct.unpack("<8c", possible_comm)
            str_content = possible_comm
            if all( ord(c) >= 47 and ord(c) <= 122 or ord(c)==0 for c in str_content ):
                if len(possible_comm.strip('\x00')) > 4:
                    print "[-] task_struct at offset", p, "address", hex(valid_paddr[p]), "comm\t", possible_comm
            
            #if content[0] < struct.unpack("<Q", "zzzzzzzz")[0]:
            #    if content[0] > 0:
            #        print "[---] task_struct at offset", p, "address", hex(valid_paddr[p]), "comm\t", possible_comm

            
            possible_comm = self.read_memory(valid_paddr[p] + 368-p, 8)
            content = struct.unpack("<Q", possible_comm)
            str_content = struct.unpack("<8c", possible_comm)
            if all( ord(c) >= 47 and ord(c) <= 122 or ord(c)==0 for c in str_content ):
                if len(possible_comm.strip('\x00')) > 4:
                    pass
                    print "[-] list_head at", p, "pointer", hex(valid_paddr[p]), "comm\t", possible_comm
            if "systemd" in possible_comm:
                systemd_init = valid_paddr[p] - p
                print "[--] init_addr for systemd:", hex(valid_paddr[p] - p), str_content

        print "[--------------------------------------------------]"
        valid_paddr = self.extract_info(systemd_init, "./tmp")
        keys = valid_paddr.keys()
        keys.sort()
        for p in keys:
            if valid_paddr[p] == 0:
                continue
            possible_comm = self.read_memory(valid_paddr[p] + 368, 8)
            content = struct.unpack("<Q", possible_comm)
            str_content = struct.unpack("<8c", possible_comm)
            if all( ord(c) >= 47 and ord(c) <= 122 or ord(c)==0 for c in str_content ):
                if len(possible_comm.strip('\x00')) > 4:
                    print "[-] task_struct at offset", p, "address", hex(valid_paddr[p]), "comm\t", possible_comm
                    

            #if content[0] < struct.unpack("<Q", "zzzzzzzz")[0]:
            #    if content[0] > 0:
            #        print "[---] task_struct at offset", p, "address", hex(valid_paddr[p]), "comm\t", possible_comm
            #        print "[---] ", str_content
            possible_comm = self.read_memory(valid_paddr[p] + 368-p, 8)
            content = struct.unpack("<Q", possible_comm)
            str_content = struct.unpack("<8c", possible_comm)
            if all( ord(c) >= 47 and ord(c) <= 122 or ord(c)==0 for c in str_content ):
                if len(possible_comm.strip('\x00')) > 4:
                    print "[-] list_head at", p, "pointer", hex(valid_paddr[p]), "comm\t", possible_comm

            if "kthreadd" in possible_comm:
                kthreadd_init = valid_paddr[p] - p
                #print "[--] init_addr for systemd:", hex(valid_paddr[p] - p)

        print "[--------------------------------------------------]"
        valid_paddr = self.extract_info(kthreadd_init, "./tmp")
        keys = valid_paddr.keys()
        keys.sort()
        for p in keys:
            if valid_paddr[p] == 0:
                continue
            possible_comm = self.read_memory(valid_paddr[p] + 368, 8)
            content = struct.unpack("<Q", possible_comm)
            str_content = struct.unpack("<8c", possible_comm)
            if all( ord(c) >= 47 and ord(c) <= 122 or ord(c)==0 for c in str_content ):
                if len(possible_comm.strip('\x00')) > 4:
                    print "[-] task_struct at offset", p, "address", hex(valid_paddr[p]), "comm\t", possible_comm
                    

            #if content[0] < struct.unpack("<Q", "zzzzzzzz")[0]:
            #    if content[0] > 0:
            #        print "[---] task_struct at offset", p, "address", hex(valid_paddr[p]), "comm\t", possible_comm
            #        print "[---] ", str_content
            possible_comm = self.read_memory(valid_paddr[p] + 368-p, 8)
            content = struct.unpack("<Q", possible_comm)
            str_content = struct.unpack("<8c", possible_comm)
            if all( ord(c) >= 47 and ord(c) <= 122 or ord(c)==0 for c in str_content ):
                if len(possible_comm.strip('\x00')) > 4:
                    print "[-] list_head at", p, "pointer", hex(valid_paddr[p]), "comm\t", possible_comm

            if "kthreadd" in possible_comm:
                kthreadd_init = valid_paddr[p] - p
                #print "[--] init_addr for systemd:", hex(valid_paddr[p] - p)

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
        print value[idx: idx+8]
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
    #addr_space = AddressSpace(mem_path, 0x3809000)
    #addr_space = AddressSpace(mem_path, 0x11209000)
    addr_space = AddressSpace(mem_path)
    
    #paddr = addr_space.vtop(0xffffffffac413740)
    #print paddr
    #paddr = 384804864
    #print paddr
    addr_space.extract_info(paddr, "./tmp")
    #addr_space.find_comm()
    #addr_space.parse_system_map('/home/zhenxiao/ProfileGenerator/volatility/volatility/plugins/overlays/linux/413/boot/System.map-4.13.0-041300-generic')
    #print addr_space.read_memory(paddr+2608, 8)
    #addr_space.extract_info(376393600, "./tmp")
    #addr_space.extract_info(467322696, "./tmp")
    # 0x1bdab208 this should be where the *next pointer points to. so this is the value in the field *next

    
    

    pass

if __name__ == "__main__":
    main()