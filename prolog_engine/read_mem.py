import mmap, struct, os, sys
from time import gmtime, strftime
import LinuxMemory as linux
# debian_x64
# lububntu_x64
offset = [
    (0, 1208, 655360),
    (655360, 656568, 65536),
    (786432, 722104, 536084480),
    (4244635648, 536806584, 16777216),
    (4294705152, 553583800, 262144)
]
# 4.11 4.15 4.16 4.19 4.20
# centos 8 
offset2 = [ 
    (0, 400, 816),
    (0, 1216, 655360),
    (655360, 656576, 65536),
    (786432, 722112, 536084480),
    (4244635648, 536806592, 16777216),
    (4294705152, 553583808, 262144)
]
# cenos7
offset3 = [
    (0, 400, 816),
    (0, 1216, 655360),
    (655360, 656576, 65536),
    (786432, 722112, 133431296),
    (4244635648, 134153408, 16777216),
    (4294705152, 150930624, 262144)
]
#centos6
offset4 = [
    (0, 344, 816),
    (0, 1160, 655360),
    (786432, 656520, 267649024),
    (4244635648, 268305544, 16777216),
    (4294705152, 285082760, 262144)
]
# lede-4.4.50
# openwrt
offset5 = [
    (0, 344, 816),
    (0, 1160, 655360),
    (786432, 656520, 133431296),
    (4244635648, 134087816, 16777216),
    (4294705152, 150865032, 262144)
]
#goldfish
offset6 = [
    (0, 344, 816),
    (0, 1160, 655360),
    (786432, 656520, 267649024),
    (4244635648, 268305544, 16777216),
    (4294705152, 285082760, 262144)
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
        self.verbose = 2
        #offset: debian_x64 lububntu_x64
        #offset2: lubuntu20 centos8 4.11 4.12 4.13 4.14 4.15 4.16 4.18 4.19 4.20 5.3    
        #offset3: cenos7
        #offset4: centos6
        self.offset = offset6
        self.mem_path = mem_path
        self.mem.seek(0)
        
        if "ELF" in self.mem.read(6):
            #print "ELF headers"
            self.has_elf_header = True
        else:
            #print "not elf headers"
            self.has_elf_header = False

        vdtb_idx = self.mem.find("SYMBOL(swapper_pg_dir)=") + len("SYMBOL(swapper_pg_dir)=")
        if vdtb_idx-len("SYMBOL(swapper_pg_dir)=")>0:
            self.mem.seek(vdtb_idx)
            dtb_vaddr = "0x" + self.mem.read(16)
            print "dtb_vaddr", dtb_vaddr
        else:
            print "cannot find dtb_vaddr"
            dtb_vaddr = "0xffffffff815c0920"
        '''
        init_task_vaddr = self.mem.find("SYMBOL(init_top_pgt)=")
        if init_task_vaddr < 0:
            init_task_vaddr = self.mem.find("SYMBOL(init_level4_pgt)=")
            if init_task_vaddr < 0:
                print "[-] Error: cannot find init_pgt form the image"
            else:
                init_task_vaddr += len("SYMBOL(init_level4_pgt)=")
        else:
            init_task_vaddr +=  len("SYMBOL(init_top_pgt)=")
        if init_task_vaddr:
            self.mem.seek(init_task_vaddr)
            self.init_task = '0x'+self.mem.read(16)
        else:
            self.init_task = 0
        '''

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
            pass
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
        
        print "[-] init_task_from_system_map: {}, init_top_pgt_from_system_map: {}".format(init_task_from_system_map, init_top_pgt_from_system_map)


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
    def find_pointer(self):
        #for step in range(0, self.mem.size(), 4096):
        for step in range(0x1479600, 0x1479600 + 4096, 4096):

            page = self.read_memory(step & 0xffffffffff000, 0x200 * 8)
            if not page:
                continue
            value = self.v(4096, page)
            print page
            print value
            if "swapper_pg_dir" in page:
                #print page
                print "found swapper in page"
            for item in range(len(value)):
                str_content = page[item*8:(item+1)*8]
                number = value[item]
                if number == 0xffffffff81605000:
                    print "found _stext at", hex(step + item*8)
                if "ffffffff81605000" in page[(item-2)*8:(item+2)*8]:
                    print "found pointer"
                    print page[(item-4)*8:(item+2)*8]
                    print "addr", hex(step + item*8)
                if "SYMBOL" in str_content:
                    pass
                    #print "found string at", hex(step + item*8), page[item*8:(item+2)*8]


    def extract_info(self, paddr, output, size = 4096):
        valid_pointer = {}
        valid_long = {}
        valid_int = {}
        valid_stirng = {}
        unknown_pointer = {}
        content = self.read_memory(paddr, size)
        if not content:
            print "no available content"
            return -1
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
                    str_content = content[item*8:(item+1)*8]
                    if all( ord(c) >= 47 and ord(c) <= 122 or ord(c)==0 for c in str_content ):
                        if len(str_content.replace('\x00', '')) >= 4:
                            if self.verbose:
                                print "[-] ", item*8, hex(paddr+item*8), "string: ", str_content, hex(number)
                            valid_stirng[item*8] = number
                    if self.verbose:
                        pass
                        print "[-] ", item*8, hex(paddr+item*8), "unsigned long: ", hex(number), content[item*8:item*8+8]
                    valid_long[item*8] = number
                elif number == 0xffffffffffffffff:
                    pass
                else:
                    # add for test randstruct
                    str_content = content[item*8:(item+1)*8]
                    if all( ord(c) >= 45 and ord(c) <= 122 or ord(c)==0 for c in str_content ):
                        if len(str_content.replace('\x00', '')) > 4:
                            if self.verbose:
                                print "[-] ", item*8, hex(paddr+item*8), "string: ", str_content, hex(number)
                            valid_stirng[item*8] = number
                    else:
                        if self.verbose:
                            print "[-] ", item*8, hex(paddr+item*8), "unknow pointer: ", hex(number), content[item*8:item*8+8]
                        unknown_pointer[item*8] = number



                    
        value = struct.unpack("<1024I", content)
        for idx in range(len(value)):
            number = value[idx] 
            # This value is very ad hoc
            if number < 0x7fff:
                #print "int: ", hex(number), idx*4
                valid_int[idx*4] = number
        '''
        with open(output, 'a') as output:
            output.write("pointer_addr([\n")
            keys = valid_pointer.keys()
            keys.sort()
            for key in keys:
                #fact = "ispointer(" + hex(paddr) + "," + str(key) + "," + str(valid_pointer[key]) + ")." + "\n"
                fact = "\t\t" + hex(paddr + key) + "," + "\n"
                output.write(fact)
            output.write("\t\t0\n]).\n")
            output.write("pointer_val([\n")
            keys = valid_pointer.keys()
            keys.sort()
            for key in keys:
                #fact = "ispointer(" + hex(paddr) + "," + str(key) + "," + str(valid_pointer[key]) + ")." + "\n"
                fact = "\t\t" + str(valid_pointer[key]) + "," + "\n"
                output.write(fact)
            output.write("\t\t0\n]).\n")

            output.write("unknown_addr([\n")
            keys = unknown_pointer.keys()
            keys.sort()
            for key in keys:
                #fact = "ispointer(" + hex(paddr) + "," + str(key) + "," + str(valid_pointer[key]) + ")." + "\n"
                fact = "\t\t" + hex(paddr + key) + "," + "\n"
                output.write(fact)
            output.write("\t\t0\n]).\n")
            output.write("unknown_val([\n")
            keys = unknown_pointer.keys()
            keys.sort()
            for key in keys:
                #fact = "ispointer(" + hex(paddr) + "," + str(key) + "," + str(valid_pointer[key]) + ")." + "\n"
                fact = "\t\t" + str(unknown_pointer[key]) + "," + "\n"
                output.write(fact)
            output.write("\t\t0\n]).\n")

            output.write("long_addr([\n")
            keys = valid_long.keys()
            keys.sort()
            for key in keys:
                #fact = "ispointer(" + hex(paddr) + "," + str(key) + "," + str(valid_pointer[key]) + ")." + "\n"
                fact = "\t\t" + hex(paddr + key) + "," + "\n"
                output.write(fact)
            output.write("\t\t0\n]).\n")
            output.write("long_val([\n")
            keys = valid_long.keys()
            keys.sort()
            for key in keys:
                #fact = "ispointer(" + hex(paddr) + "," + str(key) + "," + str(valid_pointer[key]) + ")." + "\n"
                fact = "\t\t" + str(valid_long[key]) + "," + "\n"
                output.write(fact)
            output.write("\t\t0\n]).\n")

            output.write("int_addr([\n")
            keys = valid_int.keys()
            keys.sort()
            for key in keys:
                #fact = "ispointer(" + hex(paddr) + "," + str(key) + "," + str(valid_pointer[key]) + ")." + "\n"
                fact = "\t\t" + hex(paddr + key) + "," + "\n"
                output.write(fact)
            output.write("\t\t0\n]).\n")
            output.write("int_val([\n")
            keys = valid_int.keys()
            keys.sort()
            for key in keys:
                #fact = "ispointer(" + hex(paddr) + "," + str(key) + "," + str(valid_pointer[key]) + ")." + "\n"
                fact = "\t\t" + str(valid_int[key]) + "," + "\n"
                output.write(fact)
            output.write("\t\t0\n]).\n")


            output.write("str_addr([\n")
            keys = valid_stirng.keys()
            keys.sort()
            for key in keys:
                #fact = "ispointer(" + hex(paddr) + "," + str(key) + "," + str(valid_pointer[key]) + ")." + "\n"
                fact = "\t\t" + hex(paddr + key) + "," + "\n"
                output.write(fact)
            output.write("\t\t0\n]).\n")
            output.write("str_val([\n")
            keys = valid_stirng.keys()
            keys.sort()
            for key in keys:
                #fact = "ispointer(" + hex(paddr) + "," + str(key) + "," + str(valid_pointer[key]) + ")." + "\n"
                fact = "\t\t" + str(valid_stirng[key]) + "," + "\n"
                output.write(fact)
            output.write("\t\t0\n]).\n")
        '''
        with open(output, 'a') as output:
            output.write("pointer([\n")
            keys = valid_pointer.keys()
            keys.sort()
            for key in keys:
                #fact = "ispointer(" + hex(paddr) + "," + str(key) + "," + str(valid_pointer[key]) + ")." + "\n"
                fact = "\t\t[" + hex(paddr + key) + "," + str(valid_pointer[key]) + "]," + "\n"
                output.write(fact)
            output.write("\t\t[0, 0]\n]).\n")

            output.write("unknown([\n")
            keys = unknown_pointer.keys()
            keys.sort()
            for key in keys:
                #fact = "unknownpointer(" + hex(paddr) + "," + str(key) + "," + str(unknown_pointer[key]) + ")." + "\n"
                fact = "\t\t[" + hex(paddr + key) + "," + str(unknown_pointer[key]) + "]," + "\n"
                output.write(fact)
            output.write("\t\t[0, 0]\n]).\n")

            output.write("long([\n")
            keys = valid_long.keys()
            keys.sort()
            for key in keys:
                #fact = "islong(" + hex(paddr) + "," + str(key) + "," + str(valid_long[key]) + ")." + "\n"
                fact = "\t\t[" + hex(paddr + key) + "," + str(valid_long[key]) + "]," + "\n"
                output.write(fact)
            output.write("\t\t[0, 0]\n]).\n")

            output.write("int([\n")
            keys = valid_int.keys()
            keys.sort()
            for key in keys:
                #fact = "isint(" + hex(paddr) + "," + str(key) + "," + str(valid_int[key]) + ")." + "\n"
                fact = "\t\t[" + hex(paddr + key) + "," + str(valid_int[key]) + "]," + "\n"
                output.write(fact)
            output.write("\t\t[0, 0]\n]).\n")

            output.write("string_val([\n")
            keys = valid_stirng.keys()
            keys.sort()
            for key in keys:
                #fact = "isstring(" + hex(paddr) + "," + str(key) + "," + str(valid_stirng[key]) + ")." + "\n"
                fact = "\t\t[" + hex(paddr + key) + "," + str(valid_stirng[key]) + "]," + "\n"
                output.write(fact)
            output.write("\t\t[0, 0]\n]).\n")
        
        return valid_pointer

    
    def pslist(self, init):
        init_addr = 123798656
        while True:
            content = self.read_memory(init_addr + 1976, 8)
            value = struct.unpack("<Q", content)[0]
            p_next_task = self.vtop(value)
            if not p_next_task:
                print "cannot find next task"
                return
            pname = self.read_memory(p_next_task - 1976 + 2656, 8)
            init_addr = p_next_task - 1976
            pid = self.read_memory(init_addr + 2232, 4)
            pid = struct.unpack("<I", pid)[0]
            print "next process", pname, "at", hex(init_addr), "with pid", pid
            if init_addr == 123798656:
                break

    
    def find_swapper_page(self):
        for step in range(0, self.mem.size(), 4096):
            page = self.read_memory(step & 0xffffffffff000, 0x200 * 8)
            if not page:
                continue
            for idx in range(0, 4096, 8):
                if "swapper/" in page[idx:idx+8]:
                    print "found swapper", hex(step+idx)
                    return step+idx
            
        print "[-] Error: Swapper page not found"
        exit(0)
    # This function is to find the address of target process name
    def find_string(self, target):
        '''
        This function is to find the address of the target process name in the memory.
        It is used to facilitate find_tasks method.
        '''
        for step in range(0, self.mem.size(), 4096):
            page = self.read_memory(step & 0xffffffffff000, 0x200 * 8)
            if not page:
                continue
            for idx in range(0, 4096, 8):
                #print hex(step+idx), page[idx:idx+8], hex(self.is_user_pointer(page[idx:idx+8], 0))
                if target in page[idx:idx+16]:
                    print "found ", target, hex(step+idx), page[idx:idx+16]
                    #for tmpidx in range(0, 4096, 8):
                    #    print hex(step+tmpidx), hex(self.is_user_pointer(page[tmpidx:tmpidx+8], 0))
                    #return step
            
        print "[-] Error: target not found", self.read_memory(0x15c04c0+1192, 8)
        '''
        page = self.read_memory(0x15c0000, 0x200 * 8)
        
        for idx in range(0, 4096, 8):
            print hex(0x15c0000+idx), page[idx:idx+8], hex(self.is_user_pointer(page[idx:idx+8], 0))
        '''
        exit(0)
    # This function is to find the init address of task structure. 
    # It starts from kthread and use the property of parent structure, which is swapper structure. 
    def find_tasks(self, addr):
        '''
        This function is to find the address of the global symbol `init_task`.
        At this point, we do not know the start address of a task structure, the only thing we know is the location of process name field (comm).
        Another helpful information we can use is that there is a parent field above comm that points to the init address of another task structure. 
        We first gues the location of initial address of a task struct A, and we know the comm location B, then we can have the gap B-A. 
        If there is a pointer between A and B, which points to a location where there is a string value at the same gap B-A, then we know A is a correct initial
        address of a task structure. 
        It starts from `kthread` process, which is in the first argument. 
        '''
        page = self.read_memory(addr, 0x200 * 8)
        value = struct.unpack("<512Q", page)
        
        for item in range(len(value)):
            number = value[item]
            phys_addr = self.vtop(number)
            if phys_addr:
                #print "find pointer", hex(number), ""
                for gap in range(addr, addr+3000, 8):
                    target_comm = phys_addr + addr+3000 - gap
                    comm = self.read_memory(target_comm, 8)
                    if not comm:
                        continue
                    if "swapper" in comm:
                        print "found next task at", comm , hex(addr + item * 8), hex(phys_addr), addr+3000 - gap
                    '''
                    if all( ord(c) >= 45 and ord(c) <= 122 or ord(c)==0 for c in comm ):
                        if len(comm.replace('\x00', '')) > 4:
                            #if self.verbose:
                            print "found task struct at", comm , phys_addr, 0x7040f78 - gap
                    '''
                gap = addr+3000 - (addr + item * 8)
                target_comm = phys_addr + gap
                comm = self.read_memory(target_comm, 8)
                if not comm:
                    continue
                if "swapper" in comm:
                    print "found next task at", comm , hex(addr + item * 8)
                '''
                if all( ord(c) >= 45 and ord(c) <= 122 or ord(c)==0 for c in comm ):
                    if len(comm.replace('\x00', '')) > 4:
                        #if self.verbose:
                        print "found next task at", comm , hex(addr + item * 8)
                '''        
    def v(self, size, content):
        s = "<" + str(size/8) + "Q"
        value = struct.unpack(s, content)
        return value

    def ispointer(self, pointer_v):
        if self.vtop(pointer_v):
            return 1
        else:
            return 0

    def isstring(self, str_content):
        if all( ord(c) >= 45 and ord(c) <= 122 or ord(c)==0 for c in str_content):
            if len(str_content.replace('\x00', '')) > 4:
                return 1
        return 0
    
    def find_modules(self, addr = 0):
        '''
        This function is to locate the golbal symbol 'modules'. It first starts from a random kernel module 
        that is very likely to be loaded and identifies its location in the memory as well as the next and prev pointers in that module structure.
        Then it traverse the module list until reaching the first one in the double linked list. 
        We rely on the following evidence to find the top one in the list:
                                         | module_struct |     | module_struct |
            global symbol `modules` -->  | next          | --> | next          |
                                         | prev          |     | prev          |
                                         | module name   |     | module name   |

            The prev of the first element points to the global symbol module, and it does not have a string value (module name) below.  
            In other words, it prev points to a location where there is a string value below, then it is not the first element. 

        Based on the above information, we can locate the global symbol `modules` in the memory. 
        Then we just find its virtual address and put it in the profile. 
    
        '''
        self.log("start searching")
        for step in range(addr, self.mem.size(), 4096):
            page = self.read_memory(step & 0xffffffffff000, 0x200 * 8)
            if not page:
                continue
            #value = struct.unpack("<512Q", page)
            prev_ = 0
            next_ = 0
            last_next = 1
            last_prev = 0
            target_v = 1
            module_v = 0
            found = 0
            # We start from a random kernel module that is very likely to be loaded. 
            module_name = "binfmt"
            value = self.v(4096, page)
            for item in range(len(value)):
                str_content = page[item*8:(item+1)*8]
                number = value[item]
                if "ipv6head" in str_content:
                #if self.isstring(str_content):
                    prev_ = value[item-1]
                    next_ = value[item-2]

                    if prev_ == next_:
                        continue
                    if not self.vtop(prev_) or not self.vtop(next_):
                        continue
                    #print "found ", str_content, hex(prev_), hex(next_), hex(step + item*8)
                    

                    last_next = self.read_memory(self.vtop(prev_), 0x8)
                    if not last_next or not len(last_next) == 8:
                        continue
                    last_next_v = self.v(8, last_next)[0]
                    target = self.read_memory(self.vtop(last_next_v), 8)
                    if not target or not len(target) == 8:
                        continue
                    target_v = self.v(8, target)[0]
                    #print "prev_", hex(prev_), self.vtop(prev_), "next", hex(next_), self.vtop(next_), "module", hex(module_v), "target", hex(target_v), str_content, hex(step+item*8)
                    module_name = str_content
                    if target_v == next_:
                        found = 1
                    else:
                        found = 0
                    break
            if found:
                while self.isstring(module_name):
                    print "found new module", module_name
                    next_ = self.read_memory(self.vtop(prev_), 8)
                    if not next_:
                        break
                    next_ = self.v(8, next_)[0]
                    module_name = self.read_memory(self.vtop(prev_)+16, 8)
                    prev_ = self.read_memory(self.vtop(prev_)+8, 8)
                    if not prev_:
                        break
                    prev_ = self.v(8, prev_)[0]

                    last_next = self.read_memory(self.vtop(prev_), 0x8)
                    if not last_next or not len(last_next) == 8:
                        continue
                    last_next_v = self.v(8, last_next)[0]
                    target = self.read_memory(self.vtop(last_next_v), 8)
                    if not target or not len(target) == 8:
                        continue
                    target_v = self.v(8, target)[0]
                

                if target_v == next_ and target_v > 0xffffffff00000000:
                    print "found modlues", hex(target_v), hex(module_v), hex(prev_)
                    #break
                    modules = 0
                    for step in range(0, self.mem.size(), 4096):
                        page = self.read_memory(step & 0xffffffffff000, 0x200 * 8)
                        if not page:
                            continue
                        value = self.v(4096, page)
                        for item in range(len(value)):
                            number = value[item]
                            if number == target_v:
                                if self.isstring(page[(item+1)*8:(item+2)*8]):
                                    continue
                                print "found global symbol at", hex(step + item*8), hex(number), hex(target_v)
                                modules = step + item*8
                    
                    for step in range(0x0, 0xf0000000, 4096):
                        vaddr = step + 0xffffffff00000000
                        paddr = self.vtop(vaddr)
                        if paddr == modules & 0xffffffffff000:
                            print "found vaddr", hex(vaddr), hex(vaddr + (modules & 0xfff))
                            self.log("Finish searching")

                        pass
        
        if not found:
            return
        print "the first module is at", hex(target_v)
        if target_v == 1:
            return
        
        # To find the golbal symbol modules, we need to search in the memory to find the location which contains target_v
        modules = 0
        for step in range(0, self.mem.size(), 4096):
            page = self.read_memory(step & 0xffffffffff000, 0x200 * 8)
            if not page:
                continue
            value = self.v(4096, page)
            for item in range(len(value)):
                number = value[item]
                if number == target_v:
                    if self.isstring(page[(item+1)*8:(item+2)*8]):
                        continue
                    print "found global symbol at", hex(step + item*8), hex(number), hex(target_v)
                    modules = step + item*8

        print (self.vtop(0xffffffff9e288ef0) == modules)
        
        for step in range(0x0, 0xf0000000, 4096):
            vaddr = step + 0xffffffff00000000
            paddr = self.vtop(vaddr)
            if paddr == modules & 0xffffffffff000:
                print "found vaddr", hex(vaddr), hex(vaddr + (modules & 0xfff))
                self.log("Finish searching")

            pass

    def find_comm(self):
        # This function wants to find whether the shuffled offsets in task structure 
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
    #addr_space.extract_info(paddr, "./tmp")
    #addr_space.find_comm()
    #addr_space.parse_system_map('/home/zhenxiao/ProfileGenerator/volatility/volatility/plugins/overlays/linux/413/boot/System.map-4.13.0-041300-generic')
    paddr = addr_space.read_memory(0x15c04c0 + 784, 8)
    paddr = addr_space.vtop(0xffffffffc0168580)
    #paddr = addr_space.vtop(0xffffffff9e288ef0)
    paddr = addr_space.vtop(0xffffffff81479600)
    print hex(paddr)
    '''
    tmp = addr_space.read_memory(paddr, 8)
    if not tmp:
        print "error"
        return
    paddr = addr_space.v(8, tmp)[0]
    paddr = addr_space.vtop(0xffffffff81c336f0)
    paddr = addr_space.vtop(0xffffffff81ed67c0)
    '''
    addr_space.extract_info(paddr, "./tmp")
    #addr_space.find_modules()
    #addr_space.find_pointer()
    #print hex(paddr)
    #addr_space.extract_info(467322696, "./tmp")
    # 0x1bdab208 this should be where the *next pointer points to. so this is the value in the field *next

    #addr_space.find_string("kthreadd")
    #addr_space.find_tasks(0x1c2349d8-3000)

    
    

    pass

if __name__ == "__main__":
    s = '\xe9\xee\x00\x00\x07\x1F\xFE\x72\x74\xA2\x33\x32\x04\x54\x5f\x74'
    s = '\x04\x54'
    print s
    main()