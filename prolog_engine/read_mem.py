import mmap, struct, os, sys
from time import gmtime, strftime
import LinuxMemory as linux
import AddressSpaceARM as arm
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
#arm goldfish
offset7 = [
    (0, 284, 134217728)
]
#arm64
offset8 = [
    (1073741824, 2096, 268435456)
]
#runs (1073741824, 2096, 268435456)

#5.3_2048
#4.18_2048
offset9 = [
    (0, 1216, 655360),
    (655360, 656576, 65536),
    (786432, 722112, 2146697216),
    (4244635648, 2147419328, 16777216),
    (4294705152, 2164196544, 262144)
]
#4.18_1024/53/411
offset10 = [
    (0, 1216, 655360),
    (655360, 656576, 65536),
    (786432, 722112, 1072955392),
    (4244635648, 1073677504, 16777216),
    (4294705152, 1090454720, 262144)
]

class AddressSpace(linux.AMD64PagedMemory):
#class AddressSpace(linux.ArmAddressSpace):
    def __init__(self, mem_path, dtb = 0, verbose = 1):
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
        self.verbose = verbose
        #offset: debian_x64 lububntu_x64
        #offset2: lubuntu20 centos8 4.11 4.12 4.13 4.14 4.15 4.16 4.18 4.19 4.20 5.3    
        #offset3: cenos7
        #offset4: centos6
        self.offset = offset2
        self.mem_path = mem_path
        self.mem.seek(0)
       
        if "ELF" in self.mem.read(6):
            print "ELF headers"
            self.has_elf_header = True
            self.offset = self.parse_elf_header()


        else:
            print "No ELF headers"
            self.has_elf_header = False
        # Identify Linux version
        version_idx = self.mem.find("Linux version") + len("Linux version ")
        if version_idx:
            self.mem.seek(version_idx)
            version = self.mem.read(8)
            v = version[:version.index('-')]
            if len(v) >= 7:
                self.version = v[:-3]
            else:
                self.version = v[:-2]
            print "Linux version", float(self.version)
        else:
            print "[Error] - cannot identify Linux version"
            self.version = 0
        #self.find_KASLR_shift("kallsyms_on_each_symbol")
        vdtb_idx = self.mem.find("SYMBOL(swapper_pg_dir)=") + len("SYMBOL(swapper_pg_dir)=")
        if vdtb_idx-len("SYMBOL(swapper_pg_dir)=")>0:
            self.mem.seek(vdtb_idx)
            dtb_vaddr = "0x" + self.mem.read(16)
            print "dtb_vaddr", dtb_vaddr
        else:
            print "cannot find dtb_vaddr"
            dtb_vaddr = "0xffffffffaee0a000"
        #self.find_kallsyms_address_pre_46_arm()
        self.image_name = os.path.basename(mem_path)
        store_dtb = "./" + self.image_name + "_dtb"
        g_dtb = 0
        '''
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
        
        if not g_dtb:
            try: 
                with open(self.image_name + "_symbol_table", 'r') as fd:
                    line = fd.readline()
                    while line:
                        symbol_name = ["swapper_pg_dir", "init_level4_pgt", "init_top_pgt"]
                        if any(c in line for c in symbol_name):
                            g_dtb = int(line[:line.find('\t')][:-1], 16)
                            if dtb_vaddr:
                                self.shift = int(dtb_vaddr, 16) - g_dtb
                                print "shift", hex(self.shift)
                            else:
                                self.shift = 0
                        if " init_task" in line:
                            init_task_vaddr = int(line[:line.find('\t')][:-1], 16)
                        line = fd.readline()
            except IOError:
                g_dtb = None
            if g_dtb:
                print "try dtb"
                g_dtb = self.try_dtb(g_dtb, dtb_vaddr)
            self.dtb_vaddr = dtb_vaddr
            self.dtb = dtb
        if dtb:
            self.dtb = dtb
        elif g_dtb:
            print "get dtb", g_dtb
            self.dtb = g_dtb
            with open(store_dtb, 'w') as fd:
                fd.write(str(self.dtb))
        else:
            pass
            #self.find_dtb(0x1a000000)
            
            self.find_dtb(0x1000000)
            # There is another page table when searchingfrom 0x0. but not complete.
            #self.find_dtb(0x0)
            with open(store_dtb, 'w') as fd:
                fd.write(str(self.dtb))
        #self.find_dtb(0)
        '''

    def parse_elf_header(self):
        '''
            Parse elf header 64 
        '''
        #elf64_header definition from Volatility
        elf64_header = {
            'e_ident' : [ 0, ['String', dict(length = 16)]], 
            'e_type' : [ 16, ['Enumeration', dict(target = 'unsigned short', choices = {
                0: 'ET_NONE', 
                1: 'ET_REL', 
                2: 'ET_EXEC', 
                3: 'ET_DYN', 
                4: 'ET_CORE', 
                0xff00: 'ET_LOPROC', 
                0xffff: 'ET_HIPROC'})]],
            'e_machine' : [ 18, ['unsigned short']], 
            'e_version' : [ 20, ['unsigned int']], 
            'e_entry' : [ 24, ['unsigned long long']], 
            'e_phoff' : [ 32, ['unsigned long long']], 
            'e_shoff' : [ 40, ['unsigned long long']], 
            'e_flags' : [ 48, ['unsigned int']], 
            'e_ehsize'    : [ 52, ['unsigned short']], 
            'e_phentsize' : [ 54, ['unsigned short']], 
            'e_phnum'     : [ 56, ['unsigned short']], 
            'e_shentsize' : [ 58, ['unsigned short']], 
            'e_shnum'     : [ 60, ['unsigned short']], 
            'e_shstrndx'  : [ 62, ['unsigned short']],
        }
        elf64_pheader = {
            'p_type' : [ 0, ['Enumeration', dict(target = 'unsigned int', choices = {
                0: 'PT_NULL', 
                1: 'PT_LOAD',
                2: 'PT_DYNAMIC', 
                3: 'PT_INTERP', 
                4: 'PT_NOTE', 
                5: 'PT_SHLIB', 
                6: 'PT_PHDR', 
                7: 'PT_TLS', 
                0x60000000: 'PT_LOOS', 
                0x6fffffff: 'PT_HIOS', 
                0x70000000: 'PT_LOPROC', 
                0x7fffffff: 'PT_HIPROC'})]],
            'p_flags' : [ 4, ['unsigned int']], 
            'p_offset' : [ 8, ['unsigned long long']], 
            'p_vaddr' : [ 16, ['unsigned long long']], 
            'p_paddr' : [ 24, ['unsigned long long']], 
            'p_filesz' : [ 32, ['unsigned long long']], 
            'p_memsz' : [ 40, ['unsigned long long']], 
            'p_align' : [ 48, ['unsigned long long']], 
        }
        header_size = 56
        e_phoff = self._read_memory(elf64_header['e_phoff'][0], 2)
        e_phnum = self._read_memory(elf64_header['e_phnum'][0], 2)
        runs = []
        for i in range(e_phnum):
            idx = i * header_size
            p_paddr = self._read_memory(e_phoff + idx + elf64_pheader['p_paddr'][0], 4)
            p_offset = self._read_memory(e_phoff + idx + elf64_pheader['p_offset'][0], 4)
            p_memsz = self._read_memory(e_phoff + idx + elf64_pheader['p_memsz'][0], 4)
            runs.append((int(p_paddr), int(p_offset), int(p_memsz)))

        #for item in runs:
        #    print item

        return runs




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
    def _read_memory(self, paddr, length):
        '''
            This function is for reading elf header
        '''
        if paddr > 1024:
            print "Error: This function is for reading elf header."
            sys.exit(1)
        self.mem.seek(paddr)
        value = self.mem.read(length)
        if not value:
            print "Error: fail to read memory at", hex(paddr)
            sys.exit(1)
        if length == 2:
            value = struct.unpack('<H', value)[0]
        elif length == 4:
            value = struct.unpack('<I', value)[0]

        return value

    def read_memory(self, paddr, length):
        # Comment out for testing

        if self.has_elf_header :
            paddr = self.translate(paddr)
            if not paddr:
                #print "Error: translate failed.\n"
                return None
                #sys.exit(1)
        
        if self.mem.size() - paddr < length:
            print "Error: read out of bound memory.", hex(paddr), hex(self.mem.size())
            sys.exit(1)

        self.mem.seek(paddr)
        value = self.mem.read(length)
        if not value:
            print "Error: fail to read memory at", hex(paddr)
            sys.exit(1)
        return value

    def try_dtb(self, dtb, dtb_vaddr):
        tmp_dtb = 0
        for step in range(0, self.mem.size(), 4096):
            if self.maybe_vtop(dtb_vaddr, step) == step:
                print "try dtb", hex(step)
                break
        return step

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
                    print "[-] ", item*8, hex(paddr+item*8), "pointer", hex(number), hex(self.vtop(number)), [c for c in content[item*8:item*8+8]]
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
                            print "[-] ", item*8, hex(paddr+item*8), "pointer", number, [c for c in content[item*8:item*8+8]]
                        valid_pointer[item*8] = number
                        #valid_long[item*8] = number
                    else:
                        str_content = content[item*8:(item+1)*8]
                        if all( ord(c) >= 36 and ord(c) <= 122 or ord(c)==0 for c in str_content ):
                            if len(str_content.replace('\x00', '')) >= 1:
                                if self.verbose:
                                    print "[-] ", item*8, hex(paddr+item*8), "string: ", str_content, hex(number)
                                valid_stirng[item*8] = number
                        else:
                            if self.verbose:
                                print "[-] ", item*8, hex(paddr+item*8), "value", number, [c for c in content[item*8:item*8+8]]
                            valid_long[item*8] = number
                elif number < 0xffffffffffff:
                    str_content = content[item*8:(item+1)*8]
                    if all( ord(c) >= 36 and ord(c) <= 122 or ord(c)==0 for c in str_content ):
                        if len(str_content.replace('\x00', '')) >= 4:
                            if self.verbose:
                                print "[-] ", item*8, hex(paddr+item*8), "string: ", str_content, hex(number)
                            valid_stirng[item*8] = number
                    if self.verbose:
                        pass
                        print "[-] ", item*8, hex(paddr+item*8), "unsigned long: ", hex(number), [c for c in content[item*8:item*8+8]]
                    valid_long[item*8] = number
                elif number == 0xffffffffffffffff:
                    pass
                else:
                    # add for test randstruct
                    str_content = content[item*8:(item+1)*8]
                    if all( ord(c) >= 32 and ord(c) <= 122 or ord(c)==0 for c in str_content ):
                        if len(str_content.replace('\x00', '')) > 4:
                            if self.verbose:
                                print "[-] ", item*8, hex(paddr+item*8), "string: ", str_content, hex(number)
                            valid_stirng[item*8] = number
                    else:
                        if self.verbose:
                            print "[-] ", item*8, hex(paddr+item*8), "unknow pointer: ", hex(number), [c for c in content[item*8:item*8+8]], str_content
                        unknown_pointer[item*8] = number
                    
        value = struct.unpack("<1024I", content)
        for idx in range(len(value)):
            number = value[idx] 
            # This value is very ad hoc
            #print "int: ", hex(number), idx*4
            if number < 0x7fff:
                #print "int: ", hex(number), idx*4
                valid_int[idx*4] = number

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

    def find_KASLR_shift(self, target):
        location = 0
        self.log("start search KASLR shift")
        for step in range(0, self.mem.size(), 4096):
            page = self.read_memory(step & 0xffffffffff000, 0x200 * 8)
            if not page:
                continue
            for idx in range(0, 4096, 8):
                #print hex(step+idx), page[idx:idx+8], hex(self.is_user_pointer(page[idx:idx+8], 0))
                if target in page[idx:idx+2*len(target)]:
                    print "found ", target, hex(step+idx), page[idx-16:idx+32]
                    for tmpidx in range(idx, idx+2*len(target), 1):
                        if target == page[tmpidx:tmpidx+len(target)]:
                            print "found ", target, hex(step+tmpidx), page[idx-16:idx+32]
                            location = step+tmpidx
                            break
                        if location:
                            break
                    #for tmpidx in range(0, 4096, 8):
                    #    print hex(step+tmpidx), hex(self.is_user_pointer(page[tmpidx:tmpidx+8], 0))
                    #return step
        self.log("end search KASLR shift")
            
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
                if target in page[idx:idx+len(target)]:
                    print "found ", target, hex(step+idx), page[idx-16:idx+32]
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

    def find_task_list_head(self, addr):
        # comm offset is 1488
        page = self.read_memory(addr, 0x200 * 8)
        value = struct.unpack("<512Q", page)
        for item in range(len(value)):
            number = value[item]
            phys_addr = self.vtop(number)
            if phys_addr:
                comm = self.read_memory(phys_addr + (1488-item*8), 8)
                print comm, item*8
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
        It starts from `kthreadd` process, which is in the first argument. 
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
    def v32(self, size, content):
        s = "<" + str(size/4) + "L"
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

    def find_kallsyms_address(self, init_addr = 0):
        self.log("start to find kernel symbols")
        kallsyms_address = 0
        found = 0
        #for step in range(0x13b12450, 0x13b12450+4096, 4096):
        #for step in range(0x13b12000, 0x13b12000+4096, 4096):
        for step in range(init_addr, self.mem.size(), 4096):
            page = self.read_memory(step, 0x200 * 8)
            if not page:
                #print "no content available"
                continue
            value = list(struct.unpack("<1024I", page))
            #print [hex(i) for i in value]
            if value.count(0) > len(value)/2:
                continue
            # Find the longest increasing or descending numbers
            # The offsets array contains a sequence of unsigned int numbers in incresing order. 
            index = 0
            while index < len(value):
                tmp_idx = index + 1
                current_val = value[index]
                while tmp_idx < len(value) and value[tmp_idx] > current_val:
                    current_val = value[tmp_idx]
                    tmp_idx += 1
                # This threshold is somehow experimental. 
                if tmp_idx - index > 100:
                    #print "found part symbol offsets", hex(step+index*4), hex(value[index])
                    found = 1
                    break
                index = tmp_idx
            if not found:
                continue

            # The offsets array also contains a sequence of unsigned int negative numbers in descending order.
            index = 0
            while index < len(value):
                tmp_idx = index + 1
                current_val = value[index]
                while tmp_idx < len(value) and value[tmp_idx] < current_val:
                    current_val = value[tmp_idx]
                    tmp_idx += 1
                if value[index] < 0xf0000000:
                    break
                # This threshold is somehow experimental. 
                if tmp_idx - index > 300:
                    print "found part symbol offsets", hex(step+index*4), hex(value[index])
                    if index % 2 == 1:
                        index += 1
                    kallsyms_address = step + index*4
                    break
                index = tmp_idx
            if kallsyms_address:
                break
        #print [hex(i) for i in value]
        if not kallsyms_address:
            print "Cannot find kallsyms_address."
            return
        print "kallsyms address", hex(kallsyms_address)
        
        # Now we found a rough address of kallsyms_offsets. Then we just need to continue 
        # to search for the kallsyms_relative_base symbol. 
        kallsyms_relative_base = kallsyms_address
        content = self.read_memory(kallsyms_relative_base, 0x8)
        value = self.v(8, content)
        while value[0] & 0xffffffff00000000 != 0xffffffff00000000:
            kallsyms_relative_base += 0x8
            content = self.read_memory(kallsyms_relative_base, 0x8)
            value = self.v(8, content)
        # If we have luck, this is the kallsyms_relative_base address
        kallsyms_relative_base_v = value[0]

        print "kallsyms_relative_base", hex(kallsyms_relative_base), hex(kallsyms_relative_base_v)
        # The value after it should be kallsyms_num_syms
        content = self.read_memory(kallsyms_relative_base + 0x8, 0x8)
        value = self.v(8, content)
        kallsyms_num_syms = value[0]
        print "kallsyms_num_syms", kallsyms_num_syms, [hex(int(ord(c))) for c in content]
        if kallsyms_num_syms > 1200000:
            self.find_kallsyms_address(kallsyms_relative_base)
            return
        # Then the init address of kallsyms_offsets can be found by 
        # kallsyms_relative_base - 0x8 - kallsyms_num_syms/2*8
        kallsyms_offsets = kallsyms_relative_base - 0x8 - (kallsyms_num_syms/2*8)
        print "kallsyms_offsets", hex(kallsyms_offsets)
        
        # Now we have kallsyms_offsets and kallsyms_relative_base, we can
        # recover the symbol addresses.
        symbol_address = []
        offsets = []
        number_sysms = kallsyms_num_syms
        while number_sysms >= -1:
            content = self.read_memory(kallsyms_offsets, 0x8)
            #print content
            value = struct.unpack('<2I', content)
            #print value
            for item in value:
                #print "physical addr: ", hex(kallsyms_offsets), "content", [hex(int(ord(c))) for c in content], "value", hex(item)
                if item > 0xf000000:
                    symbol_address.append(kallsyms_relative_base_v + (item^0xffffffff)-0x5400000)
                    offsets.append(item)
                else:
                    symbol_address.append(item)
                    offsets.append(item)
                    #symbol_address.append(kallsyms_relative_base_v + item)
            kallsyms_offsets += 0x8
            number_sysms -= 2 
        #print [hex(i) for i in symbol_address]
        #print "len of symbol address", len(symbol_address)
        self.log("Found kernel symbols")
        '''
        with open("symbol_address", 'w') as output:
            for item in [hex(i) for i in symbol_address]:
                output.write(item+'\n')
        '''
        '''
            | kallsyms_offsets       |
            | kallsyms_relative_base |
            | kallsyms_num_syms      |
            | kallsyms_names         |
            | kallsyms_markers       |
            | kallsyms_token_table   |
            | kallsyms_token_index   |
        '''
        kallsyms_names_addr = kallsyms_relative_base + 16
        kallsyms_token_table_addr = self.find_token_table(kallsyms_names_addr)
        kallsyms_token_index_addr = self.find_token_index(kallsyms_token_table_addr)
        print "symbols:", hex(kallsyms_names_addr), hex(kallsyms_token_table_addr), hex(kallsyms_token_index_addr)
        self.log("FINISH!")

        symbol_name = []
        # Size of kallsyms_names in page granularity. 
        # It's ok to use a larger name size, if we do not know the exact size.
        name_size = 0x115*2
        self.extract_kallsyms_symbols(symbol_name, kallsyms_names_addr, name_size, kallsyms_num_syms, kallsyms_token_table_addr, kallsyms_token_index_addr)
        #print symbol_name
        with open(self.image_name + "_symbol_table", 'w') as output:
            for index in range(min(len(symbol_address), len(symbol_name))):
                output.write(hex(symbol_address[index]) + "\t" + hex(offsets[index]) + " " + symbol_name[index] + "\n")
            #print symbol_name[index], "\t\t", hex(symbol_address[index])
        self.log("finished parsing and saving kernel symbols")

        '''
        if number > 0xf000000:
            print hex(0xffffffff9d400000 + (number^0xffffffff)-0x1c400000), hex(number)
        else:
            print hex(0xffffffff9d400000 + number-0x1c400000), hex(number)
        '''


    def find_kallsyms_address_pre_46(self):
        '''
            [-] For Linux kernel before 4.6
            This function is to find the symbol table in the memory. There are some patterns of the values in the symbol
            table that can help us locate the table. First, the symbol values are valid pointers. Second, they are sorted according
            to the values in an accessdening order. 
        '''
        kallsyms_address = 0
        for step in range(0, self.mem.size(), 4096):
            page = self.read_memory(step & 0xffffffffff000, 0x200 * 8)
            if not page:
                print "Error: no available content"
                continue
            if "swapper" in page:
                print "Found swapper at", hex(step)
            value = self.v(4096, page)
            count = 0
            for item in range(len(value)):
                if value[item] == 0xffffffff9e209000:
                    print "found the first element in symbol table", hex(step)
                if item == 0 or item == len(value)-1:
                    if value[item] & 0xffffffff00000000 == 0xffffffff00000000:
                        count += 1
                else:
                    if value[item] & 0xffffffff00000000 == 0xffffffff00000000:
                        if value[item] > value[item-1] and value[item] < value[item+1]:
                            count += 1
            # An assumption here is that the symbol table is at least larger than one page
            if count == 4096/8:
                print "found partial symbol table at", hex(step)
                kallsyms_address = step
                break
        if kallsyms_address == 0:
            print "cannot find symbol table"
            return
        # Now we find a page that contains a parital symbol table. Then scan backwards to
        # find the start address of symbol table.
        content = self.read_memory(kallsyms_address, 0x8)
        value = self.v(8, content)
        while value[0] & 0xffffffff00000000 == 0xffffffff00000000:
            kallsyms_address -= 0x8
            content = self.read_memory(kallsyms_address, 0x8)
            value = self.v(8, content)
        print "kallsyms_address", hex(kallsyms_address)
        #kallsyms_candidate = [kallsyms_address, kallsyms_address - 0x8, kallsyms_address - 0x16]
        # After finding kallsyms_address, scan the memory and save the symbol table. 
        symbol_address = []
        kallsyms_address += 0x8
        content = self.read_memory(kallsyms_address, 0x8)
        value = self.v(8, content)
        while value[0] & 0xffffffff00000000 == 0xffffffff00000000:
            symbol_address.append(value[0])
            kallsyms_address += 0x8 
            content = self.read_memory(kallsyms_address, 0x8)
            value = self.v(8, content)
        print "len of symbol table", len(symbol_address)
        # After the symbol table, the value should be kallsyms_num
        kallsyms_num_syms = kallsyms_address
        content = self.read_memory(kallsyms_address, 0x8)
        value = self.v(8, content)
        print "kallsyms_num", value[0]
        # Now we can locate the init address of the symbol table
        kallsyms_address = kallsyms_address - value[0]*8
        print "kallsyms_address", hex(kallsyms_address)
        # We have the symbol table. We can find kallsyms_address in the symbol list, which points to the init address
        # of the symbol table. kallsyms_num, kallsyms_token_index and kallsyms_token_table are adjacent. 

        '''
            | kallsyms_addresses     |
            | kallsyms_num_syms      |
            | kallsyms_names         |
            | kallsyms_markers       |
            | kallsyms_token_table   |
            | kallsyms_token_index   |
        '''
        kallsyms_names_addr = kallsyms_num_syms + 8
        kallsyms_token_table_addr = self.find_token_table(kallsyms_names_addr)
        kallsyms_token_index_addr = self.find_token_index(kallsyms_token_table_addr)
        print "kallsyms_names_addr:", hex(kallsyms_names_addr), "token_table:", hex(kallsyms_token_table_addr), "token_index", hex(kallsyms_token_index_addr)
        self.log("FINISH!")

        symbol_name = []
        # Size of kallsyms_names in page granularity. 
        # It's ok to use a larger name size, if we do not know the exact size.
        name_size = 0x115*2
        name_size = (kallsyms_token_table_addr - kallsyms_names_addr) / 4096
        self.extract_kallsyms_symbols(symbol_name, kallsyms_names_addr, name_size, kallsyms_num_syms, kallsyms_token_table_addr, kallsyms_token_index_addr)
        #print symbol_name
        with open(self.image_name + "_symbol_table", 'w') as output:
            for index in range(min(len(symbol_address), len(symbol_name))):
                output.write(hex(symbol_address[index]) + "\t" + hex(0) + " " + symbol_name[index] + "\n")
            #print symbol_name[index], "\t\t", hex(symbol_address[index])
        self.log("finished parsing and saving kernel symbols")

    def _find_kallsyms_address_pre_46_arm(self):
        '''
            [-] For Linux kernel before 4.6
            This function is to find the symbol table in the memory. There are some patterns of the values in the symbol
            table that can help us locate the table. First, the symbol values are valid pointers. Second, they are sorted according
            to the values in an accessdening order. 
        '''
        kallsyms_address = 0
        for step in range(0, self.mem.size(), 4096):
            page = self.read_memory(step & 0xffffffffff000, 0x200 * 8)
            if not page:
                #print "Error: no available content"
                continue
            if "swapper" in page:
                print "Found swapper at", hex(step)
            value = self.v(4096, page)
            count = 0
            for item in range(len(value)):
                if item == 0 or item == len(value)-1:
                    if value[item] & 0xffff800000000000 == 0xffff800000000000:
                        count += 1
                else:
                    if value[item] & 0xffff800000000000 == 0xffff800000000000:
                        if value[item] > value[item-1] and value[item] < value[item+1]:
                            count += 1
            # An assumption here is that the symbol table is at least larger than one page
            if count == 4096/8:
                print "found partial symbol table at", hex(step)
                kallsyms_address = step
                break
        if kallsyms_address == 0:
            print "cannot find symbol table"
            return
        # Now we find a page that contains a parital symbol table. Then scan backwards to
        # find the start address of symbol table.
        content = self.read_memory(kallsyms_address, 0x8)
        value = self.v(8, content)
        while value[0] & 0xffff800000000000 == 0xffff800000000000:
            kallsyms_address -= 0x8
            content = self.read_memory(kallsyms_address, 0x8)
            value = self.v(8, content)
        print "kallsyms_address", hex(kallsyms_address)
        #kallsyms_candidate = [kallsyms_address, kallsyms_address - 0x8, kallsyms_address - 0x16]
        # After finding kallsyms_address, scan the memory and save the symbol table. 
        symbol_table = []
        kallsyms_address += 0x8
        content = self.read_memory(kallsyms_address, 0x8)
        value = self.v(8, content)
        while value[0] & 0xffff800000000000 == 0xffff800000000000:
            symbol_table.append(value[0])
            kallsyms_address += 0x8
            content = self.read_memory(kallsyms_address, 0x8)
            value = self.v(8, content)
        kallsyms_num_syms = len(symbol_table)
        print "len of symbol table", kallsyms_num_syms
        step = 0
        while step < 10:
            kallsyms_address += step*8
            content = self.read_memory(kallsyms_address, 0x8)
            value = self.v(8, content)
            if value[0] == kallsyms_num_syms:
                print "Found kallsyms_num_syms", kallsyms_num_syms
                kallsyms_address += 0x8
                break
            step += 1
        while True:
            content = self.read_memory(kallsyms_address, 0x8)
            value = self.v(8, content)
            if not value[0] == 0:
                break
            kallsyms_address += 0x8
        # Now kallsyms_address points to kallsyms_names

        kallsyms_names_addr = kallsyms_address
        kallsyms_token_table_addr = self.find_token_table(kallsyms_names_addr)
        kallsyms_token_index_addr = self.find_token_index(kallsyms_token_table_addr)
        print hex(kallsyms_names_addr), hex(kallsyms_token_table_addr), hex(kallsyms_token_index_addr)
        
        symbol_name = []
        # Size of kallsyms_names in page granularity. 
        # It's ok to use a larger name size, if we do not know the exact size.
        name_size = 0x115*2
        self.extract_kallsyms_symbols(symbol_name, kallsyms_names_addr, name_size, kallsyms_num_syms, kallsyms_token_table_addr, kallsyms_token_index_addr)
        #print symbol_name
        with open(self.image_name + "_symbol_table", 'w') as output:
            for index in range(min(len(symbol_table), len(symbol_name))):
                output.write(hex(symbol_table[index]) + "\t" + symbol_name[index] + "\n")
            #print symbol_name[index], "\t\t", hex(symbol_address[index])

        # Now we can locate the init address of the symbol table
        kallsyms_address = kallsyms_address - kallsyms_num_syms*8
        print "kallsyms_address", hex(kallsyms_address)
        # We have the symbol table. We can find kallsyms_address in the symbol list, which points to the init address
        # of the symbol table. kallsyms_num, kallsyms_token_index and kallsyms_token_table are adjacent. 



    def find_kallsyms_address_pre_46_32bit(self):
        '''
            [-] For Linux kernel before 4.6
            This function is to find the symbol table in the memory. There are some patterns of the values in the symbol
            table that can help us locate the table. First, the symbol values are valid pointers. Second, they are sorted according
            to the values in an accessdening order. 
        '''
        kallsyms_address = 0
        for step in range(0, 0x7ffffff, 4096):
            page = self.read_memory(step, 0x200 * 8)
            if not page:
                print "Error: no available content"
                continue
            if "swapper" in page:
                print "Found swapper at", hex(step)
            value = self.v32(4096, page)
            count = 0
            for item in range(len(value)):
                if item == 0 or item == len(value)-1:
                    if value[item] & 0xc0000000 == 0xc0000000:
                        count += 1
                else:
                    if value[item] & 0xc0000000 == 0xc0000000:
                        if value[item] > value[item-1] and value[item] < value[item+1]:
                            count += 1
            # An assumption here is that the symbol table is at least larger than one page
            if count == 4096/4:
                print "found partial symbol table at", hex(step)
                kallsyms_address = step
                break
        if kallsyms_address == 0:
            print "cannot find symbol table"
            return
        # Now we find a page that contains a parital symbol table. Then scan backwards to
        # find the start address of symbol table.
        content = self.read_memory(kallsyms_address, 0x4)
        value = self.v32(4, content)
        while value[0] & 0xc0000000 == 0xc0000000:
            kallsyms_address -= 0x4
            content = self.read_memory(kallsyms_address, 0x4)
            value = self.v32(4, content)
        print "kallsyms_address", hex(kallsyms_address+0x4)
        #kallsyms_candidate = [kallsyms_address, kallsyms_address - 0x8, kallsyms_address - 0x16]
        # After finding kallsyms_address, scan the memory and save the symbol table. 
        
        #symbol_table = []
        kallsyms_address += 0x4
        content = self.read_memory(kallsyms_address, 0x4)
        value = self.v32(4, content)
        while value[0] & 0xc0000000 == 0xc0000000:
            #symbol_table.append(value[0])
            kallsyms_address += 0x4
            content = self.read_memory(kallsyms_address, 0x4)
            value = self.v32(4, content)
        #print "len of symbol table", len(symbol_table)
        
        # After the symbol table, the value should be kallsyms_num
        '''
            Something tricky here, if the symbol table len is odd, then maybe should add 4 to it. 
        '''
        content = self.read_memory(kallsyms_address, 0x4)
        value = self.v32(4, content)
        if value[0] == 0:
            content = self.read_memory(kallsyms_address+4, 0x4)
            value = self.v32(4, content)
            kallsyms_names_paddr = kallsyms_address + 8
        else:
            kallsyms_names_paddr = kallsyms_address + 4
        kallsyms_num_syms = value[0]
        print "kallsyms_num", kallsyms_num_syms
        # Now we can locate the init address of the symbol table
        kallsyms_address = kallsyms_address - (kallsyms_num_syms-1)*4
        print "kallsyms_address", hex(kallsyms_address)

        symbol_table = []
        sym_cnt = kallsyms_num_syms
        while sym_cnt:
            content = self.read_memory(kallsyms_address, 0x4)
            value = self.v32(4, content)
            symbol_table.append(value[0])
            kallsyms_address += 0x4
            sym_cnt -= 1
        '''
        content = self.read_memory(kallsyms_address, 0x4)
        value = self.v32(4, content)
        while value[0] & 0xc0000000 == 0xc0000000:
            symbol_table.append(value[0])
            kallsyms_address += 0x4
            content = self.read_memory(kallsyms_address, 0x4)
            value = self.v32(4, content)
        '''
        print "len of symbol table", len(symbol_table)

        kallsyms_token_table_addr = self.find_token_table_32bit(kallsyms_names_paddr)
        kallsyms_token_index_addr = self.find_token_index_32bit(kallsyms_token_table_addr)
        print hex(kallsyms_names_paddr), hex(kallsyms_token_table_addr), hex(kallsyms_token_index_addr)

        symbol_name = []
        # Size of kallsyms_names in page granularity. 
        # It's ok to use a larger name size, if we do not know the exact size.
        name_size = 0x115*2
        #kallsyms_num_syms = 35271
        self.extract_kallsyms_symbols_32bit(symbol_name, kallsyms_names_paddr, name_size, kallsyms_num_syms, kallsyms_token_table_addr, kallsyms_token_index_addr)
        #print symbol_name
        with open(self.image_name + "_symbol_table", 'w') as output:
            for index in range(min(len(symbol_table), len(symbol_name))):
                output.write(hex(symbol_table[index]) + "\t" + " " + symbol_name[index] + "\n")
            #for index in range(35271):
            #    output.write(symbol_name[index] + "\n")

        # We have the symbol table. We can find kallsyms_address in the symbol list, which points to the init address
        # of the symbol table. kallsyms_num, kallsyms_token_index and kallsyms_token_table are adjacent. 
        #print hex(symbol_table[0])
        for idx in range(len(symbol_table)):
            #print "symbol address", hex(symbol_table[idx])
            if self.vtop(symbol_table[idx]) == kallsyms_address:
                print "found kallsyms"
            if symbol_table[idx]&0xffff == kallsyms_address&0xffff:
                print "find kallsyms in symbol table", idx, hex(symbol_table[idx])
            
    def kallsyms_expand_symbol(self, off, symbol_name,
                                kallsyms_names, 
                                kallsyms_token_table, kallsyms_token_index):
        skipped_first = 0
        max_len = 128
        '''
            Get the index of compressed symbol length from the first symbol byte.
        '''
        data = off
        # Convert char to decimal. 
        length = ord(kallsyms_names[data])
        data += 1
        '''
            length should be an int
            Update the offset to return the offset for the next symbol on
	        the compressed stream.
        '''
        #print "length", length
        off += length + 1
        result = ''
        '''
            For every byte on the compressed symbol data, copy the table
	        entry for that byte.
        '''
        
        while length:
            #print "token_index", len(kallsyms_names), data, length, ord(kallsyms_names[data])
            if data >= len(kallsyms_names)-1:
                print "names out of bound"
                return -1
            if ord(kallsyms_names[data]) >= len(kallsyms_token_index):
                print "token index out of bound"
                return -1
            token_table_index = kallsyms_token_index[ord(kallsyms_names[data])]
            #print "token_table_index", token_table_index
            #print "len", length
            data += 1
            length -= 1
            
            while ord(kallsyms_token_table[token_table_index]):
                #print "index", token_table_index, ord(kallsyms_token_table[token_table_index])
                if skipped_first:
                    if max_len <= 1:
                        break
                    result += kallsyms_token_table[token_table_index]
                    max_len -= 1
                else:
                    skipped_first = 1
                token_table_index += 1
            
        #print "result:", result
        symbol_name.append(result)
        return off
    
    def find_token_table(self, kallsyms_names_paddr):
        # token_table address is larger than kallsyms_names_paddr
        # Start search from kallsyms_names_paddr
        self.log("Start to find kallsyms_token_table")
        #Estimisted gap 4096*0x100
        kallsyms_token_table_addr = kallsyms_names_paddr #+ 4096*250
        candidate = []
        # Read the content
        for step in range(kallsyms_token_table_addr, self.mem.size(), 8):
            kallsyms_token_table = ""
            kallsyms_token_table_v = []
            # Table_size is larger than 512 in reality
            table_size = 512/8
            init_addr = step
            while table_size:
                content = self.read_memory(init_addr, 8)
                if not content:
                    break
                for item in content:
                    kallsyms_token_table_v.append(struct.unpack("<c", item)[0])
                kallsyms_token_table += content
                init_addr += 8
                table_size -= 1
            if table_size > 1:
                continue
            table_size = 512/8
            
            
            #print "t in table", kallsyms_token_table.count('\x00'), kallsyms_token_table.count('r'), len(kallsyms_token_table)
            # table length is less than 1000. around 300 zeros in it. let's exam 512 element of them. 
            '''
                The characters in token_table are valid as per naming rules; they are combinations of 
                letters, numbers and symbols like underscores
            '''
            # I changed this range for ARM64 images, it used to be 46-125 for x86_64
            if not all(ord(c)>=36 and ord(c)<125 or ord(c)==0 for c in kallsyms_token_table):
                #print "pass"
                continue
            '''
                The elements in token_table in grouped and bounded by '\x00'
                no successive apperance of '\x00'
            '''
            if "\x00\x00" in kallsyms_token_table:
                #print "not pass"
                continue
            '''
                Compute the distance of each '\x00'. distance >= 1 and is normally less than 15.
                15 is somehow experimental.
            '''
            zero_index = [i for i, j in enumerate(kallsyms_token_table) if j == '\x00']
            #print zero_index
            for idx in reversed(range(1, len(zero_index))):
                zero_index[idx] = zero_index[idx] - zero_index[idx-1]
            #print zero_index
            #21 is somehow based on heuristic
            if any(c > 21 for c in zero_index):
                #print zero_index
                continue
            candidate.append(step)
            break
        if len(candidate) == 0:
            print "kallsyms_token_table not found"
        else:
            #print "found kallsyms_token_table_addr"
            self.log("kallsyms_token_table found")

            print [hex(c) for c in candidate]
            '''
            with open("table", 'w') as output:
                for item in kallsyms_token_table:
                    output.write(str((item, hex(int(ord(item)))))+'\n')
            '''
            return candidate[0]

    def find_token_index(self, token_table_paddr):
        self.log("Start to find kallsyms_token_index")
        result = 0
        for kallsyms_token_index_addr in range(token_table_paddr, self.mem.size(), 8):
            kallsyms_token_index = []
            kallsyms_token_index_v = []
            # From script/kallsyms.c, it has 256 entry, 256*2/8 = 64
            index_size = 64
            #print "index_addr", hex(kallsyms_token_index_addr), index_size
            init_addr = kallsyms_token_index_addr
            while index_size:
                content = self.read_memory(init_addr, 8)
                if not content:
                    break
                for idx in range(0, 7, 2):
                    kallsyms_token_index.append(content[idx:idx+2])
                init_addr += 8
                index_size -= 1
            if index_size > 1:
                continue
            index_size = 64
            for index in range(len(kallsyms_token_index)):
                content = struct.unpack("<H", kallsyms_token_index[index])
                kallsyms_token_index_v.append(content[0])
                #print content
                #print [i for i in kallsyms_token_index[index]]
            #print "len of token index array", len(kallsyms_token_index_v)
            '''
                The token index start from zero, and in an increasing order. 
            '''
            if not kallsyms_token_index_v[0] == 0:
                continue
            if kallsyms_token_index_v[1] == 0:
                continue
            #print kallsyms_token_index_v
            print "kallsyms_token_index_addr", hex(kallsyms_token_index_addr)
            result = kallsyms_token_index_addr
            break
        self.log("kallsyms_token_index found")
        
        with open("index", 'w') as output:
            for item in kallsyms_token_index_v:
                output.write(hex(int(str(item)))+'\n')
        #for index in range(len(kallsyms_token_index)):
        #    print [c for c in kallsyms_token_index[index]]
        if not result:
            print "Cannot find token_index"
        else:
            return result

    def find_token_table_32bit(self, kallsyms_names_paddr):
        # token_table address is larger than kallsyms_names_paddr
        # Start search from kallsyms_names_paddr
        kallsyms_token_table_addr = kallsyms_names_paddr
        #kallsyms_token_table_addr = 0x13b81000
        candidate = []
        # Read the content
        for step in range(kallsyms_token_table_addr, self.mem.size(), 4):
            kallsyms_token_table = ""
            kallsyms_token_table_v = []
            # Table_size is larger than 512 in reality
            table_size = 512/4
            init_addr = step
            while table_size:
                content = self.read_memory(init_addr, 4)
                if not content:
                    break
                for item in content:
                    kallsyms_token_table_v.append(struct.unpack("<c", item)[0])
                kallsyms_token_table += content
                init_addr += 4
                table_size -= 1
            if table_size > 1:
                continue
            table_size = 512/4
            '''
            with open("table", 'w') as output:
                for item in kallsyms_token_table:
                    output.write(str((item, ord(item)))+'\n')
            '''
            #print "t in table", kallsyms_token_table.count('\x00'), kallsyms_token_table.count('r'), len(kallsyms_token_table)
            # table length is less than 1000. around 300 zeros in it. let's exam 512 element of them. 
            '''
                The characters in token_table are valid as per naming rules; they are combinations of 
                letters, numbers and symbols like underscores
            '''
            if not all(ord(c)>=46 and ord(c)<125 or ord(c)==0 for c in kallsyms_token_table):
                #print "pass"
                continue
            '''
                The elements in token_table in grouped and bounded by '\x00'
                no successive apperance of '\x00'
            '''
            if "\x00\x00" in kallsyms_token_table:
                #print "not pass"
                continue
            '''
                Compute the distance of each '\x00'. distance >= 1 and is normally less than 15.
                15 is somehow experimental.
            '''
            zero_index = [i for i, j in enumerate(kallsyms_token_table) if j == '\x00']
            #print zero_index
            for idx in reversed(range(1, len(zero_index))):
                zero_index[idx] = zero_index[idx] - zero_index[idx-1]
            #print zero_index
            if any(c > 15 for c in zero_index):
                #print zero_index
                continue
            candidate.append(step)
            break
        if len(candidate) == 0:
            print "kallsyms_token_table not found"
        else:
            print "found kallsyms_token_table_addr"
            print [hex(c) for c in candidate]
            
            with open("table", 'w') as output:
                for item in kallsyms_token_table:
                    output.write(str((item, ord(item)))+'\n')
            
            return candidate[0]

    def find_token_index_32bit(self, token_table_paddr):
        result = 0
        for kallsyms_token_index_addr in range(token_table_paddr, self.mem.size(), 4):
            kallsyms_token_index = []
            kallsyms_token_index_v = []
            # From script/kallsyms.c, it has 256 entry, 256*2/8 = 64
            index_size = 64
            #print "index_addr", hex(kallsyms_token_index_addr), index_size
            init_addr = kallsyms_token_index_addr
            while index_size:
                content = self.read_memory(init_addr, 4)
                if not content:
                    break
                for idx in range(0, 3, 2):
                    kallsyms_token_index.append(content[idx:idx+2])
                init_addr += 4
                index_size -= 1
            if index_size > 1:
                continue
            index_size = 64
            for index in range(len(kallsyms_token_index)):
                content = struct.unpack("<H", kallsyms_token_index[index])
                kallsyms_token_index_v.append(content[0])
                #print content
                #print [i for i in kallsyms_token_index[index]]
            #print "len of token index array", len(kallsyms_token_index_v)
            '''
                The token index start from zero, and in an increasing order. 
            '''
            if not kallsyms_token_index_v[0] == 0:
                continue
            if kallsyms_token_index_v[1] == 0:
                continue
            #print kallsyms_token_index_v
            print "kallsyms_token_index_addr", hex(kallsyms_token_index_addr)
            result = kallsyms_token_index_addr
            break
        
        with open("index", 'w') as output:
            for item in kallsyms_token_index_v:
                output.write(str(item)+'\n')
        
        if not result:
            print "Cannot find token_index"
        else:
            return result
    
    def extract_kallsyms_symbols(self, symbol_name, 
                                    kallsyms_names_addr, 
                                    name_size,
                                    kallsyms_num_syms,
                                    kallsyms_token_table_addr, 
                                    kallsyms_token_index_addr):
        size = kallsyms_num_syms
        # 4.11.bin
        #kallsyms_names_addr = 0xffffffff81b6bf88 + 0x1c400000
        # 4.12.bin
        #kallsyms_names_addr = 0xffffffff81b6bf88 + 0x5400000
        #kallsyms_names_addr = 0xffffffff81479600
        #kallsyms_names_addr = self.vtop(kallsyms_names_addr)
        if not kallsyms_names_addr:
            print "[-]Error: invalid kallsyms_names_addr"
            exit(0)
        kallsyms_names = ""
        # 4.11.bin
        #name_size = (0xffffffff81c811c8 - 0xffffffff81b6bf88) / 4096
        #name_size = (0xffffffff814bd860 - 0xffffffff81479600) / 4096
        #kallsyms_token_table_addr = 0xffffffff81c81d00 + 0x1c400000
        # 4.12.bin
        #kallsyms_token_table_addr = 0xffffffff81c81d00 + 0x5400000

        #kallsyms_token_table_addr = 0xff17248
        #kallsyms_token_table_addr = self.vtop(kallsyms_token_table_addr)
        print "kallsyms_token_table_addr paddr", kallsyms_token_table_addr
        if not kallsyms_token_table_addr:
            print "[-]Error: invalid kallsyms_token_table_addr"
            exit(0)
        kallsyms_token_table = ""
        kallsyms_token_table_v = []
        
        #kallsyms_token_index_addr = 0xffffffff814bded0
        # 4.11.bin
        #kallsyms_token_index_addr = 0xffffffff81c82090 + 0x1c400000
        # 4.12.bin
        #kallsyms_token_index_addr = 0xffffffff81c82090 + 0x5400000
        
        #kallsyms_token_index_addr = self.vtop(kallsyms_token_index_addr)
        if not kallsyms_token_index_addr:
            print "[-]Error: invalid kallsyms_token_index_addr"
            exit(0)
        kallsyms_token_index = []
        kallsyms_token_index_v = []
        #kallsyms_names_addr =  0x1a171ae0 + 16
        # Extract kallsyms_names
        while name_size:
            content = self.read_memory(kallsyms_names_addr, 4096)
            kallsyms_names += content
            kallsyms_names_addr += 4096
            name_size -= 1

        print hex(len(kallsyms_names))
        #print kallsyms_names
        '''
        with open("names", 'w') as output:
            for item in kallsyms_names:
                output.write(str((item, ord(item)))+'\n')
        '''
        

        # Extract kallsyms_token_table
        table_size = (kallsyms_token_index_addr - kallsyms_token_table_addr)/8
        table_size = 1200
        #kallsyms_token_table_addr = 0x1a28c098
        #table_size = 512
        #kallsyms_token_table_addr -= 16
        while table_size+32:
            content = self.read_memory(kallsyms_token_table_addr, 8)
            for item in content:
                kallsyms_token_table_v.append(struct.unpack("<c", item)[0])
            kallsyms_token_table += content
            kallsyms_token_table_addr += 8
            table_size -= 1

        print "length of token table", hex(len(kallsyms_token_table))
        tmp = ''
        
        with open("table", 'w') as output:
            for item in kallsyms_token_table:
                output.write(str((item, ord(item)))+'  ')
        
        #print [ord(i) for i in kallsyms_token_table]
        
        # Extract kallsyms_token_index
        # Not sure about the index_size
        # From script/kallsyms.c, it has 256 entry, 256*2/8 = 64
        index_size = 64
        #print "index_addr", hex(kallsyms_token_index_addr), index_size
        #kallsyms_token_index_addr = 0x1a28c430
        while index_size:
            content = self.read_memory(kallsyms_token_index_addr, 8)
            for idx in range(0, 7, 2):
                kallsyms_token_index.append(content[idx:idx+2])
            kallsyms_token_index_addr += 8
            index_size -= 1
        for index in range(len(kallsyms_token_index)):
            content = struct.unpack("<H", kallsyms_token_index[index])
            kallsyms_token_index_v.append(content[0])
            #print content
            #print [i for i in kallsyms_token_index[index]]
        #print "len of token index array", len(kallsyms_token_index_v)
        '''
        with open("index", 'w') as output:
            for item in kallsyms_token_index_v:
                output.write(str(item)+'  ')
        print "expand compressed strings"
        '''
        off = 0
        for index in range(size+1):
            if off == -1:
                break
            off = self.kallsyms_expand_symbol(off, symbol_name, kallsyms_names, kallsyms_token_table, kallsyms_token_index_v)
        #off = self.kallsyms_expand_symbol(off, kallsyms_names, kallsyms_token_table_v, kallsyms_token_index_v)

    def extract_kallsyms_symbols_32bit(self, symbol_name, 
                                    kallsyms_names_addr, 
                                    name_size,
                                    kallsyms_num_syms,
                                    kallsyms_token_table_addr, 
                                    kallsyms_token_index_addr):
        size = kallsyms_num_syms
        if not kallsyms_names_addr:
            print "[-]Error: invalid kallsyms_names_addr"
            exit(0)

        kallsyms_names = ""
        print "kallsyms_token_table_addr paddr", kallsyms_token_table_addr
        if not kallsyms_token_table_addr:
            print "[-]Error: invalid kallsyms_token_table_addr"
            exit(0)
        kallsyms_token_table = ""
        kallsyms_token_table_v = []

        if not kallsyms_token_index_addr:
            print "[-]Error: invalid kallsyms_token_index_addr"
            exit(0)
        kallsyms_token_index = []
        kallsyms_token_index_v = []
        #kallsyms_names_addr =  0x1a171ae0 + 16
        # Extract kallsyms_names
        while name_size:
            content = self.read_memory(kallsyms_names_addr, 4096)
            kallsyms_names += content
            kallsyms_names_addr += 4096
            name_size -= 1

        print hex(len(kallsyms_names))
        #print kallsyms_names
        with open("names_32", 'w') as output:
            for item in kallsyms_names:
                output.write(str((item, ord(item)))+'\n')
        

        # Extract kallsyms_token_table
        table_size = (kallsyms_token_index_addr - kallsyms_token_table_addr)/4
        #kallsyms_token_table_addr = 0x1a28c098
        #table_size = 512
        while table_size:
            content = self.read_memory(kallsyms_token_table_addr, 4)
            for item in content:
                kallsyms_token_table_v.append(struct.unpack("<c", item)[0])
            kallsyms_token_table += content
            kallsyms_token_table_addr += 4
            table_size -= 1

        #print "length of token table", hex(len(kallsyms_token_table))
        tmp = ''
        with open("table", 'w') as output:
            for item in kallsyms_token_table:
                output.write(str((item, ord(item)))+'  ')

        #print [ord(i) for i in kallsyms_token_table]
        
        # Extract kallsyms_token_index
        # Not sure about the index_size
        # From script/kallsyms.c, it has 256 entry, 256*2/8 = 64
        index_size = 64 * 2
        #print "index_addr", hex(kallsyms_token_index_addr), index_size
        #kallsyms_token_index_addr = 0x1a28c430
        while index_size:
            content = self.read_memory(kallsyms_token_index_addr, 4)
            for idx in range(0, 3, 2):
                kallsyms_token_index.append(content[idx:idx+2])
            kallsyms_token_index_addr += 4
            index_size -= 1
        for index in range(len(kallsyms_token_index)):
            content = struct.unpack("<H", kallsyms_token_index[index])
            kallsyms_token_index_v.append(content[0])
            #print content
            #print [i for i in kallsyms_token_index[index]]
        #print "len of token index array", len(kallsyms_token_index_v)
        with open("index", 'w') as output:
            for item in kallsyms_token_index_v:
                output.write(str(item)+'  ')
        print "expand compressed strings"
        off = 0
        for index in range(size+1):
            off = self.kallsyms_expand_symbol(off, symbol_name, kallsyms_names, kallsyms_token_table, kallsyms_token_index_v)
        #off = self.kallsyms_expand_symbol(off, kallsyms_names, kallsyms_token_table_v, kallsyms_token_index_v)




class AddressSpace_test(linux.AMD64PagedMemory):
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
        #offset: debian_x64 lububntu_x64
        #offset2: lubuntu20 centos8 4.11 4.12 4.13 4.14 4.15 4.16 4.18 4.19 4.20 5.3    
        #offset3: cenos7
        #offset4: centos6
        self.offset = offset6
        self.mem_path = mem_path
        self.mem.seek(0)
    


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
    
    kallsyms_address = 0
    for step in range(0, mem.size(), 4096):
        page = mem.read(step & 0xffffffffff000, 0x200 * 8)
        if not page:
            print "Error: no available content"
            continue
        value = self.v(4096, page)
        count = 0
        for item in range(len(value)):
            if value[item] == 0xffffffff9e209000:
                print "found the first element in symbol table", hex(step)
            if item == 0 or item == len(value)-1:
                if value[item] & 0xffffffff00000000 == 0xffffffff00000000:
                    count += 1
            else:
                if value[item] & 0xffffffff00000000 == 0xffffffff00000000:
                    if value[item] > value[item-1] and value[item] < value[item+1]:
                        count += 1
        # An assumption here is that the symbol table is at least larger than one page
        if count == 4096/8:
            print "found partial symbol table at", hex(step)
            kallsyms_address = step
            break
    if kallsyms_address == 0:
        print "cannot find symbol table"
        return
    # Now we find a page that contains a parital symbol table. Then scan backwards to
    # find the start address of symbol table.
    content = self.read_memory(kallsyms_address, 0x8)
    value = self.v(8, content)
    while value[0] & 0xffffffff00000000 == 0xffffffff00000000:
        kallsyms_address -= 0x8
        content = self.read_memory(kallsyms_address, 0x8)
        value = self.v(8, content)
    print "kallsyms_address", hex(kallsyms_address)
    #kallsyms_candidate = [kallsyms_address, kallsyms_address - 0x8, kallsyms_address - 0x16]
    # After finding kallsyms_address, scan the memory and save the symbol table. 
    symbol_table = []
    kallsyms_address += 0x8
    content = self.read_memory(kallsyms_address, 0x8)
    value = self.v(8, content)
    while value[0] & 0xffffffff00000000 == 0xffffffff00000000:
        symbol_table.append(value[0])
        kallsyms_address += 0x8
        content = self.read_memory(kallsyms_address, 0x8)
        value = self.v(8, content)
    print "len of symbol table", len(symbol_table)
    # After the symbol table, the value should be kallsyms_num
    content = self.read_memory(kallsyms_address, 0x8)
    value = self.v(8, content)
    print "kallsyms_num", value[0]
    # Now we can locate the init address of the symbol table
    kallsyms_address = kallsyms_address - value[0]*8
    print "kallsyms_address", hex(kallsyms_address)
    # We have the symbol table. We can find kallsyms_address in the symbol list, which points to the init address
    # of the symbol table. kallsyms_num, kallsyms_token_index and kallsyms_token_table are adjacent. 
    #print hex(symbol_table[0])
    for idx in range(len(symbol_table)):
        print "symbol address", hex(symbol_table[idx])
        if self.vtop(symbol_table[idx]) == kallsyms_address:
            print "found kallsyms"
        if symbol_table[idx]&0xffff == kallsyms_address&0xffff:
            print "find kallsyms in symbol table", idx, hex(symbol_table[idx])

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
    '''
        Set dtb to 1 to avoid searching for dtb
    '''
    addr_space = AddressSpace(mem_path, 1)
    #addr_space = arm.AddressSpaceARM(mem_path, 1)

    '''
    tmp = addr_space.read_memory(paddr, 8)
    if not tmp:
        print "error"
        return
    paddr = addr_space.v(8, tmp)[0]
    paddr = addr_space.vtop(0xffffffff81c336f0)
    paddr = addr_space.vtop(0xffffffff81ed67c0)
    '''
    size = 0x166c9/4096*8
    while size:
        #addr_space.extract_info(paddr, "./tmp")
        #paddr += 4096
        size -= 1
    #addr_space.extract_info(paddr, "./tmp")
    #addr_space.extract_kallsyms_symbols([],0,0,93398,0,0)
    addr_space.find_kallsyms_address()
    #addr_space.find_kallsyms_address_pre_46()
    #addr_space.find_kallsyms_address_pre_46_arm()
    #addr_space.find_kallsyms_address_pre_46_32bit()
    #addr_space.find_token_table(0xff17368)
    #addr_space.find_token_index(0x1a28c098)
    #addr_space.find_modules()
    #addr_space.find_pointer()
    #print hex(paddr)
    #addr_space.extract_info(467322696, "./tmp")
    # 0x1bdab208 this should be where the *next pointer points to. so this is the value in the field *next

    #addr_space.find_KASLR_shift("kallsyms_on_each_symbol")
    #addr_space.find_tasks(0x1c2349d8-3000)

if __name__ == "__main__":
    main()