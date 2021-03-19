import mmap, struct, os, sys
from time import gmtime, strftime
import LinuxMemory as linux
class AddressSpaceARM(linux.ArmAddressSpace):
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
        #self.offset = offset8
        self.mem_path = mem_path
        self.mem.seek(0)
        
        if "ELF" in self.mem.read(6):
            print "ELF headers"
            self.has_elf_header = True
        else:
            print "No ELF headers"
            self.has_elf_header = False
        # Identify Linux version
        version_idx = self.mem.find("Linux version") + len("Linux version ")
        if version_idx:
            self.mem.seek(version_idx)
            version = self.mem.read(8)
            index = version.index('.')
            index2 = version[index+1:].index('.')
            self.version = version[:index+index2+1]
            print "Linux version", self.version
        else:
            print "[Error] - cannot identify Linux version"
            self.version = 0
        #self.extract_info(self.vtop(0xffffffc0010f5cf0), "./tmp")
        '''
        self.image_name = os.path.basename(mem_path)
        if not os.path.exists(self.image_name + '_symbol_table'):
            self.find_kallsyms_address_pre_46_arm()

        self.shift = self.find_KASLR_shift("kallsyms_on_each_symbol")
        '''
        '''
        store_dtb = "./" + self.image_name + "_dtb"
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
        #self.dtb_vaddr = dtb_vaddr
        self.dtb = dtb
        if dtb:
            self.dtb = dtb
        elif g_dtb:
            self.dtb = g_dtb
        else:
            self.find_dtb(0x1000000)
            with open(store_dtb, 'w') as fd:
                fd.write(str(self.dtb))
        '''
    
    def log(self, message):
        print('%s\t%s' %(strftime("%Y-%m-%d %H:%M:%S", gmtime()), message))
        sys.stdout.flush()

    def find_KASLR_shift(self, target):
        location = 0
        symbol_file = self.image_name + "_symbol_table"
        self.log("start search KASLR shift")
        for step in range(0, self.mem.size(), 4096):
            page = self.read_memory(step & 0xffffffffff000, 0x200 * 8)
            if not page:
                continue
            for idx in range(0, 4096, 8):
                #print hex(step+idx), page[idx:idx+8], hex(self.is_user_pointer(page[idx:idx+8], 0))
                if target in page[idx:idx+2*len(target)]:
                    #print "found ", target, hex(step+idx), page[idx-16:idx+32]
                    for tmpidx in range(idx, idx+2*len(target), 1):
                        if target == page[tmpidx:tmpidx+len(target)]:
                            print "found ", target, hex(step+tmpidx), page[idx-16:idx+32]
                            location = step+tmpidx
                            with open(symbol_file, 'r') as symbol:
                                line = symbol.readline()
                                while line:
                                    index = line.find('\t')
                                    if "__kstrtab_"+target in line[index:].strip():
                                        print "find", line[index:].strip()
                                        print "virtual to physical shift:", hex(int(line[:line.find('\t')][:-1], 16) - location)
                                        self.log("end search KASLR shift")
                                        return int(line[:line.find('\t')][:-1], 16) - location
                                    line = symbol.readline()
                            return 0
                            
                        if location:
                            break

        self.log("end search KASLR shift")

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
    def v(self, size, content):
        s = "<" + str(size/8) + "Q"
        value = struct.unpack(s, content)
        return value

    def vtop(self, vaddr):
        if vaddr == 0xffffffffffffffff:
            return None
        if vaddr > 0xffffffc000000000 and vaddr & 0xffffffc000000000 == 0xffffffc000000000:
            paddr = vaddr - 0xffffffc000000000
            if paddr > self.mem.size():
                return None
            else:
                return paddr
        if vaddr > 0xffffff8008000000 and vaddr & 0xffffff8008000000 == 0xffffff8008000000:
            paddr = vaddr - 0xffffff8008000000
            if paddr > self.mem.size():
                return None
            else:
                return paddr
        '''
        #if vaddr & 0xffff800000000000 == 0xffff800000000000:
        #if vaddr & 0xffffffc000000000 == 0xffffffc000000000:
        if vaddr & 0xffffff8008000000 == 0xffffff8008000000:
            paddr = vaddr - 0xffffff8008000000
            if paddr > self.mem.size():
                return None
            else:
                return paddr
        elif vaddr & 0xffffffc000000000 == 0xffffffc000000000:
            paddr = vaddr - 0xffffffc000000000
            if paddr > self.mem.size():
                return None
            else:
                return paddr
        else:
            return None
        '''
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
                    print "[-] ", item*8, hex(paddr+item*8), "pointer", hex(number), hex(self.vtop(number)), [c for c in content[item*8:item*8+8]]
                valid_pointer[item*8] = phys_addr
            else:
                if number < 0xffff:
                    if number == 0x0:
                        if self.verbose:
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

    def find_task_struct(self, paddr):
        #init_task = self.vtop(vaddr)
        page = self.read_memory(paddr, 0x200 * 8)
        value = struct.unpack("<512Q", page)
        
        for item in range(len(value)):
            if "swapper" in page[item*8:(item+1)*8]:
                print "found swapper", item*8
                break
        comm_offset = item*8
        for item in range(len(value)):
            num = value[item]
            target_addr = self.vtop(value[item])
            if not target_addr:
                continue
            if target_addr == paddr+item*8:
                continue
            comm = self.read_memory(target_addr -item*8 + comm_offset, 8)
            print [c for c in comm]
            if all(ord(c) >= 36 and ord(c) <= 122 or ord(c)==0 for c in comm):
                if len(comm.replace('\x00', '')) >= 4:
                    print "found task", item*8, comm
                    return self.vtop(value[item+1])-item*8
        task_offset = item*8

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
                if target in page[idx:idx+len(target)+8]:
                    for tmp_idx in range(idx, idx+len(target)+8, 1):
                        if target == page[tmp_idx:tmp_idx+len(target)]:
                            print "found ", target, hex(step+idx), page[idx-16:idx+32]
                    #for tmpidx in range(0, 4096, 8):
                    #    print hex(step+tmpidx), hex(self.is_user_pointer(page[tmpidx:tmpidx+8], 0))
                    #return step
            
        print "[-] Error: target not found"
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
                            print "found task struct at", comm , phys_addr, addr + 3000 - gap
                    '''
                gap = addr+3000 - (addr + item * 8)
                target_comm = phys_addr + gap
                comm = self.read_memory(target_comm, 8)
                if not comm:
                    continue
                if "swapper" in comm:
                    print "found next task at", comm , hex(addr + item * 8)
                
                if all( ord(c) >= 45 and ord(c) <= 122 or ord(c)==0 for c in comm ):
                    if len(comm.replace('\x00', '')) > 4:
                        #if self.verbose:
                        print "found next task at", comm , hex(addr + item * 8), gap
    def find_tasks2(self, addr):
        page = self.read_memory(addr, 4096)
        value = struct.unpack("<512Q", page)
        for index in range(len(value)):
            number = value[index]
            paddr = self.vtop(number)
            if not paddr:
                continue
            for init_addr in range(addr, addr+3000, 8):
                target_pname = paddr + addr+3000 - init_addr
                pname = self.read_memory(target_pname, 8)
                if "swapper" in pname:
                    print "found swapper"
                if all(ord(c) >= 45 and ord(c) <= 122 or ord(c)==0 for c in pname) and len(pname.replace('\x00', '')) > 4:
                    print "found task struct at", pname , hex(init_addr), addr + 3000 - init_addr
                    for tasks_addr in range(init_addr, addr+3000, 8):
                        p_addr = self.vtop(value[(tasks_addr-addr)/8])
                        if not p_addr:
                            continue
                        tasks_name_addr = p_addr - (tasks_addr-init_addr) + addr + 3000 - init_addr
                        tasks_name = self.read_memory(tasks_name_addr, 8)
                        if all(ord(c) >= 45 and ord(c) <= 122 or ord(c)==0 for c in tasks_name) and len(tasks_name.replace('\x00', '')) > 4:
                            print "found tasks list", tasks_name, hex(tasks_addr), tasks_addr - init_addr
                            #break
                    print "name offset", addr+3000-init_addr
                    print '----------------------'

                   

    def find_kallsyms_address_pre_46_arm(self):
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

    def extract_kallsyms_symbols(self, symbol_name, 
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
        '''
        with open("names", 'w') as output:
            for item in kallsyms_names:
                output.write(str((item, ord(item)))+'\n')
        '''

        # Extract kallsyms_token_table
        table_size = (kallsyms_token_index_addr - kallsyms_token_table_addr)/8
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

        #print "length of token table", hex(len(kallsyms_token_table))
        tmp = ''
        '''
        with open("table", 'w') as output:
            for item in kallsyms_token_table:
                output.write(str((item, ord(item)))+'  ')
        '''
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
        '''
        print "expand compressed strings"
        off = 0
        for index in range(size+1):
            off = self.kallsyms_expand_symbol(off, symbol_name, kallsyms_names, kallsyms_token_table, kallsyms_token_index_v)
        #off = self.kallsyms_expand_symbol(off, kallsyms_names, kallsyms_token_table_v, kallsyms_token_index_v)

    def find_token_table(self, kallsyms_names_paddr):
        # token_table address is larger than kallsyms_names_paddr
        # Start search from kallsyms_names_paddr
        kallsyms_token_table_addr = kallsyms_names_paddr
        #kallsyms_token_table_addr = 0x13b81000
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

    def find_token_index(self, token_table_paddr):
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
        '''
        with open("index", 'w') as output:
            for item in kallsyms_token_index_v:
                output.write(str(item)+'\n')
        '''
        
        if not result:
            print "Cannot find token_index"
        else:
            return result

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

    def find_KASLR_shift(self, target):
        location = 0
        symbol_file = self.image_name + "_symbol_table"
        self.log("start search KASLR shift")
        for step in range(0, self.mem.size(), 4096):
            page = self.read_memory(step & 0xffffffffff000, 0x200 * 8)
            if not page:
                continue
            for idx in range(0, 4096, 8):
                #print hex(step+idx), page[idx:idx+8], hex(self.is_user_pointer(page[idx:idx+8], 0))
                if target in page[idx:idx+2*len(target)]:
                    #print "found ", target, hex(step+idx), page[idx-16:idx+32]
                    for tmpidx in range(idx, idx+2*len(target), 1):
                        if target == page[tmpidx:tmpidx+len(target)]:
                            print "found ", target, hex(step+tmpidx), page[idx-16:idx+32]
                            location = step+tmpidx
                            with open(symbol_file, 'r') as symbol:
                                line = symbol.readline()
                                while line:
                                    index = line.find('\t')
                                    if "__kstrtab_" + target in line[index:].strip():
                                        print "find", line[index:].strip()
                                        print "virtual to physical shift:", hex(int(line[:line.find('\t')][:-1], 16) - location)
                                    line = symbol.readline()
                            self.log("end search KASLR shift")
                            return
                        if location:
                            break
                    #for tmpidx in range(0, 4096, 8):
                    #    print hex(step+tmpidx), hex(self.is_user_pointer(page[tmpidx:tmpidx+8], 0))
                    #return step
        self.log("end search KASLR shift")