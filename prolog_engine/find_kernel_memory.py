import mmap, struct, os, sys
from time import gmtime, strftime, time
GB = 1024*1024*1024
MB = 1024*1024

class memory_dump():
    def __init__(self, image_path):
        try:
            f = os.open(image_path, os.O_RDONLY)
        except:
            print "Error: open image fail."
            sys.exit(1)
        try:
            self.mem = mmap.mmap(f, 0, mmap.MAP_SHARED, mmap.ACCESS_READ)
        except:
            print "Error: mmap fail."
            sys.exit(1)
        self.image_name = os.path.basename(image_path)
        #Parse elf header
        self.mem.seek(0)
        if "ELF" in self.mem.read(6):
            #print "ELF headers"
            self.has_elf_header = True
            self.offset = self.parse_elf_header()
        else:
            #print "No ELF headers"
            self.has_elf_header = False

    def _read_memory(self, paddr, length):
        '''
            This function is to read memory dump without elf header info.
        '''
        self.mem.seek(paddr)
        value = self.mem.read(length)
        if not value:
            print "Error: fail to read memory at", hex(paddr)
            sys.exit(1)
        if length == 2:
            value = struct.unpack('<H', value)[0]
        elif length == 4:
            value = struct.unpack('<I', value)[0]
        #elif length == 8:
        #    value = struct.unpack('<Q', value)[0]
        return value
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
        
        if self.mem.size() - paddr < length:
            print "Error: read out of bound memory.", hex(paddr), hex(self.mem.size())
            sys.exit(1)

        self.mem.seek(paddr)
        value = self.mem.read(length)
        if not value:
            print "Error: fail to read memory at", hex(paddr)
            sys.exit(1)
        return value
    
    def parse_elf_header(self):
        '''
            Parse elf header 64-bit
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
    def log(self, message):
        print('%s\t%s' %(strftime("%Y-%m-%d %H:%M:%S", gmtime()), message))
        sys.stdout.flush()

    def search_init_task(self):
        '''
        This function is to find the address of the target process name in the memory.
        It is used to facilitate find_tasks method.
        '''
        current = time()
        for step in range(0, self.mem.size(), 4096):
            page = self._read_memory(step, 0x200 * 8)
            if not page:
                continue
            for idx in range(0, 4096, 8):
                #print hex(step+idx), page[idx:idx+8], hex(self.is_user_pointer(page[idx:idx+8], 0))
                if "swapper/0" in page[idx:idx+len("swapper/0")]:
                    print "found swapper/0", hex(step+idx), page[idx-16:idx+32], "time", time() - current
                    current = time()
                    self.find_kallsyms_address(step+idx-31*MB)
                    print "finish recovering kernel symbols, time", time() - current
                    current = time()
                    self.find_KASLR_shift("kallsyms_on_each_symbol", step+idx-31*MB)
                    print "finish computing KASLR shift, time", time() - current
                    return step+idx-31*MB
                    #for tmpidx in range(0, 4096, 8):
                    #    print hex(step+tmpidx), hex(self.is_user_pointer(page[tmpidx:tmpidx+8], 0))
                    #return step
        return None

    def v(self, size, content):
        s = "<" + str(size/8) + "Q"
        value = struct.unpack(s, content)
        return value
    def find_kallsyms_address(self, init_addr = 0):
        #log("start to find kernel symbols")
        kallsyms_address = 0
        found = 0
        for step in range(init_addr, init_addr+62*MB, 4096):
            page = self._read_memory(step, 0x200 * 8)
            if not page:
                #print "no content available"
                continue
            value = list(struct.unpack("<1024I", page))
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
        content = self._read_memory(kallsyms_relative_base, 0x8)
        value = self.v(8, content)
        while value[0] & 0xffffffff00000000 != 0xffffffff00000000:
            kallsyms_relative_base += 0x8
            content = self._read_memory(kallsyms_relative_base, 0x8)
            value = self.v(8, content)
        # If we have luck, this is the kallsyms_relative_base address
        kallsyms_relative_base_v = value[0]

        print "kallsyms_relative_base", hex(kallsyms_relative_base), hex(kallsyms_relative_base_v)
        # The value after it should be kallsyms_num_syms
        content = self._read_memory(kallsyms_relative_base + 0x8, 0x8)
        value = self.v(8, content)
        kallsyms_num_syms = value[0]
        print "kallsyms_num_syms", kallsyms_num_syms, [hex(int(ord(c))) for c in content]
        if kallsyms_num_syms > 1200000 or kallsyms_num_syms == 0:
            find_kallsyms_address(kallsyms_relative_base)
            return
        # Then the init address of kallsyms_offsets can be found by 
        # kallsyms_relative_base - 0x8 - kallsyms_num_syms/2*8
        if not kallsyms_num_syms%2 == 0:
            kallsyms_num_syms += 1
        kallsyms_offsets = kallsyms_relative_base - (kallsyms_num_syms/2*8)
        print "kallsyms_offsets", hex(kallsyms_offsets)
        
        # Now we have kallsyms_offsets and kallsyms_relative_base, we can
        # recover the symbol addresses.
        symbol_address = []
        offsets = []
        number_sysms = kallsyms_num_syms
        while number_sysms >= -1:
            content = self._read_memory(kallsyms_offsets, 0x8)
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
        #log("Found kernel symbols")
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
        #log("FINISH!")

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
        #self.log("finished parsing and saving kernel symbols")

    def find_token_table(self, kallsyms_names_paddr):
        # token_table address is larger than kallsyms_names_paddr
        # Start search from kallsyms_names_paddr
        #log("Start to find kallsyms_token_table")
        #Estimisted gap 4096*0x100
        kallsyms_token_table_addr = kallsyms_names_paddr #+ 4096*250
        candidate = []
        # Read the content
        for step in range(kallsyms_token_table_addr, kallsyms_token_table_addr+31*MB, 8):
            kallsyms_token_table = ""
            kallsyms_token_table_v = []
            # Table_size is larger than 512 in reality
            table_size = 512/8
            init_addr = step
            while table_size:
                content = self._read_memory(init_addr, 8)
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
            print "found kallsyms_token_table_addr"
            #log("kallsyms_token_table found")

            #print [hex(c) for c in candidate]
            '''
            with open("table", 'w') as output:
                for item in kallsyms_token_table:
                    output.write(str((item, hex(int(ord(item)))))+'\n')
            '''
            return candidate[0]

    def find_token_index(self, token_table_paddr):
        #self.log("Start to find kallsyms_token_index")
        result = 0
        for kallsyms_token_index_addr in range(token_table_paddr, token_table_paddr+31*MB, 8):
            kallsyms_token_index = []
            kallsyms_token_index_v = []
            # From script/kallsyms.c, it has 256 entry, 256*2/8 = 64
            index_size = 64
            #print "index_addr", hex(kallsyms_token_index_addr), index_size
            init_addr = kallsyms_token_index_addr
            while index_size:
                content = self._read_memory(init_addr, 8)
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
        #self.log("kallsyms_token_index found")
        '''
        with open("index", 'w') as output:
            for item in kallsyms_token_index_v:
                output.write(hex(int(str(item)))+'\n')
        '''
        #for index in range(len(kallsyms_token_index)):
        #    print [c for c in kallsyms_token_index[index]]
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

        # Extract kallsyms_names
        while name_size:
            content = self._read_memory(kallsyms_names_addr, 4096)
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
        #table_size = 512
        #kallsyms_token_table_addr -= 16
        while table_size+32:
            content = self._read_memory(kallsyms_token_table_addr, 8)
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
            content = self._read_memory(kallsyms_token_index_addr, 8)
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
    def find_KASLR_shift(self, target, init_addr):
        location = 0
        symbol_file = self.image_name + "_symbol_table"
        with open(symbol_file, 'r') as symbol:
            line = symbol.readline()
            while line:
                index = line.find('\t')
                if "__kstrtab_" + target in line[index:].strip():
                    target_vaddr = int(line[:line.find('\t')][:-1], 16)
                line = symbol.readline()
        self.log("start search KASLR shift")
        init_addr &= 0xffffffffff000
        for step in range(init_addr, init_addr+62*MB, 4096):
            page = self.read_memory(step & 0xffffffffff000, 0x200 * 8)
            if not page:
                continue
            for idx in range(0, 4096, 8):
                #print hex(step+idx), page[idx:idx+8], hex(self.is_user_pointer(page[idx:idx+8], 0))
                if not target in page[idx:idx+2*len(target)]:
                    continue
                #print "found ", target, hex(step+idx), page[idx-16:idx+32]
                for tmpidx in range(idx, idx+2*len(target), 1):
                    if target == page[tmpidx:tmpidx+len(target)]:
                        print "found ", target, hex(step+tmpidx), page[idx-16:idx+32]
                        target_paddr = step + tmpidx
                        break
                if not target_vaddr & 0xffff == target_paddr & 0xffff:
                    continue
                self.log("end search KASLR shift")
                return target_vaddr - target_paddr
        self.log("[-] Error: cannot find KASLR shift")


def main():
    # kernel_mem = find_kernel()
    image_path = sys.argv[1]
    mem = memory_dump(image_path)
    mem.search_init_task()



if __name__ == "__main__":
    main()