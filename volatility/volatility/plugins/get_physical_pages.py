import os
import sys
import volatility.utils as utils
import volatility.plugins.common as common
import volatility.plugins.taskmods as taskmods
import volatility.plugins.addrspaces.i386 as i386
import volatility.plugins.addrspaces.x64 as x64
from time import gmtime, strftime

PAGES_OUTPUT_PATH = os.getenv("HOME") + '/ProfileGenerator/prolog_engine/pages/'
WIN32_OR_64 = 64

class get_physical_pages(taskmods.DllList):
    '''Get page table mapping information'''

    def __init__(self, config, *args, **kwargs):
        taskmods.DllList.__init__(self, config, *args, **kwargs)
        self.kernel_address_space = None
        config.add_option("VIRTUAL", short_option = "V", default = True, action = "store_true", help = "Scan virtual space instead of physical")

    def is_user_pointer(self, buf, idx=0):
        dest = (ord(buf[idx+7]) << 56) + (ord(buf[idx+6]) << 48) + (ord(buf[idx+5]) << 40) + (ord(buf[idx+4]) << 32) + (ord(buf[idx+3]) << 24) + (ord(buf[idx+2]) << 16) + (ord(buf[idx+1]) << 8) + ord(buf[idx])
        return dest

    def get_continuous_pages(self, available_pages):
        dict_page_addr_to_size = {}
        dict_tail_to_page_head = {}
        for (page_addr, page_size) in available_pages:
            if WIN32_OR_64 == 64:
                page_addr += 0xffff000000000000
                kernel_space_start_addr = 0xffff080000000000
            else:
                kernel_space_start_addr = 0x80000000
            if page_addr > kernel_space_start_addr:
                if page_addr not in dict_tail_to_page_head:
                    dict_tail_to_page_head[page_addr + page_size] = page_addr
                    dict_page_addr_to_size[page_addr] = page_size
                else:
                    page_head = dict_tail_to_page_head[page_addr]
                    dict_tail_to_page_head[page_addr + page_size] = page_head
                    dict_page_addr_to_size[page_head] += page_size
        return dict_page_addr_to_size

    def calculate(self):
        #image_name = os.path.basename(self._config.LOCATION)
        image_path = os.path.abspath(self._config.LOCATION).split(":")[1]
        print "image path", image_path
        image_name = os.path.basename(self._config.LOCATION)
        self.log(image_name)
        #self.kernel_address_space = utils.load_as(self._config)

        if WIN32_OR_64 == 32:
            self.kernel_address_space = i386.I386PagedMemory(image_path, 0x1420000)
        elif WIN32_OR_64 == 64:
            self.kernel_address_space = utils.load_as(self._config)
            #self.kernel_address_space = x64.X64PagedMemory(image_path, 0xff1490)
            #self.kernel_address_space = x64.X64PagedMemory(image_path, 0x1605000)
            
        available_pages = self.kernel_address_space.get_available_pages()
        page_info = self.kernel_address_space.get_page_info(0x3810500, 4096)
        addr = page_info.keys()
        addr.sort()
        idx = 0
        for key in addr:
            value = self.is_user_pointer(page_info[key], 0)
            phys = self.kernel_address_space.vtop(value)
            if phys:
                #print hex(key), key-0x3810500, hex(value), hex(phys)
                pass
        
        #    print hex(key), key-0x3810500, hex(self.is_user_pointer(page_info[key], 0)), page_info[key] 
            idx += 1

        p = self.kernel_address_space.vtop(0xffffffff81e10500)
        print "paddr: ", p
        tmp_i = 0
        while tmp_i < 0x5000000:
            s1 = self.kernel_address_space.base.read(0x1000000 + tmp_i, 8)
            s2 = self.kernel_address_space.read_long_long_phys(0x3809000 + tmp_i)
            if s2 and bin(s2 & 0b111111111111) == '0b1100111' and len(bin(s2)) <= 32 and len(bin(s2)) >= 25:
                print "addr", hex(0x3809000 + tmp_i), "content", bin(s2), s1, bin(s2 & 0b1111111), len(bin(s2))
            #print "addr", hex(0x3809000 + tmp_i), "content", bin(s2), s1, bin(s2 & 0b1111111)
            tmp_i += 8
        self.log('Get continuous pages')
        dict_page_addr_to_size = {}
        if WIN32_OR_64 == 64:
            dict_page_addr_to_size = self.get_continuous_pages(available_pages)
            #for addr, size in available_pages:
            #    if addr > 0x80000000:
            #        dict_page_addr_to_size[addr] = size
        elif WIN32_OR_64 == 32:
            for addr, size in available_pages:
                if addr > 0x80000000:
                    dict_page_addr_to_size[addr] = size

        with open(PAGES_OUTPUT_PATH + 'pages.' + image_name, 'w') as output:
            list_addr = dict_page_addr_to_size.keys()
            list_addr.sort()
            for addr in list_addr:
                size = dict_page_addr_to_size[addr]
                physical_addr = self.kernel_address_space.vtop(addr)
                output.write(hex(addr)[:-1] + '\t' + hex(physical_addr)[:-1] + '\t' + str(size) + '\n')
        self.log('Finish')

    def render_text(self, outfd, data):
        if data!=None:
            outfd.write(data)

    def log(self, message):
        print strftime("%Y-%m-%d %H:%M:%S\t", gmtime()), message
        sys.stdout.flush()
