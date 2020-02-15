import os
import sys
from time import gmtime, strftime
from pyswip.core import *
from pyswip import *
import random

PAGE_PATH = './pages/'
MAX_NODE_SIZE = 64
SEARCH_LEN = 128
MAX_NODE_COUNT = 220000
WIN32_OR_64 = 64
WORD_SIZE = WIN32_OR_64 / 8
g_dict_paddr_to_vaddr = {}
g_dict_vaddr_to_paddr = {}
set_vaddr_page = set()
# image_path = "/home/zhenxiao/DeepMem/memory_dumps/linux-sample-1.bin"

global info_global
def main():
    image_path = sys.argv[1]
    print_configure()
    image_name = os.path.basename(image_path)
    log(image_name)

    log('get available_pages')
    dict_paddr_to_size, set_vaddr_page = read_available_pages(image_name)

    log('find pointer-dest map')
    #dict_vaddr_to_dest = get_pointer_to_dest(image_path, dict_paddr_to_size, set_vaddr_page)
    #addr = dict_vaddr_to_dest.keys()
    #addr.sort()


    paddr = vaddr_to_paddr(0xFFFF88001C278080) # apache task struct address
    print("paddr: ", hex(paddr))
    keys = dict_paddr_to_size.keys()
    keys.sort()
    #kb1, kb2, kb3 = extract_info(image_path, paddr, 4096, set_vaddr_page, "placeholder")

    point = read_pointer(paddr+408)
    print hex(point)
    #query_task_struct(image_path, paddr)
    #query_mm_struct(424)

    assertz = Functor("assertz")
    ispointer = Functor("ispointer", 1)
    isstring = Functor("isstring", 1)
    isint = Functor("isint", 1)

    X = Variable()
    Y = Variable()
    q = Query(ispointer(X))
    while q.nextSolution():
        pass
        #print(X.value)
    q.closeQuery()

    file_h = open("./pages/kb_all.pl", 'w')
    file_h.write(":- discontiguous(ispointer/3)." + "\n")
    file_h.write(":- discontiguous(isint/3)." + "\n")
    file_h.write(":- discontiguous(isstring/3)." + "\n")
    file_h.close()


    valid_p = extract_info_r(image_path, paddr, 1024, set_vaddr_page, "ts_struct")
    keys = valid_p.keys()
    for key in keys:
        extract_info_r(image_path, valid_p[key], 1024, set_vaddr_page, "ts_struct")
    #extract_info(image_path, 526256192, 400, set_vaddr_page, "mm_struct")
    
    log('finish')


def read_pointer(paddr):
    with open("/home/zhenxiao/DeepMem/memory_dumps/linux-sample-1.bin", 'r') as image:
        image.seek(paddr)
        content = image.read(8)
        target_vaddr = hex(is_valid_pointer_64(content, 0, set_vaddr_page))[:-1]
        target_paddr = vaddr_to_paddr(int(target_vaddr, base=16))
    if not target_paddr:
        return False
    else:
        return target_paddr


def extract_info(image_path, paddr, size, set_vaddr_page, name, file_h = None):
    global info_global
    valid_pointer = {}
    valid_comm = {}
    valid_int = {}
    with open(image_path, 'r') as image:
        image.seek(paddr)
        print "base address", hex(paddr)
        content = image.read(size)
        i = 0
        while i < 4096:
            if len(content[i:i+8]) < 8:
                break
            #if hex(is_user_pointer(content[i:i+8], 0)) == "0x160d3b8":
        #    print "find it at", i
        #if not hex(is_user_pointer(content[i:i+8], 0)) == '0x0':
            print("raw bytes at ", hex(paddr + i), i, content[i:i+8], hex(is_user_pointer(content[i:i+8], 0)))
            i += 8 

def extract_info_r(image_path, paddr, size, set_vaddr_page, output):
    valid_pointer = {}
    valid_comm = {}
    valid_int = {}
    valid_long = {}
    
    image = open(image_path, 'r')
    image.seek(paddr)
    content = image.read(size)
    # find pointers
    i = 0
    while i < len(content):
        tmp = content[i:i+8]
        if(tmp.endswith("\xff\xff")):
            if not len(tmp)==8:
                break
            dest = is_valid_pointer_64(tmp, 0, set_vaddr_page)
            if dest: 
                valid_pointer[i] = vaddr_to_paddr(int(hex(dest)[:-1], 16))
                i += 7
                
        i += 1
    # find strings
    idx = 0
    while idx < len(content):
        tmp = content[idx:idx+8]
        if tmp.startswith('\x00'):
            idx += 1
            continue
        find_comm = tmp.replace('\x00', '').replace('\xff', '')
        tmp_len = 0
        for item in find_comm:
            if ord(item) >= 0x30 and ord(item) <= 0x7f:
                tmp_len += 1
        if tmp_len == len(find_comm) and len(find_comm) > 2:
            valid_comm[idx] = find_comm
            #print("found string at", idx, tmp)
            idx = idx + 7
        idx += 1
    # find unsigned long 
    i = 0
    while i < len(content):
    #for i in range(len(content)):
        tmp = content[i:i+4]
        if not tmp.endswith("\x00\x00"):
            i += 1
            continue
        # not entirely true    
        if len(tmp.replace('\xff', '')) < 4:
            i += 4
            continue
        tmp_len = 0
        summ = 0
        for idx in reversed(range(len(tmp))):
            summ += ord(tmp[idx]) << 8*idx
            if ord(tmp[idx]) < 0xff and ord(tmp[idx]) > 0x00:
                tmp_len += 1
        if summ < 9000 and tmp_len > 0:
            valid_int[i] = summ
            i += 3
            #print("found pid", i, tmp, summ)
        i += 1

    i = 0  
    while i < len(content)-8:
        tmp = content[i:i+8]
        if not tmp.endswith("\x00\x00"):
            i += 1
            continue
        # not entirely true    
        if len(tmp.replace('\xff', '')) < 4:
            i += 8
            continue
        if len(tmp.replace('\x00', '')) < 4:
            i += 8
            continue
        tmp_len = 0
        summ = 0
        for idx in reversed(range(len(tmp))):
            summ += ord(tmp[idx]) << 8*idx
            if ord(tmp[idx]) < 0xff and ord(tmp[idx]) > 0x00:
                tmp_len += 1
        if tmp_len > 0 and summ > 0x10000000000:
            valid_long[i] = is_user_pointer(tmp, 0)
            #if paddr == 526256192:
            #    print("found unsigned long", i, tmp, hex(is_user_pointer(tmp, 0)))
            #i += 7
                
        i += 1
    #if paddr == 0x1605000:
    i = 0
    #while i < 4096:
    #    if content[i:i+2] == "\xe3\x01":
        #    print "find it at", i
        #if not hex(is_user_pointer(content[i:i+8], 0)) == '0x0':
    #        print("raw bytes at ", paddr + i, content[i:i+8], hex(is_user_pointer(content[i:i+8], 0)))
    #    i += 8 
    image.close()

    kb_all = open(output, 'a')
    keys = valid_pointer.keys()
    keys.sort()
    for key in keys:
        fact = "ispointer(" + str(paddr) + "," + str(key) + "," + str(valid_pointer[key]) + ")." + "\n"
        kb_all.write(fact)
          
    keys = valid_int.keys()
    keys.sort()
    for key in keys:
        fact = "isint(" + str(paddr) + "," + str(key) + "," + str(valid_int[key]) + ")." + "\n"
        kb_all.write(fact)

    keys = valid_comm.keys()
    keys.sort()
    for key in keys:
        fact = "isstring(" + str(paddr) + "," + str(key) + "," + "string" + ")." + "\n"
        kb_all.write(fact)
        
    keys = valid_long.keys()
    keys.sort()
    for key in keys:
        fact = "islong(" + str(paddr) + "," + str(key) + "," + str(valid_long[key]) + ")." + "\n"
        kb_all.write(fact)

    kb_all.write("\n")
    kb_all.close()
    
    return valid_pointer


def output_dict(file_path, dicts, paddr):
    keys = dicts.keys()
    keys.sort()
    # check this should be a or r
    with open(file_path, 'a') as output:
        output.write("from " + hex(paddr) + '\n')
        for key in keys:
            output.write(str(key) + '\t' + str(dicts[key]) + '\n')

def write_output_file(file_path, list_node_vaddr, dict_node_to_ln, dict_node_to_rn, dict_node_to_lp, dict_node_to_rp, dict_node_vaddr_to_size, dict_vaddr_to_vector, dict_vaddr_to_label, obj_type=None):#, set_node_vaddr_train):
    output_graph = open(file_path, 'w')
    for node_vaddr in list_node_vaddr:
        ln_str = rn_str = ''
        if node_vaddr in dict_node_to_ln:
            ln_str = str(hex(dict_node_to_ln[node_vaddr]))
        if node_vaddr in dict_node_to_rn:
            rn_str = str(hex(dict_node_to_rn[node_vaddr]))
        lp_str = set_to_string(dict_node_to_lp[node_vaddr])
        rp_str = set_to_string(dict_node_to_rp[node_vaddr])
        if node_vaddr in dict_node_vaddr_to_size and node_vaddr in dict_vaddr_to_vector:
            output_str = str(hex(node_vaddr)) + '\t' + ln_str + '\t' + rn_str + '\t' + lp_str + '\t' + rp_str + '\t' + str(dict_node_vaddr_to_size[node_vaddr]) + '\t' + list_to_str(dict_vaddr_to_vector[node_vaddr])
            if node_vaddr in dict_vaddr_to_label and (obj_type == None or obj_type in dict_vaddr_to_label[node_vaddr]):
                output_str += '\t' + dict_vaddr_to_label[node_vaddr]
            output_str += '\n'
            output_graph.write(output_str)
    output_graph.close()

def print_configure():
    log('PAGE_PATH:\t%s' %PAGE_PATH)
    log('MAX_NODE_SIZE:\t%d' %MAX_NODE_SIZE)
    log('32_OR_64:\t%d' %WIN32_OR_64)
    log('WORD_SIZE:\t%d' %WORD_SIZE)
    sys.stdout.flush()

def segmentation(list_ptr):
    set_ptr = set(list_ptr)
    word_size = WIN32_OR_64 / 8
    dict_node_vaddr_to_size = {}
    list_ptr.sort()
    for idx, ptr in enumerate(list_ptr):
        if ptr + word_size not in set_ptr:
            if idx + 1 < len(list_ptr):
                node_size = list_ptr[idx + 1] - (ptr + word_size)
                if node_size >= 4096:
                    pass
                elif node_size > MAX_NODE_SIZE:
                    dict_node_vaddr_to_size[ptr + word_size] = MAX_NODE_SIZE
                else:
                    dict_node_vaddr_to_size[ptr + word_size] = node_size
    return dict_node_vaddr_to_size



def read_available_pages(image_name):
    global g_dict_paddr_to_vaddr
    global g_dict_vaddr_to_paddr
    dict_paddr_to_size = {}
    global set_vaddr_page
    with open(PAGE_PATH + 'pages.' + image_name, 'r') as page:
        for line in page:
            s = line.strip().split('\t')
            vaddr = int(s[0])
            paddr = int(s[1])
            size = int(s[2])
            dict_paddr_to_size[paddr] = size
            for i in range(0, size, 4096):
                g_dict_paddr_to_vaddr[paddr + i] = vaddr + i
                g_dict_vaddr_to_paddr[vaddr + i] = paddr + i
                set_vaddr_page.add(vaddr + i)
    return dict_paddr_to_size, set_vaddr_page
    

def get_continuous_pages(available_pages):
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

def set_to_string(set_x):
    return str([hex(x) for x in set_x]).replace('[]','').replace('[\'','').replace('\']','').replace('\', \'',',')

def list_to_str(l):
    out = ''
    for x in l:
        out += str(x) + ' '
    return out.strip()

def get_obj_list(path, obj_type):
    obj_list = {}
    f = open(path, 'r')
    for line in f:
        line = line.strip()
        s = line.split('\t')
        if s[0] == obj_type:
            obj_offset = int(s[1])
            obj_type = s[0]
            obj_size = int(s[2])
            obj_list[obj_offset] = (obj_type, obj_size)
    f.close()
    return obj_list

def is_valid_pointer_32(buf, idx, set_vaddr_page):
    if ord(buf[idx+3]) > 0x80 and ord(buf[idx]) % 4 == 0:
        dest = (ord(buf[idx+3]) << 24) + (ord(buf[idx+2]) << 16) + (ord(buf[idx+1]) << 8) + ord(buf[idx])
        if (dest >> 12 << 12) in set_vaddr_page:
            return dest 
    return None

def is_valid_pointer_64(buf, idx, set_vaddr_page):
    #if ord(buf[idx+7]) == 0xff and ord(buf[idx+6]) == 0xff and ord(buf[idx+5]) > 0x08 and ord(buf[idx]) % 4 == 0:
    dest = (ord(buf[idx+7]) << 56) + (ord(buf[idx+6]) << 48) + (ord(buf[idx+5]) << 40) + (ord(buf[idx+4]) << 32) + (ord(buf[idx+3]) << 24) + (ord(buf[idx+2]) << 16) + (ord(buf[idx+1]) << 8) + ord(buf[idx])
    if (dest >> 12 << 12) in set_vaddr_page:
        return dest 
    return None

def is_user_pointer(buf, idx):
    dest = (ord(buf[idx+7]) << 56) + (ord(buf[idx+6]) << 48) + (ord(buf[idx+5]) << 40) + (ord(buf[idx+4]) << 32) + (ord(buf[idx+3]) << 24) + (ord(buf[idx+2]) << 16) + (ord(buf[idx+1]) << 8) + ord(buf[idx])
    return dest
def get_page_content(available_pages):
    dict_page_addr_to_content = {}
    dict_addr_to_page_head = {}
    set_page_break = set()
    for (page_addr, page_size) in available_pages:
        if WIN32_OR_64 == 64:
            page_addr += 0xffff000000000000
            kernel_space_start_addr = 0xffff080000000000
        else:
            kernel_space_start_addr = 0x80000000
        if page_addr > kernel_space_start_addr:
            page_content = kernel_address_space.read(page_addr, page_size)
            page_content = [ord(c) for c in page_content]
            if page_content != None:
                if page_addr - page_size not in dict_page_addr_to_content:
                    dict_page_addr_to_content[page_addr] = page_content
                else:
                    dict_page_addr_to_content[page_addr - page_size] += page_content
    for (page_addr, page_content) in dict_page_addr_to_content.iteritems():
        for i in range(len(page_content)/0x1000):
            dict_addr_to_page_head[page_addr + i*0x1000] = page_addr
        set_page_break.add(page_addr + len(page_content))
    return dict_page_addr_to_content, set_page_break, dict_addr_to_page_head

def get_pointer_to_dest(image_path, dict_paddr_to_size, set_vaddr_page):
    dict_vaddr_to_dest = {}
    list_paddr = dict_paddr_to_size.keys()
    list_paddr.sort()
    with open("./pages/address.txt", 'w') as address_output:
        for k in list_paddr:
            address_output.write(hex(k) + '\n')
    with open(image_path, 'r') as image:
        for paddr in list_paddr:
            page_size = dict_paddr_to_size[paddr]
            image.seek(paddr)
            page_content = image.read(page_size)
            if len(page_content) == 0:
                continue
            for offset in range(0, len(page_content), WIN32_OR_64 / 8):
                if WIN32_OR_64 == 64:
                    dest = is_valid_pointer_64(page_content, offset, set_vaddr_page)
                elif WIN32_OR_64 == 32:
                    dest = is_valid_pointer_32(page_content, offset, set_vaddr_page)
                if dest != None:
                    dict_vaddr_to_dest[paddr_to_vaddr(paddr + offset)] = dest
    return dict_vaddr_to_dest

def paddr_to_vaddr(paddr):
    if paddr >> 12 << 12 in g_dict_paddr_to_vaddr:
        return g_dict_paddr_to_vaddr[paddr >> 12 << 12] + paddr % 4096
    else:
        return None

def vaddr_to_paddr(vaddr):
    if vaddr >> 12 << 12 in g_dict_vaddr_to_paddr:
        return g_dict_vaddr_to_paddr[vaddr >> 12 << 12] + vaddr % 4096
    else:
        return None

def log(message):
    print('%s\t%s' %(strftime("%Y-%m-%d %H:%M:%S", gmtime()), message))
    sys.stdout.flush()

if __name__ == "__main__":
    main()
    
    