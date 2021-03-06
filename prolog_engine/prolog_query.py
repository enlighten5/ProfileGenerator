import read_mem as rm
from program import *
from pyswip.core import *
from pyswip import *
import time, mmap, struct
import AddressSpaceARM as arm
class PrologQuery(rm.AddressSpace):
#class PrologQuery(arm.AddressSpaceARM):
    def __init__(self, image_path):
        #arm.AddressSpaceARM.__init__(self, image_path, 0, 0)
        rm.AddressSpace.__init__(self, image_path, 0, 0)

    def construct_kb(self, paddr, input_f, output_f):
        #base_addr = paddr & 0xffffffffff000
        base_addr = paddr
        with open(output_f, 'w') as kb:
            kb.write(":- use_module(library(clpfd))." + "\n")
            kb.write(":- style_check(-singleton).\n")
        #self.extract_info(paddr, output_f)
        self.extract_info(base_addr, output_f)


        with open(output_f, 'a') as outfile:
            with open(input_f, 'r') as inputfile:
                outfile.write(inputfile.read())

    def start_query(self, paddr, query):
        self.log("construct kb \t- " + query)
        self.construct_kb(paddr, "./knowledge/query_rules.pl", "./knowledge/test_query.pl")
    
        self.log("start query \t- " + query)
        p = Prolog()
        p.consult("./knowledge/test_query.pl")
        count = 0
        self.log("finish kb \t- " + query)

        query_cmd = "query_" + query + "(" + str(paddr) + ")" 
        for s in p.query(query_cmd, catcherrors=False):
            count += 1
            if count:
                break
            #print(s["Base_addr"])
        print "count result:", count
        self.log("finish query \t- " + query)



def parse_profile():
    profile = {}
    with open('profile.txt', 'r') as p:
        line = p.readline()
        while line:            
            line = line.strip('\n')
            content = line.split(':')
            if content[0] in profile.keys():
                #print content[0], "in profile"
                if not content[1] in profile[content[0]]:
                    profile[content[0]].append(content[1])
            else:
                #print content[0], "not in profile"
                profile.update({content[0] : [content[1]]})
            line = p.readline()

    keys = profile.keys()
    with open('final_profile', 'w') as output:
        for key in keys:
            #print key, profile[key]
            content = str(key) + '\t' + str(profile[key]) + "\n"
            output.write(content)

def generate_result():
    current_time = time.time()
    while time.time() - current_time < 500:
        pass
    parse_profile()
    print "profile saved in final_profile"


def test():
    prolog_query = PrologQuery(sys.argv[1])
    #prolog_query.find_string("kthreadd")
    #prolog_query.find_string("swapper")
    prolog_query.find_tasks(0xb91b88-3000)

    
    #openwrt
    #prolog_query.find_tasks(0x7040f78-3000)
    #lede
    #prolog_query.find_tasks(0x7058e68-3000)
    #prolog_query.find_tasks(0xed30ee0-3000)
    

    

def main():
    '''
    if len(sys.argv) < 3:
        print "[-] Usage: please provide image path and System.map path at inputs"
        exit(0)
    '''
    prolog_query = PrologQuery(sys.argv[1])
    query = sys.argv[2]
    os.environ["IMAGE_PATH"] = sys.argv[1]
    print os.environ["IMAGE_PATH"]
    image_name = os.path.basename(sys.argv[1])
    symbol_file = image_name + "_symbol_table"
    #prolog_query.parse_system_map(sys.argv[2])
    #print prolog_query.init_top_pgt_from_system_map, prolog_query.init_task_from_system_map
    '''
    virtual_shift = int(prolog_query.dtb_vaddr, 16) - int(prolog_query.init_top_pgt_from_system_map, 16)
    vaddr_init_task = int(prolog_query.init_task_from_system_map, 16) + virtual_shift
    #print hex(vaddr_init_task)
    #vaddr_init_task = 0xffffffff81c18480
    paddr = prolog_query.vtop(vaddr_init_task)
    '''
    #paddr = 0x4018af8-1656
    paddr = 0x1ed8c900 - 1984
    #paddr = prolog_query.find_swapper_page()
    print paddr
    #openwrt
    paddr = 0x1c10480
    #lede
    paddr = 0x15c04c0
    #paddr = prolog_query.vtop(0xffff800000db58b0)
    #goldfish
    #paddr = 0x1e114a0
    #a mount struct
    paddr = 0x19a2d600
    #net_device addr
    #inet_sock
    #paddr = prolog_query.vtop(0xffff9584ded45f80)
    #iomem_resource
    #paddr = prolog_query.vtop(0xffffffff81e4d500+0x1c400000)
    #dentry
    paddr = 0x18ef7a80
    #init_fs
    paddr = 0x38bc070
    #paddr = prolog_query.find_task_struct(paddr)
    #prolog_query.find_string('kthreadd')
    #prolog_query.start_query(int(paddr), "test")
    '''
    What global symbols are needed to start the logic inference?
    init_task
    init_fs -> dentry...
    init_files
    modules
    mount_hashtable -> mount (*)
    file_systems -> file_system_type
    neigh_tables -> neigh_table (*)
    '''
    #for modules, read the first pointer at modules
    #query_cmd = ["init_task", "init_fs", "modules", "mount_hashtable", "neigh_tables", "iomem_resource",
    #             "tcp4", "udp4", "tty_drivers", "proc_root"]
    #"idt_table", "module_kset" do not need to infer layouts
    #query_cmd = ["init_fs"]
    # pre_4.18
    if float(prolog_query.version)*100 < 418:
        query_cmd = ["init_task", "init_fs", "modules", "mount_hashtable", "neigh_tables", "iomem_resource",
                 "tcp4_seq_afinfo", "udp4_seq_afinfo", "tty_drivers", "proc_root", "inet_sock"]
        query_cmd = ["modules"]
        query_object = {"init_task": "task_struct", "init_fs": "fs_struct", "modules": "module", 
                    "mount_hashtable": "mount_hash",
                    "neigh_tables": "neigh_tables", "iomem_resource": "resource",
                    "tcp4_seq_afinfo": "tcp_seq_afinfo", "udp4_seq_afinfo": "udp_seq_afinfo",
                    "tty_drivers": "tty_driver",
                    "proc_root": "proc_dir_entry",
                    "idt_table": "gate_struct",
                    "module_kset": "kset",
                    "inet_sock": "inet_sock"}
    # after_4.18
    elif float(prolog_query.version)*100 >= 418:
        query_cmd = ["init_task", "init_fs", "modules", "mount_hashtable", "neigh_tables", "iomem_resource",
                 "tcp4_seq_ops", "udp_seq_ops", "tty_drivers", "proc_root", "inet_sock", "init_mm"]
        #query_cmd = ["modules"]
        query_object = {"init_task": "task_struct", "init_fs": "fs_struct", "modules": "module", 
                    "mount_hashtable": "mount_hash",
                    "neigh_tables": "neigh_tables", "iomem_resource": "resource",
                    "tcp4_seq_ops": "seq_operations", "udp_seq_ops": "seq_operations",
                    "tty_drivers": "tty_driver",
                    "proc_root": "proc_dir_entry",
                    "idt_table": "gate_struct",
                    "module_kset": "kset",
                    "inet_sock": "inet_sock",
                    "init_mm": "mm_struct"}
    symbol_table = {}

    with open(symbol_file, 'r') as symbol:
        line = symbol.readline()
        while line:
            index = line[::-1].find(' ')
            index = len(line) - index
            #print line[index:]
            if line[index:].strip() in query_cmd:
                print "find", line[index:].strip()
                #Need to add the KASLR shift
                symbol_table[line[index:].strip()] = int(line[:line.find('\t')][:-1], 16) + prolog_query.v_shift
            line = symbol.readline()
    symbol_table["inet_sock"] = 0xffff8c7a578a1c00
    for item in symbol_table.keys():
        print item, symbol_table[item], hex(symbol_table[item])
    '''
    #paddr = prolog_query.vtop(0xffffffff81e104c0+0x1c400000)
    #prolog_query.start_query(paddr, "task_struct")
    paddr = prolog_query.vtop(symbol_table[query])
    if query == 'modules':
        addr = prolog_query.read_memory(int(paddr), 8)
        paddr = prolog_query.vtop(struct.unpack("<Q", addr)[0])

    #if query == "mount_hashtable":

    print "[-]Retrive {0} from symbol table: paddr: {1}".format(query, hex(paddr))
    #Somehow int() is important, otherwise there would be errors. 
    #paddr = prolog_query.vtop(0xffff9f8b94cc8c00)
    prolog_query.start_query(int(paddr), "init_task")
    '''    
    for query in query_cmd:
        paddr = prolog_query.vtop(symbol_table[query])
        if query == 'modules':
            addr = prolog_query.read_memory(int(paddr), 8)
            #module list is the second field in module object, so minus 0x8 to get the initial address
            paddr = prolog_query.vtop(struct.unpack("<Q", addr)[0]) - 0x8
        if query == "mount_hashtable":
            addr = prolog_query.read_memory(int(paddr), 8)
            paddr = prolog_query.vtop(struct.unpack("<Q", addr)[0])
        if query == "neigh_tables":
            #This works for Linux kernel 3.19 and newer
            #addr = prolog_query.read_memory(int(paddr)+8, 8)
            #paddr = prolog_query.vtop(struct.unpack("<Q", addr)[0])
            pass
        if query == "tty_drivers":
            addr = prolog_query.read_memory(int(paddr), 8)
            paddr = prolog_query.vtop(struct.unpack("<Q", addr)[0])
            #tty_driver object remains unchanged. 168 is the object size. 
            paddr -= 168
        if query == "idt_table":
            addr = prolog_query.read_memory(int(paddr), 8)
            paddr = prolog_query.vtop(struct.unpack("<Q", addr)[0])
        if query == "init_task":
            paddr = prolog_query.find_task_struct(paddr)
            print "task:", hex(paddr)

        prolog_query.start_query(int(paddr), query_object[query])

if __name__ == "__main__":
    main()
    #test()

        