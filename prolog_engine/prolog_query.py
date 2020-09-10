import read_mem as rm
from program import *
from pyswip.core import *
from pyswip import *
import time
class PrologQuery(rm.AddressSpace):
    def __init__(self, image_path):
        #rm.AddressSpace.__init__(self, image_path, 0x3809000)
        rm.AddressSpace.__init__(self, image_path, 0)

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

    def start_query(self, paddr):
        self.log("construct kb")
        #self.construct_kb(paddr, "./knowledge/init_rules.pl", "./knowledge/start_query.pl")
        self.construct_kb(paddr, "./knowledge/query_rules.pl", "./knowledge/test_query.pl")
    
        self.log("start query")
        p = Prolog()
        p.consult("./knowledge/test_query.pl")
        count = 0
        self.log("finish kb")

        #query_cmd = "possible_anything_no_order(Base_addr)"
        #query_cmd = "possible_task_struct(" + str(paddr) + ")" 
        query_cmd = "query_task_struct(" + str(paddr) + ")" 
        #query_cmd = "test(" + str(paddr) + ")" 
        for s in p.query(query_cmd, catcherrors=False):
            count += 1
            if count:
                break
            #print(s["Base_addr"])
        print "count result:", count


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
    prolog_query.find_string("kthreadd")
    #openwrt
    #prolog_query.find_tasks(0x7040f78-3000)
    #lede
    #prolog_query.find_tasks(0x7058e68-3000)
    #prolog_query.find_tasks(0xed30ee0-3000)
    

    

def main():
    if len(sys.argv) < 3:
        print "[-] Usage: please provide image path and System.map path at inputs"
        exit(0)
    
    prolog_query = PrologQuery(sys.argv[1])
    os.environ["IMAGE_PATH"] = sys.argv[1]
    prolog_query.parse_system_map(sys.argv[2])
    print prolog_query.init_top_pgt_from_system_map, prolog_query.init_task_from_system_map
    '''
    virtual_shift = int(prolog_query.dtb_vaddr, 16) - int(prolog_query.init_top_pgt_from_system_map, 16)
    vaddr_init_task = int(prolog_query.init_task_from_system_map, 16) + virtual_shift
    #print hex(vaddr_init_task)
    #vaddr_init_task = 0xffffffff81c18480
    paddr = prolog_query.vtop(vaddr_init_task)
    '''
    #paddr = 0x4018af8-1656
    paddr = 0x1ed8c900 - 1984
    paddr = prolog_query.find_swapper_page()
    print paddr
    #openwrt
    paddr = 0x1c10480
    #lede
    paddr = 0x15c04c0
    paddr = prolog_query.vtop(0xffffffff872104c0)
    paddr = 0x1c2349d8 - 2584
    #goldfish
    #paddr = 0x1e114a0

    pid = os.fork()
    if pid > 0:
        # start_query takes a number (dec or hex) as input, not string
        #paddr = prolog_query.find_swapper_page()
        prolog_query.start_query(int(paddr))
        print os.environ["IMAGE_PATH"]
        #prolog_query.pslist(paddr)
    else:
        pass
        #generate_result()

    # Ubuntu_x64
    #prolog_query.start_query(0x3810500)
    # Linux-sample
    #prolog_query.start_query(0x160d020)
    # Debian
    #prolog_query.start_query(0x14871f0)
    # lubuntu_x64_ASLR
    #prolog_query.start_query(0x11210500)
    # 4.11
    #prolog_query.start_query(0x13e104c0)
    # 4.12
    #prolog_query.start_query(0x1a4104c0)
    # 4.13
    #prolog_query.start_query(0x16210480)
    # 4.14_2
    #prolog_query.start_query(0x7610480)
    # 4.18_2
    #prolog_query.start_query(0x5c12740)
    # 4.20 randstruct
    #prolog_query.start_query(0x9413740)

if __name__ == "__main__":
    #main()
    test()

        