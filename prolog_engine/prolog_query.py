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
        with open(output_f, 'w') as kb:
            kb.write("use_module(library(clpfd))." + "\n")
            kb.write(":- discontiguous(ispointer/3)." + "\n")
            kb.write(":- discontiguous(isint/3)." + "\n")
            kb.write(":- discontiguous(isstring/3)." + "\n" + "\n")
            kb.write(":- discontiguous(islong/3)." + "\n" + "\n")

        self.extract_info(paddr, output_f)

        with open(output_f, 'a') as outfile:
            with open(input_f, 'r') as inputfile:
                outfile.write(inputfile.read())

    def start_query(self, paddr):
        self.log("construct kb")
        self.construct_kb(paddr, "./knowledge/init_rules.pl", "./knowledge/start_query.pl")
    
        self.log("start query")
        p = Prolog()
        p.consult("./knowledge/start_query.pl")
        count = 0
        #query_cmd = "possible_anything_no_order(Base_addr)"
        query_cmd = "possible_anything(Base_addr)"
        for s in p.query(query_cmd, catcherrors=False):
            count += 1
            #print(s["Base_addr"])
        #print "count result:", count


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
    while time.time() - current_time < 600:
        pass
    parse_profile()
    print "profile saved in final_profile"


def main():
    if len(sys.argv) < 3:
        print "[-] Usage: please provide image path and System.map path at inputs"
        exit(0)
    
    prolog_query = PrologQuery(sys.argv[1])
    prolog_query.parse_system_map(sys.argv[2])
    #print prolog_query.init_top_pgt_from_system_map, prolog_query.init_task_from_system_map

    virtual_shift = int(prolog_query.dtb_vaddr, 16) - int(prolog_query.init_top_pgt_from_system_map, 16)
    vaddr_init_task = int(prolog_query.init_task_from_system_map, 16) + virtual_shift
    #print hex(vaddr_init_task)

    paddr = prolog_query.vtop(vaddr_init_task)
    #print paddr
    pid = os.fork()
    if pid > 0:
        # start_query takes a number (dec or hex) as input, not string
        prolog_query.start_query(int(paddr))
    else:
        generate_result()

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
    main()

        