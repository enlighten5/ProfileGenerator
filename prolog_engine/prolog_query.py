import read_mem as rm
from program import *
from pyswip.core import *
from pyswip import *

class PrologQuery(rm.AddressSpace):
    def __init__(self, image_path):
        rm.AddressSpace.__init__(self, image_path, 0x3809000)

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
        query_cmd = "possible_anything(Base_addr)"
        for s in p.query(query_cmd, catcherrors=False):
            count += 1
            print(s["Base_addr"])
        print "count result:", count

def main():
    prolog_query = PrologQuery(sys.argv[1])
    prolog_query.start_query(0x3810500)

if __name__ == "__main__":
    main()

        