import sys
from program import *
from pyswip.core import *
from pyswip import *
import os

PWD = os.getenv('HOME') + "/ProfileGenerator/prolog_engine"
"""
Never print in this file, the stdout is directed to prolog
"""
def main():
    base_addr = sys.argv[1]
    query_rule = sys.argv[2]
    #print("check ", query_rule, "at ", base_addr)
    construct_kb(base_addr)
    p = Prolog()
    p.consult(PWD + "/knowledge/temp_kb.pl")
    query = "possible_" + query_rule + "(Base)."
    result = []
    for s in p.query(query, catcherrors=False):
        result.append(s["Base"])
    #os.system("rm " + PWD + "/knowledge/temp_kb.pl")
    # 0 is false, 1 is true
    if len(result) > 0:
        print 1
    else:
        print 0


def construct_kb(paddr):
    size = 1024
    # change to the path of the memory image. 
    image_path = "/home/zhenxiao/images/linux-sample-1.bin"
    dict_paddr_to_size, set_vaddr_page = read_available_pages("linux-sample-1.bin")
    with open(PWD + "/knowledge/temp_kb.pl", 'w') as kb:
            kb.write("use_module(library(clpfd))." + "\n")
            kb.write(":- discontiguous(ispointer/3)." + "\n")
            kb.write(":- discontiguous(isint/3)." + "\n")
            kb.write(":- discontiguous(isstring/3)." + "\n" + "\n")
            kb.write(":- discontiguous(islong/3)." + "\n" + "\n")
    
    valid_pointers = extract_info_r(image_path, int(paddr), size, set_vaddr_page, PWD + '/knowledge/temp_kb.pl')

    with open(PWD + "/knowledge/temp_kb.pl", 'a') as outfile:
        with open(PWD + "/knowledge/rules.pl", 'r') as inputfile:
            outfile.write(inputfile.read())

if __name__ == "__main__":
    main()