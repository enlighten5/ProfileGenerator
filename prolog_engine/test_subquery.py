import sys
from program import *
from pyswip.core import *
from pyswip import *
import os
import prolog_query as pq
import test_query as tq
import random
PWD = os.getenv('HOME') + "/ProfileGenerator/prolog_engine"
"""
Never print in this file, the stdout is directed to prolog
"""
class SubQuery(tq.PrologQuery):
    def __init__(self):
        # TODO: inherit prologquery without provides image path as a parameter
        # Replace the parameter with the path to memory dump
        mem_dump = "/home/zhenxiao/images/4.11.bin"
        if not os.path.exists(mem_dump):
            print "[-] Error: replace the mem_dump with the path to the memory dump in subquery.py"
            exit(1)
        tq.PrologQuery.__init__(self, mem_dump)


    def subquery(self, base_addr, query_rule, comm_offset = None, task_offset = None):
        #tmp_name = "./knowledge/" + str(random.random()) + ".pl"
        tmp_name = "./knowledge/" + hex(base_addr & 0xffffffffff000).strip('L') + ".pl"

        if not os.path.exists(tmp_name):
            self.construct_kb(base_addr, "./knowledge/rules.pl", tmp_name)
        p = Prolog()
        #p.consult("./knowledge/temp_kb.pl")
        p.consult(tmp_name)
        if comm_offset and not task_offset:
            query_cmd = "possible_" + query_rule + "(Base, " + str(comm_offset) + ")."
        if comm_offset and task_offset:
            query_cmd = "possible_" + query_rule + "(Base, " + str(comm_offset) + ", " + str(task_offset) + ")."
        if not comm_offset and not task_offset:
            query_cmd = "possible_" + query_rule + "(Base)."
        result = []
        #for s in p.query(query_cmd, catcherrors=False):
        #    result.append(s["Base"])

        if len(result) > 0:
            print 1
        else:
            print 0
        #os.remove(tmp_name)

def main():
    base_addr = int(sys.argv[1])
    query_rule = sys.argv[2]
    if len(sys.argv) > 3:
        comm_offset = sys.argv[3]
    else:
        comm_offset = None
    if len(sys.argv) == 5:
        task_offset = sys.argv[4]
    else:
        task_offset = None
    sq = SubQuery()
    sq.subquery(base_addr, query_rule, comm_offset, task_offset)


if __name__ == "__main__":
    main()