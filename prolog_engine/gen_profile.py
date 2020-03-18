from program import *
from pyswip.core import *
from pyswip import *

def main():
    image_path = sys.argv[1]
    image_name = os.path.basename(image_path)
    log(image_name)

    log('get available_pages')
    page_folder = os.listdir('./pages/')
    '''
    To get available pages, we either need the page directory address(cr3) or scan for certain signature. 
    The latter is not implemented yet. Therefore, for testing purpose, we get the page directory address from the System.map of the target image
    '''
    if 'pages.' + image_name not in page_folder:
        gen_pages = 'cd ../volatility; python vol.py -f ' + image_path + ' --profile=Linuxbookx64 get_physical_pages; cd -'
        os.system(gen_pages)

    dict_paddr_to_size, set_vaddr_page = read_available_pages(image_name)

    log('construct knowledge base')

    '''
    Scan for the swapper process and start from there
    '''
    #extract_info_r("/home/zhenxiao/images/lubuntu_x64.bin", 0x3810500, 4096, set_vaddr_page, "/home/zhenxiao/images/tmp.txt")
    
    #paddr = vaddr_to_paddr(0xffff88001c278080) # apache task struct address
    paddr = 0x3810500
    
    construct_kb(image_path, paddr, 4096, set_vaddr_page)
    
    log('start prolog reasoning')

    p = Prolog()
    #p.consult("./knowledge/start_query.pl")
    count = 0
    query_cmd = "possible_task_struct(Base_addr)"
    #query_cmd = "task_struct_r(472350848)."
    #for s in p.query(query_cmd, catcherrors=False):
    #    count += 1
    #    print(s["Base_addr"], s["Pid_offset"], s["MM_offset"], s["MM_offset2"], s["MM_pointer"])
    print "count result:", count
    
log('finish')
    


def construct_kb(image_path, paddr, size, set_vaddr_page):
    with open("./knowledge/start_query.pl", 'w') as kb:
        kb.write("use_module(library(clpfd))." + "\n")
        kb.write(":- discontiguous(ispointer/3)." + "\n")
        kb.write(":- discontiguous(isint/3)." + "\n")
        kb.write(":- discontiguous(isstring/3)." + "\n" + "\n")
        kb.write(":- discontiguous(islong/3)." + "\n" + "\n")

    extract_info_r(image_path, paddr, size, set_vaddr_page, './knowledge/start_query.pl')

    with open("./knowledge/start_query.pl", 'a') as outfile:
        with open("./knowledge/init_rules.pl", 'r') as inputfile:
            outfile.write(inputfile.read())
    
if __name__ == "__main__":
    main()