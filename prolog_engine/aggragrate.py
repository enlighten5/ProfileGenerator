import program as pg
import sys, os
result = {}
def main():
    paddr = 0x1605ff8

    paddr = 0xc0000
    while paddr < 0xc0000 + 0xfb48:
    #    extract_info("/home/zhenxiao/images/lubuntu_x64.bin", paddr, 4096)
        paddr += 4096


    paddr = 0x14775a8
    #extract_info("/home/zhenxiao/images/debian_x64.bin", paddr, 8)
    #extract_info_r("/home/zhenxiao/images/debian_x64.bin", paddr, 2048, "/home/zhenxiao/ProfileGenerator/debian.pl")
    #parse_dwarf("/home/zhenxiao/Desktop/sysmap/debian_2.6/module.dwarf")
    #extract_info("/home/zhenxiao/images/lubuntu_x64_ASLR.bin", 0x11210500, 4096)
    #fname = sys.argv[1]
    #parse_profile(fname)
    result = []
    tp = 0.0
    fp = 0.0
    total_t = 0.0
    for file_name in os.listdir("./profile"):
        result.append(parse_profile(file_name))
    for index in range(len(result)):
        tp += result[index][0]
        fp += result[index][1]
        total_t += result[index][2]
    print "final result: tp:", tp, "fp:", fp, "precision", 169 / (169 + fp), "time", total_t



    
    
def test(file_path):
    with open(file_path) as f:
        global result
        line = f.readline()
        while line:
            if "average" in line or "send" in line or "executed" in line or "Aborted" in line or "Flush" in line:
                idx1 = line.find(" ")
                idx2 = line.find(":")
                name = line[idx1:idx2]
                idx3 = line.find(" ", idx2+2)
                value = line[idx2+2:idx3]
                #tmp_list.append(line[idx:idx])
                line = f.readline()
                #print "[-] name {}, value {}".format(name, value)
                if name not in result.keys():
                    result[name] = [value]
                else:
                    result[name].append(value)
            else:
                line = f.readline()


def parse_dwarf(file_path):
    with open(file_path, 'r') as dwarf:
        line = dwarf.readline()
        while line:
            if "DW_TAG_structure_type" in line:
                name_idx = line.find("DW_AT_name") + 1
                name_end = line.find(">", name_idx)
                name_idx += len("DW_AT_name")
                print "struct:", line[name_idx: name_end]
            elif "location" in line and "name" in line:
                name_idx = line.find("DW_AT_name") + 1
                name_end = line.find(">", name_idx)
                name_idx += len("DW_AT_name")
                offset_idx = line.find("DW_AT_data_member_location") + 1
                offset_end = line.find(">", offset_idx)
                offset_idx += len("DW_AT_data_member_location")
                print "name", line[name_idx: name_end], "offset", line[offset_idx: offset_end]
            line = dwarf.readline()


def parse_profile(fname):
    profile = {}
    with open("./profile/" + fname, 'r') as p:
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
    for key in keys:
        print key, profile[key]
    names = os.listdir("./profile/")
    fp = 0.0
    tp = 0.0
    total_t = 0.0
    for key in keys:
        if key in fname:
            #time
            total_t += float(profile[key][0])
            print "time for", key, total_t
        else:
            if len(profile[key]) > 1:
                fp += len(profile[key]) - 1
                tp += 1
            else:
                tp += 1
    print "false positive", fp, "true positive", tp, "precision", tp/(tp+fp)
    print " "
    return tp, fp, total_t

def is_user_pointer(buf, idx):
    dest = (ord(buf[idx+7]) << 56) + (ord(buf[idx+6]) << 48) + (ord(buf[idx+5]) << 40) + (ord(buf[idx+4]) << 32) + (ord(buf[idx+3]) << 24) + (ord(buf[idx+2]) << 16) + (ord(buf[idx+1]) << 8) + ord(buf[idx])
    return dest

def extract_info(image_path, paddr, size):
    with open(image_path, 'r') as image:
        image.seek(paddr)
        #print "base address", hex(paddr)
        content = image.read(size)
        i = 0
        while i < 4096:
            if len(content[i:i+8]) < 8:
                break
            #if hex(is_user_pointer(content[i:i+8], 0)) == "0x160d3b8":
        #    print "find it at", i
        #if not hex(is_user_pointer(content[i:i+8], 0)) == '0x0':
            #if '1f8fddc0' in hex(is_user_pointer(content[i:i+8], 0)):
            #if not hex(is_user_pointer(content[i:i+8], 0)) == '0x0':
            #print("raw bytes at ", hex(paddr+i), i, content[i:i+8], hex(is_user_pointer(content[i:i+8], 0)))
            print hex(paddr+i), i, content[i:i+8], hex(is_user_pointer(content[i:i+8], 0))
            if 'swapper' in content[i:i+8]:
                print "found swapper at", hex(paddr + i), i, content[i:i+8]
            i += 8 
        
        # find strings
        idx = 0
        valid_comm = {}
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
                print("found string at", hex(paddr+idx), idx, find_comm)
                idx = idx + 7
            idx += 1


def extract_info_r(image_path, paddr, size, output):
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
        if len(content[i:i+8]) < 8:
                break
        tmp = content[i:i+8]
        if(tmp.endswith("\xff\xff\xff\xff")):
            valid_pointer[i] = hex(is_user_pointer(content[i:i+8], 0))[:-1]
        i += 8
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

if __name__ == "__main__":
    main()