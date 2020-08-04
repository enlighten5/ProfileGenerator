import os
import commands

versions = ["v4.11", "v4.12", "v4.13", "v4.14", "v4.15", "v4.16", "v4.17", "v4.18", "v4.19", "v4.20", "v5.0", "v5.1", "v5.2", "v5.3", "v5.4", "v5.5"]
#versions = [1]
key_start = {
    "task_struct": "task_struct {", 
    "mm_struct": "mm_struct {",
    "vm_area_struct": "vm_area_struct {",
    "fs_struct": "fs_struct {"
}

key_end = {
    "task_struct": "};",
    "mm_struct": "} __randomize_layout;",
    "vm_area_struct": "} __randomize_layout;",
    "fs_struct": "} __randomize_layout;"
}

file_name = {
    "task_struct": "sched.h",
    "mm_struct": "mm_types.h",
    "vm_area_struct": "mm_types.h",
    "fs_struct": "fs_struct.h"
}
def download(struct_name):
    for v in versions:
        link = " https://raw.githubusercontent.com/torvalds/linux/" + v + "/include/linux/" + file_name[struct_name]
        os.system("wget -O " + v + link)

def process_file(struct_name):
    for v in versions:
        file_name = v
        print "processing ", file_name
        ts_struct = []
        current_line = 0
        ts_line = 0
        with open(file_name, 'r') as f:
            line = f.readline()
            while line:
                current_line += 1
                if key_start[struct_name] in line:
                    print "found mm_struct"
                    ts_line = current_line
                if ts_line:
                    line = line.strip()
                    if len(line) == 0:
                        line = f.readline()
                        continue
                    ts_struct.append(line)
                    if line == key_end[struct_name]:
                        print "finish"
                        break
                line = f.readline()

        with open(file_name, 'w') as f:
            for value in ts_struct:
                f.write(value + '\n')

def converse_diff(struct_name):
    os.system("cp v4.11 result.h")
    for v in versions:
        file_name = v
        cmd = "grep -F -x -f result.h " + file_name 
        print "diffing " + file_name
        result = commands.getstatusoutput(cmd)
        with open("result.h", "w") as output:
            output.write(result[1])
        #with open("temp" + v, 'w') as output:
        #    output.write(result[1])

def main(struct_name):
    if not os.path.isdir("./"+struct_name):
        os.system("mkdir " + struct_name)
    os.chdir("./" + struct_name)
    download(struct_name)
    process_file(struct_name)
    converse_diff(struct_name)



if __name__ == '__main__':
    main("fs_struct")