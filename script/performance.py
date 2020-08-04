import subprocess
import os
import time
import matplotlib.pyplot as plt
def measure():
    pid = []
    new_pid = []
    current = time.clock()
    while time.clock() - current < 5:
        output = subprocess.check_output("ps aux | grep subquery.py", shell=True)
        candidate = []
        #print output

        
        start_idx = [i for i in range(len(output)) if output.startswith('zhenxiao ', i)]
        if len(start_idx)==1:
            continue
        
        for index in range(len(start_idx)):
            if index == len(start_idx)-1:
                candidate.append(output[start_idx[index]:-1])
            else:
                candidate.append(output[start_idx[index]:start_idx[index+1]])
        #print start_idx
        #print output
        #print candidate
        found_process = []
        for item in candidate:
            if "/usr/bin/python" in item:
                found_process.append(item)
        if len(found_process)==0:
            continue

        for item in found_process:
            tmp_idx = item.find(" ", 11)
            find_pid = int(item[11:tmp_idx])
            if find_pid not in pid:
                pid.append(find_pid)
                new_pid.append(find_pid)
                print item[item.find("subquery"):-1]

        #for item in new_pid:
            #print "issue psrecord {pname} --interval 1 --plot {output}.png".format(pname=item, output=str(item))
            #os.system("psrecord {pname} --interval 1 --plot {output}.png".format(pname=item, output=str(item)))
        new_pid = []
def memory():
    usage = []
    count = 0
    x_axis = []
    current = time.time()
    while time.time() - current < 300:
        output = subprocess.check_output("sudo python mem.py | grep python2.7", shell=True)
        idx = output.find("=")
        idx2 = output.find("M", idx+2)
        mem_usage = float(output[idx+2:idx2])
        usage.append(mem_usage)
        x_axis.append(count)
        count += 2
        time.sleep(2)
    plt.plot(x_axis, usage)
    plt.ylabel("memory usage in MB")
    plt.xlabel("time in seconds")
    plt.show()

def main():
    #measure()
    memory()
    print "1"
    time.sleep(2)
    print "2"
if __name__ == "__main__":
    main()
