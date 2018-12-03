import os
import wmi
import sys
import gui
import toasty
from tkinter import *
from subprocess import PIPE, Popen


class Process(object):
    def __init__(self, name):
        super(Process, self).__init__()
        self.name = name
        self.filePaths = []
        self.status = 0

def cmdline(command):
    process = Popen(
        args=command,
        stdout=PIPE,
        shell=True
    )
    return process.communicate()[0]

# Function to Write to File
def writeFile(processes):
    try:
        baselineFile = open("baseline.txt", "w")
    except:
        file = open("baseline.txt", 'w')
        file.close

    for i in processes:
        baselineFile.write(i + "\n")
# Save Statistics
def saveStat(time):
    statFile = open("avgTime.txt", "a+")
    statFile.write(time + "\n")

# Function to read file
def readFile(filepath):
    f = open(filepath)

    baseList = []
    while f:
        goodLine = f.readline().replace('\n', '')
        if (goodLine == ''):
            break

        baseList.append(goodLine)
    return baseList       

#for testing
def print_procs():
    #prints process ids and names
    c = wmi.WMI()
    for process in c.Win32_Process():
        print(process.ProcessId, process.Name)

def pull_proc_name(safe):
    #Pulls running windows processes
    #Search for known safe processes
    #Return list for API
    print("Searching for new processes...")
    procs = []
    
    c = wmi.WMI()
    for proc in c.Win32_Process():
        process = Process(proc.Name)
        procs.append(process)
    #Check procs against safe

    for m in safe:
        for n in procs:
            if n.name.strip() == m.strip():
                procs.remove(n)
                # print("Removed: " + n)
        
    return procs

def pull_proc_dirs(proc_names):
    
    count = 0
    print("Found " + str(len(proc_names)) + " processes")
    for n in proc_names:
        count += 1
                
        print("Analyzing " + n.name)
        filepaths = (cmdline("where /R C:\ "+str(n.name)))
        filepaths = filepaths.decode("utf-8")
        filepaths = filepaths.splitlines()
        for x in filepaths:
            n.filePaths.append(x)
        print(str(count) + "/" + str(len(proc_names)) + ": " + str(n.name))
    
    return proc_names  
    

def kill_proc(proc_name):
    #kill a process by name
    os.system("taskkill /f /fi \"imagename eq "+proc_name+"\" /im *")

def append_to_safe(proc_name, safe):
    #append a safe process to safe list
    safe.append(proc_name)

def injest_procs(proc_names, safe):
    #Recieves list from API
    #currently assumes list of tuples
    #(State #, Proc Name)
    # 0 = Safe, 1 =  Malicious, 2 = Unsure, 3 = unknown
    for n in proc_names:
        if n.status == 0:
            append_to_safe(n.name, safe) 
        elif n.status == (2 or 3):
        #    Do Something
            pass
        elif n.status == 1:
            toasty.harmful_alert(n.name)
            kill_proc(n.name)
    toasty.core_run_completed()
    print("Finished scan")
    print("Scanned " + str(len(proc_names)) + " processes")
    return safe

def getInititalWhiteList(canvas):
    canvas.destroy()
    print("Generating initial white list...")
    procs = []
    safe = []
    c = wmi.WMI()
    for proc in c.Win32_Process():
        procs.append(proc.Name)

    for x in procs:
        append_to_safe(x.strip(), safe)
    
    
    writeFile(safe)
    

    print("Found " + str(len(safe)) + " processes")
    print(" Finished Generating initial white list...")
    toasty.initial_run_completed()




def main():
  
    root = Tk()
    root.geometry("600x400+400+400")
    root.resizable(width=False, height=False)
    app = gui.ProCatch()
    root.mainloop()  
    
if __name__ == '__main__':
    main()  
