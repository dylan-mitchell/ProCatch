import queue
import api
import gui
import toasty
import time
import core
from tkinter import *
from tkinter import ttk
import threading
import pythoncom


class ProCatch(Frame):
    
  
    def __init__(self):
        super().__init__()   
        self.progressCount = 0
        self.initUI()
    
    def tb_click(self):
        self.queue = queue.Queue()
        self.desText.configure(text='''Scanning...''')
        # Progress Bar
        self.progress = ttk.Progressbar(self.desFrame, orient=HORIZONTAL, length=200, mode='determinate', maximum=200*5+8)
        self.progress.place(relx=0.050, rely=0.744, relheight=0.167 , relwidth=0.892)


        ThreadedTask(self.queue).start()
        self.after(100, self.process_queue)

    def process_queue(self):
        try:
            proc_names = self.queue.get(0)
            print("Attempting to close")
            self.progress["value"] = 200*5+8
            self.update()
            time.sleep(1)
            self.desText.configure(text='''Finished Scan''')
            
                       
            self.progress.destroy()

            
            self.Listthread.insert(END, "Scanned " + str(len(proc_names)) + " processes")
            
            count = 1
            red = []
            green = []
            for process in proc_names:
                # 0 = Safe, 1 =  Malicious, 2 = Unsure, 3 = unknown
                if process.status == 0:
                    insert = str(process.name + " : Safe")
                    green.append(count)
                if process.status == 1:
                    insert = str(process.name + " : Malicious")
                    red.append(count)
                if process.status == 2:
                    insert = str(process.name + " : Caution")
                if process.status == 3:
                    insert = str(process.name + " : Unknown")
                                    
                self.Listthread.insert(END, insert)
                count += 1
            
            for x in red:
                self.Listthread.itemconfig(x, {'bg':'red', 'fg':'white'})
                
            for x in green:
                self.Listthread.itemconfig(x, {'bg':'green', 'fg':'white'})
            
            self.queue.task_done()
              
                
        except:
            
            if self.progressCount < 200*5*.8:
                self.progressCount += 1
            self.progress["value"] = self.progressCount
            self.after(100, self.process_queue)
            

    def stop(self):
        sys.exit(0)


    def openSettings(self):
        def generateInitial():
            
            core.getInititalWhiteList(popup)

            self.destroy()


        popup = Toplevel()
        popup.wm_title("Settings")
        popup.geometry("400x200+200+200")
        popup.resizable(width=False, height=False)
        popup.btnGenerate = Button(popup)
        popup.btnGenerate.grid(row=1, column=0)
        popup.btnGenerate.configure(text='''Generate Initial White List''', background = "#8fd8b1", command=generateInitial)

        popup.Text = Label(popup)
        popup.Text.grid(row=2, column=0)
        popup.Text.configure(text='''Schedule Scans for every:''')
        popup.Text.config(font=("Courier", 10))

        schedule = IntVar(value=6)
        radio = []
        radio.append(Radiobutton(popup, text="10 minutes", padx = 20, variable=schedule, value=1, tristatevalue=100))
        radio.append(Radiobutton(popup, text="30 minutes", padx = 20, variable=schedule, value=2, tristatevalue=100))
        radio.append(Radiobutton(popup, text="1 hour", padx = 20, variable=schedule, value=3, tristatevalue=100))
        radio.append(Radiobutton(popup, text="4 hours", padx = 20, variable=schedule, value=4, tristatevalue=100))
        radio.append(Radiobutton(popup, text="24 hours", padx = 20, variable=schedule, value=5, tristatevalue=100))
        radio.append(Radiobutton(popup, text="Never", padx = 20, variable=schedule, value=6, tristatevalue=100))
        rowNumber = 4
        columnNumber = 0
        for button in radio:
            button.config(font=("Courier", 10))
            button.grid(row=rowNumber, column=columnNumber)
            columnNumber += 1
            if columnNumber == 2:
                rowNumber += 1
                columnNumber = 0
          
        
    def initUI(self):
        
        self.master.title("ProCatch")
        self.pack(fill=BOTH, expand=True)
    #button Frame   
        self.btnFrame = Frame()
        self.btnFrame.place(relx=0.033, rely=0.044, relheight=0.878, relwidth=0.208)
        self.btnFrame.configure(width=125, borderwidth="2", relief='groove')

        self.btnSetting = Button(self.btnFrame)
        self.btnSetting.place(relx=0.16, rely=0.886, height=24, width=87)
        self.btnSetting.configure(text='''Setting''', background = "#d8a847", command=self.openSettings)
        self.btnSetting.configure(width=87)

        self.btnStop = Button(self.btnFrame)
        self.btnStop.place(relx=0.16, rely=0.785, height=24, width=87)
        self.btnStop.configure(text='''Stop''', background = "#d85050", command=self.stop)
        self.btnStop.configure(width=87)

        self.btnStart = Button(self.btnFrame)
        self.btnStart.place(relx=0.16, rely=0.051, height=34, width=87)
        self.btnStart.configure(text='''Run Scan''', background = "#8fd8b1", command=self.tb_click)
        self.btnStart.configure(width=87)
    #thread Frame
        self.threadFrame = Frame()
        self.threadFrame.place(relx=0.267, rely=0.222, relheight=0.7, relwidth=0.692)
        self.threadFrame.configure(width=415, borderwidth="2", relief='groove')
        #all of the threads will list under this Listbox
        self.Listthread = Listbox(self.threadFrame)
        self.Listthread.place(relx=0.024, rely=0.032, relheight=0.921, relwidth=0.925)
        self.Listthread.configure(width=384)
    #description frame
        self.desFrame = Frame()
        self.desFrame.place(relx=0.267, rely=0.044, relheight=0.167 , relwidth=0.692)
        self.desFrame.configure(width=415, borderwidth="2", relief='groove')

        self.desText = Message(self.desFrame)
        self.desText.place(relx=0.0, rely=0.033, relheight=0.707, relwidth=0.964)
        self.desText.configure(text='''''')
        self.desText.config(font=("Courier", 20))
        self.desText.configure(width=400)
    

class ThreadedTask(threading.Thread):
    def __init__(self, queue):
        threading.Thread.__init__(self)
        self.queue = queue
    def run(self):
        pythoncom.CoInitialize()
              
        start_time = time.perf_counter()
        
        safe = core.readFile(".\\baseline.txt")
                
        proc_names = core.pull_proc_dirs(core.pull_proc_name(safe))
        proc_names = api.api_call(proc_names)
        
        
        safe = core.injest_procs(proc_names, safe)
            
        core.writeFile(safe)
        
        
        if len(proc_names) > 0:
            avg_time = (time.perf_counter() - start_time)/len(proc_names)
            core.saveStat(str(avg_time))
        print("--- %s seconds ---" % round(time.perf_counter() - start_time, 5))
        self.queue.put(proc_names)
        self.queue.join()
        # print("Finished thread")