#!/bin/python3

"""
Copyright © 2020-2022 Patrick Gouin

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""
__author__ = "Patrick Gouin"
__copyright__ = "Copyright 2020-2022, Patrick Gouin"
__credits__ = [daichifukui]
__license__ = "GPL V3"
__version__ = "1.1"
__maintainer__ = "Patrick Gouin"
__email__ = "patrickg.github@free.fr"
__status__ = "Production"


from tkinter import *
from tkinter.ttk import *
import os
import platform
import subprocess
import shlex
import time 
import time 
from ToolTip import *

OutputWindow = None
OutputMsg = None

ttDelay = 0.1

OptionList =    [   ['-V', 'Version',       'Show version and exit'],
                    ['-v', 'Verbose',       "Be verbose, display warning message (default : don't display).  This option may be repeated more than once."],
                    ['-h', 'Help',          'Display help'],
#                    ['-m', 'more checks (available only with procfs, checkopendir & checkchdir commands)'],
                    ['-m', 'More checks',   'Do more checks. As of 2021-xx-xx version, this option has only effect for the procfs, procall, checkopendir and checkchdir tests.\nImplies -v'],
                    ['-r', 'Alternate sysinfo', 'Use alternate version of sysinfo check in standard tests'],
                    ['-f', 'Log result',    'Write a log file (unhide-linux.log) in the current directory.'],
                    ['-o', 'Log result',    'Write a log file (unhide-linux.log) in the current directory.'],
                    ['-d', 'Double check',  'Do a double check in brute test to avoid false positive.'],
                    ['-H', 'Human friendly',  'Output a slightlu human friendlier result'],
                ]

TcpOptionList = [   ['-h', 'Help',          "Display help"],
                    ['--brief', 'Quiet',    "Don't display warning messages"],
                    ['-f',      'fuser',    "On Linux, display fuser output (if available). On FreeBSD displays the output of sockstat"],
                    ['-l',      'lsof',     "Display lsof output (if available)"],
                    ['-n',      'netstat',  "Use /bin/netstat instead of /sbin/ss."],
                    ['-s',      'Server',   "Use a very quick strategy of scanning (for servers)."],
                    ['-o',      'Log',      "Write a log file."],
                    ['-V',      'Version',  "Show version and exit"],
                    ['-v',      'Verbose',  "Be verbose, display warning message"],
                    ['-H', 'Human friendly',  'Output a slightlu human friendlier result'],
                ]



StandardTestsList = [ ['brute',      "The brute technique consists of bruteforcing the all process IDs.\nThis technique is only available with version unhide-linux."],
                      ['proc',       "The proc technique consists of comparing /proc with the output of /bin/ps."],
                      ['procall',    "The procall technique combinates proc and procfs tests.\nThis technique is only available with version unhide-linux."],
                      ['procfs',     "The procfs technique consists of comparing information gathered from /bin/ps with information gathered by walking in the procfs.\nWith -m option, this test makes more checks, see checkchdir test.\nThis technique is only available with version unhide-linux."],
                      ['quick',      "The quick technique combines the proc, procfs and sys techniques in a quick way. It's about 20 times faster but may give more false positives.\nThis technique is only available with version unhide-linux."],
                      ['reverse',    "The  reverse  technique consists of verifying that all threads seen by ps are also seen in procfs and by system calls. It is intended to verify that a rootkit has not killed a security tool (IDS or other) and make ps showing a fake process instead.\nThis technique is only available with version unhide-linux."],
                      ['sys',        "The sys technique consists of comparing information gathered from /bin/ps with information gathered from system calls."],
                    ]
                   
ElementaryTestsList = [ [ 'checkRRgetinterval',     "The checkRRgetinterval technique consists of comparing information gathered from /bin/ps with the result of call to the sched_rr_get_interval() system function.\nThis technique is only available with version unhide-linux."],
                        [ 'checkbrute',             "The checkbrute technique consists of bruteforcing the all process IDs.\nThis technique is only available with version unhide-linux."],
                        [ 'checkchdir',             "The checkchdir technique consists of comparing information gathered from /bin/ps with information gathered by making chdir() in the procfs.\nWith the -m option, it also verify that the thread appears in its 'leader process' threads list.\nThis technique is only available with version unhide-linux."],
                        [ 'checkgetaffinity',       "The checkgetaffinity technique consists of comparing information gathered from /bin/ps with the result of call to the sched_getaffinity() system function.\nThis technique is only available with version unhide-linux."],
                        [ 'checkgetparam',          "The checkgetparam technique consists of comparing information gathered from /bin/ps with the result of call to the sched_getparam() system function.\nThis technique is only available with version unhide-linux."],
                        [ 'checkgetpgid',           "The checkgetpgid technique consists of comparing information gathered from /bin/ps with the result of call to the getpgid() system function.\nThis technique is only available with version unhide-linux."],
                        [ 'checkgetprio',           "The checkgetprio technique consists of comparing information gathered from /bin/ps with the result of call to the getpriority() system function.\nThis technique is only available with version unhide-linux."],
                        [ 'checkgetsched',          "The checkgetsched technique consists of comparing information gathered from /bin/ps with the result of call to the sched_getscheduler() system function.\nThis technique is only available with version unhide-linux."],
                        [ 'checkgetsid',            "The checkgetsid technique consists of comparing information gathered from /bin/ps with the result of call to the getsid() system function.\nThis technique is only available with version unhide-linux."],
                        [ 'checkkill',              "The checkkill technique consists of comparing information gathered from /bin/ps with the result of call to the kill() system function.\nNote : no process is really killed by this test.\This technique is only available with version unhide-linux."],
                        [ 'checknoprocps',          "The checknoprocps technique consists of comparing the result of the call to each of the system functions. No comparison is done against /proc or the output of ps.\nThis technique is only available with version unhide-linux."],
                        [ 'checkopendir',           "The checkopendir technique consists of comparing information gathered from /bin/ps with information gathered by making opendir() in the procfs.\nThis technique is only available with version unhide-linux."],
                        [ 'checkproc',              "The checkproc technique consists of comparing /proc with the output of /bin/ps.\nThis technique is only available with version unhide-linux."],
                        [ 'checkquick',             "The checkquick technique combines the proc, procfs and sys techniques in a quick way. It's about 20 times faster but may give more false positives.\nThis technique is only available with version unhide-linux."],
                        [ 'checkreaddir',           "The checkreaddir technique consists of comparing information gathered from /bin/ps with information gathered by making readdir() in /proc and /proc/pid/task.\nThis technique is only available with version unhide-linux."],
                        [ 'checkreverse',           "The checkreverse technique consists of verifying that all threads seen by ps are also seen in procfs and by system calls. It is intended to verify that a rootkit has not killed a security tool (IDS\n\nor other) and make ps showing a fake process instead.\nThis technique is only available with version unhide-linux."],
                        [ 'checksysinfo',           "The checksysinfo technique consists of comparing the number of process seen by /bin/ps with information obtained from sysinfo() system call.\nThis technique is only available with version unhide-linux."],
                        [ 'checksysinfo2',          "The  checksysinfo2  technique  is  an alternate version of checksysinfo test.  It might (or not) work better on kernel patched for RT, preempt or latency and with kernel that don't use the standard\nscheduler.\nIt's also invoked by standard tests when using the -r option\nThis technique is only available with version unhide-linux."],
                        [ 'checksysinfo3',          "The  checksysinfo2  technique  is  an alternate version of checksysinfo test.  It might (or not) work better on kernel patched for RT, preempt or latency and with kernel that don't use the standard\nscheduler.\nIt's also invoked by standard tests when using the -r option\nThis technique is only available with version unhide-linux."],
                      ]




TestGroupList = { 'brute'   : ['checkbrute'],
                  'proc'    : ['checkproc'],
                  'procall' : ['checkchdir', 'checkopendir', 'checkproc', 'checkreaddir'],
                  'procfs'  : ['checkchdir', 'checkopendir', 'checkreaddir'],
                  'quick'   : ['checkquick'],
                  'reverse' : ['checkreverse'],
                  'sys'     : ['checkRRgetinterval', 'checkgetaffinity', 'checkgetparam', 'checkgetpgid', 'checkgetprio', 'checkgetsched', 'checkgetsid', 'checkkill', 'checknoprocps'],
                }

# "Macros"
CHKB = 0
VARB = 1

TNAME = 0
TDESC = 1

                    
def CheckOpt(idx) :
    GenCmd()

def CheckTcpOpt(idx) :
    GenTcpCmd()

def CheckCtest(idx) :
    ctest = CTestBut[idx][CHKB].cget('text')
    ctest_state = CTestBut[idx][VARB].get()
    if ctest_state == '1':
        if ctest in TestGroupList :
            print('Ctest in TestGroupList')
            for etest in TestGroupList[ctest] :
                for count, l in enumerate(ElementaryTestsList) :
                    if etest in l :
                        idx = count
                        break
                ETestBut[idx][VARB].set(1)
    else :
        if ctest in TestGroupList :
            for etest in TestGroupList[ctest] :
                for count, l in enumerate(ElementaryTestsList) :
                    if etest in l :
                        idx = count
                        break
                ETestBut[idx][VARB].set(0)
    GenCmd()


def CheckEtest(idx) :
    etest = ETestBut[idx][CHKB].cget('text')
    etest_state = ETestBut[idx][VARB].get()
    if etest_state == '0' :
        for key in TestGroupList :
            if etest in TestGroupList[key] :
                for count, l in enumerate(StandardTestsList) :
                    if key in l :
                        idx_c = count
                        break
                CTestBut[idx_c][VARB].set(0)
    else :
        for key in TestGroupList :
            if etest in TestGroupList[key] :
                nb = 0
                for test in TestGroupList[key] :
                    for count, l in enumerate(ElementaryTestsList) :
                        if test in l :
                            idx_e = count
                            break
                    if ETestBut[idx_e][VARB].get() == '1' :
                        nb += 1
                if nb == len(TestGroupList[key]) :
                    idx_c = StandardTestsList.index(key)
                    CTestBut[idx_c][VARB].set(1)
    GenCmd()


def GenCommand() :
    SelTab = ToolNote.index("current")
    if SelTab == 0 :
        GenCmd()
    else :
        GenTcpCmd()

def TabEvent(event) :
    GenCommand()
    

def GenCmd() :
    Cmd = './unhide-linux '
    idx = 0
    for opt in OptionBut :
        if opt[VARB].get() == '1' :
            Cmd += OptionList[idx][0] + ' '
        idx += 1
    idx = 0
    etestlist = []
    for ctest in CTestBut :
        if ctest[VARB].get() == '1' :
            Cmd += StandardTestsList[idx][TNAME] + ' '
            etestlist += TestGroupList[StandardTestsList[idx][TNAME]]
        idx += 1
    idx = 0
    for etest in ETestBut :
        if etest[VARB].get() == '1' and ElementaryTestsList[idx][TNAME] not in etestlist:
            Cmd += ElementaryTestsList[idx][TNAME] + ' '
        idx += 1
    Ucmd.set(Cmd)
    CmdText.config(width = len(Cmd))
        
def GenTcpCmd() :
    Cmd = './unhide-tcp '
    idx = 0
    for opt in TcpOptionBut :
        if opt[VARB].get() == '1' :
            Cmd += TcpOptionList[idx][0] + ' '
        idx += 1
    idx = 0
    Ucmd.set(Cmd)
    CmdText.config(width = len(Cmd))
        
    

def CpyCmd() :
    root.clipboard_clear()
    root.clipboard_append(Ucmd.get())


def RunCmd() :
    # print(os.environ['COMSPEC']) 
    # Attention, sous Windows le module subprocess ne fonctionne que si la variable 
    # d'environnement COMSPEC ne contient qu'un seul élément (en l'occurence :
    #   "%SystemRoot%\system32\cmd.exe"
    command = Ucmd.get() +'\n'
    
    p = subprocess.Popen(command, stdout=subprocess.PIPE, shell=True)

    ## Talk with unhide command i.e. read data from stdout and stderr. Store this info in tuple ##
    (output, err) = p.communicate()
    ## Wait for unhide to terminate. Get return returncode ##
    p_status = p.wait()
    print("Command output : \n", output.decode('utf-8'))
    print("Command exit status/return code : ", p_status)

def delOutput() :
    global OutputWindow, OutputMsg
    OutputWindow.destroy()
    OutputWindow = None
    OutputMsg = None

def RunCmd_2() :
    global OutputWindow, OutputMsg
   
    if platform.system() == 'Windows' :
        UnhCommand = ["C:\\Windows\\System32\\HOSTNAME.EXE"]
        UnhCommand = ["dir"]
    else :
        UnhCommand = shlex.split(Ucmd.get())


    # Do not wait till UCmd finish, start displaying output immediately #
    if OutputWindow == None :
        OutputWindow = Toplevel()

        rX = root.winfo_x()
        rW = root.winfo_width()
        rY = root.winfo_y()
        rH = root.winfo_height()
        # print('rx : {} - rw : {} - ry : {} - rh : {}'.format(rX, rW, rY, rH)) 

        OutputWindow.geometry('+%d+%d' % (rX + (rW//3), rY + (rH//3)))
        OutputWindow.title(Ucmd.get())
        OutputWindow.grid_rowconfigure(0, weight = 1)
        OutputWindow.grid_columnconfigure(0, weight = 1)
        # intercepte la fermeture de la fenêtre par la croix
        OutputWindow.protocol("WM_DELETE_WINDOW", delOutput)

        
        Line1 = Frame(OutputWindow)
        # Le stickyness permet de resizer la frame avec la fenêtre : collé au 4 côtés.
        Line1.grid(row = 0, column = 0, sticky = 'nsew')
        Line1.grid_rowconfigure(0, weight = 1)
        Line1.grid_columnconfigure(0, weight = 1)

        Line2 = Frame(OutputWindow)
        Line2.grid(row = 1, column = 0, sticky = 'nw')

        OutputMsg = Text(Line1)
        OutputMsg.grid(row = 0, column = 0, sticky = 'nsew')
        
        Outbutton = Button(Line2, text="Close", command = delOutput)
        Outbutton.grid(row = 1, column = 0, sticky = 'nw')
        
        Clearbutton = Button(Line2, text="Clear", command = lambda OutputMsg = OutputMsg : OutputMsg.delete(1.0, END))
        Clearbutton.grid(row = 1, column = 1, sticky = 'nw')

        S = Scrollbar(Line1)
        # en ne collant pas à l'ouest, la barre conserve sa largeur quand la fenêtre grandit.
        S.grid(row = 0, column = 1, sticky = 'nse')

        S.config(command = OutputMsg.yview)
        OutputMsg.config(yscrollcommand = S.set)
        OutputMsg.insert(END, 'Coming soon\n\n')
        OutputWindow.update()

    p = subprocess.Popen(UnhCommand, universal_newlines = True, bufsize = 1 , stdout = subprocess.PIPE)

    outline = ''
    while True :
        outline = p.stdout.readline()
        if outline == '' and p.poll() != None:
            break

        if outline != '':
            if platform.system() == 'Windows' :
                OutputMsg.insert(END, str(outline,'cp850'))
                outline = b''
            else :
                OutputMsg.insert(END, outline)
                outline = ''
                OutputWindow.update()
    OutputMsg.insert(END, '\n')
    
# Construct TKinter Gui
root=Tk(className = "UnhideGUI")

root.grid_columnconfigure(3, weight=1)

# Frame permettant de contenir les tab des outils
ToolFrame = Frame(root, relief = RIDGE)
ToolFrame.grid(sticky = 'nw',row = 0, column = 0, columnspan = 4)

# Notebook
ToolNote = Notebook(ToolFrame)
ToolNote.grid(sticky = 'nw',row = 0, column = 0, columnspan = 4)

# Les deux frames des onglets
ProcessFrame = Frame(ToolNote, relief = RIDGE)
ProcessFrame.grid(sticky = 'nw',row = 0, column = 0, columnspan = 4)
TcpFrame = Frame(ToolNote, relief = RIDGE)
TcpFrame.grid(sticky = 'nw',row = 0, column = 0, columnspan = 4)

# Onglet Unhide
OptionFrame = Labelframe(ProcessFrame, text = 'Options', relief = RIDGE)
OptionFrame.grid(sticky = 'nw',row = 0, column = 0)



OptIdx = 0
OptionBut = []
for opt in OptionList :
    # print(OptIdx, ' - ', opt)
    tempo = StringVar()
    OptCB = Checkbutton(OptionFrame, text = opt[1], variable = tempo, command = lambda OptIdx = OptIdx: CheckOpt(OptIdx))
    OptCBTT = ToolTip( OptCB, msg = opt[2], follow = 1, delay = ttDelay)

    OptionBut.append([OptCB, tempo, OptCBTT])
    del tempo
    del OptCB
    del OptCBTT
    OptionBut[OptIdx][VARB].set(0)
    OptionBut[OptIdx][CHKB].grid(sticky = 'w', row = OptIdx, column = 0)
    OptIdx += 1

CTestFrame = Labelframe(ProcessFrame, text = 'Compound Tests', relief = RIDGE)
CTestFrame.grid(sticky = 'nw',row = 0, column = 1)

CTestIdx = 0
CTestBut = []
for ctest in StandardTestsList :
    # print(CTestIdx, ' - ', ctest)
    tempo = StringVar()
    # print('ctest[TNAME] :{}'.format(ctest[TNAME]))
    TCB = Checkbutton(CTestFrame, text = ctest[TNAME], variable = tempo, command = lambda CTestIdx = CTestIdx: CheckCtest(CTestIdx))
    TCBTT = ToolTip( TCB, msg = ctest[TDESC], follow = 1, delay = ttDelay)
    CTestBut.append([TCB, tempo, TCBTT])
    del tempo
    del TCBTT
    del TCB
    CTestBut[CTestIdx][VARB].set(0)
    CTestBut[CTestIdx][CHKB].grid(sticky = 'w', row = CTestIdx, column = 0)
    CTestIdx += 1


ETestFrame = Labelframe(ProcessFrame, text = 'Elementary Tests', relief = RIDGE)
ETestFrame.grid(sticky = 'nw',row = 0, column = 2)

ETestIdx = 0
ETestBut = []
Ecol = 0
Erow = 0
NumEtest = len(ElementaryTestsList)
for etest in ElementaryTestsList :
    # print(ETestIdx, ' - ', etest)
    tempo = StringVar()
    TCB = Checkbutton(ETestFrame, text = etest[TNAME], variable = tempo, command = lambda ETestIdx = ETestIdx: CheckEtest(ETestIdx))
    TCBTT = ToolTip( TCB, msg = etest[TDESC], follow = 1, delay = ttDelay)
    ETestBut.append([TCB, tempo, TCBTT])
    del tempo
    del TCBTT
    del TCB
    ETestBut[ETestIdx][VARB].set(0)
    ETestBut[ETestIdx][CHKB].grid(sticky = 'w', row = Erow, column = Ecol)
    ETestIdx += 1
    Erow += 1
    if ETestIdx == (NumEtest // 2) + 1 :
        Ecol += 1
        Erow =  0

# Onglet Unhide-tcp
TcpOptionFrame = Labelframe(TcpFrame, text = 'Options', relief = RIDGE)
TcpOptionFrame.grid(sticky = 'nw',row = 0, column = 0)

TcpOptIdx = 0
TcpOptionBut = []
for opt in TcpOptionList :
    # print(TcpOptIdx, ' - ', opt)
    tempo = StringVar()
    OptCB = Checkbutton(TcpOptionFrame, text = opt[1], variable = tempo, command = lambda TcpOptIdx = TcpOptIdx: CheckTcpOpt(TcpOptIdx))
    OptCBTT = ToolTip( OptCB, msg = opt[2], follow = 1, delay = ttDelay)
    TcpOptionBut.append([OptCB, tempo, OptCBTT])
    del tempo
    del OptCB
    del OptCBTT
    TcpOptionBut[TcpOptIdx][CHKB].grid(sticky = 'w', row = TcpOptIdx, column = 0)
    TcpOptIdx += 1

# Met les 2 onglets dans le noteBook
ToolNote.add(ProcessFrame, text = "Unhide-linux")
ToolNote.add(TcpFrame, text = "Unhide-tcp")
ToolNote.bind("<<NotebookTabChanged>>", TabEvent)

UCmdFrame = Labelframe(root, text = 'Command Unhide', relief = RIDGE)
UCmdFrame.grid(sticky = 'nw',row = 1, column = 0, columnspan = 4)
# ici il faut ajouter columnspan = 4 (=nb colonne + 1) pour que les frames au-dessus ne soit pas étendues inopinément.

Ucmd = StringVar()
CmdText = Entry(UCmdFrame, textvariable = Ucmd, state="readonly")
CmdText.grid(sticky = 'w', row = 0, column = 0, columnspan = 4 )

#buttons
RunUCmd = Button(UCmdFrame, text="Run", command = RunCmd_2)
RunUCmd.grid(sticky = 'w', row = 1, column = 0)

GenUCmd = Button(UCmdFrame, text="Generate", command = GenCommand)
GenUCmd.grid(sticky = 'w', row = 1, column = 1)

CopyCmd = Button(UCmdFrame, text="Copy to ClipBoard", command = CpyCmd)

CopyCmd.grid(sticky = 'w', row = 1, column = 2)

UCmdFrame.grid_columnconfigure(3, weight=1)


screen_width = root.winfo_screenwidth()
screen_height = root.winfo_screenheight()
root.geometry('+%d+%d' % (screen_width/3, screen_height/3))


root.update()

root.mainloop()

