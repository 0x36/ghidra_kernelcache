# -*- coding: utf-8 -*-
#@category iOS.kernel
#@toolbar logos/kc.png
#@keybinding Meta Shift K

from utils.helpers import *
from utils.class import *
from utils.iometa import ParseIOMeta

def fix_map():
    prog = currentProgram
    memory = prog.getMemory()
    blocks = memory.getBlocks()
    for b in blocks:
        if "__got" in b.getName():
            b.setWrite(False)

def loadAll():
    default = "/Users/mg/ghidra_kernelcache/kernel.txt"
    ff = askString("iometa symbol file","Symbol file: ",default)
    
    iom = ParseIOMeta(ff)
    Obj = iom.getObjects()

    kc = kernelCache(Obj)
    kc.process_all_classes()
    
    #kc.update_classes()
    #kc.process_class("AppleUSBEthernetControllerAX88")
    #kc.process_class("IOGraphicsAccelerator2")
    #kc.process_class("_IOServiceNullNotifier")

if __name__ == "__main__":
    DeclareDataTypes()
    prepare()
    fix_map()
    loadAll()
