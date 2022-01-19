# -*- coding: utf-8 -*-
#@category iOS.kernel
#@toolbar logos/kc.png
#@keybinding Meta Shift K

from utils.helpers import *
from utils.ios_kc import *
from utils.iometa import ParseIOMeta

def fix_map():
    prog = currentProgram
    memory = prog.getMemory()
    blocks = memory.getBlocks()
    for b in blocks:
        if "__got" in b.getName():
            b.setWrite(False)

def loadAll():
    default = "/tmp/kernel.txt"
    ff = askString("iometa symbol file","Symbol file: ",default)

    iom = ParseIOMeta(ff)
    Obj = iom.getObjects()
    kc = kernelCache(Obj)

    #kc.clear_class_structures()

    kc.process_all_classes()

    #kc.process_class("IOUserClient")

    #kc.process_classes_for_bundle("com.apple.iokit.IOSurface")

    #kc.explore_pac()

if __name__ == "__main__":
    #DeclareDataTypes()
    prepare()
    #fix_map()
    loadAll()
