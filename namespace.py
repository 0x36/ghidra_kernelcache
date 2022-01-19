#@author simo
#@category iOS.kernel
#@keybinding Meta Shift N
# -*- coding: utf-8 -*-

from utils.helpers import *
from utils.methods import *

if __name__ == "__main__":

    targetFunction = getSymbolAt(currentAddress)

    if targetFunction == None :
        targetFunction = askString("You didn't select a method", "Method name:")
        exit(-1)

    # how to track the history of strings ?
    className = askString("Fix Namespace","namespace of "+ targetFunction.toString())
    symbolTable = currentProgram.getSymbolTable()

    namespace = symbolTable.getNamespace(className,None)
    if namespace == None:
        popup("%s class not found" %(className))
        exit(-1)

    fix_namespace(className,getFunctionAt(targetFunction.getAddress()))
    print "Done"
