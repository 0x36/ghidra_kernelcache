# Symbolicate the kernelcache from jtool2
#@author simo
#@category iOS.kernel
from utils.methods import *

if __name__ == "__main__":
    
    default_file = "test"
    fname = askString("Kernelcache symbol file","Symbol file: ",default_file)
    f = open(fname,"rb+")
    buf = f.read().split('\n')
    i = 0
    for line in buf:
        if len(line) == 0:
            continue
        addr , symbol , empty = line.split("|")
        if len(symbol) == 0:
            continue

        if "func_" in symbol:
            continue
        print addr,symbol
        symbol = symbol.strip()#.replace(" ","_")
        symbolicate(addr,symbol)
        i+= 1
