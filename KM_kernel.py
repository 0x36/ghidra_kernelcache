# symbolication macOS kernel + kexts
#@category iOS.kernel
#@toolbar logos/km.png
#@keybinding Meta Shift M

from utils.helpers import *
from utils.kext import *

def main():
    default = "/tmp/kernel.txt"
    ff = askString("iometa symbol file","Symbol file: ",default)
    iom = ParseIOMeta(ff)
    Obj = iom.getObjects()

    kc = Kext(Obj,shared_p="macOS_12.1")

    kc.process_kernel_kext()

if __name__ == "__main__":
    print("Parsing 1 ... ")
    main()
