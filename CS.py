# Create a custom class
#@category iOS.kernel

from utils.helpers import *
from utils.custom_kc import *

if __name__ == "__main__":
    default = "/tmp/kernel.txt"
    ff = askString("iometa symbol file","Symbol file: ",default)
    iom = ParseIOMeta(ff)
    Obj = iom.getObjects()

    kc = Custom(Obj)

    #kc.process_class(["IOSurface"])

    kc.process_all_classes()
    kc.explore_pac()
