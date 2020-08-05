#iometa -n  -A iokit/kernel.1.2    > kernel_iphoneX_12.1.2_16C104.syms
import sys
import re

def create_str_buf(init,size=None):
    if size is None:
        size = len(init) + 1
    buftype = c_char_p(init)
    return buftype

# This will parse the data from iometa tool
class ParseIOMeta(object):
    def __init__(self,filename):
        self.filename = filename
        self.data = []
        self.cursor = 0
        self.thisObject = "" # current Object Name
        self.thisMethodsTable = [] # Hold a list of MethodInfo dictionary
        # Holds full information {"thisObject" : ..... }
        self.Objects = {}
        
        self.parseObjects()

    def _getObjectHead(self):
        for line in self.data:
            if "vtab=" in line: # means a new object to be parsed 
                # save self.thisMethodsTable to the previous object
                if len(self.thisMethodsTable) != 0:
                    self.Objects[self.thisObject].append(self.thisMethodsTable) # Takes index 1
                    # Clearing previous data to acquire new ones
                    self.thisMethodsTable = []
                    self.thisObject = ""
                
                self._parseVtableInfo()
                self.cursor += 1
                continue
            
            self._parseMethod()
            self.cursor += 1

        # the last one must be added as well 
        if len(self.thisMethodsTable) != 0:
                    self.Objects[self.thisObject].append(self.thisMethodsTable) # Takes index 1
                    # Clearing previous data to acquire new ones
                    self.thisMethodsTable = []
                    self.thisObject = ""
    
    def _printMethod(self,methodDict,overridenOnly=False):
        fmt = "0x%x func=0x%lx overrides=0x%lx pac=0x%x %s"
        m = methodDict
        if overridenOnly == True and m['methodAddr'] != m['overrides']:
            print( "OVERRIDEN: ", fmt %(m['off'],m['methodAddr'],m['overrides'],m['pac'],m['name']))
        elif overridenOnly == False:
            print(fmt %(m['off'],m['methodAddr'],m['overrides'],m['pac'],m['name']))
    
    def printAll(self,overriden=False):
        for className,infos in self.Objects.items():
            if len(infos) != 2:
                #print( "%s's vtable is not recognized" %(className)
                continue
            classInfo,methodsInfo = infos[0],infos[1]
            classInfo,methodsInfo = infos[0],infos[1]
            #print( "ClassName=%s vtable=0x%lx" %(classInfo['className'],classInfo['vtab'])
            for methodInfo in methodsInfo:
                self._printMethod(methodInfo,overriden)
            #exit(0)

    def _resolveSymbolName(self,stringName):
        name = stringName
        if "(" in name:
            name = name.split("(")[0]
        return name


    def _parseMethod(self):
        line = self.data[self.cursor]
        if len(line) == 0:
            return
        pattern = ".*(\S+)\W+func=(\S+)\W+overrides=(\S+)\W+pac=(\S+)\W+(\S+\(.*\))"
        match = re.search(pattern,line)
        
        idx = line.find("pac=")
        idx+=  line[idx:].find(" ")
        signature = line[idx+1:]
        #print "Signature : %s" %(signature) 
        if match == None or len(match.groups()) < 5:
            raise Exception("Failed to parse RE")
        
        off = int(match.group(1),16)
        methodAddr = int(match.group(2),16)
        overrides = int(match.group(3),16)
        pac = int(match.group(4),16)
        signature = match.group(5)
        
        methodName = self._resolveSymbolName(signature) # to be fixed later
        
        thisMethodDict = {
            "name": methodName,
            "off" : off,
            "methodAddr": methodAddr,
            "overriden" : methodAddr != overrides,
            "overrides" : overrides,
            "pac"       : pac,
            "signature" : signature
        }
        
        self.thisMethodsTable.append(thisMethodDict)

    def getObjectInfoByName(self,className):
        classesIter = self.Objects.keys() 
        if className not in classesIter:
            return
        
        return self.Objects[className]


    def printOverridenMethodsByClassName(self,className):
        
        infos = self.getObjectInfoByName(className)
        if len(infos) != 2:
            #print( "%s's vtable is not recognized" %(className)
            return

        classInfo,methodsInfo = infos[0],infos[1]
        #print( "ClassName=%s vtable=0x%lx" %(classInfo['className'],classInfo['vtab'])
        for method in methodsInfo:
            self._printMethod(method,overridenOnly=True)


    def printOverridenMethodsByBundle(self,bundle):
        classes = []
        for name,infos in self.Objects.items():
            classInfo = infos[0]
            if bundle in classInfo['bundle']:
                classes.append(name)
        
        if len(classes) == 0:
            print( "[-] %s is invalid" %(bundle))
            return
        
        for className in classes:
            self.printOverridenMethodsByClassName(className)

        
    def _parseVtableInfo(self):
        c = self.cursor
        line = self.data[c]
        
        pattern = "^vtab=(\S+)\W+size=(\S+)\W+meta=(\S+)\W+parent=(\S+)\W+metavtab=(\S+)\W+(\S+)\W+\((\S+)\)$"
        match = re.search(pattern, line)
        if match == None or len(match.groups()) != 7 :
            raise Exception ("Failed to parse vtable infos")
        
        vtab = int(match.group(1),16)
        size = int(match.group(2),16)
        meta = int(match.group(3),16)
        parent =int(match.group(4),16)
        metavtab = int(match.group(5),16)
        className = match.group(6)
        bundle = match.group(7)
        self.thisObject = className

        #print match.groups()
        objectInfoDict = {
            "className": self.thisObject,
            "vtab"  : vtab,
            "size"  : size,
            "meta"  : meta,
            "parent": parent,
            "metavtab" : metavtab,
            "bundle"   : bundle
        }
        self.Objects[self.thisObject] = [objectInfoDict]

    def parseObjects(self): 
        self.f = open(self.filename)
        self.data = self.f.read().split("\n")
        self._getObjectHead()

    def getObjects(self):
        return self.Objects
    
    def saveObject(self,name):
        print( "[+] Save symbol database in %s" %(name))
        handle = open('%s' %(name), 'wb')    
        pickle.dump(self.Objects, handle, protocol=pickle.HIGHEST_PROTOCOL)
        
if __name__ == "__main__":

    if len(sys.argv) != 3:
        print( "%s <iometa input> <output file>" %(sys.argv[0]))
        sys.exit(-1)
    
    fIn = sys.argv[1]
    fOut = sys.argv[2]

    v = ParseIOMeta(fIn)
    v.saveObject(fOut)
    v = ParseIOMeta("kernel_iphoneX_12.1.2_16C104.syms")
    v.saveObject('kernel_iphoneX_12.1.2_16C104')

    """
    v.printOverridenMethodsByClassName("IOStream")
    v.printOverridenMethodsByBundle("__kernel__")
    v.printAll(True)
    print v.Objects
    
    

    
    v = ParseIOMeta("/Users/mg/ghidra_ios/test.syms")
    """
