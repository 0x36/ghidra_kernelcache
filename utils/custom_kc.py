from helpers import *
from __main__ import *
import logging
from utils.ios_kc import *
from utils.iometa import ParseIOMeta
from kext import *
from iometa import ParseIOMeta

def create_class_structures(vtab):
    pass

class Custom(kernelCache):
    def __init__(self,objects,isKernel=False):
        print "Custom Kernel Creation"
        kernelCache.__init__(self,objects,macOS=True)
        self.sym_project = "macOS11.2.3"
        mn,mx = currentProgram.getMinAddress(),currentProgram.getMaxAddress()
        self.addrRange = AddressRangeImpl(mn,mx)
        self.ns = {}
        f = File( currentProgram.getExecutablePath())
        if f.exists() == False:
            f = askFile("Could not find the executable path","give a path:")
        self.read64 = lambda off: struct.unpack("<Q",self.br.readByteArray(off,8))[0]
        self.read32 = lambda off: struct.unpack("<I",self.br.readByteArray(off,4))[0]
        self.image_base = currentProgram.getImageBase()
        self.provider = RandomAccessByteProvider(f)
        self.header = MachHeader.createMachHeader( RethrowContinuesFactory.INSTANCE, self.provider )
        self.br = BinaryReader(self.provider,True)

        self.vtables = self._collect_vtables()
        self.objects = {}
        self.process_vtables()
        self.objects = self.vtables

    def _collect_vtables(self):
        vtables = {}
        self.symbolTable = currentProgram.getSymbolTable()
        self.bookmark = currentProgram.getBookmarkManager()
        syms = currentProgram.getSymbolTable().getSymbols("vtable")
        for i in syms:
            name = i.getName(True)
            if "::MetaClass::" in name or "OSMetaClass" in name:
                    continue

            addr = i.getAddress()
            n = i.getParentNamespace().getName()
            addr = addr.add(0x10)
            s = getSymbolAt(addr)
            if s == None:
                createSymbol(addr,n+"_vtable",True)#,SourceType.USER_DEFINED)
            else:
                s.setName(n+"_vtable",SourceType.USER_DEFINED)
            self.bookmark.setBookmark(addr,"macOS",None,"")
            if vtables.has_key(n) == False and self.objects.has_key(n) == False:
                print "[+] Found a class %s" %(n)
                vtables[n] = [{'parent' : None,"vtab" :int(addr.toString(),16), 'className' : n, 'metavtab' : 0,
                               'meta' : 0, 'size' : 0x1000,"bundle" : "undefined"}]
        return vtables

    def process_vtables(self):
        cnames = self.vtables.keys()
        off = 0
        for cname in cnames:
            methods = []
            methods = []
            vtable = self.vtables[cname][0]["vtab"]
            addr = toAddr("%x" % vtable)
            off = 0
            external = False
            while monitor.isCancelled() == False:
                memoff =  int(addr.toString(),16)
                try:
                    pac_ptr =  self.read64(memoff)
                except Exception as e:
                    del self.vtables[cname]
                    external = True
                    print(e)
                    raise Exception
                if pac_ptr == 0:
                    break
                tag = (pac_ptr >> 32) & 0xffff
                meth_info = self._collect_method_info(cname,addr,None,tag,off)
                if meth_info == None:
                    break
                setEOLComment(addr,hex(off))
                methods.append(meth_info)
                off+=8
                addr = addr.add(8)

            if external == False:
                self.vtables[cname].append(methods)

    def _collect_method_info(self,className,addr_ptr,methAddr,tag,offset):
        meth = {}
        meth["off"] = offset
        meth["pac"] = tag
        print className,addr_ptr,methAddr
        if methAddr == None:
            methAddr = getDataAt(addr_ptr)
            if methAddr == None:
                return None
            methAddr = methAddr.getValue()
            assert methAddr != None
        meth["methodAddr"] = int(methAddr.toString(),16)


        func = getFunctionAt(methAddr)
        signature = None
        funcName = None
        if func == None :
            fixLabel(methAddr)
            func = getFunctionAt(methAddr)
        if func == None:
            return None

        funcName = func.getName(True)
        sig = func.getSignature(True)
        sg = FunctionDefinitionDataType(sig)
        sg.setName(funcName)
        signature = sg.getPrototypeString(False)
        signature = signature[signature.find(" ")+1:]
        if "___cxa_pure_virtual" in signature:
            signature = "%s::virtual_method(void)" %(className)
            funcName = "%s::virtual_method"

        curr_ns = None
        mthod_ns = None

        if self.ns.has_key(className) == True:
            curr_ns = self.ns[className]
        else:
            curr_ns = self.symbolTable.getNamespace(className,None)
            self.ns[className] = curr_ns
        if curr_ns == None:
            curr_ns = self.create_namespace_custom(className)
            self.ns[className] = curr_ns

        assert curr_ns != None
        try:
            x = len(signature.split("::"))
            fns = signature.split("::")[x-2:x-1][0]
        except:
            return None

        if self.ns.has_key(fns) == True:
            meth_ns = self.ns[fns]
        else:
            meth_ns = self.symbolTable.getNamespace(fns,None)
            self.ns[fns] = meth_ns

        meth["signature"] = signature
        meth["name"] = funcName
        if meth_ns == None:
            meth["overriden"] = False
            return meth

        if curr_ns.toString() == meth_ns.toString():
            meth["overriden"] = True
        else :
            meth["overriden"] = False

        return meth

    def create_namespace_custom(self,name):
        new = self.symbolTable.createNameSpace(None,name,SourceType.USER_DEFINED)
        return new

    def prepare_iometa(self):
        names = self.vtables.keys()
        for name in names:
            print name, self.vtables[name]
