from helpers import *
from __main__ import *
import logging
from iometa import ParseIOMeta

from ghidra.program.model.data import DataTypeConflictHandler
from ios_kc import *



MH_EXECUTE =                   0x00000002
MH_KEXT_BUNDLE =               0x0000000b
LC_DYLD_CHAINED_FIXUPS =       0x80000034

class Kext(kernelCache):
    def __init__(self,objects,isKernel=False,shared_p = "macOS11.2.3"):
        kernelCache.__init__(self,objects,macOS=True)
        self.macOS = True
        self.sym_project = shared_p
        self.filetype = None
        self.dtm = currentProgram.getDataTypeManager()
        self.mem = currentProgram.getMemory()
        self.obj = {}
        self.listing = currentProgram.getListing()
        self.symbolTable = currentProgram.getSymbolTable()
        self.ifc = get_decompiler()
        self.ns = {}
        self.shm_dt = None
        mn,mx = currentProgram.getMinAddress(),currentProgram.getMaxAddress()
        self.addrRange = AddressRangeImpl(mn,mx)

        self.class_methods ={}
        self.vtables = {}
        self._collect_vtables()
        f = File( currentProgram.getExecutablePath())
        if f.exists() == False:
            f = askFile("Could not find the executable path","give a path:")

        assert f.exists() == True
        self.read64 = lambda off: struct.unpack("<Q",self.br.readByteArray(off,8))[0]
        self.read32 = lambda off: struct.unpack("<I",self.br.readByteArray(off,4))[0]
        self.image_base = currentProgram.getImageBase()
        self.provider = RandomAccessByteProvider(f)
        self.header = MachHeader.createMachHeader( RethrowContinuesFactory.INSTANCE, self.provider )
        self.header.parse()
        self.br = BinaryReader(self.provider,True)

    def depac(self):
        if self.header.getFileType() == MH_KEXT_BUNDLE:
            self.filetype = MH_KEXT_BUNDLE
            self.depac_kext()
        else:
            self.filetype = MH_EXECUTE
            self.depac_kernel()
        #self.get_all_classes_info()

    def process_kernel_kext(self):
        self.shm_dt = self.get_shared_dt_mgr()
        if self.filetype == MH_EXECUTE:
            self.process_all_classes()
            print ("[+] Commit objects to shared datatype manager ... ")
            self.resolve_kernel_objects()

        else: # **** KEXT handling ****
            structs =  self.shm_dt.getAllStructures()

            tid = self._start_transaction("commit symbols")
            for s in structs:
                tmp = self._find_local_struct(s.getName())
                if tmp == None:
                    self.dtm.addDataType(s,None)
                    continue
                self.dtm.replaceDataType(tmp,s,True)
            self._end_trans(tid)

            self.process_all_classes()
            self.resolve_kernel_objects()
        print ("[+] Done")

    def override_kernel_kext(self):
        self.shm_dt = self.get_shared_dt_mgr()
        if self.filetype == MH_EXECUTE:
            return
        else: # **** KEXT handling ****
            structs =  self.shm_dt.getAllStructures()

            tid = self._start_transaction("commit symbols")
            for s in structs:
                tmp = self._find_local_struct(s.getName())
                if tmp == None:
                    self.dtm.addDataType(s,None)
                    continue
                self.dtm.replaceDataType(tmp,s,True)
            self._end_trans(tid)
        print ("[+] Done")

    def import_kext_structs(self):
        self.shm_dt = self.get_shared_dt_mgr()
        if self.filetype == MH_EXECUTE:
            raise Exception("not implmented yet")
        else:
            self.get_all_classes_info()
            structs =  self.shm_dt.getAllStructures()

            tid = self._start_transaction("commit symbols")
            for s in structs:
                tmp = self._find_local_struct(s.getName())
                if tmp == None:
                    self.dtm.addDataType(s,None)
                    continue
                self.dtm.replaceDataType(tmp,s,True)
            self._end_trans(tid)

    def process_all_classes(self):
            names = self.objects.keys()
            for name in names:
                addr = toAddr(hex(self.objects[name][0]["vtab"]).replace("L",""))
                if self.addrRange.contains(addr) == False:
                    continue
                self._process_class(name)
            for name in names:
                addr = toAddr(hex(self.objects[name][0]["vtab"]).replace("L",""))
                if self.addrRange.contains(addr) == False:
                    continue
                kernelCacheClass(self.objects[name],False,self.macOS)

    # Broken
    def depac_kernel(self):
        cnames = self.vtables.keys()
        off = 0
        for cname in cnames:
            methods = []
            vtable = self.vtables[cname]
            addr = vtable
            off = 0
            while monitor.isCancelled() == False:
                # Set a check against unmapped addresses
                data = getDataAt(addr)
                if data == None:
                    self.listing.clearCodeUnits(addr,addr.add(8),False)
                    self.listing.createData(addr,PointerDataType())

                data = getDataAt(addr)
                assert data != None
                # Experienced when a vtable is an export
                if data.value == None:
                    return False
                pointer =  data.value.getOffset()
                if pointer == 0:
                    break
                pac_ptr =  data.value.toString()
                offset = int(pac_ptr,16) & 0xffffffff
                raw_ptr = self.image_base.add(offset)
                tag = (int(pac_ptr,16) >> 32) & 0xffff
                b = struct.pack("<Q",int(raw_ptr.toString(),16))
                self.mem.setBytes(addr,b,0,8)
                self.listing.clearCodeUnits(addr,addr.add(8),False)
                self.listing.createData(addr,PointerDataType())
                func = getFunctionContaining(raw_ptr)
                if func == None:
                    func = createFunction(raw_ptr,None)

                if func == None:
                    raise Exception("Function Not found")

                off+=8
                addr = addr.add(8)

    def depac_kext(self):
        print "[+] dePACing KEXT driver ...",
        self.cmds = self.header.getLoadCommands()
        self.mem = currentProgram.getMemory()
        tcmd = None
        for cmd in self.cmds:
            if cmd.getCommandType() & 0xffffffff != LC_DYLD_CHAINED_FIXUPS:
                continue
            tcmd = cmd
            break

        assert tcmd != None
        index =  tcmd.getStartIndex()

        ll = self.br.readIntArray(index,cmd.getCommandSize()/4)

        cmd = ll[0] & 0xffffffff
        cmdsize = ll[1]
        dataoff = ll[2]
        datasize = ll[3]

        off = dataoff
        fixup =self.br.readIntArray(dataoff,7)
        symbols_offset = fixup[3]
        imports_offset = fixup[2]
        starts_offset = fixup[1]

        import_off = dataoff + imports_offset

        syms_off = dataoff + symbols_offset
        segs_off = off + starts_offset
        segs_count = self.read32(segs_off)
        segs = self.br.readIntArray(segs_off + 4,segs_count)

        for seg_i in range(segs_count):
            if segs[seg_i] == 0:
                continue

            starts_off = segs_off + segs[seg_i]
            starts = self.br.readByteArray(starts_off,24)
            tmp = struct.unpack("<IHHQIHH",starts)
            page_count = tmp[5]
            page_starts = self.br.readByteArray(starts_off+22,page_count*2)
            page_starts = struct.unpack("<"+"H" * page_count,page_starts)
            page_size, segment_offset = tmp[1],tmp[3]

            i = 0
            for idx in page_starts:
                if idx == 0xffff:
                    continue


                addr = self.image_base.add(segment_offset + i * page_size + idx )
                off = segment_offset + i * page_size + idx
                i+=1
                j= 0
                while True and monitor.isCancelled() == False:
                    content = self.read64(off)
                    offset = content & 0xffffffff
                    nxt = (content >> 51) & 2047
                    bind = (content >> 62) & 1
                    tag = (content >> 32) & 0xffff
                    if bind == 1:
                        name_off = self.read32(import_off + offset * 4)
                        name_off = (name_off >> 9)
                        symbol = self.br.readAsciiString(syms_off + name_off )

                        symbolTable = currentProgram.getSymbolTable()
                        ns = symbolTable.getNamespace("Global",None)
                        #sm = symbolTable.getSymbol(symbol,ns)
                        sm = getSymbol(symbol,ns)
                        if sm != None:
                            sym_addr = sm.getAddress().toString()#,hex(offset)
                        b = struct.pack("<Q",int(sym_addr,16))
                        self.mem.setBytes(addr,b,0,8)
                    else:
                        target = self.image_base.add(offset)
                        b = struct.pack("<Q",int(target.toString(),16))
                        self.mem.setBytes(addr,b,0,8)
                        #setEOLComment(addr,"tag")

                    self.listing.clearCodeUnits(addr,addr.add(8),False)
                    self.listing.createData(addr,PointerDataType())
                    skip = nxt * 4
                    addr = addr.add(skip)
                    off+=skip
                    j+=1
                    if skip == 0:
                        break
        print "OK"

    def _collect_method_info(self,className,addr_ptr,methAddr,tag,offset):
        meth = {}
        meth["off"] = offset
        meth["pac"] = tag
        meth["methAddr"] = int(methAddr.toString(),16)

        func = getFunctionAt(methAddr)
        signature = None
        funcName = None
        if func == None :
            fixLabel(methAddr)
            func = getFunctionAt(methAddr)
        assert func != None

        funcName = func.getName(True)
        #signature = func.getPrototypeString(True,False)
        sig = func.getSignature(True)
        sg = FunctionDefinitionDataType(sig)
        sg.setName(funcName)
        signature = sg.getPrototypeString(False)
        signature = signature[signature.find(" ")+1:]

        if signature == None or "FUN_" in signature:
            if offset == 0 :
                signature = className + "::" + className+"(void)"
            elif offset == 8:
                signature = className + "::~" + className+"(void)"
            else:
                signature = className + "::unkown_0x%x"%(offset) +"(void)"

        curr_ns = None
        mthod_ns = None

        if self.ns.has_key(className) == True:
            curr_ns = self.ns[className]
        else:
            curr_ns = self.symbolTable.getNamespace(className,None)
            self.ns[className] = curr_ns
        assert curr_ns != None
        fns,_ = signature.split("::")

        if self.ns.has_key(fns) == True:
            meth_ns = self.ns[fns]
        else:
            meth_ns = self.symbolTable.getNamespace(fns,None)
            self.ns[fns] = meth_ns
        assert meth_ns != None

        if curr_ns.toString() == meth_ns.toString():
            meth["overriden"] = True
        else :
            meth["overriden"] = False

        meth["signature"] = signature
        meth["name"] = funcName
        return meth

    def _collect_vtables(self):
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
                createLabel(addr,n+"_vtable",True,SourceType.USER_DEFINED)
            else:
                s.setName(n+"_vtable",SourceType.USER_DEFINED)
            self.bookmark.setBookmark(addr,"macOS",None,"")
            if self.vtables.has_key(n) == False:
                self.vtables[n] = addr


    def get_all_classes_info(self):
        """
        Get class objects, theis sizes and class parents
        """
        print "[+] Collecting all IOKit class information ..."
        metaClassSym = "__ZN11OSMetaClassC2EPKcPKS_j"
        syms = currentProgram.getSymbolTable().getSymbols(metaClassSym)
        if syms.hasNext() == False:
            raise Exception("Could not get metaclass constructor")

        mc_sym = None
        while syms.hasNext():
            sym = syms.next()
            if sym.getParentNamespace().getName() == "__stubs":
                mc_sym = sym
                break
        # Fixme : iOS15/macOS12
        if mc_sym == None:
            return

        mc_ea =  mc_sym.getAddress()
        refs = getReferencesTo(mc_ea)

        newmetaClassSym = "__ZN11OSMetaClassC2EPKcPKS_jPP4zoneS1_19zone_create_flags_t"
        syms = currentProgram.getSymbolTable().getSymbols(newmetaClassSym)
        mc_sym = None
        while syms.hasNext():
            sym = syms.next()
            if sym.getParentNamespace().getName() == "__stubs":
                mc_sym = sym
                break
        if mc_sym != None:
            mc_ea =  mc_sym.getAddress()
            refs += getReferencesTo(mc_ea)

        for ref in refs:
            if ref.getReferenceType().toString() != "UNCONDITIONAL_CALL":
                continue
            callSite = ref.getFromAddress()
            listing = currentProgram.getListing();
            caller = getFunctionContaining(callSite)
            hfunc = decompile_func(self.ifc,caller)
            pcodesOps = hfunc.getPcodeOps(callSite)
            for op in pcodesOps:
                if op.opcode == PcodeOp.CALL:
                    if op.getNumInputs() < 5:
                        raise ValueError

                    #1. get class name
                    className_arg = op.getInput(2)
                    # className_arg = COPY (const, ADDRESS, 8)
                    op1 = className_arg.getDef()
                    if op1 == None:
                        continue
                    addr = toAddr(op1.getInput(0).getOffset())
                    className = listing.getDataAt(addr).getValue()

                    #2. get its size
                    size_arg = op.getInput(4)
                    classSize = size_arg.getOffset()

                    #3. get class parent
                    classParent = self._get_class_parent(op)
                    if self.obj.has_key(className) ==True:
                        continue

                    self.obj[className] = [{"className":className, "size" : classSize, "parent":classParent}]
                    if classParent == None:
                        continue


                    parent_meta = "gMetaClass" #self.obj[className][0]["parent"]+"::gMetaClass"
                    syms = currentProgram.getSymbolTable().getSymbols(parent_meta)
                    for sym in syms:
                        if sym.getParentNamespace().getName() == classParent:
                            paddr = int(sym.getAddress().toString(),16)
                            if self.objects.has_key(className):
                                self.objects[className][0].update({"parent" : paddr})

        syms = currentProgram.getSymbolTable().getSymbols("vtable")
        for i in syms:
            name = i.getName(True)
            if "::MetaClass::" in name or "OSMetaClass" in name:
                continue

            addr = i.getAddress()
            n = i.getParentNamespace().getName()
            if self.obj.has_key(n) == False:
                continue
            addr = addr.add(0x10)
            s = getSymbolAt(addr)

            self.obj[n][0].update({"vtab" : addr})

    def get_class_parent(self,classInfo):
        if self.filetype != MH_KEXT_BUNDLE :# and self.objects.has_key(classInfo["className"]) == True:
            return kernelCache.get_class_parent(self,classInfo)
        if classInfo["parent"] == 0:
            return None

        addr = toAddr(hex(classInfo["parent"]).replace("L",""))
        if self.addrRange.contains(addr) == False:
                    return None
        parent = getSymbolAt(addr).getParentNamespace().getName()
        p = {}
        p[parent] = [{"size": 0x100,'className' : parent}]
        return p[parent][0]

    # # overload KernelCache
    def _process_class(self,className):
        if self.objects.has_key(className) == True:
            kernelCache._process_class(self,className)
            return
        return None
        #parent = self.create_parent_class(classInfo)
        #ret = self.create_class_structures(classInfo,parent)

    def _get_class_parent(self,op):
        classParent_arg = op.getInput(3)
        op1 = classParent_arg.getDef()
        if op1 == None:
            opp = classParent_arg
            addr = toAddr(opp.getOffset())
        else:
            assert (op1.opcode == PcodeOp.CAST)

            if op1.getInput(0).isUnique() == False:
                addr = toAddr(op1.getInput(0).getOffset())
            else:
                op2 = op1.getInput(0).getDef()
                if op2.opcode == PcodeOp.PTRSUB:
                    addr = toAddr(op2.getInput(1).getOffset())
                elif op2.opcode == PcodeOp.COPY:
                    addr = toAddr(op2.getInput(0).getOffset())
                else:
                    raise Exception

        p = getSymbolAt(addr).getName(True)
        if "PTR_gMetaClass" in p:
            d = getDataAt(addr)
            p = getSymbolAt(d.getValue()).getName(True)
        elif "DAT_" in p:
            return None
        classParent =  p.split("::")[0]

        return classParent

    def get_shared_dt_mgr(self):
        tool = state.getTool()
        service = tool.getService(DataTypeManagerService)
        dataTypeManagers = service.getDataTypeManagers();

        for manager in dataTypeManagers:
            if manager.name == self.sym_project:
                return manager

        raise Exception("Could not find shared DataType project manager %s" %(self.sym_project))

    # Associate the IOKit classes from the shared project to the current program database
    # if found skip, otherwise associate them
    def resolve_kernel_objects(self):
        if self.shm_dt == None:
            self.shm_dt = self.get_shared_dt_mgr()
        tid = self._start_transaction("move symbols")
        classes = self.objects.keys()
        for className in classes :
            find_cs = find_struct(className)
            find_cm = find_struct(className+"_members")

            assert(find_cm != None)

            self.dtm.associateDataTypeWithArchive(find_cs,self.shm_dt.getLocalSourceArchive())
            self.dtm.associateDataTypeWithArchive(find_cm,self.shm_dt.getLocalSourceArchive())
        self._end_trans(tid)



    def _start_transaction(self,name):
        return self.shm_dt.startTransaction(name)

    def _end_trans(self,tid):
        self.shm_dt.endTransaction(tid,True)

    def _find_local_struct(self,structName):
        locs = ["/","/Demangler/"]
        for loc in locs:
            dt = self.dtm.getDataType(loc+structName)
            if dt:
                return dt
