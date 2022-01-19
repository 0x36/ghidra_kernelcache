from helpers import *
from __main__ import *
from methods import *

from ghidra.program.model.data import DataTypeConflictHandler

class kernelCache(object):
    def __init__(self,objects,macOS=False):
        self.objects = objects
        self.macOS = macOS
        if self.macOS == False:
            del self.objects["OSKext"]
        self.log = setup_logging("kernelcache")
        self.symbolTable = currentProgram.getSymbolTable()
        self.listing = currentProgram.getListing()
        self.refMgr = currentProgram.getReferenceManager()

        OSMetaClassBase = find_struct("OSMetaClassBase")
        if OSMetaClassBase == None:
            OSMetaClassBase = StructureDataType("OSMetaClassBase",0)
        namespace = self.symbolTable.getNamespace("OSMetaClassBase",None)

        if namespace == None:
            namespace = self.symbolTable.createClass(None,"OSMetaClassBase",SourceType.USER_DEFINED)

        mn,mx = currentProgram.getMinAddress(),currentProgram.getMaxAddress()
        self.memRange = AddressRangeImpl(mn,mx)

    def process_classes_for_bundle(self,bundle_str):
        names = self.get_classes_by_bundle(bundle_str)
        for name in names:
            self._process_class(name)

        for name in names:
            kernelCacheClass(self.objects[name],False,self.macOS)


    def process_classes(self,names):
        for name in names:
            self._process_class(name)
        for name in names:
            kernelCacheClass(self.objects[name],False,self.macOS)

    # Construct every class found in objects
    def process_all_classes(self):
        names = self.objects.keys()
        for name in names:
            self._process_class(name)
        for name in names:
            kernelCacheClass(self.objects[name],False,self.macOS)

    def process_class(self,className):
        self._process_class(className,True)

    def _process_class(self,className,single=False):
        classInfo = self.objects[className][0]
        parent = self.create_parent_class(classInfo)
        ret = self.create_class_structures(classInfo,parent)
        # if the structures already defined, return
        if ret == None:
            return
        if parent == None:
            # Needs to be tested
            #kernelCacheClass(self.objects[className])
            return

        pclassName,pclassSize = parent['className'], parent['size']
        pclassMembers = find_struct(pclassName+"_members")
        classMembers = find_struct(className+"_members")

        class_struct = find_struct(className)
        pclass_struct = find_struct(pclassName)

        if pclassMembers == None or classMembers == None:
            msg = "Fatal: Could not get %s_members or %s_members" %(className,pclassName)
            raise Exception(msg)

        pnamespace = self.symbolTable.getNamespace(pclassName,None)
        namespace = self.symbolTable.getNamespace(className,None)
        if namespace == None or pnamespace == None:
            raise Exception("%s's Namespace not found " %(pnamespace))

        # namespace.setParentNamespace(pnamespace)
        # some classes are there but without vtable
        if len(self.objects[className]) != 2:
                return
        if single == True:
            kernelCacheClass(self.objects[className],False,self.macOS)

    def update_class(self,name,obj):
        # tbd
        pass


    def remove_classes(self):
        names =  self.objects.keys()
        for name in names:
            struc = find_struct(name)
            if struc == None:
                return

            struc.deleteAll() # clear all old vtable fields

    def update_classes_vtable(self):
        names =  self.objects.keys()
        for name in names:
            vtable = find_struct(name+"_vtable")
            if vtable == None:
                return

            vtable.deleteAll() # clear all old vtable fields
            kernelCacheClass(self.objects[name],True,self.macOS)

    # Clears the content of the class structures (vtables are excluded)
    def clear_class_structures(self):
        names = self.objects.keys()
        for name in names:
            class_member = find_struct(name+"_members")
            class_struct = find_struct(name)

            if class_member:
                class_member.deleteAll()
            if class_struct:
                class_struct.deleteAll()

    def get_classes_by_bundle(self,bundle):
        l = []
        names = self.objects.keys()
        for name in names:
            if self.objects[name][0]["bundle"] == bundle:
                l.append(name)
        return l

    def fix_kernelcache(self):
        names = self.objects.keys()
        for name in names:
            if len(self.objects[name]) < 2:
                return
            kernelCacheClass(self.objects[name],self.macOS)


    def get_class_parent(self,classInfo):
        parent = classInfo["parent"]
        name = classInfo["className"]
        cs = self.objects.keys()
        for c in cs:
            obj = self.objects[c]
            if obj[0]['meta'] == parent:
                return obj[0]
        return None

    def create_parent_class(self,classInfo):
        namespace = self.symbolTable.getNamespace(classInfo['className'],None)
        if namespace == None:
            namespace = self.symbolTable.createClass(None,classInfo['className'],SourceType.USER_DEFINED)
        parent = self.get_class_parent(classInfo)
        if parent == None:
            return None

        self._process_class(parent['className'])
        #self.create_class_structures(parent,None)
        return parent

    def create_class_structures(self,classInfo,classInfoParent):
        className,classSize = classInfo['className'], classInfo['size']
        class_struct = None
        class_members = None

        find_cs = find_struct(className)
        find_cm = find_struct(className + "_members")
        find_vt = find_struct(className + "_vtable")

        pclass_struct = None
        if classInfoParent != None:
            pclassName, pclassSize = classInfoParent["className"] , classInfoParent["size"]
            pclass_struct  = find_struct(pclassName)
        if find_cm and find_cs and find_vt:
            #print "[!] %s class structures already defined" %(className)
            return None

        sz = 0
        if find_cm == None and find_vt == None:
            class_vtable  = StructureDataType(className+"_vtable",0)
            if pclass_struct == None:
                class_members = StructureDataType(className+"_members",classSize - 8)
            else:
                sz = classSize - pclass_struct.length
                if( sz < 0):
                    self.log.error("Could not have negative size %d of %s parent=%s"
                                   %(sz,className,pclassName))
                    sz = classSize + pclass_struct.length

                class_members = StructureDataType(className+"_members",sz)

        elif find_vt == None and find_cm != None:
            class_vtable  = StructureDataType(className+"_vtable",0)
            class_members  = find_cm

        elif find_vt != None and find_cm == None:
            print "BAD ",className
            assert(1==0)

        else:

            class_members  = find_cm
            class_vtable  = find_vt

        if find_cs == None:
            class_struct  = StructureDataType(className,0)
        else:
            class_struct = find_cs

        #class_struct.setPackingValue(8)
        class_struct.setExplicitPackingValue(8)
        class_struct.add(PointerDataType(class_vtable),0,"vtable","")
        if pclass_struct == None:
            class_struct.insertAtOffset(8,class_members,classSize - 8,"m_"+className+"","")

        else:
            comps = pclass_struct.getComponents()
            num = pclass_struct.getNumComponents()
            s = 8
            for i in range(1,num):
                c = pclass_struct.getComponent(i)
                cdt = c.getDataType()
                cn = c.getFieldName()
                cz = c.getLength()
                class_struct.insertAtOffset(s,cdt,cz,cn,"")
                s += cz

            # we cannot pass 0 size structure
            if sz != 0:
                class_struct.insertAtOffset(s,class_members,0,"m_"+className+"","")
                #class_struct.insertAtOffset(s,class_members,0,className+"","")

        if find_cm == None:
            currentProgram.getDataTypeManager().addDataType(class_members,None)
            currentProgram.getDataTypeManager().addDataType(class_vtable,None)

        if find_cs == None:
            currentProgram.getDataTypeManager().addDataType(class_struct,None)
        return class_struct

    def _pac_prepare_methods(self):
        print("[+] Sorting PACs ... ")
        self.pac_dict = {}
        obj = self.objects
        get_methods = lambda key,obj: obj[key][1]

        for k in obj.keys():
            if len(obj[k]) < 2:
                continue
            l = get_methods(k,obj)
            for method in l:
                pac = method['pac']
                if self.pac_dict.has_key(pac) == True:
                    if self.has_method(method['signature'],pac) == True:
                        continue

                    self.pac_dict[pac].append(method)
                else:
                    self.pac_dict[pac] = [method]


    def has_method(self,signature,pac):
        for mm in self.pac_dict[pac]:
            if signature == mm['signature']:
                return True

        return False

    def _find_movk_instr(self):
        print("[+] Searching for MOVK instructions")
        instrs = self.listing.getInstructions(currentProgram.getImageBase(),True)

        movks = []
        for ins in instrs:
            if ins.getMnemonicString() != "movk":
                continue
            ins_addr = ins.getAddress()
            pac_val = ins.getOpObjects(1)[0]
            pac_val = int(pac_val.getValue())
            if self.pac_dict.has_key(pac_val) == False:
                continue
            movks.append((ins,pac_val))
        self.movks = movks
        return self.movks

    def add_mem_ref(self,ins,pac):
        ll = self.pac_dict[pac]
        #  Filter out the unecessary calls
        if len(ll) > 50:
            return

        self.refMgr.removeAllReferencesFrom(ins.getAddress())

        for meth in ll:
            methAddr = meth['methodAddr']
            # This means the address is exteranal
            if methAddr == 0 or self.memRange.contains(toAddr(hex(methAddr).replace("L",""))) == False:
                m = meth["name"]
                if ("::" in m) == False:
                    return
                ns,name = m.split("::")
                syms = currentProgram.getSymbolTable().getSymbols(name)
                for s in syms:
                    fname = s.getName(True)
                    if fname != m:
                        continue
                    methAddr = int(s.getAddress().toString(),16)
                    methAddr = hex(methAddr).replace("L","")

                    print "[+] Found a reference for 0x%s with pac=0x%x,%s" %(ins.getAddress().toString(),pac,methAddr)
                    self.refMgr.addMemoryReference(ins.getAddress(),
                                                   toAddr(methAddr),
                                                   RefType.COMPUTED_CALL,
                                                   SourceType.USER_DEFINED, 0)
                return

            methAddr = hex(methAddr).replace("L","")

            print "[+] Found a reference for 0x%s with pac=0x%x,%s" \
                %(ins.getAddress().toString(),pac,methAddr)
            self.refMgr.addMemoryReference(ins.getAddress(),toAddr(methAddr),RefType.COMPUTED_CALL, SourceType.USER_DEFINED, 0)

    def _resolve_refs(self):
        print("[+] Resolving PAC references ...")
        for t in self.movks:
            # Look for blraa/braa instructions
            ins,pac = t
            for i in range(100):
                ins = ins.getNext()
                if ins == None:
                    break
                if ins.getMnemonicString() != "blraa" and ins.getMnemonicString() != "braa":
                    continue
                self.add_mem_ref(ins,pac)
                break


    def explore_pac(self):
        self._pac_prepare_methods()
        movks = self._find_movk_instr()
        self._resolve_refs()


fdefs = {}
class kernelCacheClass(object):
    def __init__(self,infos,update=False,macOS=False):
        if len(infos) < 2:
            return
        self.macOS = macOS
        classInfo , methodsInfo = infos
        addr = classInfo['vtab']
        name = classInfo['className']
        size = classInfo['size']
        bundle = classInfo['bundle']#[:-1]
        print "[+] Processing %s class with vtab=0x%lx" %(name,addr)

        self.start = addr
        self.className = name
        self.classSize = size
        self.classBundle = bundle
        self.methodsInfo = methodsInfo
        self.SymVtable = toAddr(hex(addr).replace("L",""))
        self.update = update
        self.class_struct  = None
        self.vtable_struct = None
        self.refMgr = currentProgram.getReferenceManager()

        self.end = 0 # tbd
        self.dtm = currentProgram.getDataTypeManager()
        self.listing = currentProgram.getListing()
        self.symbolTable = currentProgram.getSymbolTable()
        self.bookmark = currentProgram.getBookmarkManager()
        self.tool = state.getTool()
        self.service = self.tool.getService(DataTypeManagerService)
        self.namespace = None
        # fast namesapce lookups
        self.namespaces = {}
        self.currentProgram = currentProgram
        self.decompiler = None #get_decompiler()
        self.log = setup_logging("kernelcache")
        self.pointer = self.dtm.getDataType("/pointer64")
        if self.pointer == None:
            self.pointer = self.dtm.getDataType("/pointer")
        self.void = self.dtm.findDataType("/void")

        self.renameTable()
        self.fixMethoTable()
        self.defineObjects()
        if self.decompiler != None:
            self.decompiler.dispose()

    def renameTable(self):
        """
        Assign a name of 'object_vtable' label to the virtual table
        """
        self.setBookmark()
        sym = getSymbolAt(self.SymVtable)
        if sym == None:
            createLabel(self.SymVtable,self.className+"_vtable",False)
            return 0

        sym.setName(self.className+"_vtable",SourceType.USER_DEFINED)
        return 0

    def fixMethoTable(self):
        """
        Fix Method table by making each entry as a pointer
        Get the start/end of the vtable
        """
        add = self.start
        self.end = self.start
        i = 0
        off = 0
        while True:
            Addr = toAddr(hex(add).replace("L",""))
            data = self._fixAndGetData(Addr)
            value = data.getValue()
            # if the pointer is NULL, we may have reached the end of the vtable
            v = int(value.toString(),16) & 0xfffffffffff00000
            if v == 0 or v == 0xfffffffffff00000 :
                self.end = add
                break

            setEOLComment(Addr,"0x%x"%(off))
            function = getFunctionAt(value)
            if function == None:
                if self.macOS == True:
                    pass
                else:
                    fixLabel(value)

            off+=8
            add+=8

    # define the class and the virtual table objects
    def defineObjects(self):
        self._getClassName()
        self._getClassNamespace()
        self._getVtableStruct()
        self._defineVtable()

    def _getVtableStruct(self):
        self.classNameVtable = self.className + "_vtable"
        self.vtable_struct = find_struct(self.classNameVtable)

        assert(self.vtable_struct != None)

        return self.vtable_struct

    def _defineVtable(self):

        constructor = self.methodsInfo[0]
        try:
            className,methName = constructor['name'].split("::")
        except:
            className,methName,_ = constructor['name'].split("::")

        self.methodsInfo[0]["name"] = className + "::constructor_" + className
        self.methodsInfo[1]["name"] = className + "::destructor_" + className
        self.methodsInfo[0]["signature"] = className + "::cst_" + className +"()"
        self.methodsInfo[1]["signature"] = className + "::dst_" + className +"()"
        i = 1
        meths = {}
        for method in self.methodsInfo:
            if len(method['name']) == 0:
                    continue
            methName = method['name'].split("::")[1]
            methAddr = toAddr(hex(method['methodAddr'])[:-1])

            # working with C++ function overload
            if meths.has_key(methName) == True:
                meths[methName] += 1
                old = methName
                methName = methName + "_%d" %(meths[methName])
                method['name'] = method['name'].replace(old,methName)
                method['signature'] = method['signature'].replace(old,methName)
            else:
                meths[methName] = 0

            # Ghidra doesnt like const keyword
            funcDef = self.prepareSignature(method)
            assert(funcDef)
            name = funcDef.getDisplayName()
            ret = self.vtable_struct.add(PointerDataType(funcDef), methName, "")

    def setCustomFunctionDefinition(self,name,addr,namespace,text):
        if addr.toString() == "ffffffffffffffff":
            funcDef = FunctionDefinitionDataType(namespace.getName()+"::"+name)
            return funcDef

        func = getFunctionAt(addr)
        if func == None:
            func = fixLabel(addr)

        if func == None:
            msg = "Unable to get function at %s, please undo, then manually create that function (type 'f'), save, then launch ghidra_kernelcache again" %(addr)
            raise Exception(msg )
            #return None

        func.setName(name,SourceType.USER_DEFINED)
        if namespace != None:
            func.setParentNamespace(namespace)
        func.setCustomVariableStorage(False)

        count = func.getParameterCount()
        if count == 0:
            if self.decompiler == None:
                self.decompiler = get_decompiler()
            try:
                hfunc = decompile_func(self.decompiler,func)
                HighFunctionDBUtil.commitParamsToDatabase(hfunc,True,SourceType.USER_DEFINED)
            except:
                pass

        if func.getParameterCount() != 0:
            func.removeParameter(0)

        #func.setCustomVariableStorage(False)
        func.setCallingConvention("__thiscall")
        funcName = func.getName(True)
        funcDef = FunctionDefinitionDataType(func,True)
        funcDef.setName(funcName)
        return funcDef

    # Make the content of addr as a pointer
    def _makePTR(self,addr):
        try:
            self.listing.createData(addr, self.pointer)
        except:
            self.listing.clearCodeUnits(addr,addr.add(8),False)
            self.listing.createData(addr, self.pointer)


    def _fixAndGetData(self,Addr):
        data =getDataAt(Addr)
        # GHIDRA somehow fails to identify some methods
        if data == None or data.pointer == False:
            self._makePTR(Addr)
            data = getDataAt(Addr)
        return data

    # returns a class (create it if not found)
    def _getClassNamespace(self):
        self.namespace = self.symbolTable.getNamespace(self.className,None)
        assert(self.namespace != None)
        return self.namespace

    def _getClassName(self):
        if self.class_struct:
            return self.class_struct
        self.class_struct = find_struct(self.className)
        assert(self.class_struct != None)

        return self.class_struct

    def setBookmark(self):
        bookmarks = self.bookmark.getBookmarks(self.SymVtable,"iOS")
        for bookmark in bookmarks:
            self.bookmark.removeBookmark(bookmark)
        self.bookmark.setBookmark(self.SymVtable,"iOS",None,self.classBundle)

    def prepareSignature(self,method):
        return self.parseCSignature(method)

    # Returns a function definition for the current method
    # Or Creates a new one if not found
    def parseCSignature(self,method):

        #text = "undefined4 "+ method["signature"] #.split("::")[1]
        #text = text.replace("const","")

        full_name = method['name']
        nn = full_name.split("::")
        if len(nn) == 2:
            methNS,methName = nn[0] , nn[1]
        elif len(nn) == 3:
            methNS,methName = nn[0] , nn[1]+"::" +nn[2]

        methAddr = toAddr(hex(method['methodAddr'])[:-1])
        func = None
        if methAddr != None:
            func = getFunctionAt(methAddr)

        if func == None:
            text = "undefined4 "+ method["signature"] #.split("::")[1]
            text = text.replace("const","")
        else:
            rett = func.getReturnType().getName()
            text =  rett +" "+ method["signature"] #.split("::")[1]
            text = text.replace("const","")

        if method['overriden'] == True:
            namespace = self.namespace
        else:
            if self.namespaces.has_key(methNS):
                namespace = self.namespaces[methNS]
            else:
                namespace = self.symbolTable.getNamespace(methNS,None)
                self.namespaces[methNS] = namespace

        assert(namespace != None)
        new = False
        if self.isUnknownMethod(methName) == False:
            try:
                df = None
                if fdefs.has_key(full_name) == True:
                    df = fdefs[full_name]
                    return df

                df = parseSignature(self.service,self.currentProgram,text,False)
                new = True

                assert(df != None)
                if self.macOS == True and methAddr == None:
                    name = method['name']
                    fdd = find_funcdef(name)
                    assert(fdd != None)
                    return fdd

                func = getFunctionAt(methAddr)
                # pure virtual method
                if func == None:
                    return df
                src = func.getSymbol().getSource()

                # BROKEN: more testing on this condition
                #if src == SourceType.USER_DEFINED and self.update == False:
                #    #raise Exception(func)
                #    return df

                df.setGenericCallingConvention(GenericCallingConvention.thiscall)
                df.setReturnType(func.getReturnType())

                func.setCustomVariableStorage(False)
                func.setParentNamespace(namespace)

                cmd = ApplyFunctionSignatureCmd(func.getEntryPoint(),df,SourceType.USER_DEFINED)
                cmd.applyTo(func.getProgram())
                func.setName(methName,SourceType.USER_DEFINED)
            except ghidra.app.util.cparser.C.ParseException as e:
                # Ghidra is unable to parse this signature
                # Put the original definition above, so the user will manually handle it
                setPlateComment(methAddr,text)
                df = self.setCustomFunctionDefinition(methName,methAddr,namespace,text)
        else:
            if fdefs.has_key(full_name) == True:
                df = fdefs[full_name]
                return df

            df = self.setCustomFunctionDefinition(methName,methAddr,namespace,text)
            new = True

        #insert 'this' pointer at the begining of the parameters
        args = df.getArguments()
        this = ParameterDefinitionImpl("this",PointerDataType(self.void),"")
        args.insert(0,this)
        df.setArguments(args)
        func = getFunctionAt(methAddr)
        if func != None:
            df.setReturnType(func.getReturnType())
            # Needs to be tested
            if self.update == True:
                raise Exception("Broken : Please don't enable it")
            else:
                df = self.dtm.addDataType(df,None)
                fdefs[full_name] = df
            plate = getPlateComment(methAddr)
            if plate == None:
                setPlateComment(methAddr,text)

        return df

    def isUnknownMethod(self,method_name):
        if "fn_0x" in method_name:
            return True

        return False

