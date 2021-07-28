from helpers import *
from __main__ import *

class kernelCache(object):
    def __init__(self,objects):
        self.objects = objects
        self.log = setup_logging("kernelcache")
        self.symbolTable = currentProgram.getSymbolTable()

        #
        #self.fix_kernelcache()
        OSMetaClassBase = find_struct("OSMetaClassBase")
        if OSMetaClassBase == None:
            OSMetaClassBase = StructureDataType("OSMetaClassBase",0)
        namespace = self.symbolTable.getNamespace("OSMetaClassBase",None)

        if namespace == None:
            namespace = self.symbolTable.createClass(None,"OSMetaClassBase",SourceType.USER_DEFINED)

    def process_classes_for_bundle(self,bundle_str):
        names = self.get_classes_by_bundle(bundle_str)
        for name in names:
            self.process_class(name)

    def process_classes(self,names):
        for name in names:
            self.process_class(name)
    
    def process_all_classes(self):
        names = self.objects.keys()
        for name in names:
            self.process_class(name)
        
    def process_class(self,className):
        classInfo = self.objects[className][0]
        parent = self.create_parent_class(classInfo)
        ret = self.create_class_structures(classInfo,parent)
        # if structures already defined, return
        if ret == None:
            return
        print "[+] Creating %s class with size 0x%x " %(className,classInfo['size'])
        if parent == None:
            # Needs to be tested
            kernelCacheClass(self.objects[className])
            return
        
        pclassName,pclassSize = parent['className'], parent['size']        
        pclassMembers = find_struct(pclassName+"_members")
        classMembers = find_struct(className+"_members")

        class_struct = find_struct(className)
        pclass_struct = find_struct(pclassName)
        
        if pclassMembers == None or classMembers == None:
            msg = "Fatal: Could not get %s_members or %s_members" %(className,pclassName)
            #popup(msg)
            raise Exception(msg)

        #classMembers.replace(0,pclassMembers,0,pclassName,"")
        
        pnamespace = self.symbolTable.getNamespace(pclassName,None)
        namespace = self.symbolTable.getNamespace(className,None)
        if namespace == None or pnamespace == None:
            #print namespace , pnamespace
            raise Exception("%s's Namespace not found " %(pnamespace))

        #namespace.setParentNamespace(pnamespace)
        # some classes are there without vtable
        if len(self.objects[className]) != 2:
                return
        kernelCacheClass(self.objects[className],False)

    def update_class(self,name,obj):
        # tbd
        pass

    def update_classes(self):
        names =  self.objects.keys()
        for name in names:
            vtable = find_struct(name+"_vtable")
            assert(vtable != None)

            vtable.deleteAll() # clear all old vtable fields 
            kernelCacheClass(self.objects[name],True)

    def clear_class_structures(self):
        names = self.objects.keys()
        for name in names:
            class_member = find_struct(name+"_members")
            class_struct = find_struct(name)

            class_member.deleteAll()
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
            kernelCacheClass(self.objects[name])
            
        
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
            print "[+] Defining %s namespace" %(classInfo['className'])
            namespace = self.symbolTable.createClass(None,classInfo['className'],SourceType.USER_DEFINED)
            
        parent = self.get_class_parent(classInfo)
        if parent == None:
            return None

        self.process_class(parent['className'])
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
            #print className, "form", pclassName
            pclass_struct  = find_struct(pclassName)
            #print pclass_struct
        if find_cm and find_cs and find_vt:
            #print "[!] %s class structures already defined" %(className)
            #print find_cm
            #raise Exception
            return None

        sz = 0
        #print find_cm,find_vt
        if find_cm == None and find_vt == None:
            # change this by removing -8

            class_vtable  = StructureDataType(className+"_vtable",0)
            #"""
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
            print "BAD "
            assert(1==0)
            
        else:
            
            class_members  = find_cm
            class_vtable  = find_vt
            
        if find_cs == None:
            class_struct  = StructureDataType(className,0)
        else:
            class_struct = find_cs

        class_struct.setExplicitPackingValue(8)
        class_struct.add(PointerDataType(class_vtable),0,"vtable","")
        if pclass_struct == None:
            class_struct.insertAtOffset(8,class_members,classSize - 8,className+"","")
            
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

            # we cannot pass 0 sized structure
            if sz != 0:
                class_struct.insertAtOffset(s,class_members,0,className+"","")
                
        if find_cm == None:
            currentProgram.getDataTypeManager().addDataType(class_members,None)
            currentProgram.getDataTypeManager().addDataType(class_vtable,None)

        if find_cs == None:
            currentProgram.getDataTypeManager().addDataType(class_struct,None)
        return class_struct

class kernelCacheClass(object):
#class kcClass(object):
    def __init__(self,infos,update=False):
        if len(infos) < 2:
            #self.log.warning("class %s has no info " % (infos[0]))
            return
        classInfo , methodsInfo = infos
        addr = classInfo['vtab']
        name = classInfo['className']
        size = classInfo['size']
        bundle = classInfo['bundle']#[:-1] 
        print "[+] Resolving %s class with vtab=0x%lx" %(name,addr)
        
        self.start = addr
        self.className = name
        self.classSize = size
        self.classBundle = bundle
        self.methodsInfo = methodsInfo
        self.SymVtable = toAddr(hex(addr).replace("L",""))
        self.update = update
        self.class_struct  = None
        self.vtable_struct = None
        
        self.end = 0 # to be defined 
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
            # if the pointer is NULL, we reach the end of the vtable
            v = int(value.toString(),16) & 0xfffffffffff00000
            if v == 0 or v == 0xfffffffffff00000 :
                self.end = add
                break
            
            setEOLComment(Addr,"0x%x"%(off))
            function = getFunctionAt(value)
            if function == None:
                #print value
                fixLabel(value)

            off+=8
            add+=8

    # define the class and the virtual table objects
    def defineObjects(self):
        self.getClassName()
        self.getClassNamespace()
        self.getVtableStruct()
        self.defineVtable()

    def getVtableStruct(self):
        self.classNameVtable = self.className + "_vtable"
        self.vtable_struct = find_struct(self.classNameVtable)

        assert(self.vtable_struct != None)

        return self.vtable_struct
    
    def defineVtable(self):

        constructor = self.methodsInfo[0]
        
        className,methName = constructor['name'].split("::")
        self.methodsInfo[0]["name"] = className + "::" + className
        self.methodsInfo[1]["name"] = className + "::~" + className
        self.methodsInfo[0]["signature"] = className + "::" + className +"()"
        self.methodsInfo[1]["signature"] = className + "::~" + className +"()"
        i = 0
        for method in self.methodsInfo:
            if len(method['name']) == 0:
                    continue
            methName = method['name'].split("::")[1]
            methAddr = toAddr(hex(method['methodAddr'])[:-1])
            # Ghidra doesnt like const keyword
            #methSignature = method['signature'].replace("const","")

            funcDef = self.prepareSignature(method)
            assert(funcDef)
            
            ret = self.vtable_struct.add(PointerDataType(funcDef), methName, "")

    """
    def fixMethodDefinition(self,fdef,method,namespace):
        '''
        Apply a new function signature to the appropriate method
        Create a new function definiton for vtable usage 
        '''
        if fdef == None:
            print method
            #return
        assert(fdef != None)    
        # fix function signature 
        func_address = method["methodAddr"]
        methName = method['name'].split("::")[1]
        if func_address == 0xffffffffffffffff:
            return
        function_address = toAddr(hex(method['methodAddr']).replace("L",""))
        func = getFunctionAt(function_address)

        if func == None :
            popup("Something unusual happened to this function %s" %(methName))
            
        # if the function already has a namespace, don't change it 
        sym = func.getName(True)
        if func == None:
            return
        
        #self.symbolTable.createLabel(function_address,fdef.getName().split("::")[1],namespace,SourceType.ANALYSIS)
        old_symbol = self.symbolTable.getPrimarySymbol(function_address)
        if namespace == None:
            name = fdef.getName().split("::")[0]
            namespace = self.symbolTable.getNamespace(name,None)
            
        sym = self.symbolTable.createSymbol(function_address,fdef.getName().split("::")[1],
                                      namespace,SourceType.ANALYSIS)
        #sym.setPrimary()
        func.setCallingConvention("__thiscall")
        
        # functions start with fn_ dont have a real function
        # signature, so we want to rely on Ghidra's analysis
        func.setCustomVariableStorage(False)
        
        cmd = ApplyFunctionSignatureCmd(func.getEntryPoint(),fdef,SourceType.USER_DEFINED)
        cmd.applyTo(func.getProgram())
        
        args = fdef.getArguments()

        this = ParameterDefinitionImpl("this",PointerDataType(self.void),"")
        args.insert(0,this)
        fdef.setArguments(args)
    """
    
    #def _getFunctionDefinition(self,methName):
    #    return self.dtm.findDataType(currentProgram.getName()+ "/functions/"+methName)

    def setCustomFunctionDefinition(self,name,addr,namespace,text):
        #TODO: fix me please

        if addr.toString() == "ffffffffffffffff":
            funcDef = FunctionDefinitionDataType(namespace.getName()+"::"+name)
            return funcDef
        
        func = getFunctionAt(addr)
        if func == None:
            print addr
            raise Exception
        func.setName(name,SourceType.USER_DEFINED)
        #print namespace
        if namespace != None:
            func.setParentNamespace(namespace)
        func.setCustomVariableStorage(False)

        count = func.getParameterCount()
        #print func
        #assert(count != 0)
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

    # Make a memory content as a pointer
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
        #print data.getValueClass()
        return data
    
    # return (and create if not found) a class  
    def getClassNamespace(self):
        self.namespace = self.symbolTable.getNamespace(self.className,None)
        assert(self.namespace != None)
        return self.namespace

    def getClassName(self):
        if self.class_struct:
            return self.class_struct
        self.class_struct = find_struct(self.className)
        assert(self.class_struct != None)

        return self.class_struct
    
    
    def prepareSignature(self,method):
        func = "undefined8 "+ method["signature"] #.split("::")[1]
        func = func.replace("const","")
        
        #if "fn_0x" in func:
        #    return None
        
        return self._parseCSignature(func,method)

    def setBookmark(self):
        bookmarks = self.bookmark.getBookmarks(self.SymVtable,"iOS")
        for bookmark in bookmarks:
            self.bookmark.removeBookmark(bookmark)
        self.bookmark.setBookmark(self.SymVtable,"iOS",None,self.classBundle)

    # creates function definition if no def exists before
    # returns a function definition for the current method
    def _parseCSignature(self,text,method):
        full_name = method['name']
        methNS,methName = full_name.split("::")
        methAddr = toAddr(hex(method['methodAddr'])[:-1])
        
        df = find_funcdef(full_name)
        """
        if df != None:
            # has to be well tested
            # This case is when a class has multiple same function names
            func = getFunctionAt(methAddr)
            src = func.getSymbol().getSource()
            if src == SourceType.DEFAULT:
                if method['overriden'] == True:
                    #print func,full_name
                    df = self.setCustomFunctionDefinition(methName,methAddr,self.namespace,text)
            
            return df
        """
        
        plate = getPlateComment(methAddr)
        if plate == None:
            setPlateComment(methAddr,text)
        if method['overriden'] == True:
            namespace = self.namespace
        else:        
            if self.namespaces.has_key(methNS):
                namespace = self.namespaces[methNS]
            else:
                namespace = self.symbolTable.getNamespace(methNS,None)
                self.namespaces[methNS] = namespace
                
        assert(namespace != None)
        if self.isUnknownMethod(methName) == False:
            try:
                df = parseSignature(self.service,self.currentProgram,text,False)
                assert(df != None)
                func = getFunctionAt(methAddr)
                # pure virtual method
                if func == None:
                    return df
                #assert(func != None)
                #func.setCallingConvention("__thiscall")
                src = func.getSymbol().getSource()

                # more testing on this condition 
                #if src == SourceType.USER_DEFINED and "fn_0x" not in func.getName():
                #    return df

                if src == SourceType.USER_DEFINED and self.update == False:
                    return df

                df.setGenericCallingConvention(GenericCallingConvention.thiscall)
                df.setReturnType(func.getReturnType())
                
                func.setCustomVariableStorage(False)
                func.setParentNamespace(namespace)
                
                cmd = ApplyFunctionSignatureCmd(func.getEntryPoint(),df,SourceType.USER_DEFINED)
                cmd.applyTo(func.getProgram())
                func.setName(methName,SourceType.USER_DEFINED)
                #return df
            except ghidra.app.util.cparser.C.ParseException as e:
                # Put the originale definition above, so the user will manually
                # handle it 
                setPlateComment(methAddr,text)
                
                #ns = self.symbolTable.getNamespace(methNS,None)
                
                df = self.setCustomFunctionDefinition(methName,methAddr,namespace,text)
                #return df
        else:
            """
            func = getFunctionAt(methAddr)
            assert(func != None)
            src = func.getSymbol().getSource()
            if src == SourceType.USER_DEFINED and self.update == False:
                return df
            """
            df = self.setCustomFunctionDefinition(methName,methAddr,namespace,text)
            
            
        #insert 'this' pointer at the begining of args
        args = df.getArguments()
        this = ParameterDefinitionImpl("this",PointerDataType(self.void),"")
        args.insert(0,this)
        df.setArguments(args)

        if self.update == True:
            fdef = find_funcdef(df.getName())            
            self.dtm.replaceDataType(fdef,df,False)
        else:
            # put the function definition into datatype mgr
            self.dtm.addDataType(df,None)
        return df

    def isUnknownMethod(self,method_name):
        if "fn_0x" in method_name:
            return True
        
        return False
    
