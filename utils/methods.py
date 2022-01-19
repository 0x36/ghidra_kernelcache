from helpers import *
import glob

dtm = void = this = manager = None

def convert_namespace(ns_string):
    namespaces = {
        "AGXAcceleratorG12" : "AGXAcceleratorG10",
        "AGXAcceleratorG12P_B0" : "AGXAcceleratorG10P_B0",
        "AGXAcceleratorG12P_A0" : "AGXAcceleratorG10P_A0"
    }

    if namespaces.has_key(ns_string) == False:
        return ns_string

    return namespaces[ns_string]

def defineSymbol(symbol,fdef,hasNS=True):
    print symbol
    func = getFunctionAt(symbol.getAddress())
    df = FunctionDefinitionDataType(func,False)
    if hasNS == True:
        df.setGenericCallingConvention(fdef.getGenericCallingConvention())

    df.setReturnType(fdef.getReturnType())
    df.setArguments(fdef.getArguments())
    cmd = ApplyFunctionSignatureCmd(func.getEntryPoint(),df,SourceType.USER_DEFINED)
    cmd.applyTo(func.getProgram())

def symbolicate(addr,symbol):
    symbolTable = currentProgram.getSymbolTable()
    Addr = toAddr(addr)
    sym = getSymbolAt(Addr)

    try:
        symbolTable.createLabel(Addr,symbol,None,SourceType.ANALYSIS)
    except:
        print ("[-] Cannot symbolicate")

def define_label_with_namespace(addr,class_name,func_name=None):
    symbolTable = currentProgram.getSymbolTable()
    namespace = symbolTable.getNamespace(class_name,None)
    if namespace == None:
        print "%s not found" %(class_name)
        return
    #addr = toAddr(addr_string)
    sym = getSymbolAt(addr)

    src = sym.getSource()

    if func_name != None:

        symbolTable.createLabel(addr,func_name,namespace,SourceType.USER_DEFINED)
        return


    if src != SourceType.USER_DEFINED:
        symName = "FN_"+sym.getName().split("FUN_")[1]
        symbolTable.createLabel(addr,symName,namespace,SourceType.USER_DEFINED)

    # if we want to update the namespace
    if src == SourceType.USER_DEFINED and "FN_" in sym.getName() :
        #print "yes"
        symName = sym.getName()

        func = getFunctionAt(sym.getAddress())
        symbolTable.removeSymbolSpecial(sym)
        func.setParentNamespace(namespace)
        #sym.setParentNamespace(namespace)
        #symName = "FN_" + func.getName().split("FUN_")[1]
        symbolTable.createLabel(addr,symName,namespace,SourceType.USER_DEFINED)

def _fix_method(func,class_struct):
    #try:

    func.setCustomVariableStorage(True)
    params = func.getParameters()
    newParm =  ParameterImpl("this",PointerDataType(class_struct),currentProgram)
    #assert(len(params) != 0)
    if len(params) == 0:
        decompiler = get_decompiler()
        hfunc = decompile_func(decompiler,func)
        HighFunctionDBUtil.commitParamsToDatabase(hfunc,True,SourceType.USER_DEFINED)
        params = func.getParameters()
        #assert(len(params) != 0)

    if len(params) > 0:
        params[0] = newParm
    else:
        # a small workaround is by giving the user the choice to manually add
        # the parameters
        #print "FUNCTION ", func , "params" , len(params)
        #paramsCount = askInt("I couldn't get the params","Put parameter count:")
        #print paramsCount
        paramsCount = len(params)
        ulong_dt = currentProgram.getDataTypeManager().findDataType("/ulong")
        params = [newParm]
        # Already consumed one
        for i in range(paramsCount - 1):
            param = ParameterImpl("arg_" + str(i+0),ulong_dt,currentProgram)
            params.append(param)
            pass

    func.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
            True,
            SourceType.ANALYSIS,
            params)

    #except Exception as e:
    #    print "[-] Function is invalid" ,e
    #    raise Exception(e)

def fix_method(addr,class_name):
    dtm = currentProgram.getDataTypeManager()
    class_struct = find_struct(class_name)
    if class_struct == None:
        popup( "Class struct %s not found" %(class_name))
        return

    func = getFunctionAt(addr)

    _fix_method(func,class_struct)

    func.setCallingConvention("__thiscall")

def fix_func_namespace(className,FuncName):
    if "FUN_" in FuncName:
        dlm = "FUN_"
    elif "FN_" in FuncName:
        dlm = "FN_"
        #funcs.pop()
    f = FuncName.split(dlm)[1]
    define_label_with_namespace(f,className)
    fix_method(f,className)

def fix_method_definitions(namespace,fdefs):
    if namespace == "kernel":
        for fdef in fdefs:
            name = fdef.getName()
            symbols = manager.getSymbols(name)
            for symbol in symbols:
                full_name =  symbol.getName(True)
                dt = find_funcdef(full_name) #dtm.getDataType("/functions/"+full_name)
                if dt == None:
                    continue
                dt.setReturnType(fdef.getReturnType())
                args = fdef.getArguments()
                args.insert(0,this)
                dt.setArguments(args)

        return

    for fdef in fdefs:
        name = fdef.getName()
        full_name = namespace + '::'+ name
        dt = find_funcdef(full_name)
        # probably it's not a virtual function, alright
        if dt == None:
            continue
        dt.setReturnType(fdef.getReturnType())
        args = fdef.getArguments()
        args.insert(0,this)
        dt.setArguments(args)

def makeFunction(function_ptr):
    function = getDataAt(function_ptr)
    if function == None :
        currentProgram.getListing().clearCodeUnits(function_ptr,function_ptr,False)
        PTR = currentProgram.getDataTypeManager().getDataType("/pointer")
        if PTR == None:
            addTypeDef("pointer","pointer64")
            PTR = currentProgram.getDataTypeManager().getDataType("/pointer")

        currentProgram.getListing().createData(function_ptr, PTR)

    # label address value
    label = getDataAt(function_ptr).getValue()
    if label.getOffset() == 0:
        return

    func = getFunctionAt(label)

    if func == None:
        # the function is not defined as a function"
        if fixLabel(label) == -1:
            return
    return func

def fix_namespace(className,function,func_name=None):
    function_string = function.getName(True)
    if "FUN_" in function_string:
        dlm = "FUN_"
    elif "FN_" in function_string:
        dlm = "FN_"
        #funcs.pop()
    elif "extMethod" in function_string:
        dlm = "extMethod"

    #f = function_string.split(dlm)[1]

    func_addr = function.getEntryPoint()
    define_label_with_namespace(func_addr,className,func_name)
    fix_method(func_addr,className)


def getHeaderFiles():
    return glob.glob("/Users/mg/ghidra_ios/signatures/*")

def load_signatures_from_file(filename):
    funcs = open(filename,"r").read().strip().split('\n')
    tool = state.getTool()
    service = tool.getService(DataTypeManagerService)
    dtm = currentProgram.getDataTypeManager()
    funcDefs = []

    for func in funcs:
        vtable = False
        if len(func) == 0:
            continue
        if func[0] == "#":
            continue
        if func[0] == "-":
            vtable = True

        text = func[1:]
        funcDef = parseSignature(service,currentProgram,text)
        if vtable == True:
            funcDef.setGenericCallingConvention(GenericCallingConvention.thiscall)

        funcDefs.append(funcDef)

    return funcDefs

# this fixes directly the function signature of a given function
def fix_function_signatures(namespace,fdefs):
    manager = currentProgram.getSymbolTable()
    for fdef in fdefs:
        symbol = fdef.getName()
        if namespace == "kernel":
            symbols = manager.getSymbols(symbol)
            for s in symbols:
                defineSymbol(s,fdef)
            #continue

        ns = manager.getNamespace(namespace,None)
        # get symbol only for that namespace
        symbols = manager.getSymbols(symbol,ns)
        if len(symbols) == 0 or ns == None:
            #print(" [-] Symbol/Namespace not found for %s "% (fdef.getName()) , ns)
            continue
        if symbols == None:
            continue
        if len(symbols) == 1:
            defineSymbol(symbols[0],fdef)
            continue

        #TODO : handle multi symbols below
        print("[!] Multiple symbols found for %s"%(symbol))
        #print fdef,symbols
        #raise Exception

def load_signatures():
    DeclareDataTypes()
    dtm = currentProgram.getDataTypeManager()
    void = currentProgram.getDataTypeManager().findDataType("/void")
    this = ParameterDefinitionImpl("this",PointerDataType(void),"")
    manager = currentProgram.getSymbolTable()

    files = getHeaderFiles()
    #files = ["/Users/mg/gh_projects/signatures/kernel.h"]
    for file in files:
        print ("[+] Processing %s" %(file))
        namespace = file.split(".h")[0].split("/")[-1]
        fdefs= load_signatures_from_file(file)
        fix_function_signature(namespace,fdefs)
        fix_method_definition(namespace,fdefs)
