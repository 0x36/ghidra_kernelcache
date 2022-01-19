#@category iOS.kernel
#@toolbar logos/sign.png
#@keybinding Meta Shift S

from utils.helpers import *
from utils.methods import *
import glob

dtm = void = this = manager = None

def getHeaderFiles():
    return glob.glob("/Users/mg/ghidra_kernelcache/signatures/*")

def load_signatures_from_file(filename):
    funcs = open(filename,"r").read().strip().split('\n')
    tool = state.getTool()
    service = tool.getService(DataTypeManagerService)
    dtm = currentProgram.getDataTypeManager()
    funcDefs = []
    text = ""

    for func in funcs:
        vtable = False
        if len(func) == 0:
            continue
        elif func[0:2] == "//":
            continue
        elif func[0:8] == "virtual ":
            vtable = True
            text = func[8:]

        elif func[0:7] == "struct ":
            structName = func.split(" ")[1].replace(";","")
            structDt = find_struct(structName)
            if structDt != None:
                continue
            structDt  = StructureDataType(structName,0)
            currentProgram.getDataTypeManager().addDataType(structDt,None)
            currentProgram.getDataTypeManager().addDataType(PointerDataType(structDt),None)
            continue
        elif func[0:8] == "typedef ":
            kw, old, new = func.split(" ")
            addTypeDef(new[:-1],old)
            continue

        else:
            text = func

        try:
            funcDef = parseSignature(service,currentProgram,text,True)
        except ghidra.app.util.cparser.C.ParseException as e:
            print e
            raise Exception("Failed to parse the signature")

        if vtable == True:
            funcDef.setGenericCallingConvention(GenericCallingConvention.thiscall)

        funcDefs.append(funcDef)

    return funcDefs

# this fixes directly the function signature of a given function
def fix_function_signatures(namespace,fdefs):
    tool = state.getTool()
    service = tool.getService(DataTypeManagerService)
    manager = currentProgram.getSymbolTable()
    for fdef in fdefs:
        symbol = fdef.getName()
        if namespace == "kernel":
            symbols = manager.getSymbols(symbol)
            for s in symbols:
                defineSymbol(s,fdef)

        ns = manager.getNamespace(namespace,None)
        symbols = manager.getSymbols(symbol,ns)
        if len(symbols) == 0 or ns == None:
            continue
        if symbols == None:
            continue
        if len(symbols) == 1:
            defineSymbol(symbols[0],fdef)
            continue

        #TODO : handle multi symbols below
        # a very bad workaround, but it's sufficient
        for sym in symbols:
            addr = sym.getAddress()

            plate =  getPlateComment(addr)
            if plate == None:
                continue

            plate = plate.replace("const","")
            retType = fdef.getReturnType()
            try:
                df = parseSignature(service,currentProgram,plate,True)
            except ghidra.app.util.cparser.C.ParseException as e:
                print e
                exit(0)

            if df == None:
                plate = retType.toString()+ " " + plate
                try:
                    df = parseSignature(service,currentProgram,plate,True)
                except ghidra.app.util.cparser.C.ParseException as e:
                    print e
                    exit(0)

                if df == None:
                    continue

            defineSymbol(sym,df)

def fix_method_definitions(namespace,fdefs):
    if namespace == "kernel":
        for fdef in fdefs:
            name = fdef.getName()
            symbols = manager.getSymbols(name)
            for symbol in symbols:
                full_name =  symbol.getName(True)
                dt = find_funcdef(full_name)
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
        if dt == None:
            continue

        dt.setReturnType(fdef.getReturnType())
        args = fdef.getArguments()
        args.insert(0,this)
        dt.setArguments(args)

if __name__ == "__main__":
    DeclareDataTypes()
    dtm = currentProgram.getDataTypeManager()
    void = currentProgram.getDataTypeManager().findDataType("/void")
    this = ParameterDefinitionImpl("this",PointerDataType(void),"")
    manager = currentProgram.getSymbolTable()

    files = getHeaderFiles()
    for file in files:
        print ("[+] Processing %s" %(file))
        namespace = file.split(".h")[0].split("/")[-1]
        fdefs= load_signatures_from_file(file)
        fix_function_signatures(namespace,fdefs)
        fix_method_definitions(namespace,fdefs)
