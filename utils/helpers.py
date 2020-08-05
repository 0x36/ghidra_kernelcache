from ghidra.app.services import DataTypeManagerService
from ghidra.program.model.symbol import SourceType,SymbolTable,Namespace,RefType
from ghidra.app.services import BlockModelService
from ghidra.app.cmd.function import ApplyFunctionSignatureCmd
from ghidra.app.decompiler import DecompileOptions,DecompInterface
from ghidra.app.util.cparser.C.CParserUtils import parseSignature,handleParseProblem
from ghidra.program.model.listing import Program, Parameter, ParameterImpl
from ghidra.program.model.data import FunctionDefinition,GenericCallingConvention, \
    ParameterDefinitionImpl
from ghidra.program.model.data import IntegerDataType, StructureDataType, UnsignedLongLongDataType, \
    PointerDataType,FunctionDefinitionDataType,TypedefDataType,VoidDataType
from ghidra.framework.plugintool.util import OptionsService
from ghidra.program.model.listing.Function import FunctionUpdateType
from ghidra.program.model.pcode import PcodeOp,HighFunctionDBUtil
#from ghidra.program.database.function import FunctionManager
from ghidra.app.cmd.function import CreateFunctionCmd 
import os,logging
from __main__ import *

def get_decompiler():
    ifc = DecompInterface()
    DecOptions = DecompileOptions()
    service = state.getTool().getService(OptionsService)

    opt = service.getOptions("Decompiler")
    DecOptions.grabFromToolAndProgram(None, opt, currentProgram)
    ifc.setOptions(DecOptions)

    ifc.toggleCCode(True)
    ifc.toggleSyntaxTree(True)
    ifc.setSimplificationStyle("decompile")

    ifc.openProgram(currentProgram)
    return ifc

def decompile_func(ifc,func):
    res = ifc.decompileFunction(func,ifc.options.defaultTimeout,monitor)
    if not res.decompileCompleted():
        print res.getErrorMessage()
        raise Exception("Decompilation is not completed")

    hfunc = res.getHighFunction()
    if hfunc == None:
        raise Exception("Cannot get HighFunction")
    return hfunc

def addTypeDef(name,nametype):
    dtm = currentProgram.getDataTypeManager()
    aType = find_dt(nametype) 
    #aType = dtm.getDataType("/"+nametype)
    if aType == None:
        return
    category = aType.getCategoryPath()
    newtype = TypedefDataType(category,name,aType,dtm)
    dtm.addDataType(newtype,None)
    
def DeclareDataTypes():
    addTypeDef("IOOptionBits","uint")
    addTypeDef("UInt32","uint")
    addTypeDef("IOReturn","uint")
    addTypeDef("IODirection","ulonglong")
    addTypeDef("IOVirtualAddress","ulonglong")
    addTypeDef("IOByteCount","ulonglong")
    addTypeDef("task","pointer64")
    addTypeDef("task","pointer")
    addTypeDef("OSMetaClassBase","ulonglong")
    addTypeDef("DestinationOrSource","uint")
    addTypeDef("socVersion","uint")
    addTypeDef("tUSBHostPortType","uint")
    addTypeDef("IOHIDReportType","uint")
    addTypeDef("IOReportChannelType","uint")
    addTypeDef("tUSBLinkState","uint")
    addTypeDef("IO80211LinkState","uint")
    addTypeDef("IOMbufServiceClass","ulonglong")
    addTypeDef("ChromaOrLuma","uint")
    addTypeDef("VerticalOrHorizontal","uint")
    addTypeDef("CCTimestamp","uint")
    addTypeDef("IORPC","uint")
    addTypeDef("IOPhysicalAddress","ulonglong")
    addTypeDef("IOAddressSegment","ulonglong")
    addTypeDef("IOAddressRange","ulonglong")
    addTypeDef("IOByteCount","ulonglong")
    addTypeDef("AbsoluteTime","ulonglong")
    addTypeDef("IOLock","ulonglong")
    addTypeDef("size_t","ulonglong")
    addTypeDef("u64","ulonglong")
    addTypeDef("ipc_port","ulonglong")
    addTypeDef("IOExternalMethodDispatch","void")
    addTypeDef("u32","ulong")
    
# Better Load Them from old projects    
def defineIOExternalMethodArguments():

    dtm = currentProgram.getDataTypeManager()
    dt = find_struct("IOExternalMethodArguments")
    IOMemoryDescriptor = find_struct("IOMemoryDescriptor")
    if IOMemoryDescriptor == None:
            IOMemoryDescriptor = dtm.getDataType("/ulonglong")

    new = None
    if dt == None:
        dt = StructureDataType("IOExternalMethodArguments",0)
        new = dt
        
    elif dt.getLength() > 1:
        yes = askYesNo("IOExternalMethodArguments",
                    "[-] Looks like IOExternalMethodArguments is already defined, continue ?")
        if yes == False:
            exit()

    uint = dtm.getDataType("/uint")
    ulonglong= dtm.getDataType("/ulonglong")

    st = dt
    st.add(uint,"version","")
    st.add(uint,"selector","")

    st.add(ulonglong,"asyncWakePort","")
    st.add(PointerDataType(uint),"asyncReference","")
    st.add(uint,"asyncReferenceCount","")
    
    st.add(PointerDataType(ulonglong),"scalarInput","")
    st.add(uint,"scalarInputCount","")
    st.add(PointerDataType(ulonglong),"structureInput","")
    st.add(uint,"structureInputSize","")
    
    st.add(PointerDataType(IOMemoryDescriptor),"StructureInputDescriptor","")

    st.add(PointerDataType(ulonglong),"scalarOutput","")
    st.add(uint,"scalarOutputCount","")

    st.add(PointerDataType(ulonglong),"structureOutput","")
    st.add(uint,"structureOutputSize","")

    st.add(PointerDataType(IOMemoryDescriptor),"structureOutputDescriptor","")
    st.add(uint,"structureOutputDescriptorSize","")

    st.add(uint,"__reservedA","")
    st.add(PointerDataType(ulonglong),"structureVariableOutputData","")
    st.setInternallyAligned(True)
    if new :
        dtm.addDataType(new,None)
        dtm.addDataType(PointerDataType(new),None)

def defineIOExternalTrap():
    dtm = currentProgram.getDataTypeManager()
    dt = dtm.findDataType(currentProgram.getName()+ "/"+"IOExternalTrap")

        
    uint = dtm.getDataType("/uint")
    IOService = dtm.getDataType("/IOService")
    IOTrap_def = "IOService::IOTrap(void * p1, void * p2, void * p3, void * p4, void * p5, void * p6)"
  
    fdef = FunctionDefinitionDataType(IOTrap_def)
    fdef.setReturnType(uint)
    fdef.setGenericCallingConvention(GenericCallingConvention.thiscall)
    
    st = StructureDataType("IOExternalTrap", 0)
    st.setToMachineAlignment()
    st.add(PointerDataType(IOService),"object","")
    st.add(PointerDataType(fdef),"func","")

    dtm.addDataType(PointerDataType(st),None)

def defineIOExternalMethod():
    dtm = currentProgram.getDataTypeManager()
    dt = dtm.findDataType(currentProgram.getName()+ "/"+"IOExternalMethod")
    
    IOService = dtm.getDataType("/IOService")
    IOMethod_def = "uint IOService::IOMethod(void * p1, void * p2, void * p3, void * p4, void * p5, void * p6)"
    uint = dtm.getDataType("/uint")
    ulonglong= dtm.getDataType("/ulonglong")

    fdef = parseCSignature(IOMethod_def)
    st = StructureDataType("IOExternalMethod", 0)
    
    st.setToMachineAlignment()
    st.add(PointerDataType(IOService),"object","")
    st.add(PointerDataType(fdef),"func","")
    st.add(uint,"flags","")
    st.add(ulonglong,"count0","")
    st.add(ulonglong,"count1","")

    dtm.addDataType(PointerDataType(st),None)

def defineIOExternalAsyncMethod():
    dtm = currentProgram.getDataTypeManager()
    dt = dtm.findDataType(currentProgram.getName()+ "/"+"IOExternalAsyncMethod")
    
    IOService = dtm.getDataType("/IOService")
    IOAsyncMethod_def = "uint IOService::IOAsyncMethod(uint asyncRef[8], void * p1, void * p2, void * p3, void * p4, void * p5, void * p6)"
    
    uint = dtm.getDataType("/uint")
    ulonglong= dtm.getDataType("/ulonglong")
    fdef = parseCSignature(IOAsyncMethod_def)
    st = StructureDataType("IOExternalAsyncMethod", 0)
    #BUG: Work with alignement
    st.setToMachineAlignment()
    st.add(PointerDataType(IOService),"object","")
    st.add(PointerDataType(fdef),"func","")
    st.add(uint,"flags","")
    st.add(ulonglong,"count0","")
    st.add(ulonglong,"count1","")

    dtm.addDataType(PointerDataType(st),None)

def fixLabel(data):
    name = getSymbolAt(data).getName()
    labelAddress = getSymbolAt(data).getAddress()
    #print labelAddress, name
    # ghidra refers to some functions as data, I've seen only one case
    if ("LAB_" not in name):
        currentProgram.getListing().clearCodeUnits(data,data.add(8),False)
        name = name.split("_")[1]
        ret = createFunction(labelAddress,"LAB_"+name)
        
    labelName = name.replace("LAB_","FUN_")
    #print disassemble(labelAddress)
    if disassemble(labelAddress) == False:
        popup("This Label "+ labelAddress + "cannot be disassembled !")
        return -1
    #print "labelName:",labelName
    ret = createFunction(labelAddress,labelName)
    func = getFunctionAt(labelAddress)
    if func == None:
        # Calling CreateFunction twice will force function creation
        # Don't ask me,ask NSA 
        ret = createFunction(labelAddress,labelName)
        
    # why it sometimes returns None ? last chance
    func = getFunctionAt(labelAddress)
    if(func == None):
        listing = currentProgram.getListing()
        blockModelService = state.getTool().getService(BlockModelService)
        cbm = blockModelService.getActiveSubroutineModel()
        cbIter = cbm.getCodeBlocksContaining(labelAddress, monitor)
        l = labelAddress
        currentProgram.getListing().clearCodeUnits(l,l.add(8),True)
        createFunction(labelAddress,"FUN_"+name)
        
        #x = getFunctionAt(labelAddress)
        #print cbIter
        #x = CreateFunctionCmd(labelAddress,False)
        #print type(x)
        #funcBody =  x.getFunctionBody(currentProgram,labelAddress)
        #print funcBody
        #mgr = currentProgram.getFunctionManager()
        #mgr.createFunction("test",labelAddress,funcBody,SourceType.USER_DEFINED)
        #raise Exception("Unable to create a function 0x%s" %(labelAddress.toString()))
        #x = ApplyFunctionSignatureCmd(labelName)
        #print x

        #return

    func = getFunctionAt(labelAddress)
    assert(func != None)
    func.setCustomVariableStorage(False)
    #params = func.getParameters()
    df = FunctionDefinitionDataType(func,False)
    
    # TODO : remove the below line , no need to change calling convention 
    #df.setGenericCallingConvention(GenericCallingConvention.thiscall)
    df.setReturnType(func.getReturnType())
    
    #df = FunctionDefinitionDataType(func,False)
    """
    func.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,#CUSTOM_STORAGE,
            True,
            SourceType.USER_DEFINED,
            params)
    """
    x = ApplyFunctionSignatureCmd(func.getEntryPoint(),df,SourceType.USER_DEFINED)
    x.applyTo(func.getProgram())
    
def defineLabel(symtab,namespace,addr,methodName):
    sym = getSymbolAt(addr)
    if sym == None:
        return
    src = sym.getSource()
    #The method assumes it's already defined a function
    if  "FUN_" not in sym.getName():
        return
    symtab.createLabel(addr,methodName,namespace,SourceType.ANALYSIS)

def makePTR(addr):
    PTR = currentProgram.getDataTypeManager().getDataType("/pointer")
    currentProgram.getListing().createData(addr, PTR)

def makeUint(addr,comment):
    #addr = toAddr(addr)
    uint_dt = currentProgram.getDataTypeManager().getDataType("/uint")
    currentProgram.getListing().createData(addr, uint_dt)
    #setEOLComment(addr,comment)

def makeULongLong(addr,comment= None):
    #addr = toAddr(addr)
    #uint_dt = currentProgram.getDataTypeManager().getDataType("/ulonglong")
    uint_dt = currentProgram.getDataTypeManager().getDataType("/qword")
    currentProgram.getListing().createData(addr, uint_dt)
    

def prepareClassName(className,classSize):
    locs = ["/","/Demangler/"]
    for location in locs:
        res = findDataTypeByName(location+className)
        if res:
            return
    
    class_struct = StructureDataType(className,0)
    currentProgram.getDataTypeManager().addDataType(class_struct,None)


'''
def parseCSignature(text):
    tool = state.getTool()
    service = tool.getService(DataTypeManagerService)
    dtm = currentProgram.getDataTypeManager()

    df =parseSignature(service,currentProgram,text)
    df.setGenericCallingConvention(GenericCallingConvention.thiscall)
    
    #dtm.addDataType(PointerDataType(df),None)
    return df
'''
def parseCSignature(text):
    tool = state.getTool()
    service = tool.getService(DataTypeManagerService)
    dtm = currentProgram.getDataTypeManager()
    df = None
    
    try:
        df =parseSignature(service,currentProgram,text,False)
    except ghidra.app.util.cparser.C.ParseException as e:
        # Loosy workaround , i will get back to it later 
        off = text.find("(")
        logger.warnign("[!] Please fix the definition of %s" % (text))
        text = text[:off]+"()"

        df = parseSignature(service,currentProgram,text,True)

    
    if df == None:
        return None
    df.setGenericCallingConvention(GenericCallingConvention.thiscall)
    
    #dtm.addDataType(PointerDataType(df),None)
    return df
#'''

def findDataTypeByName(name):
    tool = state.getTool()
    service = tool.getService(DataTypeManagerService)
    dataTypeManagers = service.getDataTypeManagers();
    
    for manager in dataTypeManagers:
        dataType = manager.getDataType(name)
        if dataType :
            return dataType
    
    return None

def find_struct(name):
    return find_dt(name)

def find_dt(name):
    locs = ["/","/Demangler/"]
    for location in locs:
        dt = findDataTypeByName(location+name)
        if dt:
            return dt
                
    return None

def find_funcdef(name):
    dt = findDataTypeByName("/functions/"+name)
    if dt : return dt
    return findDataTypeByName("/"+name)


def prepare():
    DeclareDataTypes()
    defineIOExternalMethodArguments()
    defineIOExternalTrap()
    defineIOExternalMethod()
    defineIOExternalAsyncMethod()
    

def setup_logging(name):
    #symbolTable = currentProgram.getSymbolTable() 
    logging.basicConfig(filename='/tmp/debug.log',level=logging.DEBUG)
    
    log = logging.getLogger(name)
    log.setLevel(logging.INFO)
    
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    #formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s: %(message)s')
    formatter = logging.Formatter('%(levelname)s: %(message)s')
    ch.setFormatter(formatter)
    
    log.addHandler(ch)

    return log

