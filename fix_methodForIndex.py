# Fix IOExternalMethod for getTargetAndMethodForIndex
#@author simo
#@category iOS.kernel
#@keybinding Meta Shift B
#@menupath
#@toolbar logos/in.png
#@description test

# -*- coding: utf-8 -*-

from utils.helpers import *
from utils.methods import *

import json

def handle_kIOUCScalarIScalarO(func,count0,count1):
    logger.debug("kIOUCScalarIScalar func=%s, count0=%d, count1=%d" %(func.getName(),count0,count1))
    tool = state.getTool()
    service = tool.getService(DataTypeManagerService)

    o = 0
    signature = ""
    if count0 == 0:
        if count1 != 0:
            signature = "%s %s("
            for i in range(0,count1):
                #for c in range(count0):
                signature += "uint32_t *scalarOut%d, " %(i)

            signature = signature[:-2]

            signature+= ")"
        else:
            signature = "%s %s(void)"
    else:
        signature = "%s %s("
        for i in range(0,count0):
            #for c in range(count0):
            if i < count0:
                signature += "uint32_t scalar%d, " %(i)

        signature = signature[:-2]
                
        signature+= ")"
    
    name = func.getName()
    ret = func.getReturnType()
    #print signature
    signature = signature %(ret.toString(),name)

    fdef = parseSignature(service,currentProgram,signature)
    return fdef

def handle_kIOUCStructIStructO(func,count0,count1):
    # if count0 and count 1 are set (input,output,inputCnt,outputCnt)
    # else (input,inputCnt)
    logger.debug("kIOUCStructIStructO func=%s, count0=%d, count1=%d" %(func.getName(),count0,count1))
    tool = state.getTool()
    service = tool.getService(DataTypeManagerService)

    signature = ""
    if count1 != 0 :
        if count0 != 0:
            signature = "%s %s(char *input,char *output,uint64_t inputCnt,uint64_t *outputCnt)"
        else:
            signature = "%s %s(char *output,uint64_t *outputCnt)"
    
    else:
        signature = "%s %s(char *input,uint64_t inputCnt)"

    name = func.getName()
    ret = func.getReturnType()
    signature = signature %(ret.toString(),name)
    
    #print signature
    fdef = parseSignature(service,currentProgram,signature)
    return fdef
    

def handle_kIOUCScalarIStructO(func,count0,count1):
    logger.debug("kIOUCScalarIStructO func=%s, count0=%d, count1=%d" %(func.getName(),count0,count1))
    tool = state.getTool()
    service = tool.getService(DataTypeManagerService)

    signature = ""
    
    if count0 == 0:
        if count1 != 0:
            signature = "%s %s(char *output,uint32_t *outputCnt)"
        else:
            signature = "%s %s(void)"
    else:
        signature = "%s %s("
        for i in range(count0):
            signature+= "uint32_t scalar%d, " %(i)

            signature+="char *output,uint32_t *outputCnt)"

    name = func.getName()
    ret = func.getReturnType()
    signature = signature %(ret.toString(),name)
    #print signature
    fdef = parseSignature(service,currentProgram,signature)
    return fdef


def handle_kIOUCScalarIStructI(func,count0,count1):
    logger.debug("kIOUCScalarIStructI func=%s, count0=%d, count1=%d" %(func.getName(),count0,count1))
    tool = state.getTool()
    service = tool.getService(DataTypeManagerService)

    signature = ""
    
    if count0 == 0:
        if count1 != 0:
            signature = "%s %s(char *input,uint32_t inputCnt)"
        else:
            signature = "%s %s(void)"
    else:
        signature = "%s %s("
        for i in range(count0):
            signature+= "uint32_t scalar%d, " %(i)

            signature+="char *input,uint32_t inputCnt)"

    name = func.getName()
    ret = func.getReturnType()
    signature = signature %(ret.toString(),name)
    fdef = parseSignature(service,currentProgram,signature)

    return fdef
    

def fix_getTargetAndMethodForIndex(target,selectors,sMethods):
    logger.info("target=%s selectors=%d ,sMethod=%s" %(target,selectors, sMethods))
    manager = currentProgram.getSymbolTable()
    symbolTable = currentProgram.getSymbolTable()
    listing = currentProgram.getListing()
    refMgr = currentProgram.getReferenceManager()
    kIOUCTypeMask       = 0x0000000f
    kIOUCScalarIScalarO = 0
    kIOUCScalarIStructO = 2
    kIOUCStructIStructO = 3
    kIOUCScalarIStructI = 4
    kIOUCForegroundOnly = 0x00000010
    kIOUCVariableStructureSize = 0xffffffff

    d = {
        kIOUCScalarIScalarO : "kIOUCScalarIScalarO",
        kIOUCScalarIStructO : "kIOUCScalarIStructO",
        kIOUCStructIStructO : "kIOUCStructIStructO",
        kIOUCScalarIStructI : "kIOUCScalarIStructI"
        }

    namespace = symbolTable.getNamespace(target,None)
    addr = toAddr(sMethods)
    assert(namespace != None)
    for sel in range(selectors):
        object_ptr = addr
        func_ptr   = addr.add(8)
        off_ptr    = addr.add(16)
        flags_ptr    = addr.add(24)
        count0_ptr    = addr.add(32)
        count1_ptr    = addr.add(40)

        listing.clearCodeUnits(addr,addr.add(48),False,monitor)
        addr = addr.add(48)
        makeULongLong(object_ptr,"object")
        makeULongLong(flags_ptr,"function")
        makeULongLong(off_ptr,"is offset")
        makeULongLong(count0_ptr,"count0")
        makeULongLong(count1_ptr,"count1")

 
        setEOLComment(object_ptr,"sel %d" %(sel))
        isOffset = getDataAt(off_ptr).getValue().getValue()

        if isOffset == 0:
            func = makeFunction(func_ptr)
            func_addr = getDataAt(func_ptr).getValue()
            func = getFunctionAt(func_addr)
            
        else:
            # function referenced as offset
            listing.clearCodeUnits(func_ptr,func_ptr,False,monitor)
            makeULongLong(func_ptr,"object")
            logger.debug("Function is Offset")
            off = getDataAt(func_ptr).getValue().getValue()

            ns = namespace.getName() +"_vtable"

            symbol = manager.getSymbol(ns,None)
            assert(symbol != None)
            ptr = symbol.getAddress().add(off)
            ref_addr = getDataAt(ptr).getValue()

            func = getFunctionAt(ref_addr)
            
            ref = refMgr.addMemoryReference(func_ptr, ref_addr,
                                            RefType.COMPUTED_CALL, SourceType.DEFAULT, 0)
            setEOLComment(func_ptr,"offset=0x%x" %(off))
            #print nss.getSymbol()
            #raise Exception("Not handled yet")
        
        flags = getDataAt(flags_ptr).getValue()
        count0 = getDataAt(count0_ptr).getValue().getValue()
        count1 = getDataAt(count1_ptr).getValue().getValue()
        
        #print func_ptr,func,func_addr
        if func == None:
            continue
        flags = flags.getValue() & kIOUCTypeMask

        if flags == kIOUCScalarIScalarO:
            fdef = handle_kIOUCScalarIScalarO(func,count0,count1)
        elif flags == kIOUCScalarIStructO:
            fdef = handle_kIOUCScalarIStructO(func,count0,count1)
        elif flags == kIOUCStructIStructO:
            fdef = handle_kIOUCStructIStructO(func,count0,count1)
        elif flags == kIOUCScalarIStructI:
            fdef = handle_kIOUCScalarIStructI(func,count0,count1)

        else:
            raise Exception("Unknown flag %d" %(flags))

        setEOLComment(flags_ptr,d[flags])
        if "FUN_" in func.getName() or "FN_" in func.getName():
            func.setName("extMethod_%d" %(sel),SourceType.USER_DEFINED)
            
        func.setParentNamespace(namespace)
        cmd = ApplyFunctionSignatureCmd(func.getEntryPoint(),fdef,SourceType.USER_DEFINED)
        cmd.applyTo(func.getProgram())
        func.setCallingConvention("__thiscall")

if __name__ == "__main__":
    sMethods = currentAddress
    if sMethods == None :
        popup("Select a The first External Method address")        
        exit(-1)

    logger = setup_logging("getTargetAndMethodForIndex")
    
    addr_str = sMethods.toString()
    target = askString("Namespace","Target name: ") # how to track the history of strings ?
    selectors = askInt("sMethod " + addr_str,"Selector count: ")
    """
    target="IOAccelSharedUserClient2"
    selectors=14
    addr_str="fffffff006e80990"
    """
    fix_getTargetAndMethodForIndex(target,selectors,addr_str)
    
    """
    
    addr_str = "fffffff006ddfe00" 
    target = "IOSurfaceAcceleratorClient"
    selectors = 10 
    fix_getTargetAndMethodForIndex(target,selectors,addr_str)
    
    addr_str = "fffffff00576c018"
    target = "IOPKEAcceleratorUserClient"
    selectors = 3
    fix_getTargetAndMethodForIndex(target,selectors,addr_str)

    addr_str = "fffffff006eacb28"
    target = "AppleJPEGDriverUserClient"
    selectors = 7
    fix_getTargetAndMethodForIndex(target,selectors,addr_str)

    addr_str = "fffffff006e6f120"
    target = "AppleSMCClient"
    selectors = 3
    fix_getTargetAndMethodForIndex(target,selectors,addr_str)
    """
    pass
