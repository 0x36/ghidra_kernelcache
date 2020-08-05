# Fix IOExternalMethodDispatch for externalMethod()
#@author simo
#@category iOS.kernel
#@keybinding Meta Shift B
#@menupath
#@toolbar logos/ext.png
#@description test

# -*- coding: utf-8 -*-

from utils.helpers import *
from utils.methods import *
import json

logger = None

def fix_extMethod(class_struct ,func):
    dtm = currentProgram.getDataTypeManager()
    IOArgs_dt = find_struct("IOExternalMethodArguments")
    assert(IOArgs_dt != None)
    
    
    this =  ParameterImpl("this",PointerDataType(class_struct),currentProgram)
    reference = ParameterImpl("reference",PointerDataType(VoidDataType()),currentProgram)
    IOArgs = ParameterImpl("args",PointerDataType(IOArgs_dt),currentProgram)

    params = [this,reference,IOArgs]

    func.replaceParameters(FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
            True,
            SourceType.USER_DEFINED,
            params)

IOExternalMethodDispatch_size = 24

external_methods = {}
def fix_externalMethods(target,selectors,sMethods):
    
    logger.info("target=%s selectors=%d ,sMethod=%s" %(target,selectors, sMethods))
    _sMethods = sMethods
    className = target
    symbolTable = currentProgram.getSymbolTable() 
    listing =  currentProgram.getListing()
    
    namespace = symbolTable.getNamespace(className,None)

    if namespace == None:
        popup("[-] %s class not found  " %(className))
        exit(-1)
    class_struct = find_struct(className)
    
    em_infos = {}
    for sel in range(selectors):
        #off = sel * 24
        function_off  = int(sMethods,16)
        checkScalarInputCount_off       = function_off + 8
        checkStructureInputSize_off     = checkScalarInputCount_off + 4
        checkScalarOutputCount_off      = checkStructureInputSize_off + 4
        checkStructureOutputSize_off    = checkScalarOutputCount_off +4
        
        smAddr = toAddr(sMethods)
        
        function_ptr = toAddr(hex(function_off).replace("L",""))
        function_end = toAddr(hex(function_off+25).replace("L",""))
        
        scalarInput_addr = toAddr(hex(checkScalarInputCount_off).replace("L",""))
        structureInput_addr = toAddr(hex(checkStructureInputSize_off).replace("L",""))
        scalarOutput_addr = toAddr(hex(checkScalarOutputCount_off).replace("L",""))
        structureOutput_addr = toAddr(hex(checkStructureOutputSize_off).replace("L",""))
                
        listing.clearCodeUnits(function_ptr,function_end,False)

        func = makeFunction(function_ptr) # make function
        func_addr = getDataAt(function_ptr).getValue()
        
        func = getFunctionAt(func_addr)
        if func != None:
            symName = "extMethod_%d" %(sel)
            fix_namespace(className,func,symName)
            fix_extMethod(class_struct,func)

            #if func.getSymbol().getSource() != SourceType.USER_DEFINED:
            #func.setName(symName,SourceType.USER_DEFINED)

        setEOLComment(function_ptr,"sel %d" %(sel))
        makeUint(scalarInput_addr,"scalarInput")
        makeUint(structureInput_addr,"structureInput")
        makeUint(scalarOutput_addr,"scalarOutput")
        makeUint(structureOutput_addr,"structureInput")

        sMethods = hex(int(sMethods,16) + 24).replace("L","")

        scalarInputCnt = getDataAt(scalarInput_addr).getValue()
        structureInputCnt = getDataAt(structureInput_addr).getValue()
        scalarOutputCnt = getDataAt(scalarOutput_addr).getValue()
        structureOutputCnt = getDataAt(structureOutput_addr).getValue()
        
        #print "SCALAR COUNT", scalarInputCnt
        #print "SCALAR COUNT", structureInputCnt
        #print "SCALAR COUNT", scalarOutputCnt
        #print "SCALAR COUNT", structureOutputCnt
        function_name = func.getName(False)
        call_info = {
            "selector"              :   sel,
            "scalarInputCnt"        :   scalarInputCnt.getValue(),
            "structInputCnt"        :   structureInputCnt.getValue(),
            "scalarOutputCnt"       :   scalarOutputCnt.getValue(),
            "structOutputCnt"       :   structureOutputCnt.getValue(),
            "async"                 :   False,
            "address": func_addr.toString()
            }
        
        em_infos[function_name] = call_info
    
    external_methods['externalMethods'] =  em_infos # externalMethods
    external_methods['target'] =  className    # userclient
    external_methods['user_client_type'] =  0      # connection type (-1 means undefiend)
    external_methods['sMethods'] =  _sMethods
    out_file = "/tmp/%s.json"%(className)
    with open(out_file, 'w') as json_file:
        json.dump(external_methods, json_file,indent=4, sort_keys=True)
    #print app
    logger.info("%s file created" %(out_file))

if __name__ == "__main__":
    sMethods = currentAddress
    #sMethods = toAddr("fffffff006dbe7a0")
    if sMethods == None :
        popup("Select a The first External Method address")        
        exit(-1)

    logger = setup_logging("external_method")
    addr_str = sMethods.toString()
    target = askString("Namespace","Target name: ") # how to track the history of strings ?
    selectors = askInt("sMethod " + addr_str,"Selector count: ")
    
    fix_externalMethods(target,selectors,addr_str)
