#@author simo
#@category iOS.kernel
#@keybinding Meta Shift P
#@menupath
#@toolbar logos/p_logo.png
#@description propagate the new symbol name/type across function arguments
# -*- coding: utf-8 -*-

from ghidra.app.script import GhidraScript,GhidraState
from ghidra.program.model.data import FunctionDefinition
from ghidra.app.util.demangler import Demangler
from ghidra.app.cmd.label import DemanglerCmd
from ghidra.program.model.data import IntegerDataType,VoidDataType,StructureDataType,UnsignedLongLongDataType,PointerDataType,FunctionDefinitionDataType
from ghidra.program.model.data import FunctionDefinitionDataType
from ghidra.program.model.listing import Parameter,ParameterImpl,Program
from ghidra.program.model.symbol import SourceType,SymbolTable,Namespace,RefType
from ghidra.program.util.GhidraProgramUtilities import getCurrentProgram
from  ghidra.app.services import DataTypeManagerService
from ghidra.app.decompiler import DecompileOptions,DecompInterface,DecompilerLocation
from  ghidra.app.decompiler.component import DecompilerUtils
from ghidra.framework.plugintool.util import OptionsService
from ghidra.program.model.pcode import PcodeOp,HighFunctionDBUtil
from ghidra.program.model.listing.Function import FunctionUpdateType
import logging
import os,sys

logger = []
ifc = None
def init_logger(name):
    log = logging.getLogger(name)
    log.setLevel(logging.DEBUG)
    
    ch = logging.StreamHandler()
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s: %(message)s')
    ch.setFormatter(formatter)
    
    log.addHandler(ch)

    return log

def _decompiler():
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

def get_caller_op(addr):
    inst = currentProgram.getListing().getInstructionAt(addr)

    for i in range(100):
        addr = inst.getAddress()

        ops = dc.getHighFunction().getPcodeOps(addr)

        for op in ops:
            if op.opcode == PcodeOp.CALLIND:
                return op

            elif op.opcode == PcodeOp.CALL:
                return op

        inst = inst.getNext()

#get high function from varnode
def get_function(caller):
    
    func_addr = caller.getAddress()
    func = getFunctionAt(func_addr)

    # we want to deal only with functions with a namespace
    if func.getParentNamespace().isGlobal() == True:
        return None
        
    hfunc = decompile_func(ifc,func)
    HighFunctionDBUtil.commitParamsToDatabase(hfunc,True,SourceType.USER_DEFINED)
        
    return hfunc

def get_input_index(op,var):
    index = -1
    inputs = op.getInputs()
    for i,input in enumerate(inputs):
        if input == var:
            index = i
            break
    index = index -1
    return index

def resolve_param(func,param_index,varname,vartype):
    params = func.getParameters()
    if len(params) < param_index:
        raise Exception("Function params are intact")
    
    print "[+] '%s' is used in %s in parameter index %d" %(varname,func.getName(True),param_index)
    target_param = params[param_index]
    target_param.setName(varname,SourceType.USER_DEFINED)
    target_param.setDataType(vartype,SourceType.USER_DEFINED)
    
def analyze_pcode(varname,vartype, dstvar , op):

    param_index = -1
    if op.opcode == PcodeOp.CALL:
        inputs = op.getInputs()
        caller = inputs[0]


        param_index = get_input_index(op,dstvar)
        if param_index == -1:
            raise Exception("target param not found ")
        
        hfunc = get_function(caller)
        # global namesapce is out of scope
        if hfunc == None:
            return
        func = hfunc.getFunction()

        resolve_param(func,param_index,varname,vartype)
    elif op.opcode == PcodeOp.CALLIND:
        # get memory reference
        pc = op.getSeqnum().getTarget()
        refMgr = currentProgram.getReferenceManager()
        refs = refMgr.getReferencesFrom(pc,0)
        if len(refs) == 0:
            raise Exception()
            return 

        # take care for one ref atm
        ref  = refs.pop()
        addr = ref.getToAddress()
        
        # get function from that address
        func = getFunctionAt(addr)
        hfunc = decompile_func(ifc,func)
        HighFunctionDBUtil.commitParamsToDatabase(hfunc,True,SourceType.USER_DEFINED)

        # get the input index from the operation varnode
        param_index = get_input_index(op,dstvar)
        if param_index == -1:
            raise Exception("target param not found ")

        

        # get parameter index from the resolved function
        # change its name/type
        resolve_param(func,param_index,varname,vartype)

if __name__ == "__main__":
    logger = init_logger("propagator")
    ifc = _decompiler()
    
    if isinstance(currentLocation,DecompilerLocation) == False:
        logger.error("Put the cursor in the decompiler window")
        raise Exception
    

    cl = currentLocation
    dc = cl.getDecompile()
    addr = cl.getAddress()
    tokenAtCursor = cl.getToken();
    var = DecompilerUtils.getVarnodeRef(tokenAtCursor);
    if var == None:
        print "[-] Cannot get the varnode "
        raise Exception("Varnode error")
    
    desc = var.getDescendants()

    varhigh = var.getHigh()

    if varhigh == None:
        raise Exception("Could not get High variable")

    varname = varhigh.getName()
    vartype = varhigh.getDataType()
    if varname == None or vartype == None:
        raise Exception("No name/type found ")
    print varname,vartype

    for op in desc :
        if op.opcode == PcodeOp.CALL or op.opcode == PcodeOp.CALLIND:
            analyze_pcode(varname,vartype,var,op)

        elif op.opcode == PcodeOp.CAST:
            varref = op.getOutput()#.getDef()
            newops = varref.getDescendants()
            for newop in newops:
                print "Cast Operation ",newop
                analyze_pcode(varname,vartype,varref,newop)
        elif op.opcode == PcodeOp.SUBPIECE:
            pass
        elif op.opcode == PcodeOp.INT_ZEXT:
            varref = op.getOutput()
            newops = varref.getDescendants()
            for newop in newops:
                analyze_pcode(varname,vartype,varref,newop)
        else:
            print "Unhandled op"
            
        print "*" * 100
Make the fastest running secure atuomanic system to run all in l 
