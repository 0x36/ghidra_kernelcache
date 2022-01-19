from helpers import *
from methods import *
from references import *

funcs = []
logger = []

black_list_ns = ["OSObject","OSArray","OSDictionary","OSData","OSString",
                 "OSBoolean","OSCollection","OSCollectionIterator",
                 "OSIterator","OSNumber","OSOrderedSet","OSSerialize",
                 "OSSerializer","OSSet","OSSymbol","OSAction","OSUserMetaClass"]

def append_to_functions(func):
    if func in funcs:
        return
    ns = func.getSymbol().getParentNamespace()
    if ns.getName() not in black_list_ns:
        funcs.append(func)

# get the DataType of the the first argument
def process_this(this):
    if this.isRegister():
        dt = this.getHigh().getDataType()
        return dt.getName().replace("*","").strip()

    thisdef = this.getDef()
    if thisdef == None:
        return None

    if thisdef.opcode == PcodeOp.CAST:
        var = thisdef.getInput(0)
        if var.isRegister():
            dt = var.getHigh().getDataType()
            return dt.getName().replace("*","").strip()
        else:
            pass

        return None

def fix_hfunc_namespaces(hfunc):
    symbolTable = currentProgram.getSymbolTable()
    global funcs
    for op in hfunc.pcodeOps:
        addr = op.getSeqnum().getTarget()
        if op.opcode  == PcodeOp.CALL:
            numParams = op.getNumInputs()
            # avoiding functions with no arguments
            if numParams < 2:
                continue
            caller = op.getInput(0)
            targetFunc = getSymbolAt(toAddr(caller.getOffset()))
            targetFuncName = targetFunc.getName()
            if "FUN_" not in targetFuncName and "FN_" not in targetFuncName :
                continue

            this = op.getInput(1)
            className = process_this(this)
            if className == None:
                continue
            namespace = symbolTable.getNamespace(className,None)
            if namespace == None:
                logger.debug("[-] I couldn't get the namespace of '%s' 0x%s" %(className,addr))
                continue
            logger.debug("[+] Namespace : Function %s with namespace %s " %(targetFuncName,className))

            func  = getFunctionContaining(targetFunc.getAddress())
            if func not in funcs :
                append_to_functions(func)
                fix_namespace(className,func)

def process_vn_for_refs(cdef,depth=0):

    logger.debug("depth=%d, def : %s",depth,cdef.toString())

    if cdef.opcode == PcodeOp.LOAD:
        varnode = cdef.getInput(1)
        if varnode.isUnique() == False:
            logger.error("This may produce undesirable output, unhandled case ")
            raise Exception

        uniqueDef = varnode.getDef()
        return process_vn_for_refs(uniqueDef,depth+1)

    elif cdef.opcode == PcodeOp.PTRSUB:
        reg , const = cdef.getInputs()
        vtable = reg.getHigh().getDataType()
        offset = const.getOffset()
        return (vtable,offset)

    elif cdef.opcode == PcodeOp.CAST:
        varnode = cdef.getInput(0)
        if varnode.isUnique() == False:
            if varnode.isRegister() == True:
                rdef = varnode.getDef()
                return process_vn_for_refs(rdef,depth+1)
            else:
                logger.warning("This may produce undesirable output, unhandled case ")
                return None

        uniqueDef = varnode.getDef()
        return process_vn_for_refs(uniqueDef,depth+1)

    elif cdef.opcode == PcodeOp.INT_ADD:
        reg,const = cdef.getInputs()

        vtable = reg.getHigh().getDataType()
        offset = const.getOffset()
        return (vtable,offset)

    elif cdef.opcode == PcodeOp.MULTIEQUAL:
        varnodes = cdef.getInputs()
        ls = []
        for vn in varnodes :
            vnDef = vn.getDef()
            x,y = process_vn_for_refs(vnDef,depth+1)
            ls.append((x,y))

        return ls

    elif cdef.opcode == PcodeOp.PTRADD:
        varnodes = cdef.getInputs()

        # The inputs may take different looks
        vtable = varnodes[0].getHigh().getDataType()
        b = varnodes[1].getOffset()
        c = varnodes[2].getOffset()

        return (vtable,b * c)
    else:
        logger.fatal("Unhandled opcode ")
        raise Exception(cdef.opcode)

def process_ptmf2ptf(callerDef):
    global funcs
    op = callerDef
    logger.debug("op %s",op.toString())
    inputs = op.getInputs()
    if len(inputs) < 2:
        logger.error("Bogus _ptmf2ptf implementation ")
        raise Exception

    target_ns = inputs[1]
    target_off = inputs[2]

    ns =  target_ns.getHigh().getDataType()
    vtable_symbol = ns.getName().replace("*","").strip()+"_vtable"

    if target_off.isConstant():
        offset = target_off.getOffset()

        if len(inputs) == 4:
            m = inputs[3].getOffset()
            offset = offset * m

        addr = callerDef.getSeqnum().getTarget()
        memory_add_reference(addr,vtable_symbol,offset,True)


    elif target_off.isUnique():
        udef = target_off.getDef()
        addr = callerDef.getSeqnum().getTarget()

        if udef.opcode == PcodeOp.PTRSUB :
            input = udef.getInput(1)
            offset = input.getOffset()
            memory_add_reference(addr,vtable_symbol,offset,True)
            # check if the offset is a function
            func = getFunctionAt(toAddr(offset))
            sym = getSymbolAt(toAddr(offset))

            # if offset is just a a vtable offset, skip
            if func == None and "LAB_" not in sym.getName():
                return
            else:
                if "LAB_" in sym.getName():
                    fn = sym.getName().replace("LAB","FUN")
                    createFunction(toAddr(offset),fn)
                    func = getFunctionAt(toAddr(offset))
                    if func == None:
                        logger.warning("Something wrong with %s" %(toAddr(offset).toString()))
                        return


                string = ns.getDataType().getName()
                fix_namespace(string,func)
                append_to_functions(func)

                pass

        else:
            pass

    else:
        logger.warning("UNKNOWN operation ")
        raise Exception(target_off)


def fix_refs(hfunc):
    func = hfunc.getFunction()
    #logger.debug("Fixing references at %s" % (func.getName()))

    for op in hfunc.pcodeOps:
        addr = op.getSeqnum().getTarget()
        logging.debug("addr: 0x%s, opcode : %s" ,addr.toString(), op.toString())
        if op.opcode  == PcodeOp.CALLIND:
            logger.debug("addr: 0x%s, opcode : %s" ,addr.toString(), op.toString())
            caller = op.getInput(0)
            callerDef = caller.getDef()
            if callerDef == None:
                print "FIXMEE : CallerDef is Nil"
                logger.error("Could not get callerDef")
                raise Exception

            # take the caller definition and get (vtable,offset)
            logger.debug("Caller Definition opcode : %s" ,callerDef.toString())
            info = process_vn_for_refs(callerDef)

            if info == None:
                logger.error("None : %s , %s" ,addr.toString(),op.toString())
                continue
            # MULTI EQUAL operation
            if isinstance(info,list) == True:
                for i in info:
                    process_reference(addr,i)
                continue
            process_reference(addr,info)


        if op.opcode == PcodeOp.CALL:
            caller = op.getInput(0)
            if caller.isAddress() == False:
                continue
            name = getSymbolAt(caller.getAddress())
            if name == None :
                continue

            if name.getName() == "_ptmf2ptf":
                process_ptmf2ptf(op)

def memory_add_reference(addr,vtable_symbol,off,primary=False):
    manager = currentProgram.getSymbolTable()
    symbol = manager.getSymbol(vtable_symbol,None)

    if symbol == None:
        print "[-] '%s' symbol not found" % (vtable_symbol)
        return

    new = symbol.getAddress().add(off)
    func = getDataAt(new)
    if func == None:
        return

    funcAddr = func.getValue()
    tfunc = getFunctionAt(funcAddr)
    append_to_functions(tfunc)

    refMgr = currentProgram.getReferenceManager()
    ref = refMgr.addMemoryReference(addr, funcAddr, RefType.COMPUTED_CALL, SourceType.DEFAULT, 0)
    if primary == True:
        refMgr.setPrimary(ref,True)

def process_reference(addr,info):
    global funcs
    dt, off = info
    vtable_symbol =  dt.getName().replace("*","").strip()
    manager = currentProgram.getSymbolTable()
    # TODO : sanity checks against vtable_symbols (ie : undefined/longlong ..etc)
    if "_vtable" not in vtable_symbol:
        logger.debug("'%s' Looks like not a valid symbol at %s" %(vtable_symbol,addr.toString()))
        return

    memory_add_reference(addr,vtable_symbol,off)


def fix_extra_refs(entry_addr):
    global funcs
    global logger
    logger = setup_logging("extra_ref")
    black_list_funcs = ["IOCommandGate::runAction"]

    ifc = get_decompiler()
    func  = getFunctionContaining(entry_addr)
    # we start from the selected function
    if func == None:
        popup("Could not get function at %s" %(entry_addr.toString()))
        return

    funcs.append(func)
    for func in funcs:
        if func in black_list_funcs:
            continue
        if "OSObject" in func.getName(True):
            continue

        logger.info("Fixing %s at 0x%s" %(func,func.getEntryPoint().toString()))
        hfunc = decompile_func(ifc,func)
        #HighFunctionDBUtil.commitParamsToDatabase(hfunc,True,SourceType.USER_DEFINED)
        # this is useful for changing method namespace on the fly
        func.setCustomVariableStorage(True)
        fix_hfunc_namespaces(hfunc)
        fix_refs(hfunc)

    funcs = []
