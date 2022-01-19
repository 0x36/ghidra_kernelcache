# Propagate variable symbol + type over a function
#@author simo
#@category iOS.kernel
#@keybinding Alt X
#@menupath
#@toolbar logos/sdsdlogo.png
#@description propagate the new symbol name/type across function arguments
# -*- coding: utf-8 -*-

# interesting link : https://github.com/NationalSecurityAgency/ghidra/issues/2236#issuecomment-685204563
from utils.helpers import *
from ghidra.app.decompiler.component import DecompilerUtils
from ghidra.app.decompiler import ClangVariableToken,ClangFieldToken
from ghidra.program.database.data import StructureDB
#from ghidra.app.decompiler import ClangToken as clang
"""
ClangOpToken: ex return, if , else ..etc
ClangSyntaxToken : {} ()
ClangFuncNameToken : a function call
"""

datatypes = {}

def setup_datatypes():
    global datatypes
    dtm = currentProgram.getDataTypeManager()
    uchar = dtm.getDataType("/uchar")
    ushort = dtm.getDataType("/ushort")
    uint = dtm.getDataType("/uint")
    ulonglong = dtm.getDataType("/ulonglong")

    datatypes[1] = uchar
    datatypes[2] = ushort
    datatypes[4] = uint
    datatypes[8] = ulonglong
    assert (uchar and ushort and uint and ulonglong)
    #exit(0)
structure = None


def validate_token_store(token):
    """
    Checks the source target token
    Support : STORE , (LOAD later)
    """
    # the token must be a variable and has an operation code
    if token.isVariableRef() == False or token.getPcodeOp() == None:
        return False

    op = token.getPcodeOp()
    if op.getOpcode() != PcodeOp.STORE:
        return False
    return True

def get_struct_fild(struct,fields):
    pass

# returns (datatype,size) of the variable token
def handle_source_token(token):
    op = token.getPcodeOp()
    if (op.getOpcode() == PcodeOp.STORE):
        inputs = op.getInputs()
        dst,src = inputs[1], inputs[2]
        #print op

        if src.isConstant():
            size = src.getSize()
            dt = None
        elif src.isRegister() or src.isUnique():
            size = src.getSize()
            high = src.getHigh()

            if (isinstance(high,ghidra.program.model.pcode.HighOther) == True):
                high = None
                return (None,size)
            dt = high.getDataType()

        # elif src.isUnique():
        #     print "UNIQ"
        #     size = src.getSize()
        #     high = src.getHigh()
        #     print size,high
        #     raise Exception
        else:
            print("hndle_source_token(): varnode type not supported [IGNORE] ")
            return (None,src.getSize())

    return (dt,size)

#returns the target variable to be modified
def handle_dest_vartoken(line,src_dt,src_size):
    var = None
    fields = []
    for tok in line.getAllTokens():
        if tok.toString() == "=":
            break

        if(isinstance(tok,ClangVariableToken) == True):
            if var != None:
                continue
            sym = tok.getHighVariable().getSymbol()
            if sym: var = tok

        elif(isinstance(tok,ClangFieldToken) == True):
            fields.append(tok)
    # now we have "this [IOBluetoothDeviceUserClient, field_0x10]"
    #if isinstance(this)
    var_dt =  var.getHighVariable().getSymbol().getDataType()
    path = var_dt.getDataTypePath()
    mgr = var_dt.getDataTypeManager()
    n =  var_dt.getName().replace("*","").strip()
    st = find_struct(n)
    if (st == None):
        raise Exception("Could not find %s structure"% n)
    #var_name =
    # fields tokens are taken recursively : dt->field1.field2. .. .fieldN
    if (isinstance(st,StructureDB) == False):
        return None

    cps = st.getComponents()
    struct =  st
    if cps == None:
        return None
    for field in fields:
        cps = struct.getComponents()
        if cps == None:
            break
        fld_name = field.toString()
        # if we hit "field_name", it does mean the field member is still undefined
        # and we reach the end of the structure parsing
        if "field_" in fld_name:
            try:
                f,idx = fld_name.split("_")
            except ValueError:
                f,idx,_ = fld_name.split("_")
            target = struct.getDataTypeAt(int(idx,16))
            fld_name = f + "_" + str(idx)
            try:
                if src_dt: dt = src_dt
                else: dt = datatypes[src_size]
                struct.replaceAtOffset(int(idx,16),dt,src_size,fld_name+"_","")

            # sometimes the variable is not aligned and is conflicting with other struct member
            # must be handled manually
            except java.lang.IllegalArgumentException as e:
                print (e)
            break

        for cp in cps:
            if cp.getFieldName() == fld_name:
                if(isinstance(cp.getDataType(),StructureDB)):
                    struct = cp.getDataType()
                break

# token: is the source target token
def handle_line_store(line,token):
    global structure
    src_dt, src_sz = handle_source_token(token)
    handle_dest_vartoken(line,src_dt,src_sz)
    """
    op = token.getPcodeOp()
    assert(op.getOpcode() == PcodeOp.STORE)
    inputs = op.getInputs()
    dst,src = inputs[1], inputs[2]

    if src.isConstant() == False:
        sym = src.getHigh().getSymbol()
        if (sym == None):
            return
        dt = sym.getDataType()
        print dt.getLength()
        print("Unable to handle no constant values")
        exit(0)
        return
    """
    return

    # now get variableRef
    var  = None
    var_name = None
    fields = []
    f_done = True

    for t in line.getAllTokens():
        #print t,type(t)
        if(isinstance(t,ClangVariableToken) == True):
            if var != None:
                continue
            sym = t.getHighVariable().getSymbol()
            if sym: var = t

        elif(isinstance(t,ClangFieldToken) == True):
            fields.append(t)

        if t == token:
            print "We are done"
            break

    var_dt = var.getHighVariable().getSymbol().getDataType()
    path = var_dt.getDataTypePath()
    mgr = var_dt.getDataTypeManager()
    n =  var_dt.getName().replace("*","").strip()
    st = find_struct(n)
    if (st == None):
        raise Exception("Could not find %s structure"% n)

    # fields tokens are taken recursively : dt->field1.field2...fieldn
    cps = st.getComponents()
    struct =  st
    if cps == None:
        return
    for field in fields:
        cps = struct.getComponents()
        if cps == None:
            break
        fld_name = field.toString()
        # if we hit "field_name", it does mean the field member is still undefined
        # and we reach the end of the structure parsing
        if "field_" in fld_name:
            f,idx = fld_name.split("_")
            #print f,idx
            target = struct.getDataTypeAt(int(idx,16))
            #target.setFieldName("f_"+idx)
            try:
                struct.replaceAtOffset(int(idx,16),datatypes[target_size],target_size,"f_"+idx,"")
            except java.lang.IllegalArgumentException as e:
                print (e)
            break
        for cp in cps:
            if cp.getFieldName() == fld_name:
                if(isinstance(cp.getDataType(),StructureDB)):
                    struct = cp.getDataType()
                break

def debug_line(lines,linum):
    for line in lines:
        if line.getLineNumber() != linum:
            continue

        print (line)
        tokens = line.getAllTokens()
        for token in tokens:
            print token, type(token),"opcode :", token.getPcodeOp()



def handle_line(line):
    tokens = line.getAllTokens()
    for token in tokens:
        if validate_token_store(token) == True:
            handle_line_store(line,token)
            pass
        else: # handle other opcodes here
            pass

def do_assign(addr):
    entry = addr
    setup_datatypes()
    print(entry)
    func = getFunctionContaining(entry)
    assert(func != None)
    print func
    decompInterface = DecompInterface()
    decompInterface.openProgram(currentProgram)
    decompiled =  decompInterface.decompileFunction(func, 120, monitor)

    lines = DecompilerUtils.toLines(decompiled.getCCodeMarkup())

    for line in lines:
        handle_line(line)

    decompInterface.dispose()
    print("Done")

if __name__ == "__main__":
    listing = currentProgram.getListing()
    do_assign(currentAddress)
