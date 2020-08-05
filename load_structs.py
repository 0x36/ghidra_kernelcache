#import structures and typedefs from old kernelcache to a new one
#@author simo
#@category iOS.kernel
#@toolbar logos/load_structs.png
#@keybinding Meta Shift L
#@menupath

from ghidra.app.services import DataTypeManagerService
from ghidra.program.model.data import StructureDataType,PointerDataType
from ghidra.app.services import ProgramManager

"""
- Get all structures from source program and copy them into destination program
- It avoids taking "_vtable" structures because fix_kernelcache will handle it 
- If struct is already there, just skip it 
"""


src_prog_string = "kernel_leaked_symbols"
#dst_prog_string = "kernel_iphoneX_13.4_17E5255a_10"
dst_prog_string = "kernel_iphone7_13.5"
dst_prog_string = "kernel_iphoneX_13.5"
#dst_prog_string = "kernel_iphoneX_12.4_16G77"
dst_prog_string = "kernel_iphoneXS_13.5"
#dst_prog_string = "kernel_iphoneX_13.4_17E5255a"
dst_prog_string = "kernel_iphone7_14.0_beta"
dst_prog_string = "kernel_iphone7_13.6"
#dst_prog_string = "kernel_ipad_13.4"

def isThere(name,programDT):        

    if "MetaClass" in name:
        return True

    if "_vtable" in name:
        return True
    
    dataType = programDT.getDataType(name)
    
    if dataType :
        return True

    return False

def findDataTypeByName(name):
    tool = state.getTool()
    service = tool.getService(DataTypeManagerService)
    dataTypeManagers = service.getDataTypeManagers();
    
    for manager in dataTypeManagers:
        
        dataType = manager.getDataType(name)
    
        if dataType :
            print "RES",name,dataType.getName()
            return dataType
        

    return None

if __name__ == "__main__":
    tool = state.getTool()
    service = tool.getService(DataTypeManagerService)
    dataTypeManagers = service.getDataTypeManagers();
    
    programManager = state.getTool().getService(ProgramManager)
    #print dir(programManager)
    progs =programManager.getAllOpenPrograms()
    if len(progs) < 2 :
        popup ("You must open at least two programs")
        exit(1)

    src = dst = None
    for prog in progs:
        if src_prog_string == prog.getName():
            src = prog
        elif dst_prog_string == prog.getName():
            dst = prog

    if src == None or dst == None:
        popup("Could not get src/dst program")
        exit(0)
        
    print src,dst
    
    src_dtm = src.getDataTypeManager()
    dst_dtm = dst.getDataTypeManager()

    structs = src_dtm.getAllStructures()
    
    for s in structs:
        name =  s.getName()
        res = isThere('/'+name,dst_dtm)
        if res == True:
            continue
        
        res = isThere('/Demangler/'+name,dst_dtm)
        if res == True:
            continue
        
        struct = StructureDataType(name,0)
        dst_dtm.addDataType(struct,None)
        dst_dtm.addDataType(PointerDataType(struct),None)
        #print name + " is not found "
        

