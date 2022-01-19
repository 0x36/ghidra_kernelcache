#@category iOS.kernel

from ghidra.program.model.listing import CodeUnit
from ghidra.app.util.bin.format.dwarf4.next import DWARFImportOptions,DWARFProgram,DWARFParser
from ghidra.program.model.data import BuiltInDataTypeManager
from ghidra.app.util.bin.format.dwarf4.next.sectionprovider import DSymSectionProvider
from  java.io import File


if __name__=='__main__':
    if (DWARFProgram.isDWARF(currentProgram) == False):
        popup("Unable to find DWARF information, aborting")
        exit(1)

    importOptions = DWARFImportOptions()
    importOptions.setPreloadAllDIEs(True)
    importOptions.setImportLimitDIECount(0x1000000);

    dwarfProg = DWARFProgram(currentProgram, importOptions, monitor)
    dtms = BuiltInDataTypeManager.getDataTypeManager()
    dp = DWARFParser(dwarfProg, dtms, monitor);
    importSummary = dp.parse()
    importSummary.logSummaryResults();
    print("[+] We're done")
