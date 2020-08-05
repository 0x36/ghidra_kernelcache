# Fix a method's vtable calls + reference making

#@author simo
#@category iOS.kernel
#@keybinding R
#@toolbar logos/refs.png
#@description Resolve references for better CFG
# -*- coding: utf-8 -*-

"""
script which does the following:
- adds references to virtual method calls
- Identifies methods belong to a specific namespace
- Handles multi value vtable reference (multi-nodes)
"""

from utils.references import *

if __name__ == "__main__":
    fix_extra_refs(currentAddress)
    
    
