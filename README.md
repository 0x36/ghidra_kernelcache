# ghidra_kernelcache: a Ghidra iOS kernelcache framework for reverse engineering

This framework is the end product of my experience in Kernelcache reverse engineering , I usually look for vulnerabilities by manually auditing the kernel and its extensions and have automated most of the things that I really wanted to see in Ghidra to speed up the process of reversing, and this has proven to be effective and saves a lot of time. 
The framework works on iOS 12/13/14/15 and on macOS 11/12  (both kernelcache and single KEXT) and has been made to the public with the intention to help people to start researching on iOS kernel without the struggle of preparing their own environment.
As I believe, this framework (including the toolset it provides and with some basic knowledge of IOKit) is sufficient to start hacking into the Kernelcache.

The framework is entirely written in Python, and can be extended to build other tools, it provides some basic APIs which you can use in almost any project and save time from reading the verbose manual, you're welcome to read the core  functionalities in **[utils/](https://github.com/0x36/ghidra_kernelcache/tree/master/utils)** directory.

Ghidra is good when it comes to analyzing Kernelcaches, but like other RE tools, it requires some manual work, `ghidra_kernelcache` provides a good entry point to fix things up at the start and even while doing reverse engineering, hence providing a good-looking decompiler output.

There is a similar project made by [@_bazad](https://twitter.com/_bazad) in IDAPro called  [ida_kernelcache](https://github.com/bazad/ida_kernelcache) which provides a good entry point for researchers wanting to work with the kernel image in IDA, my framework looks a bit similar to Brandon's work, and goes beyond by providing much more features to make the process of working with the kernelcache less painful.

## Features :
- *OS kernelcache symbolication.
- C++ class hierarchy reconstruction and virtual tables.
- Virtual method call references.
- Auto fixing external method's dispatch table for both `::externalMethod()` and `::getTargetAndMethodForIndex()`.
- Applying namespaces to class methods.
- Symbol name and type propagation over a function arguments.
- Applying function signatures for known kernel functions.
- Import old structures and classes from old project to  a new project.

These features are made as a separated tools which can be executed either by key shortcuts or by clicking on their icons in the toolbar.

## Installation
Clone the repository :

```sh
git clone https://github.com/0x36/ghidra_kernelcache.git
```

**Important note**: The project has been tested on Ghidra 10.1_PUBLIC and 10.2_DEV and it is not backward compatible. 

Go to *`Windows → Script Manager`,* click on  *`script Directory` ,* then add *`ghidra_kernelcache`* to the directory path list.
Go to *`Windows → Script Manager`,* in *scripts* listing, go to *`iOS→kernel`* category and check the plugins seen there, they will appear in GHIDRA Toolbar .

in [logos/](https://github.com/0x36/ghidra_kernelcache/tree/master/logos) directory, you can put you own logos for each tool.

## iOS kernelcache symbolication

`ghidra_kernelcache` requires at the first stage [iometa](https://github.com/Siguza/iometa/) (made by [@s1guza](https://twitter.com/s1guza)), a powerful tool providing C++ class information in the kernel binary, the great thing is that it works as a standalone binary, so the output can be imported to your favorite RE framework by just parsing it. My framework takes iometa's output and parses it to symbolicate and fix virtual tables.

### Usage
After decompressing the kernel, run the following commands : 

```sh
$ iometa -n -A /tmp/kernel A10-legacy.txt > /tmp/kernel.txt
# if you want also to symbolicate using jtool2
$ jtool2 --analyze /tmp/kernel

```

Load the kernelcache in Ghidra, ***DO NOT USE BATCH import*** , load it as Mach-O image. 
After the Kernelcache being loaded and auto-analyzed, click on the icon shown in the toolbar or just press **Meta-Shift-K**, then put the full path of iometa output which is `/tmp/kernel.txt` in our case.

if you want to use `jtool2` symbols, you can use `jsymbol.py` located `iOS→kernel` category as well.

### iOS kernelcache API
Full API examples are in [`ghidra_kernelcache/kc.py`](https://github.com/0x36/ghidra_kernelcache/blob/master/KC.py)

→ Here are some examples of manipulating class objects :
```py
from utils.helpers import *
from utils.class import *
from utils.iometa import ParseIOMeta

ff = "/Users/mg/ghidra_ios/kernel.txt"
iom = ParseIOMeta(ff)
Obj = iom.getObjects()
kc = kernelCache(Obj)


# symbolicate the kernel 
kc.process_all_classes()

# symbolicate the classes under com.apple.iokit.IOSurface bundle
kc.process_classes_for_bundle("com.apple.iokit.IOSurface")

# symbolicate the classes under __kernel__ bundle
kc.process_classes_for_bundle("__kernel__")

# Process one class (including its parents)
kc.process_class("IOGraphicsAccelerator2")

# Clears the content of the class structures (vtables are excluded)
kc.clear_class_structures()

# Overwrite the old vtable structure definition and resymbolicate it again
kc.update_classes_vtable()

# Reconstructing function call trees by enumerating all pac references and find their corresponding virtual method call
kc.explore_pac()
```

As you can see, you can fully or partially symbolicate the kernelcache, if partial symbolication was chosen, `ghidra_kernelcache` will automatically construct all class  dependencies before proceeding.
If you run the script against the whole kernelcache (full symbolication), `ghidra_kernelcache` will take several minutes to analyze the kernel image.

One finished, Ghidra will provide the following :

→ A new category has been added in Bookmark Filter called "iOS": 

<img src="https://github.com/0x36/ghidra_kernelcache/blob/master/screenshots/image1.png" alt="image1" width="200"/>
                    
                    
→ IOKit class virtual tables  are added to 'iOS' Bookmark for better and faster virtual table lookup, you can just look for a kext or a class by providing letters, words or kext bundle in the search bar.

<img src="https://github.com/0x36/ghidra_kernelcache/blob/master/screenshots/image2.png" alt="image2"/>


→ Fixing the virtual table : disassembles/compiles unknown code, fixes namespaces, re-symbolicates the class methods and applies function definition to each method:

<img src="https://github.com/0x36/ghidra_kernelcache/blob/master/screenshots/image3.png" alt="image3"/>

→  Creation of class namespaces and  put each  method to its own corresponding namespace:

<img src="https://github.com/0x36/ghidra_kernelcache/blob/master/screenshots/image4.png" alt="image4"/>

→ Creating class structure with the respect of class hierarchy :

<img src="https://github.com/0x36/ghidra_kernelcache/blob/master/screenshots/image5.png" alt="image5"/>

→ Creating class vtables, and each method has its own method definition for better decompilation output: 

<img src="https://github.com/0x36/ghidra_kernelcache/blob/master/screenshots/image6.png" alt="image6"/>

Full implementation can be found in [`utils/class.py.`](https://github.com/0x36/ghidra_kernelcache/blob/master/utils/class.py)

Here are some screenshots of before/after symbolicating using  `ghidra_kernelcache`  :

<img src="https://github.com/0x36/ghidra_kernelcache/blob/master/screenshots/image7.png" alt="image7"/>

<img src="https://github.com/0x36/ghidra_kernelcache/blob/master/screenshots/image8.png" alt="image8"/>




## macOS Kext symbolication
---
`ghidra_kernelcache` macOS support is for both kernelcache and single KEXT symbolication for ARM64e and x86_64 architectures. 
**IMPORTANT:** At the time of writing Ghidra is unable to parse the whole macOS kernelcache, but it's possible to load it in IDA for initial analysis then import  the database (idb to xml)  to Ghidra later, but this is out of scope. If you manage to do so, `ghidra_kernelcache` will take care of the rest.

There are some few steps which have to be taken before symbolicating any macOS Kernel Extension, as `ghidra_kernelcache`'s main aim is to reconstruct the class hierarchy and to manage all class structures into a single database, a kernel extension does not fulfill  those requirements, which means that the symbolication of a single KEXT does require a symbolication of the kernel and perhaps other Kernel Extensions that depends on, hence some extra work needs to be done here.
`ghidra_kernelcache`  now provides a powerful way to symbolicate Kernel Extensions including the kernel by managing and sharing class structures and virtual method definitions via Ghidra's powerful *DataType Project Archive*  

### Steps to symbolicate a Kernel Extension
- Create a new folder in your Ghidra project, then load ` /System/Library/Kernels/kernel.release.XXXXX` into that folder and let Ghidra analyzes it.
- Create a new *Project Archive* : Go to `DataType Provider` → Click on the arrow in the top right of the window → `New Project Archive` → Place it inside the newly created Folder → Name it to something (i.e macOS_12.1). 
- Now symbolicate the kernel using `ghidra_kernelcache`, the process is quite similar to iOS *kernelcache* symbolication.

```bash
$ iometa -n -A /System/Library/Kernels/kernel.release.t8101 > /tmp/kernel.txt
```
- In python console, or you can find the full script implementation in `KM.py` script : 
```py
>>> from utils.helpers import *
>>> from utils.kext import *
>>> iom = ParseIOMeta("/tmp/kernel.txt")
>>> Obj = iom.getObjects()
>>> kc = Kext(Obj,shared_p="macOS_12.1")
>>> kc.process_kernel_kext()

```
- Once finished, a database association has been created between kernel's archive and `macOS_12.1` archive. Now, right click on the `kernel.release.t8001` → `Commit DataTypes To` → `macOS_12.1`.
- Then `Right Click` →`Select All` → `Commit`.
- Save the project archive : `Right click` → `Save Archive`.
We've just created a project archive which can be shared across all Kernel Extensions.
Let's take an example of `IOSurface` Kext for Apple Silicon :
```bash
$ lipo /System/Library/Extensions/IOSurface.kext/Contents/MacOS/IOSurface -thin arm64e -output /tmp/iosurface.arm64e
$ iometa -n -A /tmp/iosurface.arm64e > /tmp/iosurface.txt
```

- Load the Kext into the same folder path where the kernel database and the project archive are located and let Ghidra finishes the analysis
- Load the project archive we've created earlier `macOS_12.1` : go to `Data Type Manager` → `Open Project Archive` , then select the `macOS_12.1`
- Run the following methods, full script can be found in `KM.py`:
```python
from utils.helpers import *
from utils.kext import *

kc = Kext(Obj,shared_p="macOS_12.1")

# This method fixes LC_DYLD_CHAINED_FIXUPS for M1 Kernel extension
kc.depac()

# This method reconstructs class hierarchy and builds virtual table for each class
kc.process_kernel_kext()

```

**Important Note** : sometimes `kc.process_kernel_kext()` fails because Ghidra was not able to demangle some C++ symbols. To fix this, go to the script manager and run `DemangleAllScript.java` script then  restart  `kc.process_kernel_kext()`  again. 

### Custom classes 
There are some cases where some C++ classes where `ghidra_kernelcache`  and `iometa` cannot symbolicate, so a new feature has been added to handle this.
`Custom()` class reconstruction iterates through all the `::vtable` symbols and checks wether the class is already defined or not, if not, it automatically creates a class structure, function definitions for each identified class method, a namespace and a virtual table for each  class. 

Custom class creation is supported on macOS only at the moment.

```bash
$ iometa -n -A /System/Library/Kernels/kernel.release.t8101 > /tmp/kernel.txt
$ iometa -n -A <kext_path> >> /tmp/kernel.txt
```

```py

from utils.helpers import *
from utils.custom_kc import *

if __name__ == "__main__":
    default = "/tmp/kernel.txt"
    ff = askString("iometa symbol file","Symbol file: ",default)
    iom = ParseIOMeta(ff)
    Obj = iom.getObjects()

    kc = Custom(Obj)

    kc.process_all_classes()
    kc.explore_pac()


```

## Miscellaneous scripts
---
### Importing KDK's Dwarf4 
Ghidra somehow fails to load the corresponding `.dsym` directory, I made a small script to fix this. It can be found [here](https://github.com/0x36/ghidra_kernelcache/dwarf4_fix.py).
**Usage** : load the kernel from your KDK path, let Ghidra finishes the analysis, then run `dwarf_fix.py`, it will load the symbols and the process may take several minutes.
<img src="https://github.com/0x36/ghidra_kernelcache/blob/master/screenshots/image12.png" alt="image12"/>

### Resolving virtual method calls references 
`ghidra_kernelcache` provides two ways to resolve virtual calls by  `kernelCache.explore_pac` or `fix_extra_refs` 

**kernelCache.explore_pac()**
If you're working on arm64e binary, `ghidra_kernelcache` can recognize virtual method calls by looking for the `Pointer Authentication Code` value. The process is straightforward and unlike `fix_extra_refs()`, `kernelCache.explore_pac` does not rely on the `Pcode` or `varnode` identification, it just iterates through all the instructions in the program, searches for `MOVK` instructions, fetches the second operand and looks for its corresponding value in the database.
Usage : 
Create a *KernelCache* instance via **kernelCache** , **Kext** or **Custom**, then call `explore_pac()` method.
```py
from utils.helpers import *
from utils.kext import *

if __name__ == "__main__":
    default = "/tmp/kernel.txt"
    ff = askString("iometa symbol file","Symbol file: ",default)
    iom = ParseIOMeta(ff)
    Obj = iom.getObjects()

    kc = Kext(Obj)

   	 kc.explore_pac()

```

**fix_extra_refs()** 
This function is based on a basic data flow analysis to find all virtual call methods and to resolve their implementations automatically, it works across all architectures and has the ability to recognize the source data type from the decompiler output and resolve all the virtual call references inside the function, so the user is able to jump forward/backward directly to/from the implementation without manually looking for it.
The most useful feature provided by `fix_extra_refs` is that it keeps the references synchronized on each execution. For example, you changed a variable data type to a class data type, `fix_extra_refs` will automatically recognize the change, and will recursively go  through  all call sites to resolve their references, and it will stop only when the call site queue became empty.

There are some other features provided by `fix_extra_refs`  such as:
- It auto-detects `_ptmf2ptf()` calls and resolves their call method for both offsets and full function address
- It identifies the namespace of an unresolved function name (functions which start with FUN_ ), and resolve it by putting the target function into its own namespace (e.g adding **this** pointer of the corresponding class).

You can find the implementation in **utils/references.py,** `fix_extra_refs` parses the [pcode](https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/package-summary.html) operations and looks for `CALLIND` and `CALL` opcodes, then gets all involved [varnodes](https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/Varnode.html) in the operation, once a Varnode definition was identified, it retrieves its [HighVariable](https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighVariable.html)  to identify the class object type, if the type is unknown (i.e does not appear to be a class structure) it just ignores it, otherwise it will take the class name, looks up its virtual call table, using the offset provided by the Varnode, it can fetch the right virtual method call and puts a reference on the call instruction. 

```py
fix_extra_refs(toAddr(address))
```
Here is an output example of using `fix_extra_refs` :

<img src="https://github.com/0x36/ghidra_kernelcache/blob/master/screenshots/image9.png" alt="image9"/>

Note that it has successfully resolved **IOService::isOpen()**, **OSArray:getNextIndexOfObject()** and **IOStream::removeBuffer()** virtual calls without any manual modification.

Next,  `fix_extra_refs` will decompile **IOStream::removeBuffer()**, gets all  HighVariables of this method, then it resolves their references like the previous method ... and so on.
<img src="https://github.com/0x36/ghidra_kernelcache/blob/master/screenshots/image10.png" alt="image10"/>

### Auto fixing external method tables

I believe that every researcher has some script to deal with this part, as it is the main attack surface of IOKit, doing it manually is a burden, and it must be automated in a way the researcher wants to dig into multiple external method tables. 
There are two scripts provided by the`ghidra_kernelcache` : **fix_methodForIndex.py** and **fix_extMethod.py.** You can enable them like the other scripts as shown above.

***Usage***: Put the cursor at the start of the external dispatch table, run the script: provide the target, and the number of selectors.
Example for  `IOStreamUserClient::getTargetAndMethodForIndex()` :

<img src="https://github.com/0x36/ghidra_kernelcache/blob/master/screenshots/image11.png" alt="image11"/>


### namespace.py :  fix method namespaces …
This is a useful script to populate the class type to all encountered methods, and it's a dependency for `extra_refs.py` script in order to recursively explore the callee functions and to resolve their references.

***Usage***: Put the cursor in the decompiler output of the wanted function, run the script from the toolbar or press **Meta-Shift-N** .

### Symbol name and type propagation
`ghidra_kernelcache` provides type propagation support for basic Pcode operations, but it will likely fails for some variables that using complex casting .
If someone wants to help, or wants to start working with low level stuff in Ghidra, this is the opportunity to do so.
Implementation can be found in [ghidra_kernelcache/propagate.py](https://github.com/0x36/ghidra_kernelcache/blob/master/propagate.py)

### Loading function signatures

Parsing C++ header files in Ghidra is not possible, and having  kernel function signatures in kernelcache can improve many things in the decompiler output.
For example, let's say we have added   `virtual IOMemoryMap * map(IOOptionBits options = 0 );`, Ghidra will automatically re-type the return value into `IOMemoryMap` pointer automatically for both function definition and function signatures.
You can add any C++ symbol into **signatures/** directory with the respect of the syntax and you can find defined function signatures in this directory.

```c++
// Defining an instance class method
IOMemoryDescriptor * withPersistentMemoryDescriptor(IOMemoryDescriptor *originalMD);

// Defining a virtual method, it must start with "virtual" keyword
virtual IOMemoryMap * createMappingInTask(task_t intoTask,  mach_vm_address_t atAddress,  IOOptionBits options,  mach_vm_size_t offset = 0,  mach_vm_size_t length = 0);

// Defining a structure
struct task_t;

// typedef'ing a type
typedef typedef uint IOOptionBits; 

// Lines begining with '//' are ignored 

```

***Usage***: After symbolicating the kernel, it is highly recommended to run the script `load_sigatnures.py` to load all available function signatures. As most of the previous tools, run this script by adding it in the toolbar or from the Plugin manager or just press **Meta-Shift-S** .

### Loading old structures:

This script is straight-froward, it imports all structures, classes, typedefs,  and function definitions and everything with `SourceType.USER_DEFINED` from an old project to a new one.

***Usage***: Open the old and the new Ghidra projects on the same tool, go to [`load_structs.py`](https://github.com/0x36/ghidra_kernelcache/blob/master/load_structs.py) script, put the old program name to **src_prog_string** variable, and the new one to **dst_prog_string** variable, then run the script.

## Contribute
If you see the project interesting and want to contribute, just do a PR and I will review it, meanwhile, I would like to see some contribution in the following areas:
* [ghidra_kernelcache/signatures/kernel.txt](https://github.com/0x36/ghidra_kernelcache/tree/master/signatures): keep importing XNU kernel functions, it is so simple just copy/paste the function definition.
* [ghidra_kernelcache/propagate.py](https://github.com/0x36/ghidra_kernelcache/blob/master/propagate.py) : support un-handled opcodes for better symbol propagation.

## Credit
I would like to thank [@s1guza](https://twitter.com/s1guza) for his awesome [iometa](https://github.com/Siguza/iometa.git) which ghidra_kernelcache depends on.