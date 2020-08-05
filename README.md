# ghidra_kernelcache: a Ghidra iOS kernelcache framework for reverse engineering

This framework is the end product of my experience in reverse engineering iOS kernelcache,I do manually look for vulnerabilities in the kernel and have automated most 
of the things I really wanted to see in Ghidra to speed up the process of reversing, and this proven to be effective and saves a lot of time. 
The framework works on iOS 12/13/14 and has been made to the public with the intention to help people to start VR in iOS kernel without the struggle of preparing their own environment,
as I believe, this framework ( including the toolset it provides and with some basic knowledge in IOKit) is sufficient to start dealing with the Kernelcache.

The whole framework is written in Python,and can be extended to build tools upon, it provides some basic APIs which you can use in almost any project and save time from reading the verbose manual, you can just read the code in **[utils/](https://github.com/0x36/ghidra_kernelcache/tree/master/utils)** directory.

Ghidra is good when it comes to analyzing the kernelcache, but like other RE tools, it needs some manual work, **ghidra_kernelcache** provides a good entry point to fix things at the start and even while doing reverse engineering thus providing a good-looking decompiler output.

There is a similar project done by [@_bazad](https://twitter.com/_bazad) in IDAPro called  [ida_kernelcache](https://github.com/bazad/ida_kernelcache) which provides a good entry point for researchers wanting to work with the kernel image in IDA, my framework looks a bit similar to Brandon's work, and goes beyond by providing much more features to make the process of working with the kernelcache a lot easier.

Here are some of the features provided by the framework :
- iOS kernelcache symbolication.
- Resolving virtual call references.
- Auto fixing external method array for both `::externalMethod()` and `::getTargetAndMethodForIndex()`.
- Applying namespaces to class methods.
- Symbol name and type propagation over function arguments.
- Applying function signatures for known kernel functions.
- Import old structures and classes from old project to  a new project.
- Auto type-casting `safeMetacast()` return value to the appropriate class object type.

These features are made as a separated tools which can be executed either by key shortcuts or by clicking on their icons in the toolbar.

## Installation
Clone the repository :

```sh
git clone https://github.com/0x36/ghidra_kernelcache.git $APATH
```

Go to *`Windows → Script Manager`,* click on  *`script Directory` ,* then add *`$APATH/ghidra_kernelcache`* to the directory path list.

Go to *`Windows → Script Manager`,* in *scripts* listing, go to *`iOS→kernel`* category and check the plugins seen there, they will appear in GHIDRA Toolbar .

in [logos/](https://github.com/0x36/ghidra_kernelcache/tree/master/logos) directory, you can put you own logos for each tool.


## iOS kernelcache symbolication

**ghidra_kernelcache** requires at the first stage [iometa](https://github.com/Siguza/iometa/) (made by [@s1guza](https://twitter.com/s1guza)), a powerful tool providing C++ class information in the kernel binary, the great thing is that it works as a standalone binary, so the output can be imported to your favorite RE framework by just parsing it. My framework takes iometa's output and parses it to symbolicate and fix virtual tables.


### Usage

After decompressing the kernel, run  the following command : 

```sh
$ iometa -n -A /tmp/kernel A10-legacy.txt > /tmp/kernel.txt
# if you want also to symbolicate using jtool2
$ jtool2 --analyze /tmp/kernel

```

Load the kernelcache in Ghidra, ***DO NOT USE BATCH import*** , load it as Mach-O image. 
After the Kernelcache being loaded and auto-analyzed, click on the icon shown in the toolbar or just press **Meta-Shift-K**, then put the full path of iometa output which is `/tmp/kernel.txt` in our case.

if you want to use jtool2 symbols, you can run `jsymbol.py` located `iOS→kernel` category as well.

### Using APIs

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

# update symbolication, this will not override the class structure, it will only update the virtual table symbol map.
kc.update_classes()

# symbolicate one class: this will also automatically symbolicate all parent classes.
kc.process_class("IOGraphicsAccelerator2")

```

If you run the script against the whole kernelcache, it may take several minutes to finish, once finished, Ghidra will provide the following :

→ a new category has been added in Bookmark Filter called "iOS": 

<img src="https://github.com/0x36/ghidra_kernelcache/blob/master/screenshots/image1.png" alt="image1" width="200"/>
                    
                    
→ IOKit class virtual tables  are added to 'iOS' Bookmark for better and faster class vtable lookup, you can just look for a kext or a class by typing letters,word or kext bundle in the search bar.


<img src="https://github.com/0x36/ghidra_kernelcache/blob/master/screenshots/image2.png" alt="image2"/>


→ Fixing the virtual table : disassembles/compiles unknown code, fixes namespaces, re-symbolicates the class methods and applies function definition to each method.

<img src="https://github.com/0x36/ghidra_kernelcache/blob/master/screenshots/image3.png" alt="image3"/>

→ Creating class namespace and make class methods adhere to it:

<img src="https://github.com/0x36/ghidra_kernelcache/blob/master/screenshots/image4.png" alt="image4"/>


→ Creating class structure with the respect of class hierarchy :

<img src="https://github.com/0x36/ghidra_kernelcache/blob/master/screenshots/image5.png" alt="image5"/>

→ Creating class vtables, and each method has its own method definition for better decompilation output: 

<img src="https://github.com/0x36/ghidra_kernelcache/blob/master/screenshots/image6.png" alt="image6"/>

Full implementation can be found in [`utils/class.py.`](https://github.com/0x36/ghidra_kernelcache/blob/master/utils/class.py)

Here are some screenshots of before/after using the scripts  to just give a clear picture :

<img src="https://github.com/0x36/ghidra_kernelcache/blob/master/screenshots/image7.png" alt="image7"/>

<img src="https://github.com/0x36/ghidra_kernelcache/blob/master/screenshots/image8.png" alt="image8"/>


## extra_refs.py: Fixing references 

***extra_refs.py*** is based on data flow analysis to find all virtual call methods and resolving their implementations automatically, it has the ability to recognize the source data type from the decompiler output and resolve all virtual call references, so the user is able to jump forward/backward directly to/from the implementation without manually looking for it.

The most useful feature provided by `extra_refs.py` is that it keeps the references updated on each execution, for example, let's say you've changed a variable data type to a class data type, `extra_refs.py` will automatically recognize the change, and will go recursively on all call sites to resolve their references, and it finishes only when the call site queue is empty.

There are other features provided by extra_refs.py like:

- It automatically identifies `_ptmf2ptf()` calls and resolves their call method for both offsets and full function address
- It identifies the namespace of an unresolved function name (functions which start with "FUN_"), and resolve it by putting the target function into its own namespace.

### Implementation

You can find the implementation in **utils/references.py,** fix_extra_refs() parses the [pcode](https://ghidra.re/courses/languages/html/pcoderef.html) operations and looks for CALLIND and CALL opcodes, then gets all involved [varnodes](https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/Varnode.html) on the operation, once a varnode definition is identified, it gets its [HighVariable](https://ghidra.re/ghidra_docs/api/ghidra/program/model/pcode/HighVariable.html)  then identifies the class object type of that variable, if the type is unknown it ignores it,otherwise, it takes the class name, looks up its virtual call table,using the offset provided by the varnode, it gets the right virtual call and puts a reference on the call instruction. 

### Exposed API:

```py
# The 'address' type is ghidra.program.model.address.GenericAddress, you can ise toAddr(),
#  to convert integer or string representation address to GenericAddress 
fix_extra_refs(address)
```

Here is an output example of running extra_refs.py :

<img src="https://github.com/0x36/ghidra_kernelcache/blob/master/screenshots/image9.png" alt="image9"/>


Note that it successfully resolved **IOService::isOpen()**, **OSArray:getNextIndexOfObject()** and **IOStream::removeBuffer()** virtual calls without any manual modification.

Next, the scripts enters to  **IOStream::removeBuffer()** virtual call, gets the HighVariables of this method then resolves their reference like the current working method and so on.
<img src="https://github.com/0x36/ghidra_kernelcache/blob/master/screenshots/image10.png" alt="image10"/>


## Auto fixing external method tables

I believe every researcher has some script to deal with this part, as it is the main attack surface of IOKit, doing so manually is a burden, and it must be automated in a way the researcher wants to dig into multiple external method tables. 

There are two scripts provided by the ghidra_kernelcache : **fix_methodForIndex.py** and **fix_extMethod.py.** You can enable them like the other scripts as shown above.

***Usage***: Put the cursor in the start of the external method table, run the script, give the target class object type, and the number of selectors. that's all.

Example for  `IOStreamUserClient::getTargetAndMethodForIndex()` :

<img src="https://github.com/0x36/ghidra_kernelcache/blob/master/screenshots/image11.png" alt="image11"/>


## namespace.py :  fix method namespaces


This is a useful script to propagate the class type through all encountered methods. and it's extremely useful for `extra_refs.py` script, to explore more functions in order to discover and resolve more references.

***Usage***: Put the cursor in the decompiler output of the wanted function, run the script from the toolbar or press **Meta-Shift-N** .

## Symbol name and type propagation


Still under development, supports basic Pcode operation, but it works in easy cases, better than nothing. I only need to add support for other exotic operations like SUBPIECE ...

If someone wants to help, or wants to start working with low level stuff in Ghidra, this is the opportunity to do so.
Implementation can be found in [ghidra_kernelcache/propagate.py](https://github.com/0x36/ghidra_kernelcache/blob/master/propagate.py)

## Signatures

Parsing C++ header files in Ghidra is not possible, and having  kernel function signatures in kernelcache is a good thing, for example, let's say we have added the symbol  `virtual IOMemoryMap * map(IOOptionBits options = 0 );`, Ghidra will automatically re-type the return value into `IOMemoryMap` pointer automatically for both function definition and function signatures ,and doing so with several symbols will drastically improve the decompilation output.

In order to accomplish this task without any manual modification or using Ghidra C header parser, I've figured out a way to do it, and even better, defining structure and typedef symbols as well.

You can add any C++ symbol into **signatures/** directory with the respect of the syntax, and you can find defined function signatures in this directory.

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

***Usage***: After symbolicating the kernel, it is highly recommended running the script `load_sigatnures.py` to load all signatures. As most of the previous tools, run this script by adding it in the toolbar or from the Plugin manager or just press **Meta-Shift-S** .


## Loading old structures:

This script is straight-froward, it imports all structures/classes/typdefs from old project to a new project.
It is highly recommended to run the script before symbolicating the kernelcache.

***Usage***: Open the old and the new Ghidra projects, go to [`load_structs.py`](https://github.com/0x36/ghidra_kernelcache/blob/master/load_structs.py) script, put the old program name to **src_prog_string** variable, and the new one to **dst_prog_string** variable, then run the script.

## safeMetacast():
I will not publish it until Ghidra 9.2 released, I still unable to make it work reliably due some limitation in the Python API provided by Ghidra.
But if you are curious and want to see the implementation snippet, you can see it [here](https://gist.github.com/0x36/7d9980d02593595d81c0dcf355bac2c7).

## Contribute
If you see the project interesting and want to contribute, just do a PR and I will review it, meanwhile, I would like to see some contribution in the following areas:
* [ghidra_kernelcache/signatures/kernel.txt](https://github.com/0x36/ghidra_kernelcache/tree/master/signatures): keep importing XNU kernel functions, it is so simple just copy/paste the function definition.
* [ghidra_kernelcache/propagate.py](https://github.com/0x36/ghidra_kernelcache/blob/master/propagate.py) : support unhandle opcodes for better symbol propagation.

