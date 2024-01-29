# The LLVM Compiler Infrastructure

Welcome to the LLVM project!

This repository contains the source code for LLVM, a toolkit for the
construction of highly optimized compilers, optimizers, and run-time
environments.

The LLVM project has multiple components. The core of the project is
itself called "LLVM". This contains all of the tools, libraries, and header
files needed to process intermediate representations and convert them into
object files. Tools include an assembler, disassembler, bitcode analyzer, and
bitcode optimizer.

C-like languages use the [Clang](http://clang.llvm.org/) frontend. This
component compiles C, C++, Objective-C, and Objective-C++ code into LLVM bitcode
-- and from there into object files, using LLVM.

Other components include:
the [libc++ C++ standard library](https://libcxx.llvm.org),
the [LLD linker](https://lld.llvm.org), and more.

## TraceRecoder Quick Start

Build and install ld.gold (optional, if you want to use LTO)
```
$ git submodule init
$ git submodule update binutils
$ cd binutils
$ mkdir build
$ cd build
$ ../configure --enable-gold --enable-plugins --disable-werror
$ make all-gold
$ sudo make install
```

Build with LLVMgold.so
```
$ mkdir build
$ cd build
$ cmake -G "Unix Makefiles" -DCMAKE_BUILD_TYPE=Release -DLLVM_BUILD_TESTS=OFF -DLLVM_INCLUDE_TESTS=OFF -DLLVM_BUILD_EXAMPLES=OFF -DLLVM_INCLUDE_EXAMPLES=OFF -DLLVM_ENABLE_ASSERTIONS=OFF -DLLVM_ENABLE_PROJECTS='clang;compiler-rt;lld;lldb' -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DLLVM_BINUTILS_INCDIR=../binutils/include/  ../llvm 
```
We highly recommend you use clang to compiler the LLVM project. 
The `-DLLVM_BINUTILS_INCDIR=../binutils/include/` is optional as it is used only to build the `LLVMgold.so`. 
If you do not intend to use LTO, `LLVMgold.so` will not be used, so it does not need to be built.

Compile your program
```
$ export TREC_DATABASE_DIR=/path/to/database/folder
$ ./build/bin/clang -g -fsanitize=trace -fno-discard-value-names /your/source/code -o ./output.out
$ export TREC_TRACE_DIR=/path/to/trace/folder
$ ./output.out
```
Note, if you use autotools to configure the compiling, please add `-g -fsanitize=trace -fno-discard-value-names` to `CFLAGS`, `CXXFLAGS`, and `LDFLAGS`.
The ENV `TREC_DATABASE_DIR` should not be unset if you want to symbolize the PCs at runtime.

TraceRecorder provides some other runtime options.
Please check `./compiler-rt/lib/trec/rtl/trec_flags.inc` for more details.
You can use `TREC_OPTIONS` to control these options, e.g., `export TREC_OPTIONS="output_trace=0"` to disable trace recording.

If you only want to record function entry/exit information, use `TREC_OPTIONS="record_mutex=0 record_rwlock=0 record_cond=0 record_alloc_free=0 record_branch=0 record_func_param=0 record_read=0 record_write=0 record_range=0"`


