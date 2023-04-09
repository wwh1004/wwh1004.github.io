---
title: .NET JIT unpacking guide and tool source
date: 2019-08-08
updated: 2023-04-09
lang: en
tags:
- .NET
- Reverse Engineering
- Unpacking
- JIT
categories:
- [.NET]
toc: true
hide: true
---

<article class="message message-immersive is-primary">
<div class="message-body">
<i class="fas fa-globe-americas mr-2"></i>This article is translated to English using GPT-3.5 and polished by the author. <a href="{% post_path net-jit-unpack-guide-and-source %}">This is the original post.</a>
</div>
</article>

<!-- # .NET JIT unpacking guide and tool source -->

This article introduces techniques for encrypting and unpacking at the JIT layer in .NET, including IL code, Tokens, exception handling clauses, and local variables. It also provides a basic JIT unpacking framework source code. The content of this article is applicable to all versions of the .NET Framework, .NET Core 1.0-3.1, and .NET 5+. If not otherwise specified, ".NET" in this article refers to the ".NET Framework".

<!-- more -->

## Introduction

JIT unpacking may be difficult for many people because there is not many documents available online. Some of the available tools and source code are limited to jitDumper3, ManagedJiter, and DNGuard_HVM_Unpacker, which are based on yck1509 (ConfuserEx author)'s work, as well as CodeCracker's Simple_MSIL_Decryptor, which is very unstable.

To study JIT unpacking, one needs to first understand the CLR source code. For .NET 2.0-3.5, one can look at the IDA decompiled mscorwks.dll and mscorjit.dll, or the SSCLI source code. For .NET 4.0+, one can look at the coreclr source code. If I remember correctly, coreclr came out of the .NET 4.6 branch.

.NET can be said to have three major versions: .NET 2.0, .NET 4.0, and .NET 4.5. There are significant changes in the CLR for these three versions.

- The CLR name for .NET 2.0 is mscorwks.dll, and the JIT name is mscorjit.dll.
- The CLR name for .NET 4.0 has changed to clr.dll, and the JIT name has changed to clrjit.dll, with minor changes to the internal structure of clr and jit.
- The CLR and JIT names for .NET 4.5 are the same as for .NET 4.0, but there are huge changes to the internal structure of the CLR, the most obvious of which is the virtual table structure and function definition of the ICorJitInfo interface provided by the CLR to the JIT for compilation, which is completely different from that of .NET 4.0.

Therefore, the several tools released by CodeCracker require .NET 4.0 to be installed using NetBox or a virtual machine, and those tools do not support .NET 4.5+.

There are some changes in the latest .NET 4.8, and DoPrestub needs to be called twice due to changes in Precode.

## CLR and JIT Introduction

For this part, I recommend reading the coreclr document [Book of the Runtime](https://github.com/dotnet/runtime/blob/main/docs/design/coreclr/botr/README.md), which is excellent material applicable to any version of the CLR, so I don't need to repeat it here.

## JIT Compilation Phases

This is a very important thing to understand, and one must understand it, or many parts of the article and the source code of the unpacker will be difficult to understand. Here, I still recommend reading the coreclr document, [RyuJIT Ooverview](https://github.com/dotnet/runtime/blob/main/docs/design/coreclr/jit/ryujit-overview.md). Although RyuJIT is only available in .NET 4.5 or .NET 4.6, the compilation process for older versions of the JIT is almost the same.

Although there are many phases, only the Pre-import and Importation stages need to be understood. These two stages also call the ICorJitInfo interface, which is what we will study.

### From DoPrestub to compileMethod

Now we can open the coreclr source code and find MethodDesc::DoPrestub. CLR generates a stub for each method, and the stub finally jumps to MethodDesc::DoPrestub, which calls the JIT compiler. Before compilation, MethodDesc::DoPrestub performs parameter checks and determines the method type, including generic parameter checks for generic methods.

![MethodDesc::DoPrestub](./method_descdoprestub.png)

Finally, DoPrestub jumps to the exported function compileMethod of jit. The corresponding code CILJit::compileMethod can also be found in coreclr.

![CILJit::compileMethod](./ciljit_compilemethod.png)

It can be said that all obfuscators use Hook ICorJitCompiler's vtable for JIT decryption, without exception.

Some may ask why not hook lower-level functions such as jitNativeCode and Compiler::compCompile. The reason is simple: inline-hooking these functions is complicated. Finding the address of these functions requires feature matching, and if the JIT changes, the features will also change, causing matching failures. This is one of the reasons why CodeCracker's unpacker cannot run on .NET 4.5+.

Some may also ask if hooking such a shallow exported function will cause security risks. The answer is no, because some packers implement the ICorJitInfo interface themselves and perform decryption operations within the ICorJitInfo interface. The dumped IL is correct, but the tokens in the IL are encrypted. Therefore, there is no basis for unpackers to hook lower-level functions such as Compiler::compCompile or other functions mentioned online for decryption. Hooking any layer of functions is the same, and the dumped IL will not change. The token will always be encrypted, and the decryption operation will still be performed at a lower level, and will not be restored to the IL after decryption!!!

CILJit::compileMethod does not perform actual compilation. It calls jitNativeCode, which instantiates the Compiler class. In fact, jitNativeCode is also a wrapper, responsible for calling Compiler::compCompile.

![jitNativeCode](./jitnativecode.png)

### JIT internals

Let's start with a JIT process diagram, for those who don't understand, you can refer to this diagram.

![ryujit-ir-overview](./ryujit-ir-overview.png)

Compiler::compCompile has two overloaded methods. Let's start with the most superficial one.

![Compiler::compCompile](./compiler_compcompile.png)

This is called by jitNativeCode. The unpacker of CodeCracker achieves the effect of hooking Compiler::compCompile by hooking the call to Compiler::compCompile in jitNativeCode and dumping the IL here.

This Compiler::compCompile is still a wrapper, without any actual execution part.

![Compiler::compCompile calls Compiler::compCompileHelper](./compiler_compcompile-call.png)

Next is the function called by this function, Compiler::compCompileHelper. This function initializes some information, where EHcount is the number of exception handling clauses, and maxStack is the maximum number of stack elements.

![Compiler::compCompileHelper](./compiler_compcompilehelper.png)

Next is the initialization of the local variable table.

![locals init 1](./locals-init-1.png)

![locals init 2](./locals-init-2.png)

The "locals" here refer to local variable information, and the corresponding structure is CORINFO_SIG_INFO.

![CORINFO_SIG_INFO](./corinfo_sig_info.png)

The field "pSig" points to the LocalSig in the #Blob heap. An unpacker can use this to dump the local variable signature. Of course, the packer can also directly remove this LocalSig and provide the JIT with local variable information through the ICorJitInfo interface, because the JIT also uses the ICorJitInfo interface to obtain local variable information instead of directly parsing CORINFO_SIG_INFO.pSig. Therefore, in some cases, the local variable signature obtained by dumping pSig may be invalid. How to decrypt or dump it, you need to study it yourself, I won't reveal too much.

Now let's go back to Compiler::compCompileHelper and continue to explore the compilation process. We can see that the function fgFindBasicBlocks is called.

![call Compiler::fgFindBasicBlocks](./call-compiler_fgfindbasicblocks.png)

![Compiler::fgFindBasicBlocks](./compiler_fgfindbasicblocks.png)

fgFindBasicBlocks is the entry function for generating basic blocks. Like my control flow analysis library, basic blocks must be generated before further analysis can be performed. This function will call ICorJitInfo::getEHinfo to obtain information about exception handling clauses.

![ehs init](./ehs-init.png)

This CORINFO_EH_CLAUSE structure is also needed for our unpacking purposes.

![CORINFO_EH_CLAUSE](./corinfo_eh_clause.png)

Now, we have obtained the three pieces of information required to decrypt the method body: IL code, local variables, and exception handling clauses. But do you remember what I said earlier about encrypted tokens in IL instructions? Yes, that's why we need to delve deeper into the JIT.

We should arrive at importer.cpp, where the JIT will use ICorJitInfo to convert the IL instructions into GenTree. Tokens need to be converted into JIT-internal definitions, so tokens will not be restored to the IL code and we need to write code to decrypt and restore them.

![Compiler::impResolveToken and CORINFO_RESOLVED_TOKEN](./compiler_impresolvetoken-and-corinfo_resolved_token.png)

This is the token-related function for .NET 4.5+. The CORINFO_RESOLVED_TOKEN structure was introduced in .NET 4.5+, which is also used in coreclr. The token inside it represents the token of the operand in the IL instruction.

![Compiler::embedGenericHandle](./compiler_embedgenerichandle.png)

In .NET 2.0~3.5 and .NET 4.0, there was also an embedGenericHandle function to obtain the token. This function was used by CodeCracker's unpacker to decrypt tokens. However, this function is hardly used anymore in .NET 4.5+.

We have now completed our understanding of the entire JIT compilation process.

## JitUnpacker

I started working on it around September of last year, and now the entire framework has been open-sourced, with the DNG unpacking code and other obfuscators code removed, leaving only the general unpacking part. Therefore, it is more appropriate to call it JitUnpacker-Framework. The GitHub link is [JitUnpacker-Framework](https://github.com/wwh1004/JitUnpacker-Framework). After being open-sourced, I will not continue to maintain this repository. It is only for research purposes. Please note!!!

### Introduction

The entire unpacker consists of two main parts.

![JitUnpacker hierarchy](./jitunpacker-hierarchy.png)

The first is the contents of the "Runtime" folder, and the second is the contents of the "Unpackers" folder.

The "Runtime" provides runtime-related information, such as DoPrestub wrappers, JitHook interfaces, etc.

"Unpackers" contains the logic code for unpacking, which can be implemented by providing implementations for the IMethodDumper, IUnpacker, and IUnpackerDetector interfaces. The "Unknown" folder is similar to the "-p un" parameter in de4dot and can handle obfuscators that are not anti-anti-unpacking.

### Runtime

This is a wrapper for CORINFO_METHOD_INFO, because the CORINFO_METHOD_INFO structure is different between .NET 2.0 and .NET 4.0+, so a wrapper is necessary.

![CorMethodInfo](./jitunpacker-cormethodinfo.png)

This is the interface for JitHook. By implementing this interface, it can provide the necessary information for IMethodDumper. Currently, the hook method used by CodeCracker's unpacker (to be exact, yck1509's with some modifications made by CodeCracker) and the compileMethod virtual table hook method have been built-in.

![JitHook interface](./jitunpacker-jithook-interface.png)

![CompileMethodStub](./jitunpacker-compilemethodstub.png)

Due to the existence of value types, there is the "UnboxingStub". When comparing method handles, we cannot compare them directly and need to do it like this. (Update: We can make _targetMethodHandle the actual value passed to the JIT without having to check like this.)

![GetRealMethodHandle](./jitunpacker-getrealmethodhandle.png)

Next is the RuntimePatcher. The first thing that needs to be patched is "canInline". If this is not patched, some methods may be compiled for inlining, causing errors during unpacking. Then there is the detection of class static constructors. When compiling a method, DoPrestub checks if the class static constructor has been executed. If it has not been executed, the CLR will execute the class static constructor first, leading to code execution outside our unpacker. The last place that needs to be patched is generic arguments detection. DoPrestub checks the generic arguments. If there are no generic arguments, compilation will be disabled.

![RuntimePatcher](./jitunpacker-runtimepatcher.png)

The code for detecting whether the class static constructor has been executed was not found in coreclr, so it is not included here. Below is the generic arguments detection.

![Generic arguments check](./gas-check.png)

### Other

Here are some miscellaneous codes. Firstly, I want to mention LoadMethodHandles. CodeCracker's code handles generics in a particular way, but it is incorrect.

Instead, I directly call ResolveMethodHandle.

![LoadMethodHandles](./jitunpacker-loadmethodhandles.png)

CodeCracker intends to instantiate generic methods, but actually, this method is wrong. I have examined the coreclr source code and tested, and the method handle obtained this way is the same as that obtained by calling ResolveMethodHandle directly.

![LoadHandles](./codecracker-loadhandles.png)

The second point to note is the UnboxingStub inside CLR. When dealing with value type methods, CLR generates this stub. If we directly call DoPrestub, CLR will not allow JIT to compile this method. Instead, we need to call GetWrappedMethodDesc and use the return value to trigger JIT in DoPrestub.

![Call GetWrappedMethodDesc](./jitunpacker-call-getwrappedmethoddesc.png)

CodeCracker's approach is to directly invoke and then write 0xC3 (the ret instruction) into compCompile hooked into.

![Handle ValueType 1](./codecracker-handles-valuetype-1.png)

![Handle ValueType 2](./codecracker-handles-valuetype-2.png)

This is a rough overview of JIT unpacking.

### Usage

Clone my code from https://github.com/wwh1004/JitUnpacker-Framework locally, and be sure to clone the submodule too. Then, compile to generate the files. You'll see a .bat file.

![Usage 1](./usage-1.png)

Next, download my ToolLoader from https://github.com/wwh1004/ToolLoader. It contains the pre-compiled files. After downloading, simply copy these five files out.

![Usage 2](./usage-2.png)

Now, you need to download the symbol files for mscorwks.dll, mscorjit.dll, clr.dll, and clrjit.dll. How to download? Don't ask me; x64dbg and windbg can both do this. Then, modify YOUR_SYMBOLS_PATH here.

![Usage 3](./usage-3.png)

For example, mine is E:\Symbols. So, change it to look like this and save it.

![Usage 4](./usage-4.png)

Run RuntimeFunctionConfigGenerator.bat, and it will generate two configuration files: "JitUnpacker.RuntimeFunctions.CLR20.x86.config" and "JitUnpacker.RuntimeFunctions.CLR40.x86.config".

![Usage 5](./usage-5.png)

Copy the file to be unpacked, including related DLLs, to the directory where JitUnpacker.dll is located. Then, hold down the shift key and right-click the folder, and select "Open command window here."

You can first take a look at the JitUnpacker parameters.

![Usage 6](./usage-6.png)

The -f parameter specifies the path of the file to be unpacked.

And the -hook-type parameter specifies the type of Jithook. You can find out what types there are by looking at the source code. The default is inlinehook.

Other parameters should be self-explanatory.

Let's take CodeCracker's tool SimpleByteArrayInit.exe as an example using dnSpy, which we can see is for .NET 2.0 x86.

![Usage 7](./usage-7.png)

Then, in the command line, enter "Tool.Loader.CLR20.x86.exe JitUnpacker.dll -f SimpleByteArrayInit.exe" and press enter.

![Usage 8](./usage-8.png)
