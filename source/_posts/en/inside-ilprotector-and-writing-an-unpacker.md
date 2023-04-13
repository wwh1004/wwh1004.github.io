---
title: Inside ILProtector and Writing an Unpacker
date: 2018-11-18
updated: 2023-04-09
lang: en
categories:
- [￫Translated, .NET Reverse Engineering]
tags:
- .NET
- Reverse Engineering
- Unpacking
- ILProtector
toc: true
hide: true
---

<article class="message message-immersive is-primary">
<div class="message-body">
<i class="fas fa-globe-americas mr-2"></i>This article is translated to English using GPT-3.5 and polished by the author. <a href="{% post_path inside-ilprotector-and-writing-an-unpacker %}">This is the original post.</a>
</div>
</article>

<!-- # Inside ILProtector and Writing an Unpacker -->

The core protection principle of ILProtector is dynamic method. This article provides a detailed introduction to the protection details of ILProtector and specifically writes out the unpacker targeting it.

<!-- more -->

## Introduction

ILProtector can be considered as an obfuscator with good compatibility and lacking strong protection capabilities. Although there is almost no information about this obfuscator online, there are unpackers released by CodeCracker and some unpackers improved based on his unpacker.

These unpackers have become invalid in the latest version of ILProtector, but the principles have not become invalid. Many people only use these unpackers without knowing the principles behind them. Once these unpackers become invalid, they will not be able to unpack the shell.

This article will explain the protection principle of ILProtector and write our own unpacker based on a project open-sourced on GitHub ([ILProtectorUnpacker by RexProg](https://github.com/RexProg/ILProtectorUnpacker)).

Before the research, we still need to find a sample of ILProtector protected. Unfortunately, we did not find the latest UnpackMe of ILProtector protected online, so we directly use the main program of ILProtector (the website says "ILProtector is protected by itself!").

During the research, version 2.0.22.4 of ILProtector was used, but when writing the article, it was discovered that ILProtector had been updated to version 2.0.22.5, which is a bit embarrassing. However, I have tested that there is no difference between version 2.0.22.5 and 2.0.22.4. Therefore, this article still uses the main program of ILProtector v2.0.22.4 as the sample for research. Here is the download link for the protected file: [ILProtector v2.0.22.4.7z](/../inside-ilprotector-and-writing-an-unpacker/ILProtector%20v2.0.22.4.7z)

## Overview of ILProtector protection

Let's first open ILProtector with dnSpy to see how it is protected:

![Decompile ILProtector](/../inside-ilprotector-and-writing-an-unpacker/decompile-ilprotector.png)

We can see that the method body has been hidden and replaced with "&ltModule&gt.Invoke(num)". Let's try to debug with dnSpy:

Set a breakpoint here at the Main method:

![Debug ILProtector 1](/../inside-ilprotector-and-writing-an-unpacker/debug-ilprotector-1.png)

After breaking, step into the code with F11:

![Debug ILProtector 2](/../inside-ilprotector-and-writing-an-unpacker/debug-ilprotector-2.png)

We can preliminarily judge that DynamicMethod was used. Let's set a breakpoint at the constructor of DynamicMethod and run with F5:

![Debug ILProtector 3](/../inside-ilprotector-and-writing-an-unpacker/debug-ilprotector-3.png)

Yes, our guess was correct. ILProtector uses DynamicMethod to dynamically generate a method body to protect the assembly.

## Unpacking principle of RexProg's ILProtectorUnpacker

### Unpacking process

To avoid various attempts without significant meaning, let's see how the mentioned open-source project achieves unpacking. Let's first open this project in vs. (This provides a packaged project for download: [ILProtectorUnpacker by RexProg.7z](/../inside-ilprotector-and-writing-an-unpacker/ILProtectorUnpacker%20by%20RexProg.7z))

Find the Main method to see what's going on (the following comments are added by myself):

![RexProg's unpacker Main method](/../inside-ilprotector-and-writing-an-unpacker/rexprog-unpacker-main.png)

It can be seen that the actual implementation is in InvokeDelegates, so let's go to this method:

![RexProg's unpacker InvokeDelegates method](/../inside-ilprotector-and-writing-an-unpacker/rexprog-unpacker-invokedelegates.png)

### Bypassing detection

Now we have a basic understanding of the unpacking process. The unpacker first loads the protected assembly, then hooks a location, manually calls Invoke to obtain the dynamic method, and uses DynamicMethodBodyReader provided by dnlib to read the method body of this dynamic method and restore it to the method body in the file. We mentioned earlier that since it is a hook, it is most likely related to bypassing detection measures. Let's see what was hooked:

![Decompile System.Diagnostics.StackFrameHelper.GetMethodBase](/../inside-ilprotector-and-writing-an-unpacker/decompile-system.diagnostics.stackframehelper.getmethodbase.png)

The corresponding detour:

![RexProg's unpacker Hook4 method](/../inside-ilprotector-and-writing-an-unpacker/rexprog-unpacker-hook4.png)

At this point, we are not quite sure why System.Diagnostics.StackFrameHelper.GetMethodBase needs to be hooked, nor do we understand what InvokeMethod means in "if (result.Name == "InvokeMethod")". Let's search for InvokeMethod again with dnSpy and decompile it:

![Decompile System.RuntimeMethodHandle.InvokeMethod](/../inside-ilprotector-and-writing-an-unpacker/decompile-system.runtimemethodhandle.invokemethod.png)

For those with some reverse engineering experience, they should know that this is where the CLR enters from managed code when calling MethodInfo.Invoke, similar to R3 transitioning to R0 in Win32 programming.

![Call stack of System.RuntimeMethodHandle.InvokeMethod](/../inside-ilprotector-and-writing-an-unpacker/call-stack-of-system.runtimemethodhandle.invokemethod.png)

Combining with some principles of detecting illegal calls, we can know that ILProtector will check the previous method in the call stack of the protected method. For example:

![ILProtector's call stack detection](/../inside-ilprotector-and-writing-an-unpacker/ilprotector-call-stack-detection.png)

Suppose the arrow 2 points to the protected method, and arrow 1 points to the non-managed code running with ILProtector (treat it as such, because dnSpy cannot step into non-managed code). Then the non-managed code at runtime will check whether the caller pointed to by arrow 2 is the protected method, i.e., "internal static FormPos Load(string fileName)" here. If we manually use Invoke to obtain the dynamic method, the non-managed code detected will not be "internal static FormPos Load(string fileName)", but "System.RuntimeMethodHandle.InvokeMethod" mentioned earlier. Therefore, RegProg's unpacker hooked GetMethodBase and wrote
``` csharp
if (result.Name == "InvokeMethod")
    // This is a very critical point. If the result's Name is "InvokeMethod", then replace this MethodBase with the MethodBase of the method to be decrypted
    result = Assembly.Modules.FirstOrDefault()?.ResolveMethod(CurrentMethod.MDToken.ToInt32());
```
to bypass detection.

This explanation may be a bit difficult to understand, although it has been explained in as much detail as possible. Readers may not fully grasp it, but they have a general idea. Therefore, it is still necessary to debug and trace it by yourself to truly learn the knowledge through practice!

### An error occurred!

Looking at what I wrote, don't you think that ILProtectorUnpacker is written perfectly? However, the higher the level, the tougher the opponents, so there will be anti-detection measures even with anti-detection measures. Let's compile and run RexProg's unpacker directly:

![RexProg's unpacker encountered an error](/../inside-ilprotector-and-writing-an-unpacker/rexprog-unpacker-error.png)
![RexProg's unpacker error location](/../inside-ilprotector-and-writing-an-unpacker/rexprog-unpacker-error-location.png)

Why did this happen? After various analysis and attempts, and for the sake of simplicity, the correct process of analyzing and detecting anti-detection measures (ILProtector detected that we manually called Invoke) will be directly written here.

## ILProtector's detection

First, ILProtector checks the call stack. We have handled it and it works normally, so why would ILProtector still detect illegal calls? The answer is that ILProtector detected our hook.

Modify Memory.Hook to output some information (the address of target and detour in hook):

![Modify Memory.Hook](/../inside-ilprotector-and-writing-an-unpacker/modify-memory_hook.png)

Open x64dbg, start the unpacker, and let the unpacker run until it stops at "Console.ReadKey(true);":

![Output of Memory.Hook](/../inside-ilprotector-and-writing-an-unpacker/output-of-memory_hook.png)

In the memory window of x64dbg, go to the first address. The first address is the address of the method being hooked, i.e., the address of System.Diagnostics.StackFrameHelper.GetMethodBase. Then set a hardware access breakpoint for System.Diagnostics.StackFrameHelper.GetMethodBase:

![Set a hardware breakpoint on System.Diagnostics.StackFrameHelper.GetMethodBase](/../inside-ilprotector-and-writing-an-unpacker/set-hwbp-on-system.diagnostics.stackframehelper.getmethodbase.png)

Press any key in the console to let the unpacker continue to execute until it breaks at ProtectXXX.dll.

![Address of ILProtector's hook detection](/../inside-ilprotector-and-writing-an-unpacker/ilprotector-hook-detection-address.png)

This is a jcc instruction, which further proves that this is checking whether it is being Hooked. For convenience, and because this is an unencrypted DLL, we can just use IDA to decompile this hook detection function. The RVA of this function is 0x31B70, so just search for "31B70" in IDA.

![IDA decompiles hook detection function](/../inside-ilprotector-and-writing-an-unpacker/ida-decompile-hook-detection.png)

I have already renamed the code, so readers can directly think about the principle of this detection. I will briefly explain this detection:

IsHooked(char *pEntry) is passed in the address to be checked, such as 0x05067850 this time using x64dbg for debugging.

``` cpp
if ( *pEntry == 0x55 )
  offset = 1;
```

This code can be considered garbage code and does not need to be understood.

``` cpp
while ( offset < 0xFF && pEntry[offset] == 0x90u )// Skip nop
  ++offset;
```

Skip nop.

``` cpp
if ( pEntry[offset] == 0xE9u )                // The first instruction is jmp XXXXXXXX
{
  result = 1;
}
else
{
  InterlockedCompareExchange(&Destination, 0x45524548, 0x4B4F4F4C);
  result = 0;
}
return result;
```

Check whether the first instruction after the nop (if there is one) is jmp. If it is jmp, return true, indicating that the hook has been detected; if it is not jmp, it means that the code is normal and has not been Hooked. Set a flag (this flag does not matter) and return false.

## Bypassing ILProtector detection again

Don't forget that we have countless ways to write junk code and directly bypass the detection.

Let's first see what the unpacker changed System.Diagnostics.StackFrameHelper.GetMethodBase into:

![Hooked System.Diagnostics.StackFrameHelper.GetMethodBase](/../inside-ilprotector-and-writing-an-unpacker/hooked-system.diagnostics.stackframehelper.getmethodbase.png)

No wonder it was detected. The first instruction is jmp, and the hook is too obvious. Let's do something fancy and add 0xEB 0x00 in front of "jmp 0x06715AA8", which is equivalent to "jmp eip/rip+2".

![Add junk code](/../inside-ilprotector-and-writing-an-unpacker/add-junk-code.png)

Step through until the hook detection returns with F8, and you can see that it returns false. Press F5 and find that the unpacker does not report an error, which means our passing of the detection was successful!

![Hook detection returns false](/../inside-ilprotector-and-writing-an-unpacker/hook-detection-returns-false.png)
![RexProg's unpacker succeed](/../inside-ilprotector-and-writing-an-unpacker/rexprog-unpacker-succeed.png)
![Decompile unpacked assembly](/../inside-ilprotector-and-writing-an-unpacker/decompile-unpacked-assembly.png)

## Our own unpacker

So the research on RexProg's ILProtectorUnpacker and on ILProtector itself can come to an end. Next, let's explain how to write our own unpacker.

Let's start with a simple framework:

![My unpacker Main](/../inside-ilprotector-and-writing-an-unpacker/my-unpacker-main.png)
![My unpacker Execute placeholder](/../inside-ilprotector-and-writing-an-unpacker/my-unpacker-execute-placeholder.png)
![My unpacker code 1](/../inside-ilprotector-and-writing-an-unpacker/my-unpacker-code-1.png)

Before calling DecryptAllMethodBodys, we need to hook System.Diagnostics.StackFrameHelper.GetMethodBase.

GetMethodBase is an instance method, so we will create a class specifically for placing the detour method, and insert reflection API initialization code in the static constructor of this class:

``` csharp
Module mscorlib;

mscorlib = typeof(object).Module;
FieldInfo_rgMethodHandle = mscorlib.GetType("System.Diagnostics.StackFrameHelper").GetField("rgMethodHandle", BindingFlags.NonPublic | BindingFlags.Instance);
ConstructorInfo_RuntimeMethodInfoStub = mscorlib.GetType("System.RuntimeMethodInfoStub").GetConstructor(BindingFlags.Public | BindingFlags.Instance, null, new Type[] { typeof(IntPtr), typeof(object) }, null);
MethodInfo_GetTypicalMethodDefinition = mscorlib.GetType("System.RuntimeMethodHandle").GetMethod("GetTypicalMethodDefinition", BindingFlags.NonPublic | BindingFlags.Static, null, new Type[] { mscorlib.GetType("System.IRuntimeMethodInfo") }, null);
MethodInfo_GetMethodBase = mscorlib.GetType("System.RuntimeType").GetMethod("GetMethodBase", BindingFlags.NonPublic | BindingFlags.Static, null, new Type[] { mscorlib.GetType("System.IRuntimeMethodInfo") }, null);
```

Note that because it has been Hooked, the "this" pointer is incorrect, and fields such as FieldInfo_rgMethodHandle should be defined as static fields. If you don't understand, you can change it to non-static and see what error occurs. We won't demonstrate it here.

Compared to using GetMethodByName directly, I prefer to use Attributes to retrieve my detour. Let's define a DetourAttribute:

``` csharp
private sealed class GetMethodBaseDetourAttribute : Attribute {
}
```

Back to the class where the detour is placed, write this code:

``` csharp
[GetMethodBaseDetour]
public virtual MethodBase GetMethodBaseDetour(int i) {
    IntPtr[] rgMethodHandle;
    IntPtr methodHandleValue;
    object runtimeMethodInfoStub;
    object typicalMethodDefinition;
    MethodBase result;

    rgMethodHandle = (IntPtr[])FieldInfo_rgMethodHandle.GetValue(this);
    methodHandleValue = rgMethodHandle[i];
    runtimeMethodInfoStub = ConstructorInfo_RuntimeMethodInfoStub.Invoke(new object[] { methodHandleValue, this });
    typicalMethodDefinition = MethodInfo_GetTypicalMethodDefinition.Invoke(null, new[] { runtimeMethodInfoStub });
    result = (MethodBase)MethodInfo_GetMethodBase.Invoke(null, new[] { typicalMethodDefinition });
    if (result.Name == "InvokeMethod")
        result = _module.ResolveMethod(_currentMethod.MDToken.ToInt32());
    return result;
}
```

Now we can use

``` csharp
private static MethodInfo GetMethodByAttribute<TClass, TMethodAttribute>() where TMethodAttribute : Attribute {
    foreach (MethodInfo methodInfo in typeof(TClass).GetMethods(BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.Instance | BindingFlags.Static)) {
        object[] attributes;

        attributes = methodInfo.GetCustomAttributes(typeof(TMethodAttribute), false);
        if (attributes != null && attributes.Length != 0)
            return methodInfo;
    }
    return null;
}
```

to get the detour without worrying about when the code is obfuscated and GetMethodByName fails.

``` csharp
private static void* GetMethodAddress(MethodBase methodBase) {
    RuntimeHelpers.PrepareMethod(methodBase.MethodHandle);
    return (void*)methodBase.MethodHandle.GetFunctionPointer();
}

private static void WriteJunkCode(ref void* address) {
    byte[] junkJmp;

    junkJmp = new byte[] {
        0xEB, 0x00
    };
    // Here we use JunkJmp, which is equivalent to jmp eip/rip+2
    Write(address, junkJmp);
    address = (byte*)address + 2;
}

private static void WriteJmp(ref void* address, void* target) {
    byte[] jmpStub;

    if (IntPtr.Size == 4) {
        jmpStub = new byte[] {
            0xE9, 0x00, 0x00, 0x00, 0x00
        };
        fixed (byte* p = jmpStub)
            *(int*)(p + 1) = (int)target - (int)address - 5;
    }
    else {
        jmpStub = new byte[] {
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, target
            0xFF, 0xE0                                                  // jmp rax
        };
        fixed (byte* p = jmpStub)
            *(ulong*)(p + 2) = (ulong)target;
    }
    Write(address, jmpStub);
    address = (byte*)address + jmpStub.Length;
}
```

With this method written, we'll write another new method to get the address of target and detour, first write junk code to tagret, and then write the actual jmp.

At this point, we can add the following to Execute(string filePath):

``` csharp
if (Environment.Version.Major == 2)
    throw new NotSupportedException();
else
    InstallHook(typeof(object).Module.GetType("System.Diagnostics.StackFrameHelper").GetMethod("GetMethodBase", BindingFlags.Public | BindingFlags.Instance), GetMethodByAttribute<StackFrameHelperDetour4, GetMethodBaseDetourAttribute>());
```

Next, let's write the previously defined DecryptAllMethodBodys(). First, define variables inside the method:

``` csharp
TypeDef globalType;
object instanceOfInvoke;
MethodInfo methodInfo_Invoke;
uint methodTableLength;
```

Then, we need to use reflection to get "internal static i Invoke" in &ltModule&gt. methodTableLength represents the total number of methods in the assembly, so we will iterate through each method using a for loop to implement it:

``` csharp
globalType = _moduleDef.GlobalType;
instanceOfInvoke = null;
foreach (FieldDef fieldDef in globalType.Fields)
    if (fieldDef.Name == "Invoke")
        instanceOfInvoke = _module.ResolveField(fieldDef.MDToken.ToInt32()).GetValue(null);
methodInfo_Invoke = instanceOfInvoke.GetType().GetMethod("Invoke");
methodTableLength = _moduleDef.TablesStream.MethodTable.Rows;
```

methodTableLength represents the total number of methods in the assembly, so we will iterate through each method using a for loop to implement.

``` csharp
for (uint rid = 1; rid <= methodTableLength; rid++) {
}
```

Define variables inside the loop body:

``` csharp
MethodDef methodDef;
object dynamicMethod;
```

methodDef represents the current method being resolved, and dynamicMethod represents the value returned by i.Invoke(num), which is a delegate. The delegate's internal code is a dynamic method.

``` csharp
methodDef = _moduleDef.ResolveMethod(rid);
if (!NeedDecryptMethodBody(methodDef))
    continue;
_currentMethod = methodDef;
dynamicMethod = methodInfo_Invoke.Invoke(instanceOfInvoke, new object[] { methodDef.Body.Instructions[1].GetLdcI4Value() });
```

At this point, we are ready to Invoke and restore, so we'll add them.

``` csharp
try {
    DynamicMethodBodyReader reader;

    reader = new DynamicMethodBodyReader(_moduleDef, dynamicMethod);
    reader.Read();
    _currentMethod.FreeMethodBody();
    _currentMethod.Body = reader.GetMethod().Body;
}
catch (Exception) {
}
```

When we run the unpacker, we can see that the method body can really be decrypted. If you truly write an unpacker from scratch, it is truly exciting and rewarding to have achieved results through research on your own, isn't it?

![My unpacker decrypt method body](/../inside-ilprotector-and-writing-an-unpacker/my-unpacker-decrypt-method-body.png)

But we can see that there seem to be some strings that have not been decrypted. Let's revisit "internal static s String" in &ltModule&gt. This is similar to Invoke - the same way to call it can decrypt strings. We won't paste the code here because it's really the same, and it's not checked, so just call it directly.

The effect of decrypting strings:

![My unpacker decrypt method body and strings](/../inside-ilprotector-and-writing-an-unpacker/my-unpacker-decrypt-method-body-and-strings.png)

Next, we need to remove the initialization code of ILProtector at runtime. Although it doesn't matter if it's not removed, for the sake of perfection, let's improve the unpacker:

``` csharp
private static void RemoveRuntimeInitializer() {
    // IL_0000: ldtoken   '<Module>'
    // IL_0005: call      class [mscorlib]System.Type [mscorlib]System.Type::GetTypeFromHandle(valuetype [mscorlib]System.RuntimeTypeHandle)
    // IL_000A: call      native int [mscorlib]System.Runtime.InteropServices.Marshal::GetIUnknownForObject(object)
    // IL_000F: stloc     V_0
    // .try
    // {
    // 	IL_0013: call      int32 [mscorlib]System.IntPtr::get_Size()
    // 	IL_0018: ldc.i4.4
    // 	IL_0019: bne.un.s  IL_0031

    // 	IL_001B: call      class [mscorlib]System.Version [mscorlib]System.Environment::get_Version()
    // 	IL_0020: callvirt  instance int32 [mscorlib]System.Version::get_Major()
    // 	IL_0025: ldloc     V_0
    // 	IL_0029: call      bool '<Module>'::g(int32, native int)
    // 	IL_002E: pop
    // 	IL_002F: br.s      IL_004D

    // 	IL_0031: call      int32 [mscorlib]System.IntPtr::get_Size()
    // 	IL_0036: ldc.i4.8
    // 	IL_0037: bne.un.s  IL_004D

    // 	IL_0039: call      class [mscorlib]System.Version [mscorlib]System.Environment::get_Version()
    // 	IL_003E: callvirt  instance int32 [mscorlib]System.Version::get_Major()
    // 	IL_0043: ldloc     V_0
    // 	IL_0047: call      bool '<Module>'::h(int32, native int)
    // 	IL_004C: pop

    // 	IL_004D: leave.s   IL_005A
    // } // end .try
    // finally
    // {
    // 	IL_004F: ldloc     V_0
    // 	IL_0053: call      int32 [mscorlib]System.Runtime.InteropServices.Marshal::Release(native int)
    // 	IL_0058: pop
    // 	IL_0059: endfinally
    // } // end handler

    MethodDef cctor;
    IList<Instruction> instructionList;
    int startIndex;
    int endIndex;
    IList<ExceptionHandler> exceptionHandlerList;

    cctor = _moduleDef.GlobalType.FindStaticConstructor();
    instructionList = cctor.Body.Instructions;
    startIndex = 0;
    for (int i = 0; i < instructionList.Count; i++)
        if (instructionList[i].OpCode == OpCodes.Call && instructionList[i].Operand is MemberRef && ((MemberRef)instructionList[i].Operand).Name == "GetIUnknownForObject")
            startIndex = i - 2;
    endIndex = 0;
    for (int i = startIndex; i < instructionList.Count; i++)
        if (instructionList[i].OpCode == OpCodes.Call && instructionList[i].Operand is MemberRef && ((MemberRef)instructionList[i].Operand).Name == "Release")
            endIndex = i + 3;
    for (int i = startIndex; i < endIndex; i++) {
        instructionList[i].OpCode = OpCodes.Nop;
        instructionList[i].Operand = null;
    }
    exceptionHandlerList = cctor.Body.ExceptionHandlers;
    for (int i = 0; i < exceptionHandlerList.Count; i++)
        if (exceptionHandlerList[i].HandlerType == ExceptionHandlerType.Finally && exceptionHandlerList[i].HandlerEnd == instructionList[endIndex]) {
            exceptionHandlerList.RemoveAt(i);
            break;
        }
}
```

The variable startIndex in the code represents the beginning of the runtime initialization code, and endIndex represents the code immediately following the end of the runtime initialization code. Due to the possibility of jumps within the method body and some features of dnlib, we cannot simply replace the Instruction with Nop, but must do it like this:

``` csharp
instructionList[i].OpCode = OpCodes.Nop;
instructionList[i].Operand = null;
```

In addition to this, there may be other residual code caused by ILProtector in the protected assembly, and we will not elaborate on the removal methods one by one.

There is not much point in releasing a finished unpacker. It is still hoped that readers can study and develop their own unpackers based on the article. Instead of just using someone else's unpacker, which will become ineffective if the packer tool is updated someday.
