---
title: .NET Dynamic Decryption and Countermeasures
date: 2018-12-09
updated: 2023-04-12
lang: en
categories:
- [￫Translated, .NET Reverse Engineering]
tags:
- .NET
- Reverse Engineering
- Unpacking
- Agile.NET
- ConfuserEx
toc: true
hide: true
---

<article class="message message-immersive is-primary">
<div class="message-body">
<i class="fas fa-globe-americas mr-2"></i>This article is translated to English using GPT-3.5 and polished by the author. <a href="{% post_path net-dynamic-decryption-and-countermeasures %}">This is the original post.</a>
</div>
</article>

<!-- # .NET Dynamic Decryption and Countermeasures -->

Reflection is an important feature in .NET. Based on this feature, we often don't need to fully analyze the encryption algorithm itself. We can simply use reflection APIs to complete decryption. This article will introduce dynamic decryption techniques in .NET and their corresponding countermeasures.

<!-- more -->

## Introduction

de4dot has not been updated for a long time, so there are no ready-made tools for removing some obfuscators. If you want to remove them, you can almost only write your own tools.

There are generally two ways to decrypt .NET encryption: static decryption and dynamic decryption. Static decryption is faster, but writing a static decryption tool is very difficult, and the compatibility is not necessarily good (for example, most of the decryption in de4dot is static decryption, and when the obfuscator updates, de4dot must be updated).

Therefore, we need to use dynamic decryption. Dynamic decryption is not without drawbacks, such as the biggest disadvantage that the decrypted assembly must be able to run normally. But compared with the advantages of easy development, easy maintenance, good compatibility, etc., this disadvantage is not significant. This article will introduce some simple dynamic decryption and anti dynamic decryption.

## Agile.NET's String Encryption

### Analysis

Let's start with the simplest one first, and try Agile.NET's string encryption. Let's take a look at Agile.NET's string encryption. This is a relatively simple dynamic decryption.

We open UnpackMe with dnSpy and see what the strings look like after they are encrypted.

![Agile.NET string encryption overview](/../net-dynamic-decryption-and-countermeasures/agile_net-string-encryption-overview.png)

As you can see, all the strings have turned into a garbled mess and are passed to a special method. This special method will convert the garbled string into a normal string, which is decryption.

Let's click on this method and see how it decrypts the strings inside.

![Agile.NET string decrypter 1](/../net-dynamic-decryption-and-countermeasures/agile_net-string-decrypter-1.png) 

![Agile.NET string decrypter no proxy call](/../net-dynamic-decryption-and-countermeasures/agile_net-string-decrypter-no-proxy-call.png)

As you can see, this decryption is very simple, mainly using XOR. For the sake of explanation, I removed the proxy call first, otherwise it is difficult to see what the string decryptor method looks like. (We will explain Agile.NET's proxy call later, so don't worry about it here.)

Such a simple decryption can certainly be done with a static decryption tool, and it is not complicated, and the efficiency is higher. But this article explains dynamic decryption. So next, we will explain how to write a dynamic decryption tool.

### Write a Decryption Tool

In the previous figure, we can see that Agile.NET's string encryption is very simple, just encrypting the string itself, and then passing it to the string decryptor. At least at the C# level, but is it the same at the IL level? Are there no other obfuscations? Let's switch dnSpy's decompilation mode from C# to IL and take a look.

![Agile.NET string encryption IL-level overview](/../net-dynamic-decryption-and-countermeasures/agile_net-string-encryption-il-overview.png)

As you can see, this is really the same as shown in C#, where the string is pushed onto the stack and the string decryptor method is called. (This is how Agile.NET does it, but it doesn't mean that other obfuscators do it like this. This needs to be analyzed specifically.) This makes it easier for us to write a decryption tool.

Here I would like to mention that, still for the sake of explanation, we write the simplest decryption tool, which cannot automatically recognize the runtime version of the target program, that is, it cannot automatically adapt to .NET 2.0 or 4.0 programs. If you want to write an adaptive one, you can read the de4dot code yourself. De4dot's code is actually quite complicated, with too many design patterns, so I didn't use the subprocess like de4dot does. I used a loader to load our decryption tool, and we manually select the loader. If you don't understand this paragraph, it doesn't matter. After writing more decryption tools, you will understand what this paragraph is talking about. Let's continue.

We create a new project and select the same version of the target runtime as the decryption tool. For example, if our UnpackMe is .NET 4.5, we choose 4.5. (Actually, 4.0 can also be used, because the CLR version is the same, but I won't go into too much detail here. You can study some technical details of .NET by yourself.)

Add code like the following to prepare the framework, initialize fields, and write the code in ExecuteImpl().

![String decrypter](/../net-dynamic-decryption-and-countermeasures/string-decrypter.png)

Let's use dnSpy again to see what features the Agile.NET string decryptor method has. First, let's locate this method.

![Agile.NET string decrypter 2](/../net-dynamic-decryption-and-countermeasures/agile_net-string-decrypter-2.png)

We can see that the string decryptor method is in the &lt;AgileDotNetRT&gt; class with an empty namespace, and the signature of the string decryptor method itself should be string (string). This means that the string decryptor has only one parameter which is a string type, and returns a string. This way, we can use feature to locate the string decryptor.

We write the following code for the location. (Of course, it's okay if it's different from mine, as long as it can accurately locate it.) These codes are added to the ExecuteImpl() method.

``` csharp
TypeDef agileDotNetRT;
MethodDef decryptorDef;
MethodBase decryptor;

agileDotNetRT = _moduleDef.Types.First(t => t.Namespace == string.Empty && t.Name == "<AgileDotNetRT>");
// Look for a class with an empty namespace and a name of "<AgileDotNetRT>"
decryptorDef = agileDotNetRT.Methods.First(m => m.Parameters.Count == 1 && m.Parameters[0].Type.TypeName == "String" && m.ReturnType.TypeName == "String");
// Find a method in the class with only one parameter of type String and a return type of String.
decryptor = _module.ResolveMethod(decryptorDef.MDToken.ToInt32());
// Convert the MethodDef of dnlib to MethodBase in .NET reflection.
```

In order to traverse all methods in ModuleDefMD more quickly, we need an extension method. We write it like this:

``` csharp
internal static class ModuleDefExtensions {
    public static IEnumerable<MethodDef> EnumerateAllMethodDefs(this ModuleDefMD moduleDef) {
        uint methodTableLength;

        methodTableLength = moduleDef.TablesStream.MethodTable.Rows;
        // Get the length of the Method table.
        for (uint rid = 1; rid <= methodTableLength; rid++)
            yield return moduleDef.ResolveMethod(rid);
    }
}
```

The Method table mentioned in the above code is a table in the .NET metadata table stream that stores information about all methods in an assembly, which is very important. Each element in the Method table is continuous. Don't ask me why, this is metadata knowledge, and it can't be explained clearly for a while. Readers need to study it by themselves. Of course, for writing a string decryption tool, we do not need to understand such low-level knowledge.

Perhaps readers still have doubts, why do we have to write like this? Can't we traverse each method like this?

``` csharp
foreach (TypeDef typeDef in _moduleDef.Types)
    foreach (MethodDef methodDef in typeDef.Methods) {
        ...
        ...
    }
```

It looks okay, but this will not traverse methods in nested types. For example, this is a nested type, and a class B is declared in a class.

![Nested type](/../net-dynamic-decryption-and-countermeasures/nested-type.png)

![ModuleDef.Types](/../net-dynamic-decryption-and-countermeasures/moduledef_types.png)

So this is not possible, ModuleDef.Types will not return nested types, we need to use ModuleDef.GetTypes(). We need to write 2 foreach loops every time we traverse a method, so it is better to use an extension method instead.

``` csharp
foreach (MethodDef methodDef in _moduleDef.EnumerateAllMethodDefs()) {
    IList<Instruction> instructionList;

    if (!methodDef.HasBody)
        continue;
    instructionList = methodDef.Body.Instructions;
    for (int i = 0; i < instructionList.Count; i++) {
    }
}
```

This way we can traverse the instructions of all methods with CliBody. Let's switch back to dnSpy and see how Agile.NET calls the string decryptor method.

![Agile.NET string encryption IL-level overview](/../net-dynamic-decryption-and-countermeasures/agile_net-string-encryption-il-overview.png)

So, we locate the position of the string to be decrypted in this way, decrypt the string, and then replace it back.

``` csharp
if (instructionList[i].OpCode.Code == Code.Call && instructionList[i].Operand == decryptorDef && instructionList[i - 1].OpCode.Code == Code.Ldstr) {
    // The feature is judged here.
    instructionList[i].OpCode = OpCodes.Nop;
    instructionList[i].Operand = null;
    // The instruction corresponding to i is Call XXXX, we nop this instruction.
    instructionList[i - 1].Operand = decryptor.Invoke(null, new object[] { instructionList[i - 1].Operand });
    // The instruction corresponding to i-1 is ldstr, we call the string decryptor method, and then replace the decrypted string back.
}
```

This way, our string decryption tool is complete.

## Agile.NET's Proxy Call

The decryption of this proxy invocation is the most difficult one in this explanation. If readers haven't understood the string decryption above, it is strongly recommended to skip this section.

### Analysis

Let's open that UnpackMe with dnSpy again.

![Agile.NET proxy call overview](/../net-dynamic-decryption-and-countermeasures/agile_net-proxy-call-overview.png)

We can see that some external method calls are obfuscated, but the method calls in the current assembly are not obfuscated. Let's debug and see what these delegates are.

![Agile.NET proxy call debug 1](/../net-dynamic-decryption-and-countermeasures/agile_net-proxy-call-debug-1.png)

Press F11 to directly enter here, with no gains.

![Agile.NET proxy call debug 2](/../net-dynamic-decryption-and-countermeasures/agile_net-proxy-call-debug-2.png)

Let's see where this delegate field is initialized. We can notice something.

![Agile.NET proxy call fields initialization](/../net-dynamic-decryption-and-countermeasures/agile_net-proxy-fields-initialization.png)

We enter the dau method, and the dnSpy decompiled result is as follows:

``` csharp
using System;
using System.Reflection;
using System.Reflection.Emit;

// Token: 0x02000030 RID: 48
public class {FE3C441D-DF9D-407b-917D-0B4471A8296C}
{
    // Token: 0x040000C2 RID: 194
    private static ModuleHandle Fzw=;

    // Token: 0x040000C3 RID: 195
    public static string Cho= = "{FE3C441D-DF9D-407b-917D-0B4471A8296C}";

    // Token: 0x060000B3 RID: 179 RVA: 0x00007984 File Offset: 0x00005B84
    static {FE3C441D-DF9D-407b-917D-0B4471A8296C}()
    {
        {FE3C441D-DF9D-407b-917D-0B4471A8296C}.Fzw= = Assembly.GetExecutingAssembly().GetModules()[0].ModuleHandle;
    }

    // Token: 0x060000B4 RID: 180 RVA: 0x000079A8 File Offset: 0x00005BA8
    [Obfuscation]
    public static void dau(int proxyDelegateTypeToken)
    {
        Type typeFromHandle;
        try
        {
            typeFromHandle = Type.GetTypeFromHandle({FE3C441D-DF9D-407b-917D-0B4471A8296C}.Fzw=.ResolveTypeHandle(33554433 + proxyDelegateTypeToken));
        }
        catch
        {
            return;
        }
        FieldInfo[] fields = typeFromHandle.GetFields(BindingFlags.Static | BindingFlags.NonPublic | BindingFlags.GetField);
        int i = 0;
        while (i < fields.Length)
        {
            FieldInfo fieldInfo = fields[i];
            string text = fieldInfo.Name;
            bool flag = false;
            if (text.EndsWith("%"))
            {
                flag = true;
                text = text.TrimEnd(new char[]
                {
                    '%'
                });
            }
            byte[] value = Convert.FromBase64String(text);
            uint num = BitConverter.ToUInt32(value, 0);
            MethodInfo methodInfo;
            try
            {
                methodInfo = (MethodInfo)MethodBase.GetMethodFromHandle({FE3C441D-DF9D-407b-917D-0B4471A8296C}.Fzw=.ResolveMethodHandle((int)(num + 167772161u)));
            }
            catch
            {
                goto IL_1D1;
            }
            goto IL_A7;
            IL_1D1:
            i++;
            continue;
            IL_A7:
            Delegate value2;
            if (methodInfo.IsStatic)
            {
                try
                {
                    value2 = Delegate.CreateDelegate(fieldInfo.FieldType, methodInfo);
                    goto IL_1C4;
                }
                catch (Exception)
                {
                    goto IL_1D1;
                }
            }
            ParameterInfo[] parameters = methodInfo.GetParameters();
            int num2 = parameters.Length + 1;
            Type[] array = new Type[num2];
            array[0] = typeof(object);
            for (int j = 1; j < num2; j++)
            {
                array[j] = parameters[j - 1].ParameterType;
            }
            DynamicMethod dynamicMethod = new DynamicMethod(string.Empty, methodInfo.ReturnType, array, typeFromHandle, true);
            ILGenerator ilgenerator = dynamicMethod.GetILGenerator();
            ilgenerator.Emit(OpCodes.Ldarg_0);
            if (num2 > 1)
            {
                ilgenerator.Emit(OpCodes.Ldarg_1);
            }
            if (num2 > 2)
            {
                ilgenerator.Emit(OpCodes.Ldarg_2);
            }
            if (num2 > 3)
            {
                ilgenerator.Emit(OpCodes.Ldarg_3);
            }
            if (num2 > 4)
            {
                for (int k = 4; k < num2; k++)
                {
                    ilgenerator.Emit(OpCodes.Ldarg_S, k);
                }
            }
            ilgenerator.Emit(flag ? OpCodes.Callvirt : OpCodes.Call, methodInfo);
            ilgenerator.Emit(OpCodes.Ret);
            try
            {
                value2 = dynamicMethod.CreateDelegate(typeFromHandle);
            }
            catch (Exception)
            {
                goto IL_1D1;
            }
            try
            {
                IL_1C4:
                fieldInfo.SetValue(null, value2);
            }
            catch
            {
            }
            goto IL_1D1;
        }
    }

    // Token: 0x060000B5 RID: 181 RVA: 0x00007BD8 File Offset: 0x00005DD8
    public {FE3C441D-DF9D-407b-917D-0B4471A8296C}()
    {
    }
}
```

This piece of code is relatively simple. It takes in a token representing a proxy type and then iterates through each field in the type, getting the MemberRef Token for the proxy method via its name and then resolving it using ResolveMethod(). If it's a static method, a delegate is created directly; if it's an instance method, a DynamicMethod is used to create a method to be invoked. Static decryption may still be simpler than dynamic decryption.

### Write a Decryption Tool

We will still write a framework like this and add the code to ExecuteImpl().

![Proxy call decrypter](/../net-dynamic-decryption-and-countermeasures/proxy-call-decrypter.png)

Based on the feature, we find where the proxy fields are initialized.

``` csharp
TypeDef[] globalTypes;
MethodDef decryptor;

globalTypes = _moduleDef.Types.Where(t => t.Namespace == string.Empty).ToArray();
// Find all types with an empty namespace
decryptor = globalTypes.Where(t => t.Name.StartsWith("{", StringComparison.Ordinal) && t.Name.EndsWith("}", StringComparison.Ordinal)).Single().Methods.Single(m => !m.IsInstanceConstructor && m.Parameters.Count == 1);
// Find proxy call decryption method
```

Because the static constructors of all proxy classes automatically decrypt the real methods, we do not need to manually call the proxy method decrypters. We only need to iterate through the fields of these proxy classes and find the corresponding MemberRef for the field.

``` csharp
foreach (TypeDef typeDef in globalTypes) {
    MethodDef cctor;

    cctor = typeDef.FindStaticConstructor();
    if (cctor == null || !cctor.Body.Instructions.Any(i => i.OpCode == OpCodes.Call && i.Operand == decryptor))
        continue;
    // Find the type that invokes the proxy call decryption method in its static constructor.
}
```

If a class static constructor calls decryptor, it means that this class is a proxy class. We iterate through the fields of the proxy class.

``` csharp
foreach (FieldInfo fieldInfo in _module.ResolveType(typeDef.MDToken.ToInt32()).GetFields(BindingFlags.NonPublic | BindingFlags.Static)) {
    int proxyFieldToken;
    FieldDef proxyFieldDef;
    MethodBase realMethod;

    proxyFieldToken = fieldInfo.MetadataToken;
    proxyFieldDef = _moduleDef.ResolveField((uint)proxyFieldToken - 0x04000000);
    realMethod = ((Delegate)fieldInfo.GetValue(null)).Method;
}
```

The realMethod here may also be a dynamic method created by Agile.NET runtime because it supports the callvirt instruction. We write a method to determine whether it is a dynamic method.

``` csharp
private static bool IsDynamicMethod(MethodBase methodBase) {
    if (methodBase == null)
        throw new ArgumentNullException(nameof(methodBase));

    try {
        int token;

        token = methodBase.MetadataToken;
        // Getting the token for a DynamicMethod will throw an InvalidOperationException exception.
    }
    catch (InvalidOperationException) {
        return true;
    }
    return false;
}
```

We first check if it's a dynamic method before replacing it.

``` csharp
if (IsDynamicMethod(realMethod)) {
    DynamicMethodBodyReader dynamicMethodBodyReader;
    IList<Instruction> instructionList;

    dynamicMethodBodyReader = new DynamicMethodBodyReader(_moduleDef, realMethod);
    dynamicMethodBodyReader.Read();
    instructionList = dynamicMethodBodyReader.GetMethod().Body.Instructions;
    ReplaceAllOperand(proxyFieldDef, instructionList[instructionList.Count - 2].OpCode, (MemberRef)instructionList[instructionList.Count - 2].Operand);
}
else
    ReplaceAllOperand(proxyFieldDef, realMethod.IsVirtual ? OpCodes.Callvirt : OpCodes.Call, (MemberRef)_moduleDef.Import(realMethod));
```

The implementation of ReplaceAllOperand is as follows.

``` csharp
private void ReplaceAllOperand(FieldDef proxyFieldDef, OpCode callOrCallvirt, MemberRef realMethod) {
    if (proxyFieldDef == null)
        throw new ArgumentNullException(nameof(proxyFieldDef));
    if (realMethod == null)
        throw new ArgumentNullException(nameof(realMethod));

    foreach (MethodDef methodDef in _moduleDef.EnumerateAllMethodDefs()) {
        IList<Instruction> instructionList;

        if (!methodDef.HasBody)
            continue;
        // Only iterate through methods with CilBody.
        instructionList = methodDef.Body.Instructions;
        for (int i = 0; i < instructionList.Count; i++) {
            // ldsfld    class xxx xxx::'xxx'
            // ...
            // call      instance void xxx::Invoke()
            if (instructionList[i].OpCode != OpCodes.Ldsfld || instructionList[i].Operand != proxyFieldDef)
                continue;
            for (int j = i; j < instructionList.Count; j++) {
                // Starting from i, find the closest call.
                if (instructionList[j].OpCode.Code != Code.Call || !(instructionList[j].Operand is MethodDef) || ((MethodDef)instructionList[j].Operand).DeclaringType != ((TypeDefOrRefSig)proxyFieldDef.FieldType).TypeDefOrRef)
                    continue;
                instructionList[i].OpCode = OpCodes.Nop;
                instructionList[i].Operand = null;
                // Clear ldsfld    class xxx xxx::'xxx'
                instructionList[j].OpCode = callOrCallvirt;
                instructionList[j].Operand = realMethod;
                // Replace call      instance void xxx::Invoke()
                break;
            }
        }
    }
}
```

## ConfuserEx's AntiTamper

### Analysis

Some time ago, I posted a post about AntiTamper. That post was about static decryption, and there seemed to be some compatibility issues. This time, let's try dynamic decryption. First, let’s open the ConfuserEx project.

![ConfuserEx's AntiTamper 1](/../net-dynamic-decryption-and-countermeasures/confuserex-antitamper-1.png)

![ConfuserEx's AntiTamper 2](/../net-dynamic-decryption-and-countermeasures/confuserex-antitamper-2.png)

This is what I commented on before: The principle of AntiTamper is to put all method bodies in a separate section and use the hash of other sections for decryption. Therefore, if the file itself has been tampered with, the runtime decryption of the section will definitely fail. This section is always inserted by ConfuserEx before other sections and can be considered encrypted as a whole, so dynamic decryption will be very easy.

### Write a Decryption Tool

Still, we write a framework like before and put the code in ExecuteImpl().

We add a PEInfo class.

``` csharp
[StructLayout(LayoutKind.Sequential, Pack = 1)]
internal unsafe struct IMAGE_SECTION_HEADER {
    public static uint UnmanagedSize = (uint)sizeof(IMAGE_SECTION_HEADER);

    public fixed byte Name[8];
    public uint VirtualSize;
    public uint VirtualAddress;
    public uint SizeOfRawData;
    public uint PointerToRawData;
    public uint PointerToRelocations;
    public uint PointerToLinenumbers;
    public ushort NumberOfRelocations;
    public ushort NumberOfLinenumbers;
    public uint Characteristics;
}

internal sealed unsafe class PEInfo {
    private readonly void* _pPEImage;
    private readonly uint _sectionsCount;
    private readonly IMAGE_SECTION_HEADER* pSectionHeaders;

    public void* PEImage => _pPEImage;

    public uint SectionsCount => _sectionsCount;

    public IMAGE_SECTION_HEADER* SectionHeaders => pSectionHeaders;

    public PEInfo(void* pPEImage) {
        byte* p;
        ushort optionalHeaderSize;

        _pPEImage = pPEImage;
        p = (byte*)pPEImage;
        p += *(uint*)(p + 0x3C);
        // NtHeader
        p += 4 + 2;
        // Skip Signature + Machine
        _sectionsCount = *(ushort*)p;
        p += 2 + 4 + 4 + 4;
        // Skip NumberOfSections + TimeDateStamp + PointerToSymbolTable + NumberOfSymbols
        optionalHeaderSize = *(ushort*)p;
        p += 2 + 2;
        // Skip SizeOfOptionalHeader + Characteristics
        p += optionalHeaderSize;
        // Skip OptionalHeader
        pSectionHeaders = (IMAGE_SECTION_HEADER*)p;
    }
}
```

Then, we read the RVA and Size of the first Section. Call the module's static constructor, and finally restore it back.

``` csharp
PEInfo peInfo;
IMAGE_SECTION_HEADER sectionHeader;
byte[] section;

peInfo = new PEInfo((void*)Marshal.GetHINSTANCE(_module));
sectionHeader = peInfo.SectionHeaders[0];
section = new byte[sectionHeader.SizeOfRawData];
RuntimeHelpers.RunModuleConstructor(_module.ModuleHandle);
Marshal.Copy((IntPtr)((byte*)peInfo.PEImage + sectionHeader.VirtualAddress), _peImage, (int)sectionHeader.PointerToRawData, (int)sectionHeader.SizeOfRawData);
```

_peImage here is a byte array that represents the program assembly to be decrypted in byte array form. Dynamic decryption of AntiTamper does not even require the use of dnlib, which is much more convenient than static decryption. After decryption, manually patch the runtime of AntiTamper.

## Anti Dynamic Decryption

Dynamic decryption also has its own disadvantages, such as being easily detected. The article describes three dynamic decryption methods, which are actually similar in principle, and the core is still the reflection API. We can use this to write some anti dynamic decryption code.

- The simplest way is to check the calling source, like ILProtector. If the caller of the current method is the bottom-level Invoke method, then it indicates that it has been illegally called.
- We can go even further and check the entire call stack, such as whether there is a de4dot in the call stack.
- Get all loaded assemblies through AppDomain.CurrentDomain.GetAssemblies(), and determine if there are any illegal assemblies inside them.
- If a program is an executable file and will not be referenced by other assemblies, you can use Assembly.GetEntryAssembly() to check whether the entry assembly is itself. If it is not, it means that the current assembly has been loaded by another assembly using reflection API.
