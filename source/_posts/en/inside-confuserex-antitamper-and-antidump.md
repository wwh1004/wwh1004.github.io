---
title: Inside ConfuserEx's Anti-tamper and Anti-dumping
date: 2018-08-14
updated: 2023-04-11
lang: en
categories:
- [￫Translated, .NET Reverse Engineering]
tags:
- .NET
- Reverse Engineering
- Unpacking
- ConfuserEx
- Anti-tamper
- Anti-dumping
toc: true
hide: true
---

<article class="message message-immersive is-primary">
<div class="message-body">
<i class="fas fa-globe-americas mr-2"></i>This article is translated to English using GPT-3.5 and polished by the author. <a href="{% post_path inside-confuserex-antitamper-and-antidump %}">This is the original post.</a>
</div>
</article>

<!-- # Inside ConfuserEx's Anti-tamper and Anti-dumping -->

Many people know that using a series of tools such as dnSpy then dump, and CodeCracker's can be used to remove the ConfuserEx obfuscator. There are many tutorials available online, but there is no article explaining the underlying principles. This article will explain in detail the Anti Tamper and Anti Dump protections of ConfuserEx.

<!-- more -->

**(Patient and know a little PE structure can fully understand)**

## ConfuserEx Project Structure

Before we begin, let's take a look at the structure of the ConfuserEx project.

Open ConfuserEx in Visual Studio and the project looks like this:

![ConfuserEx hierarchy](/../inside-confuserex-antitamper-and-antidump/confuserex-hierarchy.png)

- Confuser.CLI is the command-line version, similar to the operation mode of de4dot.
- Confuser.Core is the core that combines all parts of the Protection together.
- Confuser.DynCipher can dynamically generate encryption algorithms.
- Confuser.Protections contains all Protections and is the part that needs to be researched.
- Confuser.Renamer can rename class names, method names, etc., including multiple renaming methods, such as reversible renaming, which is not displayed in ConfuserEx's GUI.
- Confuser.Runtime is the runtime, such as the implementation of Anti Dump, which is actually in this project. As mentioned above, Confuser.Protections injects the implementation of Anti Dump from Confuser.Runtime into the target assembly.
- ConfuserEx is the GUI, needless to say.

**The entire project has almost no comments, and the comments below are added by me.**

## Anti Dump

Anti Dump is much simpler than Anti Tamper, so let's first understand Anti Dump.

The implementation of Anti Dump has only one method and is very concise.

We can find AntiDumpProtection.cs in the Confuser.Protections project.

![AntiDumpProtection.cs](/../inside-confuserex-antitamper-and-antidump/antidumpprotection_cs.png)

``` csharp
protected override void Execute(ConfuserContext context, ProtectionParameters parameters) {
    TypeDef rtType = context.Registry.GetService<IRuntimeService>().GetRuntimeType("Confuser.Runtime.AntiDump");
    // Get the AntiDump class from the Confuser.Runtime project.

    var marker = context.Registry.GetService<IMarkerService>();
    var name = context.Registry.GetService<INameService>();

    foreach (ModuleDef module in parameters.Targets.OfType<ModuleDef>()) {
        IEnumerable<IDnlibDef> members = InjectHelper.Inject(rtType, module.GlobalType, module);
        // Inject the Confuser.Runtime.AntiDump class into the target assembly and return all definitions of type IDnlibDef in the target assembly.

        MethodDef cctor = module.GlobalType.FindStaticConstructor();
        // Find <Module>::.cctor.
        var init = (MethodDef)members.Single(method => method.Name == "Initialize");
        cctor.Body.Instructions.Insert(0, Instruction.Create(OpCodes.Call, init));
        // Insert the IL instruction "call void Confuser.Runtime.AntiDump::Initialize()" in the static constructor.

        foreach (IDnlibDef member in members)
            name.MarkHelper(member, marker, (Protection)Parent);
        // Mark these IDnlibDef types as requiring renaming.
    }
}
```

AntiDumpProtection only performs injection, so we need to switch to AntiDump.cs in the Confuser.Runtime folder.

![AntiDump.cs](/../inside-confuserex-antitamper-and-antidump/antidump_cs.png)

``` csharp
static unsafe void Initialize() {
    uint old;
    Module module = typeof(AntiDump).Module;
    var bas = (byte*)Marshal.GetHINSTANCE(module);
    byte* ptr = bas + 0x3c;
    // NT headers offset
    byte* ptr2;
    ptr = ptr2 = bas + *(uint*)ptr;
    // ptr points to NT headers
    ptr += 0x6;
    // ptr points to file header's NumberOfSections
    ushort sectNum = *(ushort*)ptr;
    // Get section count
    ptr += 14;
    // ptr points to file header's SizeOfOptionalHeader
    ushort optSize = *(ushort*)ptr;
    // Get optional header size
    ptr = ptr2 = ptr + 0x4 + optSize;
    // ptr points to the first section

    byte* @new = stackalloc byte[11];
    if (module.FullyQualifiedName[0] != '<') //Mapped
    {
        // Check if the module is loaded in memory, such as by using "Assembly.Load(byte[] rawAssembly)".
        // If it is, then "module.FullyQualifiedName[0]" will return "<unknown>".
        //VirtualProtect(ptr - 16, 8, 0x40, out old);
        //*(uint*)(ptr - 12) = 0;
        byte* mdDir = bas + *(uint*)(ptr - 16);
        // ptr points to IMAGE_COR20_HEADER
        //*(uint*)(ptr - 16) = 0;

        if (*(uint*)(ptr - 0x78) != 0) {
            // If import directory RVA is not zero
            byte* importDir = bas + *(uint*)(ptr - 0x78);
            byte* oftMod = bas + *(uint*)importDir;
            // OriginalFirstThunk
            byte* modName = bas + *(uint*)(importDir + 12);
            // Import dll name
            byte* funcName = bas + *(uint*)oftMod + 2;
            // Import function name
            VirtualProtect(modName, 11, 0x40, out old);

            *(uint*)@new = 0x6c64746e;
            *((uint*)@new + 1) = 0x6c642e6c;
            *((ushort*)@new + 4) = 0x006c;
            *(@new + 10) = 0;
            // ntdll.dll

            for (int i = 0; i < 11; i++)
                *(modName + i) = *(@new + i);
            // Overwrite mscoree.dll to ntdll.dll

            VirtualProtect(funcName, 11, 0x40, out old);

            *(uint*)@new = 0x6f43744e;
            *((uint*)@new + 1) = 0x6e69746e;
            *((ushort*)@new + 4) = 0x6575;
            *(@new + 10) = 0;
            // NtContinue

            for (int i = 0; i < 11; i++)
                *(funcName + i) = *(@new + i);
            // Overwrite _CorExeMain to NtContinue
        }

        for (int i = 0; i < sectNum; i++) {
            VirtualProtect(ptr, 8, 0x40, out old);
            Marshal.Copy(new byte[8], 0, (IntPtr)ptr, 8);
            ptr += 0x28;
        }
        // Zero all section names
        VirtualProtect(mdDir, 0x48, 0x40, out old);
        byte* mdHdr = bas + *(uint*)(mdDir + 8);
        // mdHdr points to STORAGESIGNATURE(begin with BSJB)
        *(uint*)mdDir = 0;
        *((uint*)mdDir + 1) = 0;
        *((uint*)mdDir + 2) = 0;
        *((uint*)mdDir + 3) = 0;
        // Zero IMAGE_COR20_HEADER's cb, MajorRuntimeVersion, MinorRuntimeVersion and MetaData

        VirtualProtect(mdHdr, 4, 0x40, out old);
        *(uint*)mdHdr = 0;
        // Zero BSJB flag then we can't search STORAGESIGNATURE
        mdHdr += 12;
        // mdHdr points to iVersionString
        mdHdr += *(uint*)mdHdr;
        mdHdr = (byte*)(((ulong)mdHdr + 7) & ~3UL);
        mdHdr += 2;
        // mdHdr points to STORAGEHEADER's iStreams
        ushort numOfStream = *mdHdr;
        // Get metadata stream count
        mdHdr += 2;
        // mdHdr points to the first metadata stream header
        for (int i = 0; i < numOfStream; i++) {
            VirtualProtect(mdHdr, 8, 0x40, out old);
            //*(uint*)mdHdr = 0;
            mdHdr += 4;
            // mdHdr points to STORAGESTREAM.iSize
            //*(uint*)mdHdr = 0;
            mdHdr += 4;
            // mdHdr points to STORAGESTREAM.rcName
            for (int ii = 0; ii < 8; ii++) {
                VirtualProtect(mdHdr, 4, 0x40, out old);
                *mdHdr = 0;
                mdHdr++;
                if (*mdHdr == 0) {
                    mdHdr += 3;
                    break;
                }
                *mdHdr = 0;
                mdHdr++;
                if (*mdHdr == 0) {
                    mdHdr += 2;
                    break;
                }
                *mdHdr = 0;
                mdHdr++;
                if (*mdHdr == 0) {
                    mdHdr += 1;
                    break;
                }
                *mdHdr = 0;
                mdHdr++;
            }
            // Zero STORAGESTREAM.rcName. Because this is 4-byte aligned, the code is longer.
        }
    }
    else //Flat
    {
        // Here is the case of in-memory assembly, and the above is similar, I will not be specific analysis.
        //VirtualProtect(ptr - 16, 8, 0x40, out old);
        //*(uint*)(ptr - 12) = 0;
        uint mdDir = *(uint*)(ptr - 16);
        //*(uint*)(ptr - 16) = 0;
        uint importDir = *(uint*)(ptr - 0x78);

        var vAdrs = new uint[sectNum];
        var vSizes = new uint[sectNum];
        var rAdrs = new uint[sectNum];
        for (int i = 0; i < sectNum; i++) {
            VirtualProtect(ptr, 8, 0x40, out old);
            Marshal.Copy(new byte[8], 0, (IntPtr)ptr, 8);
            vAdrs[i] = *(uint*)(ptr + 12);
            vSizes[i] = *(uint*)(ptr + 8);
            rAdrs[i] = *(uint*)(ptr + 20);
            ptr += 0x28;
        }


        if (importDir != 0) {
            for (int i = 0; i < sectNum; i++)
                if (vAdrs[i] <= importDir && importDir < vAdrs[i] + vSizes[i]) {
                    importDir = importDir - vAdrs[i] + rAdrs[i];
                    break;
                }
            byte* importDirPtr = bas + importDir;
            uint oftMod = *(uint*)importDirPtr;
            for (int i = 0; i < sectNum; i++)
                if (vAdrs[i] <= oftMod && oftMod < vAdrs[i] + vSizes[i]) {
                    oftMod = oftMod - vAdrs[i] + rAdrs[i];
                    break;
                }
            byte* oftModPtr = bas + oftMod;
            uint modName = *(uint*)(importDirPtr + 12);
            for (int i = 0; i < sectNum; i++)
                if (vAdrs[i] <= modName && modName < vAdrs[i] + vSizes[i]) {
                    modName = modName - vAdrs[i] + rAdrs[i];
                    break;
                }
            uint funcName = *(uint*)oftModPtr + 2;
            for (int i = 0; i < sectNum; i++)
                if (vAdrs[i] <= funcName && funcName < vAdrs[i] + vSizes[i]) {
                    funcName = funcName - vAdrs[i] + rAdrs[i];
                    break;
                }
            VirtualProtect(bas + modName, 11, 0x40, out old);

            *(uint*)@new = 0x6c64746e;
            *((uint*)@new + 1) = 0x6c642e6c;
            *((ushort*)@new + 4) = 0x006c;
            *(@new + 10) = 0;

            for (int i = 0; i < 11; i++)
                *(bas + modName + i) = *(@new + i);

            VirtualProtect(bas + funcName, 11, 0x40, out old);

            *(uint*)@new = 0x6f43744e;
            *((uint*)@new + 1) = 0x6e69746e;
            *((ushort*)@new + 4) = 0x6575;
            *(@new + 10) = 0;

            for (int i = 0; i < 11; i++)
                *(bas + funcName + i) = *(@new + i);
        }


        for (int i = 0; i < sectNum; i++)
            if (vAdrs[i] <= mdDir && mdDir < vAdrs[i] + vSizes[i]) {
                mdDir = mdDir - vAdrs[i] + rAdrs[i];
                break;
            }
        byte* mdDirPtr = bas + mdDir;
        VirtualProtect(mdDirPtr, 0x48, 0x40, out old);
        uint mdHdr = *(uint*)(mdDirPtr + 8);
        for (int i = 0; i < sectNum; i++)
            if (vAdrs[i] <= mdHdr && mdHdr < vAdrs[i] + vSizes[i]) {
                mdHdr = mdHdr - vAdrs[i] + rAdrs[i];
                break;
            }
        *(uint*)mdDirPtr = 0;
        *((uint*)mdDirPtr + 1) = 0;
        *((uint*)mdDirPtr + 2) = 0;
        *((uint*)mdDirPtr + 3) = 0;


        byte* mdHdrPtr = bas + mdHdr;
        VirtualProtect(mdHdrPtr, 4, 0x40, out old);
        *(uint*)mdHdrPtr = 0;
        mdHdrPtr += 12;
        mdHdrPtr += *(uint*)mdHdrPtr;
        mdHdrPtr = (byte*)(((ulong)mdHdrPtr + 7) & ~3UL);
        mdHdrPtr += 2;
        ushort numOfStream = *mdHdrPtr;
        mdHdrPtr += 2;
        for (int i = 0; i < numOfStream; i++) {
            VirtualProtect(mdHdrPtr, 8, 0x40, out old);
            //*(uint*)mdHdrPtr = 0;
            mdHdrPtr += 4;
            //*(uint*)mdHdrPtr = 0;
            mdHdrPtr += 4;
            for (int ii = 0; ii < 8; ii++) {
                VirtualProtect(mdHdrPtr, 4, 0x40, out old);
                *mdHdrPtr = 0;
                mdHdrPtr++;
                if (*mdHdrPtr == 0) {
                    mdHdrPtr += 3;
                    break;
                }
                *mdHdrPtr = 0;
                mdHdrPtr++;
                if (*mdHdrPtr == 0) {
                    mdHdrPtr += 2;
                    break;
                }
                *mdHdrPtr = 0;
                mdHdrPtr++;
                if (*mdHdrPtr == 0) {
                    mdHdrPtr += 1;
                    break;
                }
                *mdHdrPtr = 0;
                mdHdrPtr++;
            }
        }
    }
}
```

The modification of the import table is actually optional and reversible. Zeroing section names is also optional.

One very important thing is to zero the IMAGE_COR20_HEADER.MetaData. The CLR has already located the metadata and saved the data (which can be verified by searching the memory using CE, searching for ImageBase+MetaData.VirtualAddress). This field is no longer needed, so it can be zeroed. However, we still need this field when reading the metadata.

Next, Anti Dump will remove the BSJB flag, so STORAGESIGNATURE cannot be searched. Also, the rcName field in the metadata stream header should be cleared, which will prevent us from locating the metadata structure. But the CLR no longer needs these things.

The solution to this problem is simple: nop out the instruction "call void Confuser.Runtime.AntiDump::Initialize()" in &lt;Module&gt;::.cctor(). How do we locate this instruction?

There is a clever way to do this. After solving Anti Tamper, in dnSpy, find the method that contains this code:

``` csharp
Module module = typeof(AntiDump).Module;
byte* bas = (byte*)Marshal.GetHINSTANCE(module);
......
if (module.FullyQualifiedName[0] != '<'){
}
```

and this method also calls VirtualProtect multiple times. Original ConfuserEx called it 14 times.

Nop out the place where this method is called, switch to IL display mode, and click on the FileOffset where the IL is located. Use a hexadecimal editor to change it to 0, otherwise there may be problems.

## Anti Tamper

**Anti Tamper is a bit more complicated. If you don't understand it, try it in the ConfuserEx project!!!!!!**

### Analysis

ConfuserEx has two AntiTamper modes: Hook JIT and in-place decryption. Hook JIT is a half-baked feature and cannot be used normally, so what we actually see is the in-place decryption mode, which is not very strong.

We go to AntiTamper\NormalMode.cs in the Confuser.Protections project.

![NormalMode.cs](/../inside-confuserex-antitamper-and-antidump/normalmode_cs.png)

I won't comment on this part because it's also an injector, similar to AntiDumpProtection.cs. If you don't understand it, it doesn't matter. You will understand it when I analyze the actual implementation later.

Find the implementation of AntiTamper in AntiTamper.Normal.cs.

![AntiTamper.Normal.cs](/../inside-confuserex-antitamper-and-antidump/antitamper_normal_cs.png)

``` csharp
static unsafe void Initialize() {
    Module m = typeof(AntiTamperNormal).Module;
    string n = m.FullyQualifiedName;
    bool f = n.Length > 0 && n[0] == '<';
    // f is true, indicating that this is an in-memory assembly.
    var b = (byte*)Marshal.GetHINSTANCE(m);
    byte* p = b + *(uint*)(b + 0x3c);
    // pNtHeader
    ushort s = *(ushort*)(p + 0x6);
    // Machine
    ushort o = *(ushort*)(p + 0x14);
    // SizeOfOptHdr

    uint* e = null;
    uint l = 0;
    var r = (uint*)(p + 0x18 + o);
    // pFirstSectHdr
    uint z = (uint)Mutation.KeyI1, x = (uint)Mutation.KeyI2, c = (uint)Mutation.KeyI3, v = (uint)Mutation.KeyI4;
    for (int i = 0; i < s; i++) {
        uint g = (*r++) * (*r++);
        // SectionHeader.Name => nameHash
        // At this point, r points to SectionHeader.VirtualSize.
        if (g == (uint)Mutation.KeyI0) {
            // See Confuser.Protections.AntiTamper.NormalMode.
            // Here, Mutation.KeyI0 is nameHash.
            // The purpose of this "if" statement is to determine whether the current section is the one where ConfuserEx stores the encrypted method bodies.
            e = (uint*)(b + (f ? *(r + 3) : *(r + 1)));
            // If f is true, e points to the content pointed to by RawAddress, otherwise it points to the content pointed to by VirtualAddress.
            l = (f ? *(r + 2) : *(r + 0)) >> 2;
            // If f is true, l equals RawSize >> 2, otherwise it equals VirtualSize >> 2.
            // Don't care why it's shifted right by 2, we will shift it back left by 2 later on.
        }
        else if (g != 0) {
            var q = (uint*)(b + (f ? *(r + 3) : *(r + 1)));
            // If f is true, q points to the content pointed to by RawAddress, otherwise it points to the content pointed to by VirtualAddress.
            uint j = *(r + 2) >> 2;
            // l equals VirtualSize >> 2
            for (uint k = 0; k < j; k++) {
                // For example, if VirtualSize is 0x200, this loop will execute 0x20 times.
                uint t = (z ^ (*q++)) + x + c * v;
                z = x;
                x = c;
                x = v;
                v = t;
                // The encryption operation itself does not require analysis.
            }
        }
        r += 8;
        // In order to ensure that r still points to the beginning of SectionHeader during the next iteration
    }

    uint[] y = new uint[0x10], d = new uint[0x10];
    for (int i = 0; i < 0x10; i++) {
        y[i] = v;
        d[i] = x;
        z = (x >> 5) | (x << 27);
        x = (c >> 3) | (c << 29);
        c = (v >> 7) | (v << 25);
        v = (z >> 11) | (z << 21);
    }
    // The encryption operation itself does not require analysis.
    Mutation.Crypt(y, d);
    // Here, ConfuserEx replaces the original encryption algorithm with a real one, which looks something like this:
    // data[0] = data[0] ^ key[0];
    // data[1] = data[1] * key[1];
    // data[2] = data[2] + key[2];
    // data[3] = data[3] ^ key[3];
    // data[4] = data[4] * key[4];
    // data[5] = data[5] + key[5];
    // And so on in a loop.

    uint w = 0x40;
    VirtualProtect((IntPtr)e, l << 2, w, out w);

    if (w == 0x40)
        // This is to prevent duplicate decryption and data corruption caused by repeated decryption.
        return;

    uint h = 0;
    for (uint i = 0; i < l; i++) {
        *e ^= y[h & 0xf];
        y[h & 0xf] = (y[h & 0xf] ^ (*e++)) + 0x3dbb2819;
        h++;
    }
}
```

Above is my commentary. The actual decryption code is located at the end of the document "*e ^= y[h & 0xf];", while the large block of code preceding it calculates the key and the position of the data to be decrypted.

Why can it be decrypted? Because xor two identical values twice is equivalent to xor 0, such as 123 ^ 456 ^ 456 == 123.

So what exactly does this code decrypt?

Let's first understand the Method table in the metadata table.

![dnSpy-Method-RVA](/../inside-confuserex-antitamper-and-antidump/dnspy-method-rva.png)

I have marked with a red box the RVA that points to the data of the method body. The method body stores ILHeader, ILCode, LocalVar, and EH.

ConfuserEx will modify the RVA to point to another red box "Chapter #0: Garbled Text". This section specifically stores the method body (if the module's static constructor and Anti Tamper's own method body were also stored in this section, the program would not be able to run).

ConfuserEx encrypts the contents of this section. Because the module's static constructor executes before the program entry point, the first IL instruction of the module's static constructor is call void AntiTamper::Initialize().

This IL instruction is executed first when the program runs. All other methods are then decrypted, and the program can run normally.

This method has much better compatibility than Hook JIT, and it is almost impossible to encounter problems that prevent it from running. However, its strength is far inferior to Hook JIT.

### AntiTamperKiller artifact

We have just finished analyzing Anti Tamper. If you understood it, you could write a static unpacker for Anti Tamper (dnSpy Dump method may damage data, and static unpacking only decrypts one section of data).

Download link for Anti Tamper unpacker: [AntiTamperKiller.7z](/../inside-confuserex-antitamper-and-antidump/AntiTamperKiller.7z)

Use it the same way you use de4dot. It supports ConfuserEx's maximum protection.
