---
title: .NET Trick to Bypass Any Anti-dumping
date: 2022-03-16
updated: 2023-04-12
lang: en
categories:
- [￫Translated, .NET Reverse Engineering]
tags:
- .NET
- Reverse Engineering
- Anti-dumping
toc: true
hide: true
---

<article class="message message-immersive is-primary">
<div class="message-body">
<i class="fas fa-globe-americas mr-2"></i>This article is translated to English using GPT-3.5 and polished by the author. <a href="{% post_path net-trick-to-bypass-any-anti-dumping %}">This is the original post.</a>
</div>
</article>

<!-- # .NET Trick to Bypass Any Anti-dumping -->

This article introduces a method for bypassing any anti-dumping techniques in CLR by utilizing internal data. This method is currently effective for all versions (.NET Framework from 2.0 to .NET 7.0), and theoretically can be used for future versions as well.

<!-- more -->

## Introduction

Anti-dumping methods in .NET are relatively simple, mainly consisting of erasing the .NET section in the PE header after running. Since CLR has already stored the offsets and sizes of all .NET metadata when loading the assembly, erasing this part of the .NET headers has no impact on the program's execution. However, if we directly dump the assembly from memory, the resulting file cannot be read by tools such as dnSpy or ILSpy since the .NET headers has been erased. By using CLR's internal objects, we can read the .NET metadata information and calculate the .NET section in the PE header. This article will explain how to achieve the goal of bypassing any anti-Dump techniques by utilizing this method.

**Before we begin, it must be clear that bypassing anti-dumping does not mean that the dumped file can be directly run and used! The purpose of bypassing anti-dumping is to restore the necessary information and allow tools such as dnSpy and ILSpy to decompile the .NET assembly quickly, rather than restoring the original .NET headers without losing any information! If you want to unpack a file, you cannot rely on this method!**

**The CLR source code used in this article comes from CoreCLR v1.0**

## The Idea of Restoring the .NET Headers

As mentioned in the introduction, necessary information can be obtained by reading CLR's internal objects in order to restore the .NET headers. Therefore, we need to understand the .NET section in the PE header and the parts that can be erased by anti-Dump techniques.

Firstly, the .NET metadata directory in Data Directories is recorded, which consists of the offset and size of the .NET directory (IMAGE_COR20_HEADER). Generally, the offset is 0x2008, which is the eighth byte in the .text section, as determined by C# and VB.NET compilers. The size is sizeof(IMAGE_COR20_HEADER), which is a fixed value of 0x48.

![](/../net-trick-to-bypass-any-anti-dumping/1.png)

The .NET Directory in CFF Explorer is IMAGE_COR20_HEADER.

![](/../net-trick-to-bypass-any-anti-dumping/2.png)

Through the previous step of analysis, we can obtain the location of IMAGE_COR20_HEADER. The definition of IMAGE_COR20_HEADER is shown below, with important parts annotated.

``` cpp
typedef struct IMAGE_COR20_HEADER
{
    DWORD                   cb;                  // sizeof(IMAGE_COR20_HEADER)
    WORD                    MajorRuntimeVersion;
    WORD                    MinorRuntimeVersion;
    IMAGE_DATA_DIRECTORY    MetaData;            // .NET Metadata
    DWORD                   Flags;               // Flags indicating the type of assembly, such as whether it is executable or pure IL
    union {
        DWORD               EntryPointToken;     // Metadata token of Main method
        DWORD               EntryPointRVA;       // RVA of the entry point (if the entry point is native code)
    } DUMMYUNIONNAME;
    IMAGE_DATA_DIRECTORY    Resources;           // .NET resources
    IMAGE_DATA_DIRECTORY    StrongNameSignature; // .NET strong name
    IMAGE_DATA_DIRECTORY    CodeManagerTable;
    IMAGE_DATA_DIRECTORY    VTableFixups;
    IMAGE_DATA_DIRECTORY    ExportAddressTableJumps;
    IMAGE_DATA_DIRECTORY    ManagedNativeHeader;
} IMAGE_COR20_HEADER, *PIMAGE_COR20_HEADER;
```

Most of this structure can be cleared (I know that Resources cannot be cleared as IMAGE_COR20_HEADER::Resources needs to be read again every time resources are retrieved), but the necessary part is only the MetaData member, and other parts such as .NET resources are just additional items. **In order for the decompiler to display as much information as possible, we only need to restore the MetaData, EntryPointToken, and these three members of the .NET headers.**

Restoring the EntryPointToken and Resources is relatively simple, only requiring the restoration of the members in IMAGE_COR20_HEADER. However, restoring MetaData is more complex, as it requires restoring the .NET metadata header pointed to by MetaData. The first structure of the .NET metadata header is STORAGESIGNATURE, followed by STORAGEHEADER, and then an array of STORAGESTREAMs. Here are their displays in CFF Explorer and definitions in CLR.

In CFF Explorer, the MetaData Header is STORAGESIGNATURE + STORAGEHEADER, and the MetaData Streams are the following array of STORAGESTREAMs.

![](/../net-trick-to-bypass-any-anti-dumping/3.png)

![](/../net-trick-to-bypass-any-anti-dumping/4.png)

``` cpp
struct STORAGESIGNATURE
{
    ULONG       lSignature;             // "Magic" signature.
    USHORT      iMajorVer;              // Major file version.
    USHORT      iMinorVer;              // Minor file version.
    ULONG       iExtraData;             // Offset to next structure of information 
    ULONG       iVersionString;         // Length of version string
    BYTE        pVersion[0];            // Version string
};

struct STORAGEHEADER
{
    BYTE        fFlags;                 // STGHDR_xxx flags.
    BYTE        pad;
    USHORT      iStreams;               // How many streams are there.
};

struct STORAGESTREAM
{
    ULONG       iOffset;                // Offset in file for this stream.
    ULONG       iSize;                  // Size of the file.
    char        rcName[MAXSTREAMNAME];  // Start of name, null terminated.
};
```

The iVersionString member in STORAGESIGNATURE represents the actual length of pVersion, which means that the actual size of the STORAGESIGNATURE structure is sizeof(STORAGESIGNATURE) + iVersionString. The iStreams member in STORAGEHEADER represents the number of elements in the STORAGESTREAM array. Generally, iStreams is 5, and the five STORAGESTREAM structures correspond to the #&#126;, #Strings, #US, #GUID, and #Blob metadata streams respectively.

In anti-dumping, the lSignature member of STORAGESIGNATURE is always erased. Similar to "MZ" in the PE header, its value is always 0x424A5342, which is "BSJB". If this member is not erased, searching for the BSJB characteristic can easily locate the .NET metadata header and circumvent anti-dumping. Like the IMAGE_COR20_HEADER structure mentioned above, all members of these three structures can also be erased. When recovering, **we mainly focus on all three members of the STORAGESTREAM structure, which save the information pointing to the .NET metadata stream and the names corresponding to these metadata streams**. The other two structures are relatively unimportant and can be filled with preset values.

Among the five metadata streams #&#126;, #Strings, #US, #GUID, and #Blob mentioned above, #&#126; is a table stream that must exist. If the table stream is uncompressed, its name can also be #-, which is consistent with #&#126; in terms of metadata structure. The header of the table stream is the CMiniMdSchemaBase structure, which is displayed in CFF Explorer and defined in CLR.

![](/../net-trick-to-bypass-any-anti-dumping/5.png)

``` cpp
class CMiniMdSchemaBase
{
    ULONG       m_ulReserved;           // Reserved, must be zero.
    BYTE        m_major;                // Version numbers.
    BYTE        m_minor;
    BYTE        m_heaps;                // Bits for heap sizes.
    BYTE        m_rid;                  // log-base-2 of largest rid.
    unsigned __int64    m_maskvalid;    // Bit mask of present table counts.
    unsigned __int64    m_sorted;       // Bit mask of sorted tables.
};
```

After the CMiniMdSchemaBase structure, there is a UINT32 array immediately following it, and the length of the array is the number of bits set to 1 in the m_maskvalid member. The elements of this array represent the row count of each existing table in order.

When the CLR loads a .NET assembly, these members are all saved internally, so these members can also be erased. **When recovering, we mainly focus on which tables exist and what their row counts are. With this data, we can recover the m_maskvalid member and the row count array.**

## Key CLR Internal Objects

With the idea of recovering the .NET header, we can now start to understand the key CLR internal objects and use them to recover the .NET headers. This section will introduce the key CLR internal objects as a prelude. **I will omit many irrelevant parts of these CLR internal objects, and the definitions also differ slightly in different versions of the CLR, so the offset of the listed members in the structure is not necessarily fixed.** How to use them specifically will be explained in detail in the next section.

### Module

The Module class corresponds to the native object layout of System.Reflection.RuntimeModule in mscorlib and is defined in ceeload.h.

``` cpp
class Module
{
    PTR_CUTF8               m_pSimpleName;
    PTR_PEFile              m_file;
    MethodDesc              *m_pDllMain;
    Volatile<DWORD>          m_dwTransientFlags;
    Volatile<DWORD>          m_dwPersistedFlags;
    VASigCookieBlock        *m_pVASigCookieBlock;
    PTR_Assembly            m_pAssembly;
    mdFile                  m_moduleRef;
};
```

- m_pSimpleName is the module name, which is equal to assembly.Module.Assembly.GetName().Name in C# code. This member did not exist before .NET Framework 4.5.3.
- m_file is a pointer to the PEFile structure, which can be used to obtain information such as the module base address and size, and is very important.
- m_pDllMain is a pointer to the DllMain method and is only valid for assemblies generated by C++/CLI.
- m_pAssembly is a pointer to the Assembly structure, which is not needed here.

### PEFile

The PEFile class is the input of the CLR loader and represents an abstract PE file. Its subclasses are PEAssembly and PEModule. If it is loaded as an assembly, then a PEAssembly is created; if it is loaded as a module using the Assembly.LoadModule method, then a PEModule is created. In .NET Core, multi-module assembly features have been removed. Therefore, there is only PEAssembly and no PEModule in .NET Core.

PEFile has multiple loading modes:

1. HMODULE - PEFile is loaded in response to "spontaneous" system callbacks. This situation only occurs when the exe main module and IJW dll are loaded through LoadLibrary, or when static imports exist in unmanaged code.
2. Fusion loads - This is the most common situation. Get the path from Fusion and load PEFile through PEImage.
    1. Display name loads - These are metadata-based bindings.
    2. Path loads - Load from a complete absolute path
3. Byte arrays - Explicitly loaded by user code. This is also loaded through PEImage.
4. Dynamic - At this time, PEFile is not an actual PE image, but a placeholder for a reflective module.

``` cpp
class PEFile
{
    PTR_PEImage              m_identity;
    PTR_PEImage              m_openedILimage;
    PTR_PEImage              m_nativeImage;
    BOOL                     m_fCanUseNativeImage;
    BOOL                     m_MDImportIsRW_Debugger_Use_Only;
    Volatile<BOOL>           m_bHasPersistentMDImport;
    IMDInternalImport       *m_pMDImport;
    IMetaDataImport2        *m_pImporter;
    IMetaDataEmit           *m_pEmitter;
};
```

- m_identity is a pointer to the PEImage structure, used as an identifier. This member is generally not used and instead, m_openedILimage is used. In the GetILimage function of PEFile, if m_openedILimage is empty, the value of m_identity is assigned to m_openedILimage.
- m_openedILimage is a pointer to the PEImage structure, used as a provider of metadata. We use this member to retrieve information when recovering the .NET headers.
- m_nativeImage is a pointer to the PEImage structure used for scenarios such as NGEN. For example, pre-compiled modules created by NGEN, such as mscorlib.ni.dll, are loaded and saved to the m_nativeImage member.
- m_pMDImport is a pointer to the IMDInternalImport interface, which we can use to read some metadata information.

We do not need to be too concerned with the subclasses of PEFile, PEAssembly, and PEModule, as there is no useful information in them. By observing the members of PEFile, we can roughly assume that PEFile wraps around PEImage and encapsulates the results of loading .NET assemblies in various cases. CLR only needs to use the abstract IMDInternalImport interface to retrieve metadata and does not need to be concerned about the specific details of the PE image.

### PEImage

PEImage is a PE file loaded by CLR's "simulated LoadLibrary" mechanism. PEImage can be loaded as FLAT (the same layout as on disk) or MAPPED (PE sections mapped to virtual addresses).

``` cpp
class PEImage
{
    SString     m_path;
    LONG        m_refCount;
    SString     m_sModuleFileNameHintUsedByDac;
    BOOL        m_bIsTrustedNativeImage;
    BOOL        m_bIsNativeImageInstall;
    BOOL        m_bPassiveDomainOnly;
    SimpleRWLock *m_pLayoutLock;
    PTR_PEImageLayout m_pLayouts[IMAGE_COUNT];
    BOOL      m_bInHashMap;
    IMDInternalImport* m_pMDImport;
    IMDInternalImport* m_pNativeMDImport;
};
```

- m_path is the path of the PE image. If PEImage is loaded through a file, then m_path is the path of the file. If PEImage is loaded through memory, such as using Assembly.Load(byte[]) method, then m_path is empty.
- m_pLayouts saves an array of pointers to PEImageLayout. PEImageLayout provides specific layout information for the PE image, including module base address and module size. So m_pLayouts is a very important member.
- m_pMDImport is a pointer to the IMDInternalImport interface, which we can use to read some metadata information. This member can be considered the same as PEFile's m_pMDImport.

### PEImageLayout

PEImageLayout refers to the specific layout of the PE image, with subclasses such as MappedImageLayout, LoadedImageLayout, and FlatImageLayout. We do not need to be concerned with the members of the subclasses, as the important parts are in the base class PEImageLayout.

``` cpp
class PEDecoder
{
    TADDR               m_base;
    COUNT_T             m_size;
    ULONG               m_flags;
    PTR_IMAGE_NT_HEADERS   m_pNTHeaders;
    PTR_IMAGE_COR20_HEADER m_pCorHeader;
    PTR_CORCOMPILE_HEADER  m_pNativeHeader;
    PTR_READYTORUN_HEADER  m_pReadyToRunHeader;
};

class PEImageLayout : public PEDecoder
{
    Volatile<LONG> m_refCount;
    PEImage* m_pOwner;
    DWORD m_Layout;
};
```

- m_base is the module base address.
- m_size is the module size.
- m_pCorHeader is a pointer to the IMAGE_COR20_HEADER structure. This member can be used to recover the offset erased by anti-dumping protection.
- m_Layout indicates the current layout type, such as FLAT, MAPPED, or LOADED.

### MDInternalRO && MDInternalRW

These two classes are implementation classes of the internal CLR metadata interface IMDInternalImport. Obtaining a pointer to the IMDInternalImport interface means obtaining an instance of these two classes. Through these two classes, we can obtain all the information about the metadata table stream and heap stream.

``` cpp
class MDInternalRO : public IMDInternalImport, IMDCommon
{
    CLiteWeightStgdb<CMiniMd>   m_LiteWeightStgdb;
    CMethodSemanticsMap *m_pMethodSemanticsMap; // Possible array of method semantics pointers, ordered by method token.
    mdTypeDef           m_tdModule;         // <Module> typedef value.
    LONG                m_cRefs;            // Ref count.
};
```

- m_LiteWeightStgdb is a member that saves metadata information. We can use it to read metadata information and recover the .NET headers.

``` cpp
class MDInternalRW : public IMDInternalImportENC, public IMDCommon
{
    CLiteWeightStgdbRW  *m_pStgdb;
    mdTypeDef           m_tdModule;         // <Module> typedef value.
    LONG                m_cRefs;            // Ref count.
    bool                m_fOwnStgdb;
    IUnknown            *m_pUnk;
    IUnknown            *m_pUserUnk;        // Release at shutdown.
    IMetaDataHelper     *m_pIMetaDataHelper;// pointer to cached public interface
    UTSemReadWrite      *m_pSemReadWrite;   // read write lock for multi-threading.
    bool                m_fOwnSem;          // Does MDInternalRW own this read write lock object?
};
```

- m_pStgdb, like MDInternalRO::m_LiteWeightStgdb, is a member that saves metadata information. We can use it to read metadata information and recover the .NET headers.

### CLiteWeightStgdb && CLiteWeightStgdbRW

These two classes wrap around CMiniMd and CMiniMdRW. The CLiteWeightStgdbRW class is not very important and does not contain the information needed to recover the .NET headers. In fact, we only need the CLiteWeightStgdb class. Their definitions are as follows.

``` cpp
template <class MiniMd>
class CLiteWeightStgdb
{
    MiniMd      m_MiniMd;               // embedded compress meta data schemas definition
    const void  *m_pvMd;                // Pointer to meta data.
    ULONG       m_cbMd;                 // Size of the meta data.
}

class CLiteWeightStgdbRW : public CLiteWeightStgdb<CMiniMdRW>
{
    UINT32      m_cbSaveSize;               // Size of the saved streams.
    int         m_bSaveCompressed;          // If true, save as compressed stream (#-, not #~)
    VOID*       m_pImage;                   // Set in OpenForRead, NULL for anything but PE files
    DWORD       m_dwImageSize;              // On-disk size of image
    DWORD       m_dwPEKind;                 // The kind of PE - 0: not a PE.
    DWORD       m_dwMachine;                // Machine as defined in NT header.
    STORAGESTREAMLST *m_pStreamList;
    CLiteWeightStgdbRW *m_pNextStgdb;
    FILETYPE m_eFileType;
    WCHAR *  m_wszFileName;     // Database file name (NULL or non-empty string)
    DWORD    m_dwDatabaseLFT;   // Low bytes of the database file's last write time
    DWORD    m_dwDatabaseLFS;   // Low bytes of the database file's size
    StgIO *  m_pStgIO;          // For file i/o.
}
```

- m_MiniMd is CMiniMd and CMiniMdRW, which will be mentioned in the next section.
- m_pvMd is a pointer to metadata, corresponding to the Metadata RVA of the .NET Directory in CFF Explorer.
- m_cbMd is the size of the metadata, corresponding to the Metadata Size of the .NET Directory in CFF Explorer. It is worth noting that for CMiniMdRW, which is an uncompressed table stream, m_cbMd is invalid, and we need to calculate the total size of the metadata ourselves.

### CMiniMd & CMiniMdRW

CMiniMd is an implementation of the internal metadata provider in CLR, and there is also a CMiniMdRW that is similar to it. The difference between the two is that CMiniMd is used for compressed table streams like #&#126;, while CMiniMdRW is used for uncompressed table streams like #-.

Structurally, they have a common base class called CMiniMdBase.

``` cpp
class CMiniMdBase
{
    CMiniMdSchema   m_Schema;                       // data header.
    ULONG           m_TblCount;                     // Tables in this database.
    BOOL            m_fVerifiedByTrustedSource;     // whether the data was verified by a trusted source
    CMiniTableDef   m_TableDefs[TBL_COUNT];
    ULONG           m_iStringsMask;
    ULONG           m_iGuidsMask;
    ULONG           m_iBlobsMask;
};
```

- m_Schema is a subclass of the CMiniMdSchemaBase structure mentioned above, and is one of the keys used to restore the header of the table stream.

CLR uses CMiniMd for compressed table streams because it cannot be expanded, has a smaller structure, and runs faster.

``` cpp
class CMiniMd : public CMiniMdBase
{
    MetaData::TableRO m_Tables[TBL_COUNT];
    struct MetaData::HotTablesDirectory * m_pHotTablesDirectory;
    MetaData::StringHeapRO m_StringHeap;
    MetaData::BlobHeapRO   m_BlobHeap;
    MetaData::BlobHeapRO   m_UserStringHeap;
    MetaData::GuidHeapRO   m_GuidHeap;
};
```

- m_Tables is an array that stores every metadata table. The element type TableRO internally holds a pointer to the start address of each metadata table, used to restore #&#126; stream.
- m_StringHeap is a string stream that stores metadata strings such as method names and class names. The ultimate base class of type StringHeapRO is StgPoolSeg, which will be explained later. Used to restore #Strings stream.
- m_BlobHeap is a binary object stream. The ultimate base class of type BlobHeapRO is StgPoolSeg, which will be explained later. Used to restore #Blob stream.
- m_UserStringHeap is a user string stream that stores user-defined strings like 'string s = "Hello World"'. The ultimate base class of type BlobHeapRO is StgPoolSeg, which will be explained later. Used to restore #US stream.
- m_GuidHeap is a GUID stream. The ultimate base class of type GuidHeapRO is StgPoolSeg, which will be explained later. Used to restore #GUID stream.

For uncompressed table streams like #-, CLR uses CMiniMdRW. It can be expanded to append data. The following are only some of its members, and there are many more that are not listed. In short, it is larger and more complex than CMiniMd.

``` cpp
class CMiniMdRW : public CMiniMdBase
{
    CMemberRefHash *m_pMemberRefHash;
    CMemberDefHash *m_pMemberDefHash;
    CLookUpHash * m_pLookUpHashs[TBL_COUNT];
    MapSHash<UINT32, UINT32> m_StringPoolOffsetHash;
    CMetaDataHashBase *m_pNamedItemHash;
    ULONG       m_maxRid;               // Highest RID so far allocated.
    ULONG       m_limRid;               // Limit on RID before growing.
    ULONG       m_maxIx;                // Highest pool index so far.
    ULONG       m_limIx;                // Limit on pool index before growing.
    enum        {eg_ok, eg_grow, eg_grown} m_eGrow; // Is a grow required? done?
    MetaData::TableRW m_Tables[TBL_COUNT];
    VirtualSort *m_pVS[TBL_COUNT];      // Virtual sorters, one per table, but sparse.
    MetaData::StringHeapRW m_StringHeap;
    MetaData::BlobHeapRW   m_BlobHeap;
    MetaData::BlobHeapRW   m_UserStringHeap;
    MetaData::GuidHeapRW   m_GuidHeap;
    IMapToken  *m_pHandler;     // Remap handler.
    ULONG m_cbSaveSize;         // Estimate of save size.
};
```

- m_Tables is an array that stores each metadata table. The element type TableRW is a subclass of StgPoolSeg, which is used to restore #&#126;.
- m_StringHeap is a string stream that stores metadata strings such as method names and class names. The final base class of the StringHeapRW type is StgPoolSeg, which will be discussed below. Used to restore #Strings.
- m_BlobHeap is a binary object stream. The final base class of the BlobHeapRW type is StgPoolSeg, which will be discussed below. Used to restore #Blob.
- m_UserStringHeap is a user string stream that stores user-defined strings, such as 'string s = "Hello World"'. The final base class of the BlobHeapRW type is StgPoolSeg, which will be discussed below. Used to restore #US.
- m_GuidHeap is a GUID stream. The final base class of the GuidHeapRW type is StgPoolSeg, which will be discussed below. Used to restore #GUID.

The difference between RW and RO here is that RW is writable and can append data segments after the data segment, while RO is read-only and cannot be changed after initialization.

### CMiniTableDef

CMiniTableDef is a structure that represents the definition of a metadata table. It stores the table's fields, size, and number of rows, where the number of rows is used to restore the .NET headers.

``` cpp
struct CMiniColDef
{
    BYTE        m_Type;                 // Type of the column.
    BYTE        m_oColumn;              // Offset of the column.
    BYTE        m_cbColumn;             // Size of the column.
};

struct CMiniTableDef
{
    CMiniColDef *m_pColDefs;            // Array of field defs.
    BYTE        m_cCols;                // Count of columns in the table.
    BYTE        m_iKey;                 // Column which is the key, if any.
    USHORT      m_cbRec;                // Size of the records.
};
```

- m_pColDefs is an array that represents the fields in the table.
- m_cCols is the number of fields in the table, which is the length of the m_pColDefs array.
- m_cbRec is the number of rows in the table, which is one of the keys used to restore the header of the table stream in .NET.

### StgPoolSeg

StringHeapRO, BlobHeapRO, GuidHeapRO, StringHeapRW, BlobHeapRW, and GuidHeapRW are all subclasses of StgPoolSeg. The key members that store the data position and size are in the base class StgPoolSeg. So understanding the structure of StgPoolSeg is sufficient.

``` cpp
class StgPoolSeg
{
    BYTE       *m_pSegData;     // Pointer to the data.
    StgPoolSeg *m_pNextSeg;     // Pointer to next segment, or NULL.
    // Size of the segment buffer. If this is last segment (code:m_pNextSeg is NULL), then it's the 
    // allocation size. If this is not the last segment, then this is shrinked to segment data size 
    // (code:m_cbSegNext).
    ULONG       m_cbSegSize;
    ULONG       m_cbSegNext;    // Offset of next available byte in segment. Segment relative.
};
```

## Restoring .NET Header through CLR Internal Objects

After roughly understanding the data that anti-dumping protection may erase and the internal objects in CLR, we can locate the CLR internal objects through code and then restore the .NET headers. Here we make the most extreme assumption that anti-dumping technology erases all possible data, and we rely on CLR internal objects to restore them layer by layer from outside to inside.

**The code mentioned below has complete implementation at the end of the article.**

### Locating IMAGE_COR20_HEADER

For the .NET MetaData Directory of Data Directories.

![](/../net-trick-to-bypass-any-anti-dumping/1.png)

we can use the Reflection API to obtain the System.Reflection.RuntimeModule. Then, using the Reflection API, we can retrieve its private field m_pData. The value of this field is a pointer to the CLR internal object Module.

After obtaining the Module object, we use Module::m_file to obtain the PEFile object, which is a PEAssembly and PEModule, but in reality, only the contents of the base class PEFile are necessary.

Then, we find PEFile::m_openedILimage, which is used to obtain the PEImage that serves as the backend of PEFile.

Finally, by obtaining the PEImageLayout from the PEImage, we can obtain the IMAGE_COR20_HEADER, which is the .NET MetaData Directory of Data Directories. However, there are several PEImageLayouts in PEImage, and what we need is the LOADED layout. LOADED refers to the one used to provide IL code, rather than a specific layout such as FLAT or MAPPED, but an abstract one. CLR selects one that has already been opened from the existing layouts to be used as the LOADED layout.

Simply put, it can be represented in C# code as follows:

``` cs
var module = assembly.Module.m_pData;
// Get native Module object
var pCorHeader = module->m_file->m_openedILimage.m_pLayouts[IMAGE_LOADED]->m_pCorHeader;
// Get IMAGE_COR20_HEADER
```

The key code for searching for member offsets is:

``` cs
static Pointer ScanLoadedImageLayoutPointer(out bool isMappedLayoutExisting) {
    const bool InMemory = true;

    var assemblyFlags = InMemory ? TestAssemblyFlags.InMemory : 0;
    var assembly = TestAssemblyManager.GetAssembly(assemblyFlags);
    nuint module = assembly.ModuleHandle;
    Utils.Check((Module*)module, assembly.Module.Assembly.GetName().Name);
    // Get native Module object

    uint m_file_Offset;
    if (RuntimeEnvironment.Version >= RuntimeVersion.Fx453)
        m_file_Offset = (uint)((nuint)(&Module_453.Dummy->m_file) - (nuint)Module_453.Dummy);
    else
        m_file_Offset = (uint)((nuint)(&Module_20.Dummy->m_file) - (nuint)Module_20.Dummy);
    nuint m_file = *(nuint*)(module + m_file_Offset);
    Utils.Check((PEFile*)m_file);
    // Module.m_file

    uint m_openedILimage_Offset = (uint)((nuint)(&PEFile.Dummy->m_openedILimage) - (nuint)PEFile.Dummy);
    nuint m_openedILimage = *(nuint*)(m_file + m_openedILimage_Offset);
    Utils.Check((PEImage*)m_openedILimage, InMemory);
    // PEFile.m_openedILimage

    nuint m_pMDImport = MetadataImport.Create(assembly.Module).This;
    uint m_pMDImport_Offset;
    bool found = false;
    for (m_pMDImport_Offset = 0x40; m_pMDImport_Offset < 0xD0; m_pMDImport_Offset += 4) {
        if (*(nuint*)(m_openedILimage + m_pMDImport_Offset) != m_pMDImport)
            continue;
        found = true;
        break;
    }
    Utils.Check(found);
    // PEFile.m_pMDImport (not use, just for locating previous member 'm_pLayouts')
    isMappedLayoutExisting = false;
    uint m_pLayouts_Loaded_Offset = m_pMDImport_Offset - 4 - (uint)sizeof(nuint);
    uint m_pLayouts_Offset_Min = m_pLayouts_Loaded_Offset - (4 * (uint)sizeof(nuint));
    nuint actualModuleBase = ReflectionHelpers.GetNativeModuleHandle(assembly.Module);
    found = false;
    for (; m_pLayouts_Loaded_Offset >= m_pLayouts_Offset_Min; m_pLayouts_Loaded_Offset -= 4) {
        var m_pLayout = *(RuntimeDefinitions.PEImageLayout**)(m_openedILimage + m_pLayouts_Loaded_Offset);
        if (!Memory.TryReadUIntPtr((nuint)m_pLayout, out _))
            continue;
        if (!Memory.TryReadUIntPtr(m_pLayout->__vfptr, out _))
            continue;
        if (actualModuleBase != m_pLayout->__base.m_base)
            continue;
        Debug2.Assert(InMemory);
        var m_pLayout_prev1 = *(RuntimeDefinitions.PEImageLayout**)(m_openedILimage + m_pLayouts_Loaded_Offset - (uint)sizeof(nuint));
        var m_pLayout_prev2 = *(RuntimeDefinitions.PEImageLayout**)(m_openedILimage + m_pLayouts_Loaded_Offset - (2 * (uint)sizeof(nuint)));
        if (m_pLayout_prev2 == m_pLayout)
            isMappedLayoutExisting = true;
        else if (m_pLayout_prev1 == m_pLayout)
            isMappedLayoutExisting = false; // latest .NET, TODO: update comment when .NET 7.0 released
        found = true;
        break;
    }
    Utils.Check(found);
    nuint m_pLayouts_Loaded = *(nuint*)(m_openedILimage + m_pLayouts_Loaded_Offset);
    Utils.Check((RuntimeDefinitions.PEImageLayout*)m_pLayouts_Loaded, InMemory);
    // PEImage.m_pLayouts[IMAGE_LOADED]

    uint m_pCorHeader_Offset = (uint)((nuint)(&RuntimeDefinitions.PEImageLayout.Dummy->__base.m_pCorHeader) - (nuint)RuntimeDefinitions.PEImageLayout.Dummy);
    nuint m_pCorHeader = *(nuint*)(m_pLayouts_Loaded + m_pCorHeader_Offset);
    Utils.Check((IMAGE_COR20_HEADER*)m_pCorHeader);
    // PEImageLayout.m_pCorHeader

    var pointer = new Pointer(new[] {
        m_file_Offset,
        m_openedILimage_Offset,
        m_pLayouts_Loaded_Offset
    });
    Utils.Check(Utils.Verify(pointer, null, p => Memory.TryReadUIntPtr(p + (uint)sizeof(nuint), out nuint @base) && (ushort)@base == 0));
    Utils.Check(Utils.Verify(Utils.WithOffset(pointer, m_pCorHeader_Offset), null, p => Memory.TryReadUInt32(p, out uint cb) && cb == 0x48));
    return pointer;
}
```

### Locating CLiteWeightStgdb

Before locating the metadata, we need to locate the CLiteWeightStgdb structure first.

It can be simply represented as:

``` cs
var pMDImport = GetMetadataImport(assembly.Module);
// Get IMDInternalImport
var pStgdb = null;
if (table_stream_is_compressed)
    pStgdb =  &(((MDInternalRO*)pMDImport)->m_LiteWeightStgdb);
else
    pStgdb =  ((MDInternalRW*)pMDImport->m_pStgdb;
// Get CLiteWeightStgdb
```

The key code is:

``` cs
static Pointer ScanLiteWeightStgdbPointer(bool uncompressed, out nuint vfptr) {
    const bool InMemory = false;

    var assemblyFlags = InMemory ? TestAssemblyFlags.InMemory : 0;
    if (uncompressed)
        assemblyFlags |= TestAssemblyFlags.Uncompressed;
    var assembly = TestAssemblyManager.GetAssembly(assemblyFlags);
    nuint module = assembly.ModuleHandle;
    Utils.Check((Module*)module, assembly.Module.Assembly.GetName().Name);
    // Get native Module object

    uint m_file_Offset;
    if (RuntimeEnvironment.Version >= RuntimeVersion.Fx453)
        m_file_Offset = (uint)((nuint)(&Module_453.Dummy->m_file) - (nuint)Module_453.Dummy);
    else
        m_file_Offset = (uint)((nuint)(&Module_20.Dummy->m_file) - (nuint)Module_20.Dummy);
    nuint m_file = *(nuint*)(module + m_file_Offset);
    Utils.Check((PEFile*)m_file);
    // Module.m_file

    var metadataImport = MetadataImport.Create(assembly.Module);
    vfptr = metadataImport.Vfptr;
    nuint m_pMDImport = metadataImport.This;
    uint m_pMDImport_Offset;
    bool found = false;
    for (m_pMDImport_Offset = 0; m_pMDImport_Offset < 8 * (uint)sizeof(nuint); m_pMDImport_Offset += 4) {
        if (*(nuint*)(m_file + m_pMDImport_Offset) != m_pMDImport)
            continue;
        found = true;
        break;
    }
    Utils.Check(found);
    // PEFile.m_pMDImport

    uint m_pStgdb_Offset = 0;
    if (uncompressed) {
        if (RuntimeEnvironment.Version >= RuntimeVersion.Fx45)
            m_pStgdb_Offset = (uint)((nuint)(&MDInternalRW_45.Dummy->m_pStgdb) - (nuint)MDInternalRW_45.Dummy);
        else
            m_pStgdb_Offset = (uint)((nuint)(&MDInternalRW_20.Dummy->m_pStgdb) - (nuint)MDInternalRW_20.Dummy);
    }
    // MDInternalRW.m_pStgdb

    var pointer = new Pointer(new[] {
        m_file_Offset,
        m_pMDImport_Offset
    });
    if (m_pStgdb_Offset != 0)
        pointer.Add(m_pStgdb_Offset);
    Utils.Check(Utils.Verify(pointer, uncompressed, p => Memory.TryReadUInt32(p, out _)));
    return pointer;
}
```

### Locating Metadata

After locating the IMAGE_COR20_HEADER, the most critical member, the MetaData, needs to be located.

![](/../net-trick-to-bypass-any-anti-dumping/2.png)

It can be simply represented as:

``` cs
var pMDImport = GetMetadataImport(assembly.Module);
// Get IMDInternalImport
var m_pvMd = null;
if (table_stream_is_compressed)
    m_pvMd =  ((MDInternalRO*)pMDImport)->m_LiteWeightStgdb.m_pvMd;
else
    m_pvMd =  ((MDInternalRW*)pMDImport->m_pStgdb->m_pvMd;
// Get metadata address
```

The key code is:

``` cs
static void ScanMetadataOffsets(Pointer stgdbPointer, bool uncompressed, out uint metadataAddressOffset, out uint metadataSizeOffset) {
    const bool InMemory = false;

    var assemblyFlags = InMemory ? TestAssemblyFlags.InMemory : 0;
    if (uncompressed)
        assemblyFlags |= TestAssemblyFlags.Uncompressed;
    var assembly = TestAssemblyManager.GetAssembly(assemblyFlags);
    nuint module = assembly.ModuleHandle;
    Utils.Check((Module*)module, assembly.Module.Assembly.GetName().Name);
    // Get native Module object

    nuint pStgdb = Utils.ReadUIntPtr(stgdbPointer, module);
    var peInfo = PEInfo.Create(assembly.Module);
    var imageLayout = peInfo.MappedLayout.IsInvalid ? peInfo.LoadedLayout : peInfo.MappedLayout;
    var m_pCorHeader = (IMAGE_COR20_HEADER*)imageLayout.CorHeaderAddress;
    nuint m_pvMd = imageLayout.ImageBase + m_pCorHeader->MetaData.VirtualAddress;
    uint m_cbMd = uncompressed ? 0x1c : m_pCorHeader->MetaData.Size;
    // *pcb = sizeof(STORAGESIGNATURE) + pStorage->GetVersionStringLength();
    // TODO: we should calculate actual metadata size for uncompressed metadata
    uint start = uncompressed ? (sizeof(nuint) == 4 ? 0x1000u : 0x19A0) : (sizeof(nuint) == 4 ? 0x350u : 0x5B0);
    uint end = uncompressed ? (sizeof(nuint) == 4 ? 0x1200u : 0x1BA0) : (sizeof(nuint) == 4 ? 0x39Cu : 0x5FC);
    uint m_pvMd_Offset = 0;
    for (uint offset = start; offset <= end; offset += 4) {
        if (*(nuint*)(pStgdb + offset) != m_pvMd)
            continue;
        if (*(uint*)(pStgdb + offset + (uint)sizeof(nuint)) != m_cbMd)
            continue;
        m_pvMd_Offset = offset;
        break;
    }
    Utils.Check(m_pvMd_Offset != 0);

    Utils.Check(Utils.Verify(Utils.WithOffset(stgdbPointer, m_pvMd_Offset), uncompressed, p => Memory.TryReadUInt32(p, out uint signature) && signature == 0x424A5342));
    metadataAddressOffset = m_pvMd_Offset;
    metadataSizeOffset = m_pvMd_Offset + (uint)sizeof(nuint);
}
```

### Locating Metadata Table Stream Header

The table stream is relatively more complicated, with more data to fill. The first step is to obtain the table stream schema.

It can be simply represented as:

``` cs
var pMDImport = GetMetadataImport(assembly.Module);
// Get IMDInternalImport
var pMiniMd = null;
if (table_stream_is_compressed)
    pMiniMd =  &(((MDInternalRO*)pMDImport)->m_LiteWeightStgdb.m_MiniMd);
else
    pMiniMd =  &(((MDInternalRW*)pMDImport->m_pStgdb->m_MiniMd);
// Get CMiniMd
var m_Schema = pMiniMd->m_Schema;
// Get metadata schema
```

The key code is:

``` cs
static void ScanSchemaOffset(Pointer stgdbPointer, MiniMetadataInfo info, bool uncompressed, out uint schemaOffset) {
    const bool InMemory = false;

    var assemblyFlags = InMemory ? TestAssemblyFlags.InMemory : 0;
    if (uncompressed)
        assemblyFlags |= TestAssemblyFlags.Uncompressed;
    var assembly = TestAssemblyManager.GetAssembly(assemblyFlags);
    nuint module = assembly.ModuleHandle;
    Utils.Check((Module*)module, assembly.Module.Assembly.GetName().Name);
    // Get native Module object

    nuint pStgdb = Utils.ReadUIntPtr(stgdbPointer, module);
    for (schemaOffset = 0; schemaOffset < 0x30; schemaOffset += 4) {
        if (*(ulong*)(pStgdb + schemaOffset) != info.Header1)
            continue;
        if (*(ulong*)(pStgdb + schemaOffset + 0x08) != info.ValidMask)
            continue;
        if (*(ulong*)(pStgdb + schemaOffset + 0x10) != info.SortedMask)
            continue;
        break;
    }
    Utils.Check(schemaOffset != 0x30);
    // CMiniMdBase.m_Schema
}
```

After obtaining the schema, we also need to obtain which metadata tables exist in the target module and how many rows they have. Since CLR does not save row numbers internally, but directly saves pointers to each metadata table, we need to obtain the address of each metadata table and calculate the number of rows for each metadata table by dividing the size of the table by the size of each row.

It can be simply represented as:

``` cs
var pMDImport = GetMetadataImport(assembly.Module);
// Get IMDInternalImport
var pMiniMd = null;
if (table_stream_is_compressed)
    pMiniMd =  &(((MDInternalRO*)pMDImport)->m_LiteWeightStgdb.m_MiniMd);
else
    pMiniMd =  &(((MDInternalRW*)pMDImport->m_pStgdb->m_MiniMd);
// Get CMiniMd
var m_TableDefs = pMiniMd->m_TableDefs;
// Get metadata table definitions (to get row size)
var m_Tables = pMiniMd->m_Tables;
// Get metadata tables (to get table address)
```

The key code is:

``` cs
static void ScanTableDefsOffsets(Pointer stgdbPointer, bool uncompressed, uint schemaOffset, out uint tableCountOffset, out uint tableDefsOffset) {
    const bool InMemory = false;

    var assemblyFlags = InMemory ? TestAssemblyFlags.InMemory : 0;
    if (uncompressed)
        assemblyFlags |= TestAssemblyFlags.Uncompressed;
    var assembly = TestAssemblyManager.GetAssembly(assemblyFlags);
    nuint module = assembly.ModuleHandle;
    Utils.Check((Module*)module, assembly.Module.Assembly.GetName().Name);
    // Get native Module object

    nuint pSchema = Utils.ReadPointer(Utils.WithOffset(stgdbPointer, schemaOffset), module);
    nuint p = pSchema + (uint)sizeof(CMiniMdSchema);
    uint m_TblCount = *(uint*)p;
    tableCountOffset = schemaOffset + (uint)(p - pSchema);
    Utils.Check(m_TblCount == TBL_COUNT_V1 || m_TblCount == TBL_COUNT_V2);
    // CMiniMdBase.m_TblCount

    if (RuntimeEnvironment.Version >= RuntimeVersion.Fx40)
        p += (uint)((nuint)(&CMiniMdBase_40.Dummy->m_TableDefs) - (nuint)(&CMiniMdBase_40.Dummy->m_TblCount));
    else
        p += (uint)((nuint)(&CMiniMdBase_20.Dummy->m_TableDefs) - (nuint)(&CMiniMdBase_20.Dummy->m_TblCount));
    tableDefsOffset = schemaOffset + (uint)(p - pSchema);
    var m_TableDefs = (CMiniTableDef*)p;
    for (int i = 0; i < TBL_COUNT; i++)
        Utils.Check(Memory.TryReadUInt32((nuint)m_TableDefs[i].m_pColDefs, out _));
    // CMiniMdBase.m_TableDefs
}

static void ScanTableOffset(Pointer stgdbPointer, MiniMetadataInfo info, bool uncompressed, out uint tableAddressOffset, out uint nextTableOffset) {
    const bool InMemory = false;

    var assemblyFlags = InMemory ? TestAssemblyFlags.InMemory : 0;
    if (uncompressed)
        assemblyFlags |= TestAssemblyFlags.Uncompressed;
    var assembly = TestAssemblyManager.GetAssembly(assemblyFlags);
    nuint module = assembly.ModuleHandle;
    Utils.Check((Module*)module, assembly.Module.Assembly.GetName().Name);
    // Get native Module object

    tableAddressOffset = 0;
    nextTableOffset = 0;
    nuint pStgdb = Utils.ReadUIntPtr(stgdbPointer, module);
    uint start = uncompressed ? (sizeof(nuint) == 4 ? 0x2A0u : 0x500) : (sizeof(nuint) == 4 ? 0x200u : 0x350);
    uint end = uncompressed ? (sizeof(nuint) == 4 ? 0x4A0u : 0x800) : (sizeof(nuint) == 4 ? 0x300u : 0x450);
    for (uint offset = start; offset < end; offset += 4) {
        nuint pFirst = pStgdb + offset;
        if (*(nuint*)pFirst != info.TableAddress[0])
            continue;

        uint start2 = 4;
        uint end2 = uncompressed ? 0x100u : 0x20;
        uint offset2 = start2;
        for (; offset2 < end2; offset2 += 4) {
            if (*(nuint*)(pFirst + offset2) != info.TableAddress[1])
                continue;
            if (*(nuint*)(pFirst + (2 * offset2)) != info.TableAddress[2])
                continue;
            break;
        }
        if (offset2 == end2)
            continue;

        tableAddressOffset = offset;
        nextTableOffset = offset2;
        break;
    }
    Utils.Check(tableAddressOffset != 0);
    Utils.Check(nextTableOffset != 0);
    // CMiniMd.m_Tables
}
```

### Locating Metadata Heap Streams

Finally, we locate the Metadata heap stream, which includes the #Strings, #US, #GUID, and #Blob heaps. When restoring, it is relatively simple, we only need to write the offset, size, and name of these four heaps into the .NET headers.

It can be simply represented as:

``` cs
var pMDImport = GetMetadataImport(assembly.Module);
// Get IMDInternalImport
var pMiniMd = null;
if (table_stream_is_compressed)
    pMiniMd =  &(((MDInternalRO*)pMDImport)->m_LiteWeightStgdb.m_MiniMd);
else
    pMiniMd =  &(((MDInternalRW*)pMDImport->m_pStgdb->m_MiniMd);
// Get CMiniMd
var m_StringHeap = pMiniMd->m_StringHeap;
// Get #Strings
var m_BlobHeap = pMiniMd->m_BlobHeap;
// Get #Blob
var m_UserStringHeap = pMiniMd->m_UserStringHeap;
// Get #US
var m_GuidHeap = pMiniMd->m_GuidHeap;
// Get #GUID
```

The key code is:

``` cs
static void ScanHeapOffsets(Pointer stgdbPointer, MiniMetadataInfo info, bool uncompressed, out uint[] heapAddressOffsets, out uint[] heapSizeOffsets) {
    const bool InMemory = false;

    var assemblyFlags = InMemory ? TestAssemblyFlags.InMemory : 0;
    if (uncompressed)
        assemblyFlags |= TestAssemblyFlags.Uncompressed;
    var assembly = TestAssemblyManager.GetAssembly(assemblyFlags);
    nuint module = assembly.ModuleHandle;
    Utils.Check((Module*)module, assembly.Module.Assembly.GetName().Name);
    // Get native Module object

    nuint pStgdb = Utils.ReadUIntPtr(stgdbPointer, module);
    uint start = uncompressed ? (sizeof(nuint) == 4 ? 0xD00u : 0x1500) : (sizeof(nuint) == 4 ? 0x2A0u : 0x500);
    uint end = uncompressed ? (sizeof(nuint) == 4 ? 0x1000u : 0x1900) : (sizeof(nuint) == 4 ? 0x3A0u : 0x600);
    heapAddressOffsets = new uint[4];
    heapSizeOffsets = new uint[heapAddressOffsets.Length];
    int found = 0;
    for (uint offset = start; offset < end; offset += 4) {
        nuint address = *(nuint*)(pStgdb + offset);
        uint size = *(uint*)(pStgdb + offset + (2 * (uint)sizeof(nuint)));
        if (address == info.StringHeapAddress) {
            Utils.Check(info.StringHeapSize - 8 < size && size <= info.StringHeapSize);
            Utils.Check(heapAddressOffsets[0] == 0);
            heapAddressOffsets[StringHeapIndex] = offset;
            heapSizeOffsets[StringHeapIndex] = offset + (2 * (uint)sizeof(nuint));
            found++;
        }
        else if (address == info.UserStringHeapAddress) {
            Utils.Check(info.UserStringHeapSize - 8 < size && size <= info.UserStringHeapSize);
            Utils.Check(heapAddressOffsets[1] == 0);
            heapAddressOffsets[UserStringsHeapIndex] = offset;
            heapSizeOffsets[UserStringsHeapIndex] = offset + (2 * (uint)sizeof(nuint));
            found++;
        }
        else if (address == info.GuidHeapAddress) {
            Utils.Check(info.GuidHeapSize - 8 < size && size <= info.GuidHeapSize);
            Utils.Check(heapAddressOffsets[2] == 0);
            heapAddressOffsets[GuidHeapIndex] = offset;
            heapSizeOffsets[GuidHeapIndex] = offset + (2 * (uint)sizeof(nuint));
            found++;
        }
        else if (address == info.BlobHeapAddress) {
            Utils.Check(info.BlobHeapSize - 8 < size && size <= info.BlobHeapSize);
            Utils.Check(heapAddressOffsets[3] == 0);
            heapAddressOffsets[BlobHeapIndex] = offset;
            heapSizeOffsets[BlobHeapIndex] = offset + (2 * (uint)sizeof(nuint));
            found++;
        }
    }
    Utils.Check(found == 4);
    // Find heeap info offsets

    for (int i = 0; i < heapAddressOffsets.Length; i++)
        Utils.Check(Utils.Verify(Utils.WithOffset(stgdbPointer, heapAddressOffsets[i]), uncompressed, p => Memory.TryReadUInt32(p, out _)));
}
```

### Restoring the .NET Headers

After finding the member offsets of the required CLR internal objects, we can use this information to restore the .NET headers.

``` cs
static unsafe void FixDotNetHeaders(byte[] data, MetadataInfo metadataInfo, PEImageLayout imageLayout) {
    fixed (byte* p = data) {
        var pNETDirectory = (IMAGE_DATA_DIRECTORY*)(p + GetDotNetDirectoryRVA(data));
        pNETDirectory->VirtualAddress = (uint)imageLayout.CorHeaderAddress;
        pNETDirectory->Size = (uint)sizeof(IMAGE_COR20_HEADER);
        // Set Data Directories
        var pCor20Header = (IMAGE_COR20_HEADER*)(p + (uint)imageLayout.CorHeaderAddress);
        pCor20Header->cb = (uint)sizeof(IMAGE_COR20_HEADER);
        pCor20Header->MajorRuntimeVersion = 0x2;
        pCor20Header->MinorRuntimeVersion = 0x5;
        pCor20Header->MetaData.VirtualAddress = (uint)metadataInfo.MetadataAddress;
        pCor20Header->MetaData.Size = GetMetadataSize(metadataInfo);
        // Set .NET Directory
        var pStorageSignature = (STORAGESIGNATURE*)(p + (uint)metadataInfo.MetadataAddress);
        pStorageSignature->lSignature = 0x424A5342;
        pStorageSignature->iMajorVer = 0x1;
        pStorageSignature->iMinorVer = 0x1;
        pStorageSignature->iExtraData = 0x0;
        pStorageSignature->iVersionString = 0xC;
        var versionString = Encoding.ASCII.GetBytes("v4.0.30319");
        for (int i = 0; i < versionString.Length; i++)
            pStorageSignature->pVersion[i] = versionString[i];
        // versionString仅仅占位用，程序集具体运行时版本用dnlib获取
        // Set StorageSignature
        var pStorageHeader = (STORAGEHEADER*)((byte*)pStorageSignature + 0x10 + pStorageSignature->iVersionString);
        pStorageHeader->fFlags = 0x0;
        pStorageHeader->pad = 0x0;
        pStorageHeader->iStreams = 0x5;
        // Set StorageHeader
        var pStreamHeader = (uint*)((byte*)pStorageHeader + sizeof(STORAGEHEADER));
        var tableStream = metadataInfo.TableStream;
        if (!tableStream.IsInvalid) {
            *pStreamHeader = (uint)tableStream.Address;
            *pStreamHeader -= (uint)metadataInfo.MetadataAddress;
            pStreamHeader++;
            *pStreamHeader = tableStream.Length;
            pStreamHeader++;
            *pStreamHeader = tableStream.IsCompressed ? 0x00007E23u : 0x000002D23;
            pStreamHeader++;
        }
        // Set #~ or #-
        var stringHeap = metadataInfo.StringHeap;
        if (!stringHeap.IsInvalid) {
            *pStreamHeader = (uint)stringHeap.Address;
            *pStreamHeader -= (uint)metadataInfo.MetadataAddress;
            pStreamHeader++;
            *pStreamHeader = stringHeap.Length;
            pStreamHeader++;
            *pStreamHeader = 0x72745323;
            pStreamHeader++;
            *pStreamHeader = 0x73676E69;
            pStreamHeader++;
            *pStreamHeader = 0x00000000;
            pStreamHeader++;
        }
        // Set #Strings
        var userStringHeap = metadataInfo.UserStringHeap;
        if (!userStringHeap.IsInvalid) {
            *pStreamHeader = (uint)userStringHeap.Address;
            *pStreamHeader -= (uint)metadataInfo.MetadataAddress;
            pStreamHeader++;
            *pStreamHeader = userStringHeap.Length;
            pStreamHeader++;
            *pStreamHeader = 0x00535523;
            pStreamHeader++;
        }
        // Set #US
        var guidHeap = metadataInfo.GuidHeap;
        if (!guidHeap.IsInvalid) {
            *pStreamHeader = (uint)guidHeap.Address;
            *pStreamHeader -= (uint)metadataInfo.MetadataAddress;
            pStreamHeader++;
            *pStreamHeader = guidHeap.Length;
            pStreamHeader++;
            *pStreamHeader = 0x49554723;
            pStreamHeader++;
            *pStreamHeader = 0x00000044;
            pStreamHeader++;
        }
        // Set #GUID
        var blobHeap = metadataInfo.BlobHeap;
        if (!blobHeap.IsInvalid) {
            *pStreamHeader = (uint)blobHeap.Address;
            *pStreamHeader -= (uint)metadataInfo.MetadataAddress;
            pStreamHeader++;
            *pStreamHeader = blobHeap.Length;
            pStreamHeader++;
            *pStreamHeader = 0x6F6C4223;
            pStreamHeader++;
            *pStreamHeader = 0x00000062;
            pStreamHeader++;
        }
        // Set #GUID
        switch (GetCorLibVersion(data).Major) {
        case 2:
            versionString = Encoding.ASCII.GetBytes("v2.0.50727");
            break;
        case 4:
            versionString = Encoding.ASCII.GetBytes("v4.0.30319");
            break;
        default:
            throw new NotSupportedException();
        }
        for (int i = 0; i < versionString.Length; i++)
            pStorageSignature->pVersion[i] = versionString[i];
        // Re set Version
    }
}
```

## Source Code and Binary Download

This method has been implemented in my latest ExtremeDumper, which can bypass anti-Dump protection for .NET assemblies.

Code for locating metadata: [wwh1004/MetadataLocator](https://github.com/wwh1004/MetadataLocator)

Restore the .NET headers through CLR internal objects: [wwh1004/ExtremeDumper.AntiAntiDump](https://github.com/wwh1004/ExtremeDumper/tree/master/ExtremeDumper.AntiAntiDump)
