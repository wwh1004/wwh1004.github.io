---
title: .NET Control Flow Analysis (II) - Deobfuscation
date: 2019-02-03
updated: 2023-04-11
lang: en
categories:
- [￫Translated, .NET Reverse Engineering]
tags:
- .NET
- Reverse Engineering
- Unpacking
- Control Flow Analysis
toc: true
hide: true
---

<article class="message message-immersive is-primary">
<div class="message-body">
<i class="fas fa-globe-americas mr-2"></i>This article is translated to English using GPT-3.5 and polished by the author. <a href="{% post_path net-control-flow-analysis-2-deobfuscation %}">This is the original post.</a>
</div>
</article>

<!-- # .NET Control Flow Analysis (II) - Deobfuscation -->

After understanding the basic knowledge of control flow, this article will continue to introduce some methods for deobfuscating control flow obfuscation, and provide an example of a deobfuscator for ConfuserEx's control flow obfuscation.

<!-- more -->

## Introduction

Originally, I planned to divide this article into two parts, because one part is simple and the other part is very difficult. But then I thought it would be better to write it all in one article, since they are all related to deobfuscation. However, I estimate that the article will be very long with a lot of words.

This article should still be read in order.

The first half of the article covers more general code and ideas, while the second half is more specific and discusses practical examples of removing ConfuserEx's control flow obfuscation. 

Why focus on ConfuserEx's control flow obfuscation? Because I believe that ConfuserEx's control flow obfuscation is the most difficult, at least compared to other obfuscators I have encountered. Other obfuscators simply use a simple switch statement like switch(num) with the case containing only num=x, but ConfuserEx's control flow obfuscation is linear, where the next executed basic block is related to the previous one, making it impossible to statically decrypt the switch obfuscation, requiring symbol execution.

## Basics

### Recursive Model

Often times, a method may contain a try block, which means there will be a small scope within the method block, specifically within the try block. Control flow obfuscation only occurs within the same scope and does not cross scopes. What does that mean?

![](/../net-control-flow-analysis-2-deobfuscation/1.png)

For example, the large red box is a scope, and the try block can be viewed as a whole. When performing control flow obfuscation, the try block is not divided into multiple parts. However, the try block is a scope, and can be divided into multiple parts for further obfuscation.

Therefore, we need to write a Helper class that can simplify the operation of traversing each scope for deobfuscation. This class is called BlockRecursiveModel, and the code is included in the attachment of the previous article in this series. Here is a screenshot of what it looks like:

![](/../net-control-flow-analysis-2-deobfuscation/2.png)

### Block Sorter

Why do we need sorting? First, it reduces the code volume. If not sorted, the IL code may look like this, with unconditional jump instructions br everywhere, making it almost impossible for us to read the IL code.

![](/../net-control-flow-analysis-2-deobfuscation/3.png)

After sorting, the logic becomes much clearer:

![](/../net-control-flow-analysis-2-deobfuscation/4.png)

This is just a very simple method body. If the method body is more complex, the code will expand significantly, making sorting very important.

Of course, sorting only affects the generated instruction stream, and does not affect the control flow, which is the tree structure we analyze after dividing the code into blocks.

Regardless of the order in which they are stored in List&lt;T&gt;, the structure of the divided blocks is the same:

![](/../net-control-flow-analysis-2-deobfuscation/5.png)

This is a tool I wrote, and the binaries will be attached at the end of the article.

With the previously mentioned BlockRecursiveModel, block sorting code is actually very simple. We first need to analyze the reference relationship between blocks within the same scope, and then use dfs sorting. Some people may say that dfs sorting can only be used for directed acyclic graphs, but we can still use dfs sorting here. I won't explain why, try it out yourself.

To analyze the reference relationship, we still need to define additional information to store our analysis results:

``` csharp
private sealed class BlockInfo {
    private readonly List<IBlock> _references;
    private bool _isVisited;

    public List<IBlock> References => _references;

    public bool IsVisited {
        get => _isVisited;
        set => _isVisited = value;
    }
}
```

References refer to the references that will be jumped to in the following blocks.

``` csharp
private void AddXref(BasicBlock source, BasicBlock target) {
    IBlock targetRoot;
    List<IBlock> references;

    targetRoot = target.GetRootBlock(_scope);
    if (targetRoot == null)
        // We won't do anything about the blocks that are out of scope.
        return;
    references = source.GetRootBlock(_scope).PeekExtraData<BlockInfo>().References;
    if (!references.Contains(targetRoot))
        references.Add(targetRoot);
}

public static IBlock GetRootBlock(this IBlock block, IBlock scope) {
    if (block == null)
        throw new ArgumentNullException(nameof(block));
    if (scope == null)
        throw new ArgumentNullException(nameof(scope));

    while (true) {
        if (block.Scope == scope)
            return block;
        else
            block = block.Scope;
        if (block == null)
            return null;
    }
}
```

In the code, source represents the basic block where a jump occurs, while target represents the basic block where the jump goes.

After analyzing all the reference relationships, we can directly use DFS sorting:

``` csharp
private sealed class DfsSorter {
    private readonly List<IBlock> _blocks;
    private readonly Stack<IBlock> _blockStack;

    public DfsSorter(List<IBlock> blocks) {
        if (blocks == null)
            throw new ArgumentNullException(nameof(blocks));

        _blocks = blocks;
        _blockStack = new Stack<IBlock>(_blocks.Count);
    }

    public Stack<IBlock> Sort() {
        DfsSort(_blocks[0]);
        return _blockStack;
    }

    private void DfsSort(IBlock block) {
        BlockInfo blockInfo;

        blockInfo = block.PeekExtraData<BlockInfo>();
        blockInfo.IsVisited = true;
        for (int i = blockInfo.References.Count - 1; i >= 0; i--)
            if (!blockInfo.References[i].PeekExtraData<BlockInfo>().IsVisited)
                DfsSort(blockInfo.References[i]);
        _blockStack.Push(block);
    }
}
```

The entire sorting code is in the compressed package of the previous article, called BlockSorter.cs.

### Remove NOP

Removing NOP is very simple because we have converted it into blocks. We just need to iterate through each basic block and remove its NOP.

Why do we mention this if it's so simple?

Because our goal is to simplify all cases as much as possible, turning them into one situation so that it is more convenient for us to process. The existence of NOP may affect our recognition of features.

### Inline Basic Block

What does inline mean? For example:

![](/../net-control-flow-analysis-2-deobfuscation/6.png)

The three basic blocks highlighted in red can be inlined together. Why? Because BLK_0002 is only referenced by one basic block, and so is BLK_0001. Moreover, the referencing side is an unconditional jump, so they can be inlined together. Although BLK_0004 is only referenced by one basic block, the referencing side BLK_0002 is a conditional jump, so we cannot inline it.

After inlining:

![](/../net-control-flow-analysis-2-deobfuscation/7.png)

Isn't it obvious that the control flow is clearer and there is no redundant information?

Here, I'll talk a little bit about my FlowGraph tool. It has an "Optimization" option, which, when enabled, will inline all the blocks that can be inlined together, remove NOP, and sort the blocks.

In addition to this case, there is another case where we can inline certain basic blocks. If a basic block is an empty block with an unconditional jump instruction br, we can inline it regardless of how many referencing sides there are and what kind of jump instruction the referencing side has.

For example:

![](/../net-control-flow-analysis-2-deobfuscation/8.png)

Here, BLK_0007 is an empty block (the NOP instruction is equivalent to non-existence, which we will optimize away), and its jump instruction is an unconditional jump instruction br. Although BLK_0007 is referenced by five basic blocks, BLK_0002, BLK_0003, BLK_0004, BLK_0005 and BLK_0006, we can inline them all together.

After inlining:

![](/../net-control-flow-analysis-2-deobfuscation/9.png)

In fact, the source code for this control flow graph is very simple, just a switch+goto compiled in Debug mode.

![](/../net-control-flow-analysis-2-deobfuscation/10.png)

Imagine that the generated code looks more like our control flow graph after optimization?

This is where inlining is amazing, as it can greatly simplify the control flow. Although amazing, the implementation is more complicated than the code above.

Actually, it's not much more complicated. The code is directly provided, with only about 200 lines.

``` csharp
using System.Collections.Generic;
using ControlFlow.Blocks;
using dnlib.DotNet.Emit;

namespace ControlFlow.Deobfuscation {
    /// <summary>
    /// Basic block A that can be removed, which may hinder our analysis if not removed:
    /// 1. A basic block A has no other instructions except for the unconditional jump instruction "br".
    /// 2. A basic block B unconditionally jumps to a basic block A with the same scope, and A is only referenced by B.
    /// </summary>
    public sealed class BlockInliner : BlockRecursiveModel {
        private BlockInliner(List<IBlock> blocks, IBlock scope) : base(blocks, scope) {
        }

        /// <summary>
        /// Inline
        /// </summary>
        /// <param name="methodBlock"></param>
        /// <returns></returns>
        public static bool Inline(MethodBlock methodBlock) {
            bool result;

            methodBlock.PushExtraDataAllBasicBlocks(() => new BlockInfo());
            new BlockXref(methodBlock, AddXref).Analyze();
            // We need to analyze all inter-block reference relationships before we can complete inlining.
            result = Execute(methodBlock, (blocks, scope) => new BlockInliner(blocks, scope));
            methodBlock.PopExtraDataAllBasicBlocks();
            return result;
        }

        private static void AddXref(BasicBlock source, BasicBlock target) {
            List<BasicBlock> references;
            List<BasicBlock> dereferences;

            references = source.PeekExtraData<BlockInfo>().References;
            if (!references.Contains(target))
                references.Add(target);
            dereferences = target.PeekExtraData<BlockInfo>().Dereferences;
            if (!dereferences.Contains(source))
                dereferences.Add(source);
        }

        /// <summary />
        protected override bool Execute() {
            bool isModified;
            bool next;

            if (_blocks.Count < 2)
                return false;
            isModified = FixEntryBlockIfBrOnly();
            // If the entry point of the scope (i.e., the first block of the scope) is an empty block, we handle it specially.
            do {
                for (int i = 1; i < _blocks.Count; i++) {
                    // Skip the entry block, as this code cannot handle it.
                    BasicBlock target;
                    BlockInfo targetInfo;

                    target = _blocks[i] as BasicBlock;
                    // Target represents a block that could potentially be merged.
                    if (target == null)
                        // A scope block cannot be merged into another block.
                        continue;
                    targetInfo = target.PeekExtraData<BlockInfo>();
                    if (CanInline(target, targetInfo)) {
                        UpdateReferencesOfDereferences(target, targetInfo);
                        // Update the references of the back reference of target.
                        UpdateDereferencesOfReferences(target, targetInfo);
                        // Update the references of target's back reference.
                        targetInfo.IsInlineed = true;
                    }
                }
                next = _blocks.RemoveAll(block => block is BasicBlock && block.PeekExtraData<BlockInfo>().IsInlineed) != 0;
                if (next)
                    isModified = true;
            } while (next);
            return isModified;
        }

        private static bool CanInline(BasicBlock target, BlockInfo targetInfo) {
            if (target.IsEmpty && target.BranchOpcode.Code == Code.Br) {
                // An empty br-jump block can be unconditionally merged.
                return true;
            }
            else {
                BasicBlock dereference;

                if (targetInfo.Dereferences.Count != 1)
                    // Target can only be inlined if it is only referenced by one block.
                    return false;
                dereference = targetInfo.Dereferences[0];
                if (dereference.BranchOpcode.Code != Code.Br)
                    // The block referencing the current block must be a basic block, and its last instruction must be br.
                    // If it is leave, it means that the back reference comes from another scope, and target and the back reference are not in the same scope. In this case, we cannot inline target.
                    return false;
                return true;
            }
        }

        private static void UpdateReferencesOfDereferences(BasicBlock target, BlockInfo targetInfo) {
            foreach (BasicBlock dereference in targetInfo.Dereferences) {
                if (dereference.BranchOpcode.Code == Code.Br) {
                    // Inline the basic block directly with br unconditional jump.
                    if (!target.IsEmpty)
                        dereference.Instructions.AddRange(target.Instructions);
                    dereference.BranchOpcode = target.BranchOpcode;
                    dereference.FallThrough = target.FallThrough;
                    dereference.ConditionalTarget = target.ConditionalTarget;
                    dereference.SwitchTargets = target.SwitchTargets;
                }
                else {
                    // Check where target is used one by one.
                    if (dereference.FallThrough == target)
                        dereference.FallThrough = target.FallThrough;
                    if (dereference.ConditionalTarget == target)
                        dereference.ConditionalTarget = target.FallThrough;
                    if (dereference.SwitchTargets != null)
                        for (int j = 0; j < dereference.SwitchTargets.Count; j++)
                            if (dereference.SwitchTargets[j] == target)
                                dereference.SwitchTargets[j] = target.FallThrough;
                }
                ListReplace(dereference.PeekExtraData<BlockInfo>().References, target, targetInfo.References);
                // Replace target in the references of the back reference of target with target's reference.
            }
        }

        private static void UpdateDereferencesOfReferences(BasicBlock target, BlockInfo targetInfo) {
            foreach (BasicBlock reference in targetInfo.References)
                ListReplace(reference.PeekExtraData<BlockInfo>().Dereferences, target, targetInfo.Dereferences);
            // Replace target in the references of target's back reference with target's back reference.
        }

        private static void ListReplace<T>(List<T> list, T oldItem, List<T> newItems) {
            if (newItems.Count > 1) {
                list.Remove(oldItem);
                foreach (T newItem in newItems)
                    if (!list.Contains(newItem))
                        list.Add(newItem);
            }
            else if (newItems.Count == 1) {
                for (int i = 0; i < list.Count; i++)
                    if (ReferenceEquals(list[i], oldItem))
                        list[i] = newItems[0];
            }
        }

        private bool FixEntryBlockIfBrOnly() {
            if (!IsBrOnlyBlock(_blocks[0]))
                return false;

            BasicBlock entryBlock;
            IBlock fallThroughRoot;

            entryBlock = (BasicBlock)_blocks[0];
            fallThroughRoot = GetNonBrOnlyFallThrough(entryBlock).GetRootBlock(_scope);
            _blocks[_blocks.IndexOf(fallThroughRoot)] = entryBlock;
            _blocks[0] = fallThroughRoot;
            // We only swap the positions of the entry basic block and the block that br-only finally reaches.
            // Therefore, FixEntryBlockIfBrOnly must be called at the very beginning so that the entry of the current scope block can be fixed.
            return false;
        }

        private static bool IsBrOnlyBlock(IBlock block) {
            BasicBlock basicBlock;

            basicBlock = block as BasicBlock;
            return basicBlock != null && IsBrOnlyBlock(basicBlock);
        }

        private static bool IsBrOnlyBlock(BasicBlock basicBlock) {
            return basicBlock.IsEmpty && basicBlock.BranchOpcode.Code == Code.Br;
        }

        private static BasicBlock GetNonBrOnlyFallThrough(BasicBlock basicBlock) {
            return IsBrOnlyBlock(basicBlock) ? GetNonBrOnlyFallThrough(basicBlock.FallThrough) : basicBlock;
        }

        private sealed class BlockInfo {
            private List<BasicBlock> _references;
            private List<BasicBlock> _dereferences;
            private bool _isInlineed;

            public List<BasicBlock> References {
                get => _references;
                set => _references = value;
            }

            public List<BasicBlock> Dereferences {
                get => _dereferences;
                set => _dereferences = value;
            }

            public bool IsInlineed {
                get => _isInlineed;
                set => _isInlineed = value;
            }

            public BlockInfo() {
                _references = new List<BasicBlock>();
                _dereferences = new List<BasicBlock>();
            }
        }
    }
}
```

It cannot be emphasized enough that the series of control flow analysis articles are definitely not easy. A superficial glance is not enough to understand the code posted above completely. To fully understand the complete process, you still need to compile the code posted above (put it in the source code released in the previous article and compile it), and step through it in VS for a thorough examination.

### Standardize

The previous three sections are all operations needed for standardization. What is standardization? Simplifying control flow to its simplest form is standardization. After standardizing the control flow, matching features will become much easier and the cleaning effect can be greatly improved.

Code:

``` csharp
/// <summary>
/// Create a standardized method block
/// </summary>
/// <param name="methodDef"></param>
/// <returns></returns>
public static MethodBlock CreateStandardMethodBlock(this MethodDef methodDef) {
    if (methodDef == null)
        throw new ArgumentNullException(nameof(methodDef));

    MethodBlock methodBlock;

    methodBlock = methodDef.CreateMethodBlock();
    methodBlock.Standardize();
    return methodBlock;
}

/// <summary>
/// Standardize the method block (remove NOP, inline, sort)
/// </summary>
/// <param name="methodBlock"></param>
public static void Standardize(this MethodBlock methodBlock) {
    if (methodBlock == null)
        throw new ArgumentNullException(nameof(methodBlock));

    NopRemover.Remove(methodBlock);
    BlockSorter.Sort(methodBlock);
    // Sorting is not for sorting purposes, but to remove invalid blocks, otherwise BlockInliner may not completely inline them.
    BlockInliner.Inline(methodBlock);
    BlockSorter.Sort(methodBlock);
    // DFS Sort
}
```

## Switch Obfuscation

The most difficult control flow obfuscation I have encountered so far should be ConfuserEx's Switch obfuscation. If you can handle ConfuserEx's Switch obfuscation, other control flow obfuscations should be no problem. Therefore, this section only discusses ConfuserEx. The compiled tool can be found at the end of the article.

ConfuserEx has many types of control flow obfuscation modes. Here, we only discuss the Control Flow Protection mode added by ConfuserEx-GUI, which is the Switch-Normal mode. Other modes can be found in the official document [Control Flow Protection - Wiki](https://github.com/yck1509/ConfuserEx/wiki/Control-Flow-Protection). The deobfuscation principles of other modes are almost the same, so we won't repeat it here.

As for some modified versions of ConfuserEx, the changes in control flow obfuscation are not particularly large, and the deobfuscation principles are also the same.

### Analysis

Find a program that has been obfuscated with ConfuserEx's control flow obfuscation and use dnSpy to check for features.

![](/../net-control-flow-analysis-2-deobfuscation/11.png)

It is clear that this type of obfuscation cannot be decrypted statically and the next case to jump to is related to the previous one. DnSpy shows that two local variables control the control flow. Is that the case?

No! One of them is generated by the decompiler.

Let's take a look at the IL:

![](/../net-control-flow-analysis-2-deobfuscation/12.png)

![](/../net-control-flow-analysis-2-deobfuscation/13.png)

Only local variable V_1 is in use.

Why are the constants generated by ConfuserEx's control flow obfuscation so large? The key is a modulo operation, such as x%7, where the range of results is {0, 1, 2, 3, 4, 5, 6}, exactly seven results.

![](/../net-control-flow-analysis-2-deobfuscation/14.png)

For example, in this switch, there are seven conditional jump targets, so it is %7, or divide by 7 and take the remainder.

We also notice that there are two types of assignments to num, one related to the value of num itself, and one unrelated:

![](/../net-control-flow-analysis-2-deobfuscation/15.png)

Why is there code that simply assigns num = ????; and that's it? Isn't using context-related linear encoding stronger? This is definitely not intentional on the part of the ConfuserEx author, and there is a reason for it. We can take a look at the ConfuserEx source code, where we can find the answer:

![](/../net-control-flow-analysis-2-deobfuscation/16.png)

![](/../net-control-flow-analysis-2-deobfuscation/17.png)

This code means that if a basic block A has an unknown source, which means that there are non-known basic blocks that will jump to basic block A, then no linear decoding code will be generated. Because if an unknown basic block jumps to basic block A, the value of num at this time is uncertain, and if num = num * xxxx ^ xxxx; is still used, the decoded num will be incorrect.

So we can draw a conclusion about this linear Switch obfuscation:

![](/../net-control-flow-analysis-2-deobfuscation/18.png)

Linear Switch obfuscation is like a bunch of tangled lines in the picture, directly entering the inside, and the obfuscation cannot be cleaned up. And linear Switch obfuscation has at least one entry point prepared for unknown sources, which is the very fine lines pointed by the arrows in the picture, which are the places where num is directly assigned in ConfuserEx Switch obfuscation.

Let's take a look at it with the tool FlowGraph (with "Optimization" option turned on):

![](/../net-control-flow-analysis-2-deobfuscation/19.png)

The blue box encloses an entry point of this linear switch.

The same is true for other method bodies, as summarized earlier.

![](/../net-control-flow-analysis-2-deobfuscation/20.png)

![](/../net-control-flow-analysis-2-deobfuscation/21.png)

![](/../net-control-flow-analysis-2-deobfuscation/22.png)

Same features as previously summarized.

Therefore, to clean up the linear switch obfuscation, we can only enter from this type of entry point and execute part of the code virtually in order to achieve the desired effect.

### Virtual Machine

Symbol execution requires a virtual machine. Although there are ready-made virtual machines, such as the one in de4dot.blocks, I prefer to write my own. It's more comfortable and convenient for me to use, and modifying it is also easy. It's too tiring to look at someone else's code and then modify it myself. It's better to start with a new one.

The complete code for the virtual machine is also provided at the end of the article.

#### Opcode Classification

We can first classify all instruction opcodes and emulate only those that we need, not those that we don't.

Here is my classification:

``` csharp
Add
Add_Ovf
Add_Ovf_Un
And
Div
Div_Un
Mul
Mul_Ovf
Mul_Ovf_Un
Neg
Not
Or
Rem
Rem_Un
Shl
Shr
Shr_Un
Sub
Sub_Ovf
Sub_Ovf_Un
Xor
// Logical operation

Ceq
Cgt
Cgt_Un
Ckfinite
Clt
Clt_Un
// Comparison

Box
Castclass
Conv_I
Conv_I1
Conv_I2
Conv_I4
Conv_I8
Conv_Ovf_I
Conv_Ovf_I_Un
Conv_Ovf_I1
Conv_Ovf_I1_Un
Conv_Ovf_I2
Conv_Ovf_I2_Un
Conv_Ovf_I4
Conv_Ovf_I4_Un
Conv_Ovf_I8
Conv_Ovf_I8_Un
Conv_Ovf_U
Conv_Ovf_U_Un
Conv_Ovf_U1
Conv_Ovf_U1_Un
Conv_Ovf_U2
Conv_Ovf_U2_Un
Conv_Ovf_U4
Conv_Ovf_U4_Un
Conv_Ovf_U8
Conv_Ovf_U8_Un
Conv_R_Un
Conv_R4
Conv_R8
Conv_U
Conv_U1
Conv_U2
Conv_U4
Conv_U8
Unbox
Unbox_Any
// Conversion

Dup
Ldarg
Ldarga
Ldc_I4
Ldc_I8
Ldc_R4
Ldc_R8
Ldelem
Ldelem_I
Ldelem_I1
Ldelem_I2
Ldelem_I4
Ldelem_I8
Ldelem_R4
Ldelem_R8
Ldelem_Ref
Ldelem_U1
Ldelem_U2
Ldelem_U4
Ldelema
Ldfld
Ldflda
Ldftn
Ldind_I
Ldind_I1
Ldind_I2
Ldind_I4
Ldind_I8
Ldind_R4
Ldind_R8
Ldind_Ref
Ldind_U1
Ldind_U2
Ldind_U4
Ldlen
Ldloc
Ldloca
Ldnull
Ldobj
Ldsfld
Ldsflda
Ldstr
Ldtoken
Ldvirtftn
Newarr
Newobj
Pop
Starg
Stelem
Stelem_I
Stelem_I1
Stelem_I2
Stelem_I4
Stelem_I8
Stelem_R4
Stelem_R8
Stelem_Ref
Stfld
Stind_I
Stind_I1
Stind_I2
Stind_I4
Stind_I8
Stind_R4
Stind_R8
Stind_Ref
Stloc
Stobj
Stsfld
// Load and Assignment

Beq
Bge
Bge_Un
Bgt
Bgt_Un
Ble
Ble_Un
Blt
Blt_Un
Bne_Un
Br
Brfalse
Brtrue
Endfilter
Endfinally
Leave
Ret
Rethrow
Switch
Throw
// Branch

Call
Calli
Callvirt
// Call

Arglist
Cpblk
Cpobj
Initblk
Initobj
Isinst
Localloc
Mkrefany
Refanytype
Refanyval
Sizeof
// Miscellaneous
```

For example, to handle ConfuserEx control flow obfuscation, we only need to virtualize partial value assignment, allocation instructions, and all arithmetic instructions, which is very simple.

#### Virtual Values

I have divided the values in the virtual machine into several common types:

![](/../net-control-flow-analysis-2-deobfuscation/23.png)

Then create one interface after another to represent virtual values.

``` csharp
/// <summary>
/// Value type
/// </summary>
public enum ValueType {
    /// <summary>
    /// <see cref="object"/>
    /// </summary>
    Object,

    /// <summary>
    /// <see cref="bool"/>, <see cref="sbyte"/>, <see cref="byte"/>, <see cref="short"/>, <see cref="ushort"/>, <see cref="int"/>, <see cref="uint"/>
    /// In CLR, the minimum unit is 4 bytes.
    /// </summary>
    Int32,

    /// <summary>
    /// <see cref="long"/>, <see cref="ulong"/>
    /// </summary>
    Int64,

    /// <summary>
    /// Null values, which are represented by <see cref="AnyValue"/>.
    /// </summary>
    Null,

    /// <summary>
    /// Unknown values are represented by any type that inherits from <see cref="IValue"/>.
    /// For example, we can use <see cref="Int32Value"/> to represent a type of <see cref="Int32Value"/>, but the value itself is not certain.
    /// </summary>
    Unknown,

    /// <summary>
    /// Arrays are represented by <see cref="AnyValue"/>. <see cref="AnyValue.Value"/> will be an array of <see cref="IValue"/>.
    /// </summary>
    Array,

    /// <summary>
    /// User-defined types.
    /// </summary>
    User
}

/// <summary>
/// Representing a value.
/// </summary>
public interface IValue {
    /// <summary>
    /// Type
    /// </summary>
    ValueType Type { get; set; }

    /// <summary>
    /// Value types return a "this" pointer, while reference types perform a deep clone of self.
    /// </summary>
    /// <returns></returns>
    IValue Clone();
}
```

#### Architecture

I used the architecture from de4dot.blocks and made some modifications by separating the virtual machine and context.

``` csharp
/*
 * The design of the virtual machine itself was based on de4dot's implementation.
 * 
 * The following code should have no relation to the ControlFlow.Blocks project.
 * The conversion part should be completed by an extension class,
 * while the Emulator class only needs to emulate the function,
 * and doesn't need to concern itself with the type of block or exception handling blocks.
 * It only needs to return failure for the user to judge and handle.
 * The user needs to determine the reason for the emulation failure.
 * 
 * Like the ControlFlow.Blocks project,
 * SimplifyMacros(MethodDef) from ControlFlow.Blocks.Extensions should be used to simplify instructions before attempting to emulate them,
 * or else the emulation may fail.
 */

/// <summary>
/// Emulation context
/// </summary>
public sealed class EmulationContext {
    private readonly Dictionary<Local, IValue> _variables;
    private readonly Stack<IValue> _evaluationStack;

    /// <summary>
    /// Local varibales
    /// </summary>
    public Dictionary<Local, IValue> Variables => _variables;

    /// <summary>
    /// Evaluation stack
    /// </summary>
    public Stack<IValue> EvaluationStack => _evaluationStack;

    /// <summary>
    /// Constructor
    /// </summary>
    public EmulationContext() {
        _evaluationStack = new Stack<IValue>();
        _variables = new Dictionary<Local, IValue>();
    }

    /// <summary>
    /// Constructor
    /// </summary>
    /// <param name="variables"></param>
    public EmulationContext(IEnumerable<Local> variables) : this() {
        if (variables == null)
            throw new ArgumentNullException(nameof(variables));

        foreach (Local variable in variables)
            _variables.Add(variable, null);
    }

    private EmulationContext(Dictionary<Local, IValue> variables, Stack<IValue> evaluationStack) {
        if (variables == null)
            throw new ArgumentNullException(nameof(variables));
        if (evaluationStack == null)
            throw new ArgumentNullException(nameof(evaluationStack));

        _variables = variables;
        _evaluationStack = evaluationStack;
    }

    /// <summary>
    /// Clone the current instance.
    /// </summary>
    /// <returns></returns>
    public EmulationContext Clone() {
        IValue[] array;
        Stack<IValue> evaluationStack;
        Dictionary<Local, IValue> variables;

        array = _evaluationStack.ToArray();
        evaluationStack = new Stack<IValue>(_evaluationStack.Count);
        for (int i = array.Length - 1; i >= 0; i--)
            evaluationStack.Push(array[i].Clone());
        variables = new Dictionary<Local, IValue>(_variables.Count);
        foreach (KeyValuePair<Local, IValue> variable in _variables)
            variables.Add(variable.Key, variable.Value?.Clone());
        return new EmulationContext(variables, evaluationStack);
    }
}

/// <summary>
/// Emulation result
/// </summary>
public sealed class EmulationResult {
    private readonly bool _success;
    private readonly Instruction _failedInstruction;
    private readonly Exception _exception;

    /// <summary>
    /// Whether it was successful.
    /// </summary>
    public bool Success => _success;

    /// <summary>
    /// The instruction that caused the emulation to fail.
    /// </summary>
    public Instruction FailedInstruction => _failedInstruction;

    /// <summary>
    /// Exception (if any).
    /// </summary>
    public Exception Exception => _exception;

    internal EmulationResult(bool success, Instruction failedInstruction, Exception exception) {
        _success = success;
        _failedInstruction = failedInstruction;
        _exception = exception;
    }
}
```

To emulate an instruction, we give the virtual machine a context and the instruction to execute, and it returns the result of the execution. It's that simple and not complicated.

For example, if we want to virtually execute an arithmetic instruction, we must use C#'s lambda.

``` csharp
private bool Template_Arithmetic(Func<int, int, int> operation32, Func<long, long, long> operation64) {
    IValue x;
    IValue y;
    IValue result;

    y = EvaluationStack.Pop();
    x = EvaluationStack.Pop();
    result = CheckAndTryGetUnknownValue_Arithmetic(x, y);
    if (result != null) {
        EvaluationStack.Push(result);
        return true;
    }
    if (x is Int32Value && y is Int32Value) {
        if (operation32 == null)
            ThrowNotImpl();
        result = new Int32Value(operation32(((Int32Value)x).Int32, ((Int32Value)y).Int32));
    }
    else {
        if (operation32 == null)
            ThrowNotImpl();
        result = new Int64Value(operation64(GetInt64_Arithmetic(x), GetInt64_Arithmetic(y)));
    }
    EvaluationStack.Push(result);
    return true;
}

private static IValue CheckAndTryGetUnknownValue_Arithmetic(IValue x) {
    if (!(x is Int32Value) && !(x is Int64Value))
        ThrowErrorType();
    if (x.Type == ValueType.Unknown)
        return x is Int32Value ? (IValue)Int32Value.Unknown : Int64Value.Unknown;
    else
        return null;
}

private static IValue CheckAndTryGetUnknownValue_Arithmetic(IValue x, IValue y) {
    if ((!(x is Int32Value) && !(x is Int64Value)) || (!(y is Int32Value) && !(y is Int64Value)))
        ThrowErrorType();
    if (x.Type == ValueType.Unknown || y.Type == ValueType.Unknown)
        return x is Int32Value ? (IValue)Int32Value.Unknown : Int64Value.Unknown;
    else
        return null;
}

private static long GetInt64_Arithmetic(IValue value) {
    return value is Int32Value ? ((Int32Value)value).Int32 : ((Int64Value)value).Int64;
}
```

To emulate an arithmetic instruction, simply call Template_Arithmetic. It's very simple.

``` csharp
protected virtual bool Emulate_Add(Instruction instruction) {
    return Template_Arithmetic((x, y) => x + y, (x, y) => x + y);
}

protected virtual bool Emulate_And(Instruction instruction) {
    return Template_Arithmetic((x, y) => x & y, (x, y) => x & y);
}

protected virtual bool Emulate_Div(Instruction instruction) {
    return Template_Arithmetic((x, y) => x / y, (x, y) => x / y);
}
```

The rest is straightforward: there's a big loop wrapped in a switch statement to determine the opcode, then it calls the corresponding method to perform the virtual execution. I won't include the code here.

### Clean up

With the virtual machine, it becomes much easier to clear away Switch obfuscation. We can start clearing it away now.

First, we'll handle some special cases.

ConfuserEx will convert conditional jump instructions to this form:

![](/../net-control-flow-analysis-2-deobfuscation/24.png)

![](/../net-control-flow-analysis-2-deobfuscation/25.png)

Here, dup and pop are intentionally interfering with our code, and they can be removed directly.

The core code to remove these dup and pop blocks (other code omitted, just understand the idea):

``` csharp
private void HandleMultiDupWithOnePop(BasicBlock popBlock) {
    // We're temporarily only handling this case, where multiple dup blocks correspond to a single pop block (ConfuserEx). 
    // I haven't seen any cases where a single dup block corresponds to multiple pop blocks.
    int popCount;
    List<BasicBlock> dupBlocks;
    int dupCount;

    popCount = GetPopCount(popBlock);
    if (popCount == 0)
        return;
    dupBlocks = popBlock.PeekExtraData<BlockInfo>().Dereferences;
    // Assuming backreferences have dup
    if (dupBlocks.Count == 0)
        // The entry point of the scope may not have a back reference, such as the method block entry point or catch block entry point.
        return;
    foreach (BasicBlock dupBlock in dupBlocks)
        if (dupBlock.BranchOpcode.Code != Code.Br)
            // It must be an unconditional jump to the pop block.
            return;
    dupCount = int.MaxValue;
    foreach (BasicBlock dupBlock in dupBlocks) {
        int temp;

        temp = GetDupCount(dupBlock);
        if (temp < dupCount)
            dupCount = temp;
    }
    // Find the minimum number of dup blocks.
    if (dupCount == 0)
        return;
    if (popCount < dupCount)
        dupCount = popCount;
    // Find the minimum number of paired dup-pop blocks.
    popBlock.Instructions.RemoveRange(0, dupCount);
    // Remove the leading pop from the pop block.
    foreach (BasicBlock dupBlock in dupBlocks)
        dupBlock.Instructions.RemoveRange(dupBlock.Instructions.Count - dupCount, dupCount);
    // Remove the trailing dup from the dup block.
    _dupCount += dupCount;
}
```

Like with BlockInliner, we also need to inline ConfuserEx's obfuscated If statements to make it easier to mark the instructions for emulation to clean them up.

![](/../net-control-flow-analysis-2-deobfuscation/26.png)

For example, in the red box below, the basic block can be inlined to the upper two basic blocks.

First, we define an abstract class to write the logic for cleaning up linear Switch obfuscation, and the recognition part is implemented in subclasses for code reuse.

Here's the code for the abstract class:

``` csharp
/// <summary>
/// Linear Switch Deobfuscation (e.g. ConfuserEx)
/// We only clean up one linear switch at a time, otherwise the code will become extremely complex.
/// </summary>
public abstract class LinearSwitchDeobfuscatorBase : BlockRecursiveModel {
    /// <summary>
    /// Instruction emulator
    /// </summary>
    protected readonly Emulator _emulator;
    /// <summary>
    /// Switch block
    /// </summary>
    protected BasicBlock _switchBlock;
    private bool _isModified;

    /// <summary />
    protected LinearSwitchDeobfuscatorBase(List<IBlock> blocks, IBlock scope, EmulationContext emulationContext) : base(blocks, scope) {
        _emulator = new Emulator(emulationContext);
    }

    /// <summary />
    protected static bool Deobfuscate(MethodBlock methodBlock, BlockRecursiveModelCreator deobfuscatorCreator) {
        return Execute(methodBlock, deobfuscatorCreator);
    }

    /// <summary />
    protected override bool Execute() {
        if (_blocks.Count < 2)
            return false;
        OnBegin();
        if (_switchBlock == null)
            return false;
        foreach (BasicBlock entry in GetEntries())
            VisitAllBasicBlocks(entry);
        OnEnd();
        return _isModified;
    }

    /// <summary>
    /// Visit the specified basic block and recursively visit all jump targets of this block.
    /// </summary>
    /// <param name="basicBlock"></param>
    protected void VisitAllBasicBlocks(BasicBlock basicBlock) {
        BlockInfoBase blockInfo;

        if (basicBlock.Scope != _scope)
            // If the specified basic block is not in the current scope, there is no need to continue visiting it.
            return;
        blockInfo = basicBlock.PeekExtraData<BlockInfoBase>();
        if (blockInfo.IsVisited && basicBlock != _switchBlock)
            // If the basic block has already been visited and is not a switch block, return directly.
            return;
        blockInfo.IsVisited = true;
        if (blockInfo.EmulationInfo != null) {
            // If emulation is required:
            EmulationInfo emulationInfo;
            EmulationResult emulationResult;

            emulationInfo = blockInfo.EmulationInfo;
            _isModified |= OnEmulateBegin(basicBlock);
            emulationResult = _emulator.Emulate(basicBlock.Instructions, emulationInfo.StartIndex, emulationInfo.Length);
            _isModified |= OnEmulateEnd(basicBlock);
            if (!emulationResult.Success)
                throw new NotImplementedException("Emulation failure handling is not yet implemented. Updating the deobfuscation model or checking whether unnecessary instructions have been emulated may be necessary.");
        }
        if (basicBlock == _switchBlock)
            // We need to set the next basic block to visit.
            VisitAllBasicBlocks(GetNextBasicBlock());
        else
            // If it is not a switch block, we recursively visit the next basic block.
            switch (basicBlock.BranchOpcode.FlowControl) {
            case FlowControl.Branch:
                // Unconditional jump does not require backing up the current emulator context.
                VisitAllBasicBlocks(basicBlock.FallThrough);
                break;
            case FlowControl.Cond_Branch:
                CallNextVisitAllBasicBlocksConditional(basicBlock);
                break;
            }
    }

    /// <summary>
    /// Triggered before all operations begin.
    /// In this method, additional information must be added to all basic blocks in _blocks and the field <see cref="_switchBlock"/> must be set.
    /// If the switch block is not found, return directly instead of throwing an exception.
    /// </summary>
    protected abstract void OnBegin();

    /// <summary>
    /// Triggered after all operations are completed.
    /// In this method, all additional information for basic blocks in _blocks must be removed.
    /// </summary>
    protected abstract void OnEnd();

    /// <summary>
    /// Get available emulation entry points.
    /// </summary>
    /// <returns></returns>
    protected abstract IEnumerable<BasicBlock> GetEntries();

    /// <summary>
    /// Triggered before emulating the specified basic block and returns whether the current basic block has been modified.
    /// </summary>
    /// <param name="basicBlock"></param>
    /// <returns></returns>
    protected abstract bool OnEmulateBegin(BasicBlock basicBlock);

    /// <summary>
    /// Triggered after emulating the specified basic block and returns whether the current basic block has been modified.
    /// </summary>
    /// <param name="basicBlock"></param>
    /// <returns></returns>
    protected abstract bool OnEmulateEnd(BasicBlock basicBlock);

    /// <summary>
    /// After encountering a switch block, get the next basic block using the emulator.
    /// </summary>
    /// <returns></returns>
    protected virtual BasicBlock GetNextBasicBlock() {
        Int32Value value;

        value = _emulator.EvaluationStack.Pop() as Int32Value;
        if (value == null)
            throw new InvalidOperationException();
        return _switchBlock.SwitchTargets[value.Int32];
    }

    /// <summary>
    /// When encountering a conditional jump, recursively call VisitAllBasicBlocks.
    /// </summary>
    /// <param name="basicBlock">Basic block with conditional jump.</param>
    protected virtual void CallNextVisitAllBasicBlocksConditional(BasicBlock basicBlock) {
        EmulationContext context;

        context = _emulator.Context.Clone();
        // For conditional jumps with multiple jump targets, back up the current emulator context.
        if (basicBlock.FallThrough != null) {
            VisitAllBasicBlocks(basicBlock.FallThrough);
            _emulator.Context = context;
            // Restore the emulator context.
        }
        if (basicBlock.ConditionalTarget != null) {
            VisitAllBasicBlocks(basicBlock.ConditionalTarget);
            _emulator.Context = context;
        }
        if (basicBlock.SwitchTargets != null)
            foreach (BasicBlock target in basicBlock.SwitchTargets) {
                VisitAllBasicBlocks(target);
                _emulator.Context = context;
            }
    }

    /// <summary>
    /// Base class for additional basic block information.
    /// </summary>
    protected abstract class BlockInfoBase {
        /// <summary />
        protected bool _isVisited;
        /// <summary />
        protected EmulationInfo _emulationInfo;

        /// <summary>
        /// Whether this basic block has been visited.
        /// </summary>
        public bool IsVisited {
            get => _isVisited;
            set => _isVisited = value;
        }

        /// <summary>
        /// Emulation-related information.
        /// If emulation is required, set this property to a non-<see langword="null"/> value; otherwise, keep it as the default, which is <see langword="null"/>.
        /// </summary>
        public EmulationInfo EmulationInfo {
            get => _emulationInfo;
            set => _emulationInfo = value;
        }
    }

    /// <summary>
    /// Provide information needed for emulation.
    /// </summary>
    protected sealed class EmulationInfo {
        private readonly int _startIndex;
        private readonly int _length;

        /// <summary>
        /// Emulate starting from the instruction at the specified index.
        /// </summary>
        public int StartIndex => _startIndex;

        /// <summary>
        /// Number of instructions to emulate.
        /// </summary>
        public int Length => _length;

        /// <summary>
        /// Constructor
        /// </summary>
        /// <param name="startIndex"></param>
        /// <param name="length"></param>
        public EmulationInfo(int startIndex, int length) {
            _startIndex = startIndex;
            _length = length;
        }
    }
}
```

The code is not much, the core part is still in the methods with "VisitAllBasicBlocks" in their names. For example, VisitAllBasicBlocks emulates the normal execution flow of the program. When encountering a Switch obfuscation, it performs emulation and completes the decryption of the Switch obfuscation in OnEmulateEnd.

After so many cleanup operations, the Switch obfuscation of ConfuserEx is almost exposed, and its features become very obvious. We can inherit from LinearSwitchDeobfuscatorBase and then identify the features to remove it.

``` csharp
public sealed class LinearSwitchDeobfuscator : LinearSwitchDeobfuscatorBase {
    private BasicBlock _lastCaseBlockAny;

    private LinearSwitchDeobfuscator(List<IBlock> blocks, IBlock scope, EmulationContext emulationContext) : base(blocks, scope, emulationContext) {
    }

    public static bool Deobfuscate(MethodBlock methodBlock) {
        bool isModified;

        isModified = false;
        while (Deobfuscate(methodBlock, (blocks, scope) => new LinearSwitchDeobfuscator(blocks, scope, methodBlock.CreateEmulationContext()))) {
            // We can only clean up one linear switch at a time, so we use a while loop.
            methodBlock.Standardize();
            isModified = true;
        }
        return isModified;
    }

    protected override void OnBegin() {
        foreach (BasicBlock basicBlock in _blocks.EnumerateAllBasicBlocks())
            if (IsLinearSwitchBlock(basicBlock)) {
                _switchBlock = basicBlock;
                break;
            }
        // First, find the switch block.
        if (_switchBlock == null)
            return;
        foreach (BasicBlock basicBlock in _blocks.EnumerateAllBasicBlocks()) {
            if (basicBlock == _switchBlock)
                basicBlock.PushExtraData(new BlockInfo(BlockType.LinearSwitch) {
                    EmulationInfo = new EmulationInfo(0, SwitchConstants.LinearSwitchCodes.Length)
                });
            else if (IsCaseBlock(basicBlock))
                basicBlock.PushExtraData(new BlockInfo(BlockType.Case) {
                    EmulationInfo = new EmulationInfo(basicBlock.Instructions.Count - SwitchConstants.CaseCodes.Length, SwitchConstants.CaseCodes.Length)
                });
            else if (IsLinearCaseBlock(basicBlock))
                basicBlock.PushExtraData(new BlockInfo(BlockType.LinearCase) {
                    EmulationInfo = new EmulationInfo(basicBlock.Instructions.Count - SwitchConstants.LinearCaseCodes1.Length, SwitchConstants.LinearCaseCodes1.Length)
                    // The lengths of LinearCaseCodes1 and LinearCaseCodes2 are the same.
                });
            else
                basicBlock.PushExtraData(new BlockInfo(BlockType.Normal));
        }
    }

    private bool IsLinearSwitchBlock(BasicBlock basicBlock) {
        return basicBlock.BranchOpcode.Code == Code.Switch && basicBlock.Instructions.CodeEquals(SwitchConstants.LinearSwitchCodes);
    }

    private bool IsCaseBlock(BasicBlock basicBlock) {
        return basicBlock.BranchOpcode.Code == Code.Br && basicBlock.FallThrough == _switchBlock && basicBlock.Instructions.EndsWith(SwitchConstants.CaseCodes);
    }

    private bool IsLinearCaseBlock(BasicBlock basicBlock) {
        return basicBlock.BranchOpcode.Code == Code.Br &&
            basicBlock.FallThrough == _switchBlock &&
            (basicBlock.Instructions.EndsWith(SwitchConstants.LinearCaseCodes1) ||
            basicBlock.Instructions.EndsWith(SwitchConstants.LinearCaseCodes2));
    }

    protected override void OnEnd() {
        foreach (BasicBlock basicBlock in _blocks.EnumerateAllBasicBlocks())
            basicBlock.PopExtraData();
    }

    protected override IEnumerable<BasicBlock> GetEntries() {
        foreach (BasicBlock basicBlock in _blocks.EnumerateAllBasicBlocks())
            if (basicBlock.PeekExtraData<BlockInfo>().Type == BlockType.Case)
                yield return basicBlock;
    }

    protected override bool OnEmulateBegin(BasicBlock basicBlock) {
        return false;
    }

    protected override bool OnEmulateEnd(BasicBlock basicBlock) {
        BlockInfo blockInfo;

        blockInfo = basicBlock.PeekExtraData<BlockInfo>();
        switch (blockInfo.Type) {
        case BlockType.LinearSwitch:
            Int32Value value;

            if (_lastCaseBlockAny == null)
                throw new InvalidOperationException();
            value = _emulator.EvaluationStack.Peek() as Int32Value;
            if (value == null)
                throw new InvalidOperationException();
            _lastCaseBlockAny.FallThrough = _switchBlock.SwitchTargets[value.Int32];
            _lastCaseBlockAny = null;
            return true;
        case BlockType.Case:
            basicBlock.Instructions.RemoveTrailingRange(SwitchConstants.CaseCodes.Length);
            _lastCaseBlockAny = basicBlock;
            break;
        case BlockType.LinearCase:
            basicBlock.Instructions.RemoveTrailingRange(SwitchConstants.LinearCaseCodes1.Length);
            _lastCaseBlockAny = basicBlock;
            break;
        }
        return false;
    }

    private enum BlockType {
        Normal,
        LinearSwitch,
        Case,
        LinearCase
    }

    private sealed class BlockInfo : BlockInfoBase {
        private readonly BlockType _type;

        public BlockType Type => _type;

        public BlockInfo(BlockType type) {
            _type = type;
        }
    }
}
```

The cleanup part of this code is in OnEmulateEnd, which is like a hook. We intercept the current calculation stack before the switch jumps to its target, get the number "num" in "switch(num)", and then we know where the previous basic block needs to jump to. Then we modify the jump target of the previous basic block to complete the cleanup operation.

If ConfuserEx's Switch obfuscation has added many layers, we need to check again whether it is really a linear switch. For example, if it is like this, it is not a linear switch:

![](/../net-control-flow-analysis-2-deobfuscation/27.png)

If we do not first clean up these non-linear switches before cleaning up the linear switch, it may cause errors.

## Download

Control Flow Graph Drawing Tool: [FlowGraph.zip](/../net-control-flow-analysis-2-deobfuscation/FlowGraph.zip)

Deobfuscation Tool: [ConfuserExSwitchDeobfuscator.zip](/../net-control-flow-analysis-2-deobfuscation/ConfuserExSwitchDeobfuscator.zip)

Emulator: [ControlFlow.Emulation.zip](/../net-control-flow-analysis-2-deobfuscation/ControlFlow.Emulation.zip)

UnpackMe used to test ConfuserExSwitchDeobfuscator, I added control flow obfuscation with 15 iterations: [test.cexcf.ultimate.dnlib.dll.zip](/../net-control-flow-analysis-2-deobfuscation/test.cexcf.ultimate.dnlib.dll.zip)
