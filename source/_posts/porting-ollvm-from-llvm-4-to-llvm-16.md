---
title: 将OLLVM从LLVM4移植到LLVM16
date: 2023-08-17 14:00:00
updated: 2023-08-17 14:00:00
lang: zh-CN
categories:
- [LLVM]
- [OLLVM]
tags:
- LLVM
- OLLVM
- 编译
toc: true
---

<!-- # 将OLLVM从LLVM4移植到LLVM16 -->

本文介绍了将OLLVM从官方的LLVM4分支移植到最新的LLVM16，包含LLVM API更新和OLLVM的BUG修复。

<!-- more -->

# 完整源码

我不想知道怎么适配的，给我源码！这是GitHub链接：[wwh1004/ollvm-16](https://github.com/wwh1004/ollvm-16)，编译教程在README.md，编译好的clang-cl.exe在Release页面下载。

# 适配教程

LLVM从4.0到16.0包含了一些API更新，还有行为的改变，所以OLLVM的代码直接编译是过不了的，而且也不适配最新的LLVM 16.0。所以这篇移植教程包括了新API的适配，和对LLVM新行为的适配，还有对OLLVM本身bug的修复。

## CMakeLists.txt更新

老的CMakeLists.txt如下：

```
add_llvm_library(LLVMObfuscation
  CryptoUtils.cpp
  Substitution.cpp
  BogusControlFlow.cpp
  Utils.cpp
  SplitBasicBlocks.cpp
  Flattening.cpp
  )

add_dependencies(LLVMObfuscation intrinsics_gen)
```

LLVMObfuscation表示项目名称，根据LLVM的项目命名规则，因为是直接嵌入到LLVM内部的，LLVM就是一个必须的前缀。

我们用新的插件方式创建项目，可以降低日后更新工作量，CMakeLists.txt这样写：

```
add_llvm_pass_plugin(Obfuscation
  CryptoUtils.cpp
  Substitution.cpp
  BogusControlFlow.cpp
  Utils.cpp
  SplitBasicBlock.cpp
  Flattening.cpp
  Plugin.cpp

  ADDITIONAL_HEADER_DIRS
  ${PROJECT_SOURCE_DIR}

  DEPENDS
  intrinsics_gen
  )
```

因为是作为插件形式（可以静态链接进LLVM，也可以外挂），所以LLVM前缀是不需要的了，项目名就叫Obfuscation。

## API更新

首先是BinaryOperator中一些关于浮点数的运算移动到了UnaryOperator中，比如：

``` diff
-void Substitution::addDoubleNeg(BinaryOperator *bo) {
-  BinaryOperator *op, *op2 = NULL;
+void addDoubleNeg(BinaryOperator *bo) {
+  Instruction *op, *op2 = NULL;
 
   if (bo->getOpcode() == Instruction::Add) {
     op = BinaryOperator::CreateNeg(bo->getOperand(0), "", bo);
     // op->setHasNoSignedWrap(bo->hasNoSignedWrap());
     // op->setHasNoUnsignedWrap(bo->hasNoUnsignedWrap());
   } else {
-    op = BinaryOperator::CreateFNeg(bo->getOperand(0), "", bo);
-    op2 = BinaryOperator::CreateFNeg(bo->getOperand(1), "", bo);
+    op = UnaryOperator::CreateFNeg(bo->getOperand(0), "", bo);
+    op2 = UnaryOperator::CreateFNeg(bo->getOperand(1), "", bo);
     op = BinaryOperator::Create(Instruction::FAdd, op, op2, "", bo);
-    op = BinaryOperator::CreateFNeg(op, "", bo);
+    op = UnaryOperator::CreateFNeg(op, "", bo);
   }
 
   bo->replaceAllUsesWith(op);
 }
```

然后许多Instruction的创建需要指定类型了，构造器第一个参数是类型，比如：

``` diff
+  Type *I32Ty = Type::getInt32Ty(F.getContext());
   // Create switch variable and set as it
-  switchVar =
-      new AllocaInst(Type::getInt32Ty(f->getContext()), 0, "switchVar", insert);
+  switchVar = new AllocaInst(I32Ty, 0, "switchVar", insert);
   new StoreInst(
       ConstantInt::get(I32Ty, llvm::cryptoutils->scramble32(0, scrambling_key)),
       switchVar, insert);
   ...
-  load = new LoadInst(switchVar, "switchVar", loopEntry);
+  load = new LoadInst(I32Ty, switchVar, "switchVar", loopEntry);
```

## 新PM适配

新Pass Manager的适配不是很麻烦，大致有2个关注点。一个是Pass类的定义需要更改，runOnFunction变成了run，基类型变了。另一个是Pass的注册和插入时机。

首先看Pass类的变化，以Flattening为例，这个是原来的定义方法：

``` cpp
struct Flattening : public FunctionPass {
  static char ID;
  Flattening() : FunctionPass(ID) {}
  bool runOnFunction(Function &F) {
    Function *tmp = &F;
    // Do we obfuscate
    if (toObfuscate(flag, tmp, "fla")) {
      if (flatten(tmp)) {
        ++Flattened;
      }
    }
    return false;
  }
};
```

然后我们需要更改成新的：

``` cpp
class FlatteningPass : public PassInfoMixin<FlatteningPass> {
public:
  PreservedAnalyses run(Function &F, FunctionAnalysisManager &AM) {
    // Do we obfuscate
    if (toObfuscate(Flattening, &F, "fla")) {
      if (flatten(F)) {
        ++Flattened;
      }
      return PreservedAnalyses::none();
    }
    return PreservedAnalyses::all();
  }
  static bool isRequired() { return true; }
};
```

isRequired返回true的作用是让O0优化级别的时候，也就是带有optnone标识的时候，Pass依然运行。

runOnFunction函数返回一个bool类型，新的run函数返回一个PreservedAnalyses结构表示哪些Analysis Pass的结果有变化。比如没有任何改变，可以返回PreservedAnalyses::all()表示保留全部分析结果；如果变化了，可以返回PreservedAnalyses::none()表示分析结果全部失效，需要重新计算。

其它Pass的修改方式相同，难度不高。

接下来是新Pass Manager的Pass注册方式变化。

老的注册方式是定义一个全局变量，调用RegisterPass类进行注册：

``` cpp
static RegisterPass<BogusControlFlow> X("boguscf", "inserting bogus control flow");
```

新的注册方式有两种，一是修改PassRegistry.def和PassBuilder.cpp文件，直接追加Pass定义进去，但是这种比较麻烦。我们使用第二种，用插件接口进行注册。

我们创建一个新的C++源码文件Plugin.cpp，名字可以随便。因为我们CMakeLists.txt里面的项目名称就是Obfuscation，那么添加函数getObfuscationPluginInfo。如果CMakeLists.txt

``` cpp
llvm::PassPluginLibraryInfo getObfuscationPluginInfo() {
  return {
      LLVM_PLUGIN_API_VERSION, "Obfuscation", LLVM_VERSION_STRING,
      [](PassBuilder &PB) {
        ...
      }};
}
```

我们不需要显式注册Pass到LLVM内部，我们只需要通过回调函数把Pass注入到PassBuilder的Pipeline里面就行。

根据OLLVM原始代码看，bcf、fla、split这三个Pass是在Pipeline最开始时运行的，那么我们使用registerPipelineStartEPCallback进行注入：

``` cpp
PB.registerPipelineStartEPCallback([](llvm::ModulePassManager &MPM, OptimizationLevel Level) {
  MPM.addPass(createModuleToFunctionPassAdaptor(SplitBasicBlockPass()));
  MPM.addPass(createModuleToFunctionPassAdaptor(BogusControlFlowPass()));
  MPM.addPass(createModuleToFunctionPassAdaptor(FlatteningPass()));
});
```

sub这个Pass是在优化完成后运行的，那么我们用registerOptimizerLastEPCallback进行注入：

``` cpp
PB.registerOptimizerLastEPCallback([](llvm::ModulePassManager &MPM, OptimizationLevel Level) {
  MPM.addPass(createModuleToFunctionPassAdaptor(SubstitutionPass()));
});
```

最后我们的文件内容如下：

``` cpp
#include "BogusControlFlow.h"
#include "Flattening.h"
#include "SplitBasicBlock.h"
#include "Substitution.h"
#include "llvm/Passes/PassBuilder.h"
#include "llvm/Passes/PassPlugin.h"

using namespace llvm;

llvm::PassPluginLibraryInfo getObfuscationPluginInfo() {
  return {
      LLVM_PLUGIN_API_VERSION, "Obfuscation", LLVM_VERSION_STRING,
      [](PassBuilder &PB) {
        PB.registerPipelineStartEPCallback([](llvm::ModulePassManager &MPM,
                                              OptimizationLevel Level) {
          MPM.addPass(createModuleToFunctionPassAdaptor(SplitBasicBlockPass()));
          MPM.addPass(
              createModuleToFunctionPassAdaptor(BogusControlFlowPass()));
          MPM.addPass(createModuleToFunctionPassAdaptor(FlatteningPass()));
        });
        PB.registerOptimizerLastEPCallback([](llvm::ModulePassManager &MPM,
                                              OptimizationLevel Level) {
          MPM.addPass(createModuleToFunctionPassAdaptor(SubstitutionPass()));
        });
      }};
}

#ifndef LLVM_OBFUSCATION_LINK_INTO_TOOLS
extern "C" LLVM_ATTRIBUTE_WEAK ::llvm::PassPluginLibraryInfo
llvmGetPassPluginInfo() {
  return getObfuscationPluginInfo();
}
#endif
```

llvmGetPassPluginInfo的意义是，如果项目不是静态链接到LLVM，也就是编译为so/dll进行动态载入，那么使用llvmGetPassPluginInfo作为导出函数给LLVM注册Pass。可惜的是Windows不支持LLVM插件，我们只能静态链接。

## 不存在createLowerSwitchPass

这个是老PM时，Pass的创建方式。Flattening.cpp里面需要这个Pass，我们改成新Pass的调用方式即可。

``` cpp
LowerSwitchPass lower;
lower.run(F, AM);
```

## 修复/dev/random打开失败

问题原因是Windows下没有/dev/random和/dev/urandom，原版的OLLVM并不适配Windows。

修复方法是使用Windows API CryptGenRandom。这里我直接从网上抄了一份下来，就不给代码了，可以去文章开头写的GitHub链接上看，在CryptoUtils.cpp里。

## 修复SplitBasicBlock

这个Pass有个问题，处理基本块指令数量为2的时候，就会出错。问题定位在：

``` cpp
// Check splitN and current BB size
if ((size_t)splitN > curr->size()) {
  splitN = curr->size() - 1;
}
```

splitN默认是2，如果基本块的指令数量也为2，那么分割肯定会下标越界。

所以修复方法是把>改成>=就行了。

``` cpp
// Check splitN and current BB size
if ((size_t)splitN >= curr->size()) {
  splitN = curr->size() - 1;
}
```

## 修复mismatched subprogram

问题定位在BogusControlFlow.cpp的createAlteredBasicBlock函数。

createAlteredBasicBlock分为三步走，第一步是调用llvm::CloneBasicBlock创建克隆的基本块。克隆的基本块是不能直接用的，比如AllocaInstr分配的指针是新的，但是StoreInstr赋值的指针还是老的，所以需要修复。

那么第二步就是对克隆后的指令进行修复，让指令的操作数映射到克隆的指令上。这里OLLVM使用了MapValue函数。

第三步就是创建随机垃圾指令，然后设置一个恒假跳转语句跳转到这个假分支上。

问题出在了第二步上，LLVM有Intrinsic叫DbgInfoIntrinsic，在LLVM IR一般都表示为：

```
call void @llvm.dbg.value(metadata ptr null, metadata !575, metadata !DIExpression()), !dbg !585
!575 = !DILocalVariable(name: "data", scope: !565, file: !3, line: 12, type: !576)
!585 = !DILocation(line: 0, scope: !565)
!565 = distinct !DISubprogram(name: "kull_m_rpc_drsr_RpcSecurityCallback", scope: !3, file: !3, line: 8, type: !566, scopeLine: 9, flags: DIFlagPrototyped, spFlags: DISPFlagDefinition | DISPFlagOptimized, unit: !2, retainedNodes: !568)
```

LLVM要求DbgInfoIntrinsic的DISubprogram与其附加的DebugLoc中的DISubprogram一致，也就是上面例子中metadata !575（作为Intrinsic的第二个参数）和!dbg !585的DISubprogram一致。因为DISubprogram表示IR对应的C++代码所在的源码文件位置，如果两处不一致显然是不合理的。

OLLVM调用MapValue会对DbgInfoIntrinsic进行映射，映射结果是正确的，但是第二个参数（metadata !575）被进行了一份拷贝，最后的DebugLoc（!dbg !585）不会进行拷贝，导致第二个参数对应的DISubprogram内容是一样的，但是与最后的DebugLoc的DISubprogram不是同一个实例了。这样比较两个DISubprogram就会返回false。

``` cpp
DISubprogram *LabelSP = getSubprogram(Label->getRawScope());
DISubprogram *LocSP = getSubprogram(Loc->getRawScope());
if (!LabelSP || !LocSP)
  return;

CheckDI(LabelSP == LocSP,
        "mismatched subprogram between llvm.dbg." + Kind +
            " label and !dbg attachment",
        &DLI, BB, F, Label, Label->getScope()->getSubprogram(), Loc,
        Loc->getScope()->getSubprogram());
```

修复方法有两个，一个是更新最后的DebugLoc，另一个是把所有DbgInfoIntrinsic删了。

显然第二个更简单，本来就是个假的基本块，不会执行的，有调试信息也没什么用。添加下面的代码到第二步的后面，就可以修复这个问题。

``` cpp
for (auto I = alteredBB->begin(), E = alteredBB->end(); I != E;) {
  Instruction *Instr = &*I++;
  if (isa<DbgInfoIntrinsic>(Instr))
    Instr->eraseFromParent();
}
```

## 修复CatchPadInst not the first non-PHI instruction

问题定位在BogusControlFlow.cpp的addBogusFlow函数。

比如有如下IR，addBogusFlow正在处理147这个基本块：

```
143:                                              ; preds = ...
  %144 = phi i32 ...
  %145 = phi i32 ...
  %146 = catchswitch within none [label %147] unwind to caller, !dbg !783

147:                                              ; preds = %143
  %148 = catchpad within %146 [ptr @"?filt$0@0@xx@@"], !dbg !783
  catchret from %148 to label %149, !dbg !783
```

第一条非PHI指令就是catchpad了，那么addBogusFlow会使用basicBlock->splitBasicBlock(i1, *var)把147这个基本块分成两份：


```
143:                                              ; preds = ...
  %144 = phi i32 ...
  %145 = phi i32 ...
  %146 = catchswitch within none [label %147] unwind to caller, !dbg !783

147:                                              ; preds = %143
  br label %originalBB147

originalBB147:                                    ; preds = %147
  %148 = catchpad within %146 [ptr @"?filt$0@0@xx@@"], !dbg !783
  catchret from %148 to label %149, !dbg !783
```

这时候问题就出现了，147基本块作为catchswitch的一个catch块，第一条指令不是catchpad了，LLVM就会处理不了这种异常表示（LLVM要求处理异常的基本块的EH指令需要是第一条）。

解决方法也很简单，在addBogusFlow函数开头判断当前处理的基本块是不是第一条指令为catchpad，如果是的话，就不处理：

``` cpp
if (basicBlock->getFirstNonPHI()->isEHPad())
  return;
```

这里使用了isEHPad来判断，原因是和这个报错同类型的不止一条，比如"The unwind destination does not have an exception handling instruction!"。原因都是EH相关指令不在基本块第一条，所以这里为了方便，只要第一条指令是EHPad，那就认为这个块是EH块，直接跳过处理。也不需要从EHPad后面的指令处理，因为这样有很多可能，比如可能改变支配关系什么的，导致什么奇奇怪怪的问题，这里就不给自己找麻烦了。

## 修复The unwind destination does not have...

这个问题和上面的问题是一致的，LLVM要求处理异常的基本块的EH指令需要是第一条，看上面的修复方法就行。

## CMake构建参数

因为用插件形式编写的项目，所以Windows下用VS编译就加上-DLLVM_OBFUSCATION_LINK_INTO_TOOLS=ON，保证项目是被静态链接进的LLVM。

最后使用上和原版OLLVM是一模一样的，因为已经适配到了新PM上，所以不需要-flegacy-pass-manager了，而且也不支持这个选项了（大概后续版本旧PM会彻底消失在LLVM中端Pipeline吧）。
