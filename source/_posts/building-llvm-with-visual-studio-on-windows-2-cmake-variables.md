---
title: Windows下使用Visual Studio编译LLVM（二）-CMake参数
date: 2023-08-10 20:00:00
updated: 2023-08-10 20:00:00
lang: zh-CN
categories:
- [LLVM]
tags:
- LLVM
- 编译
toc: true
---

<!-- # Windows下使用Visual Studio编译LLVM（二）-CMake参数 -->

本文介绍了使用CMake编译LLVM时，作用于生成器是Visual Studio的CMake参数。通过改变这些参数，可以大幅减少编译时间，同时大幅降低编译后的文件体积。

<!-- more -->

# LLVM变量

这一小节介绍的是LLVM本身的变量，来自LLVM的CMake构建文件。更多内容请参考官方的文档 [https://llvm.org/docs/CMake.html](https://llvm.org/docs/CMake.html)。

## LLVM_TARGETS_TO_BUILD - 自定义目标编译架构

比如让生成的clang.exe只能编译出X86架构和ARM架构的程序：

``` dos
"-DLLVM_TARGETS_TO_BUILD=X86;ARM"
```

可以指定一个架构或者多个架构，用分号间隔开。如果不指定参数，默认是全架构。

这个参数可以大幅降低编译出的clang.exe的文件体积，可以说是一定要配置的参数。

## LLVM_ENABLE_PROJECTS - 自定义编译项目

配置你需要的工具，比如你需要clang和lld，那么可以这样写：

``` dos
"-DLLVM_ENABLE_PROJECTS=llvm;clang;lld"
```

## LLVM_ENABLE_LTO - 开启链接时优化

这个选项可以优化生成的clang.exe的性能，同时降低clang.exe的文件体积。

``` dos
-DLLVM_ENABLE_LTO=Thin
```

这个选项有"Off, On, Thin, Full"这四个值可以选，默认是Off，也就是关。推荐开启Thin，也就是对单个编译单元进行LTO。如果用Full的话，会把所有编译单元视为一个整体进行LTO，速度很慢很慢很慢，效果并不会比Thin好太多。

## CLANG_ENABLE_STATIC_ANALYZER - 关闭静态分析器

``` dos
-DCLANG_ENABLE_STATIC_ANALYZER=OFF
```

如果和我的需求一致，只是需要一个可以编译项目的clang.exe，那么这个静态分析器是可以关闭的。它是用于产生类似如下面的告警的，只编译的话不需要这个。

```
Example_Test.c:4:19: warning: Call to main [alpha.core.MainCall]
  int exit_code = foo(argc, argv);   // actually calls main()!
                  ^~~~~~~~~~~~~~~
1 warning generated.
```

## CLANG_ENABLE_ARCMT & CLANG_ENABLE_OBJC_REWRITER - 关闭Objective-C相关工具

这两个选项是Objective-C相关的工具，压根就不用Objective-C的话，就关闭了吧。

``` dos
-DCLANG_ENABLE_ARCMT=OFF -DCLANG_ENABLE_OBJC_REWRITER=OFF
```

## LLVM_ENABLE_EH & LLVM_ENABLE_RTTI - 关闭异常处理和RTTI

如果你需要链接LLVM里面的lib文件到自己的项目，那这个选项可以不管它。如果你和我一样只是要一个用于编译的clang.exe，那么可以选择关闭。这个默认好像也是关闭的，不手动关闭也行。

``` dos
-DLLVM_ENABLE_EH=OFF -DLLVM_ENABLE_RTTI=OFF
```

## LLVM_OPTIMIZED_TABLEGEN - Debug编译LLVM时提升速度

LLVM会是tablegen.exe为自己生成头文件。编译LLVM时，LLVM会先编译tablegen项目，然后调用tablegen.exe生成头文件，再进行接下来的编译。

如果你使用Debug编译LLVM，那么默认tablegen.exe也是Debug编译的。tablegen在LLVM编译过程中时间占比也是很高的，如果使用Debug编译tablegen.exe，那么执行效率会很低，导致LLVM编译过程很慢。

这个选项可以一直开着，不会有任何副作用。

``` dos
-DLLVM_OPTIMIZED_TABLEGEN=ON
```

# CMake

这一小节介绍的是CMake的变量，由CMake自身提供支持。

## CMAKE_MSVC_RUNTIME_LIBRARY - 使用静态链接CRT

这是一个非常推荐配置的选项，让LLVM使用静态链接的CRT可以避免出现编译出的clang.exe能在自己电脑上跑，但是放在别人那里就提示缺少VC运行时。

``` dos
-DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded
```

## CMAKE_C_FLAGS & CMAKE_CXX_FLAGS - 自定义MSVC编译选项

这里推荐开"/utf-8 /Os"。"/utf-8"是让MSVC编译器把所有LLVM源码视为UTF8编码，防止下面的warning刷一大堆。

```
warning: C4819: 该文件包含不能在当前代码页(936)中表示的字符。请将该文件保存为 Unicode 格式以防止数据丢失
```

"/Os"可以随意启用，目的是针对体积优化，让编译出的clang.exe小一些。

``` dos
"-DCMAKE_C_FLAGS=/utf-8 /Os" "-DCMAKE_CXX_FLAGS=/utf-8 /Os"
```

因为有C编译器和C++编译器两种编译器，所以要同时为这两种编译器设置。

## T & A - 自定义工具链与目标架构

这两个是CMake的常用选项，-T用于设置工具链，-A用于设置编译目标架构，比如：

``` dos
-T host=x64 -A x64
```

意思是使用64位MSVC工具链生成64位clang.exe。

如果想使用clang-cl工具链，可以这样写：

``` dos
-T ClangCL -A x64
```

# 例子

这个是我自己用的编译选项：

``` dos
CMake -DLLVM_TARGETS_TO_BUILD=X86 "-DLLVM_ENABLE_PROJECTS=llvm;clang;lld" -DCLANG_ENABLE_STATIC_ANALYZER=OFF -DCLANG_ENABLE_ARCMT=OFF -DCLANG_ENABLE_OBJC_REWRITER=OFF -DLLVM_ENABLE_EH=OFF -DLLVM_ENABLE_RTTI=OFF -DLLVM_ENABLE_LTO=Thin -DLLVM_OPTIMIZED_TABLEGEN=ON -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded "-DCMAKE_C_FLAGS=/utf-8 /Os" "-DCMAKE_CXX_FLAGS=/utf-8 /Os" -SD:/llvm-16.0.4/llvm -BD:/llvm-16.0.4-build -G "Visual Studio 17 2022" -T ClangCL -A x64
```

这样可以得到一个体积很小的，不需要安装额外MSVC运行时的，只能编译到X86平台的clang.exe和lld.exe。对比之下同版本的官方的全功能clang.exe和lld.exe分别是116MB和86MB，这个参数编译出来的是48MB和29MB，也就是体积降低了60%~70%！！！
