---
title: Clang参数中的-Xclang/-mllvm意义与Clang的Driver架构
date: 2023-08-17 00:00:00
updated: 2023-08-17 00:00:00
lang: zh-CN
categories:
- [LLVM]
tags:
- LLVM
- 编译
toc: true
---

<!-- # Clang参数中的-Xclang/-mllvm意义与Clang的Driver架构 -->

本文介绍了为什么Clang的有些参数需要通过-Xclang传递，有些又需要通过-mllvm传递，这其中与Clang的Driver架构密切相关。

<!-- more -->

# Xclang参数

-Xclang参数是将参数传递给Clang的CC1前端。

比如想要禁用所有LLVM Pass的运行，也就是生成无任何优化的IR，那么你就要使用-disable-llvm-passes参数传递给CC1。但是这个参数并没有Clang Driver的表示形式（也就是不使用-Xclang传递给CC1），那么你就需要写-Xclang -disable-llvm-passes把参数透过Clang Driver把参数传递给CC1。

# mllvm参数

-mllvm参数的作用是将参数传递给作为中后端的LLVM。

如果参数是在LLVM中后端定义的，那么直接把参数给Clang的Driver或者CC1都是不行的，需要使用-mllvm将参数跳过Clang的Driver和CC1传递到LLVM。比如想要在Pass运行完成后输出IR，那么就需要使用-mllvm --print-after-all把参数传给LLVM。

# Clang的Driver架构

为什么要加-Xclang和-mllvm参数？直接丢给Clang不行么？那么这就要说到Clang的Driver架构和LLVM整体设计了。

我们平常使用的可执行文件clang.exe其实只是一个Driver，用于接收gcc兼容的参数（clang++.exe/clang-cl.exe同理，接受g++/msvc兼容的参数），然后传递给真正的clang编译器前端，也就是CC1。CC1作为前端，负责解析C++源码为语法树，转换到LLVM IR。比如选项A在gcc中默认开启，但是clang规则中是默认不开启的，那么为了兼容gcc，clang.exe的Driver就要手动开启选项A，也就是添加命令行参数，将它传递给CC1。

在CC1工作完成后，所有C++源码都转换到了LLVM IR，前端Action也就结束了。接下来就是LLVM中端和后端的工作了。LLVM中端负责执行通用优化，也就是语言无关架构无关的优化。在中端优化完成后，LLVM IR会交给后端进行目标代码生成，最后生成目标特定的机器码。关于LLVM中端的详细流程，可以看这篇文章 [LLVM: The middle-end optimization pipeline](https://www.npopov.com/2023/04/07/LLVM-middle-end-pipeline.html)

从这里我们可以知道，Clang和LLVM不是设计为一个整体的，而是松耦合的。Clang的Driver可以接收兼容各种编译器的参数，然后将它们转换为Clang规则的前中后端参数。Clang的前中后端不存在关联，开关特定的选项需要将参数分别传递给所属的前中后端。
