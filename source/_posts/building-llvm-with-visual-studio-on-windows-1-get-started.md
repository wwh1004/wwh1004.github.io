---
title: Windows下使用Visual Studio编译LLVM（一）-最简编译
date: 2023-08-10 19:00:00
updated: 2023-08-10 19:00:00
lang: zh-CN
categories:
- [LLVM]
tags:
- LLVM
- 编译
toc: true
---

<!-- # Windows下使用Visual Studio编译LLVM（一）-最简编译 -->

本文介绍了最简单的在Windows下使用Visual Studio编译LLVM的办法，用最简化的步骤和描述让小白也能看懂。

<!-- more -->

# 安装Visual Studio

首先安装Visual Studio，这里我用的是最新的Visual Studio 2022。按道理用老的2019这些也行，不过用最新的肯定是不会出错的。

打开Visual Studio Installer，在工作负载里面勾选“使用 C++ 的桌面开发”，在单个组件里面搜索CMake，勾选“用于 Windows 的 C++ CMake 工具”。具体看下图，红框里面的是要勾选的，其它的不用管。

![](./1.png)

![](./2.png)

# 下载LLVM源码

接下来我们下载LLVM源码，LLVM项目在GitHub上有镜像 [llvm-project](https://github.com/llvm/llvm-project)。转到Release页面下载发布的源码包，或者使用

``` dos
git clone https://github.com/llvm/llvm-project.git --depth 1
```

直接把最新的源码下载到本地。

# 使用CMake为LLVM源码生成Visual Studio解决方案

因为我们已经在Visual Studio Installer里面勾选了CMake安装，这里我们不需要再手动安装CMake了。

我们打开Visual Studio的"开发人员命令提示符"，此时输入CMake，可以看到CMake已经安装。

![](./3.png)

![](./4.png)

现在直接输入以下命令即可生成Visual Studio解决方案。这篇文章是针对小白写的，目的是让小白也看得懂。那么不要自作主张额外添加其它的命令行参数，因为CMake的很多参数是与对接的生成器相关的，网上找的参数不一定适用于这里。这里我们用的生成器就是Visual Studio 2022。

``` dos
CMake -SD:/llvm-16.0.4/llvm -BD:/llvm-16.0.4-build -G "Visual Studio 17 2022" -A x64
```

解释一下这条命令行，"-S"后面的是源码路径，"-B"后面的是输出解决方案的路径，这两个参数后面是直接加路径的，中间没有空格！！！并且路径是用Unix格式的'/'而不是Windows的'\'！！！

比如用"git clone"下载下来的LLVM项目文件夹是C:\llvm-project，那么"-S"后面就是C:/llvm-project/llvm。因为CMakeLists.txt文件在这个文件夹中。那么"-B"后面接的输出解决方案文件夹的路径就放在C:\llvm-project之外，不要放在这个文件夹里面。

执行成功的话就如下图所示。

![](./5.png)

# 编译Visual Studio解决方案

这一步可以选择用Visual Studio 2022直接打开生成的解决方案，也可以选择使用命令行调用CMake编译。

用Visual Studio 2022打开就和普通的解决方案一模一样，按正常的项目进行编译调试就行，不过多介绍。这里介绍下用CMake编译。

依然在"开发人员命令提示符"中输入命令：

``` dos
CMake --build D:/llvm-16.0.4-build --config Release
```

这里的"D:/llvm-16.0.4-build"与之前的"-BD:/llvm-16.0.4-build"相对应。Release代表编译类型，表示生成优化的文件，也可以替换为Debug，表示生成调试用的文件。如果只是需要使用LLVM，那么选Release即可。

配置好些的话，编译大约耗时半小时，差些可能要一个甚至两个小时。编译好的可执行文件都会放在"D:\llvm-16.0.4-build\Release\bin"中。下图的是我好早以前用自定义参数编译的，所以体积非常小，只是为了满足我的需求。

![](./6.png)

# 更多编译参数

通过指定编译参数，可以根据自己的需求生成需要的clang.exe，比如只编译为x86架构的，跳过异常处理的，只生成llvm、clang主项目的。

这里放在下一篇文章中介绍，因为这篇文章只是针对小白的，所以不写太复杂的内容。
