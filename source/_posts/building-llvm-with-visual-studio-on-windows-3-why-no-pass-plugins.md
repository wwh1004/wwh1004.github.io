---
title: Windows下使用Visual Studio编译LLVM（三）-为什么没有Pass插件
date: 2023-08-11 15:00:00
updated: 2023-08-11 15:00:00
lang: zh-CN
categories:
- [LLVM]
tags:
- LLVM
- 编译
toc: true
---

<!-- # Windows下使用Visual Studio编译LLVM（三）-为什么没有Pass插件 -->

本文介绍了为什么在Windows下用Visual Studio编译的LLVM没有插件，也不支持插件。

<!-- more -->

# 为什么需要插件

大多数时候自己编译LLVM，都是为了自定义Pass，比如添加OLLVM。其次，在映像中也是可以很容易地想到，如果使用插件，那么就不需要每次都重新编译LLVM，直接添加参数外挂一个DLL就行，显然的快捷。但是事实上并不是如此。

# 为什么Windows下不支持加载插件

可以很直接的说，Visual Studio编译的LLVM不可能支持插件，从机制上来说不可能。

加载插件的原理就是程序本身有一个DLL导出了程序所有API，插件本身提供一个导出函数用于程序注册插件。在Windows下的具体实现就是先用LoadLibrary加载插件DLL，此时Windows操作系统会自动把导出了LLVM API的DLL的链接到插件DLL上，此时插件就可以调用LLVM API了。然后LLVM用GetProcAddress获取插件DLL的注册函数，调用它并完成插件的注册。

这是LLVM加载插件的实现，其中"sys::DynamicLibrary::getPermanentLibrary"底层调用了LoadLibraryW，"Library.getAddressOfSymbol"调用了GetProcAddress：

``` c++
Expected<PassPlugin> PassPlugin::Load(const std::string &Filename) {
  std::string Error;
  auto Library =
      sys::DynamicLibrary::getPermanentLibrary(Filename.c_str(), &Error);
  if (!Library.isValid())
    return make_error<StringError>(Twine("Could not load library '") +
                                       Filename + "': " + Error,
                                   inconvertibleErrorCode());

  PassPlugin P{Filename, Library};

  // llvmGetPassPluginInfo should be resolved to the definition from the plugin
  // we are currently loading.
  intptr_t getDetailsFn =
      (intptr_t)Library.getAddressOfSymbol("llvmGetPassPluginInfo");

  if (!getDetailsFn)
    // If the symbol isn't found, this is probably a legacy plugin, which is an
    // error
    return make_error<StringError>(Twine("Plugin entry point not found in '") +
                                       Filename + "'. Is this a legacy plugin?",
                                   inconvertibleErrorCode());

  P.Info = reinterpret_cast<decltype(llvmGetPassPluginInfo) *>(getDetailsFn)();

  if (P.Info.APIVersion != LLVM_PLUGIN_API_VERSION)
    return make_error<StringError>(
        Twine("Wrong API version on plugin '") + Filename + "'. Got version " +
            Twine(P.Info.APIVersion) + ", supported version is " +
            Twine(LLVM_PLUGIN_API_VERSION) + ".",
        inconvertibleErrorCode());

  if (!P.Info.RegisterPassBuilderCallbacks)
    return make_error<StringError>(Twine("Empty entry callback in plugin '") +
                                       Filename + "'.'",
                                   inconvertibleErrorCode());

  return P;
}
```

那么LLVM支持插件加载的先决条件就是，LLVM不能编译为全静态链接的，需要编译为多个动态库（DLL）加一个主程序（EXE）的形式。但是我们可以看到，在Windows下用Visual Studio编译LLVM是不支持LLVM_BUILD_LLVM_DYLIB选项的。

```makefile
if(LLVM_BUILD_LLVM_DYLIB)
  if(MSVC)
    message(FATAL_ERROR "Generating libLLVM is not supported on MSVC")
  endif()
...
```

那么这里就要解释为什么不支持LLVM_BUILD_LLVM_DYLIB选项了。

先引用一篇LLVM社区的讨论 [Supporting LLVM_BUILD_LLVM_DYLIB on Windows](https://discourse.llvm.org/t/supporting-llvm-build-llvm-dylib-on-windows/58891)

Windows下的C/C++编译器默认所有符号是外部不可见的（-fvisibility=hidden），也就是说，不显式声明这个是导出函数，编译器就不会为其导出，那么外部就无法调用。而Unix下的行为是默认所有符号外部可见的（-fvisibility=default）。LLVM源码中并没有显示声明哪些函数是需要导出的，哪些是内部的。所以LLVM在Windows下编译时，libLLVM.dll不会导出内部的没显示声明为导出的C++函数，clang.exe也没办法正确链接到libLLVM.dll上，LLVM_BUILD_LLVM_DYLIB这个选项也不会在Windows上得到支持。

# 使用Unix下的C++编译器跨平台编译

并不是说加载插件一定不可能，比如可以使用MSYS2，在MSYS2下编译LLVM，这样是可以得到使用动态链接库的clang.exe的，也就是支持插件加载。但是这其中存在好几个问题：

1. 使用MSYS2很麻烦，友好程度一定是不如Visual Studio的，不会有GUI供你使用。
1. 插件加载需要使用同一版本的C++运行时。
1. 编译插件所用的LLVM版本需要和加载插件的LLVM的版本接近或者说一致，因为LLVM是整个类导出给外部使用的，版本不一致，类的结构大小都会有改变。

也就是说，如果使用外挂插件的形式，LLVM一更新，LLVM插件也是要重新编译的，对编译环境也有更加严格的要求。如此下来，使用插件并不会比直接把源码混入LLVM一起编译方便太多。
