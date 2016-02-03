# 基于用户模式回调函数的内核漏洞分析、利用与防范

__Tarjei Mandt__

Norman Threat Research

tarjei.mandt@norman.com

__译者__：rectigu@gmail.com，2015 年 7 月

__摘要__：十五年前，为了解决原有客户端 - 服务端模式图形子系统的内在限制，
Windows NT 4.0 引入了 Win32k.sys。
直到今天，Win32k 依然是 Windows 架构中至关重要的组件之一，
负责窗口管理器（USER）与图形设备接口（GDI）。
为了正确地与用户模式的数据交互，Win32k 采用了用户模式回调，
一种能够让内核调用回用户模式的机制。用户模式回调函数可以用来完成许多任务，
比如调用应用程序定义的钩子，提供事件通知和实现用户模式与内核的数据交换。
在这篇文章中，我们谈谈 Wink32k 用户模式回调函数所带来的挑战与安全隐患。
特别地，我们会阐明，
Win32k 在实现线程安全时对全局锁的依赖并没有很好的与用户模式回调的理念融为一体。
虽然许多与用户模式回调函数有关的漏洞都已经被修复了，
但是他们的复杂特性表明 Win32k 还可能存在更为细微的漏洞。
为了缓和一些更为普遍的漏洞类型，对于用户如何保护自己不受将来可能出现内核攻击，
我们提出了一些结论性的建议。

__关键字__：Win32k，用户模式回调函数，漏洞

# 目录

- [基于用户模式回调函数的内核漏洞分析、利用与防范](README.md)
- [1. 简介](1-introduction.md)
- [2. 背景](2-background.md)
 - [2.1. Win32k](2.1-win32k.md)
 - [2.2. 窗口管理器](2.2-window-manager.md)
 - [2.3. 用户模式回调函数](2.3-user-mode-callbacks.md)
- [3. 基于用户模式回调函数的内核漏洞分析](3-kernel-attacks-through-user-mode-callbacks.md)
 - [3.1. Win32k 命名约定](3.1-win32k-naming-convention.md)
 - [3.2. 用户对象锁](3.2-user-object-locking.md)
 - [3.3. 对象状态检查](3.3-object-state-validation.md)
 - [3.4. 缓冲区重新分配](3.4-buffer-relocation.md)
- [4. 可利用性](4-exploitability.md)
- [5. 缓和](5-mitigations.md)
- [6. 评论](6-remarks.md)
- [7. 结论](7-conclusion.md)
- [参考文献](references.md)
