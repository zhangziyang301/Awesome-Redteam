# Awesome-Redteam
轻量化红队知识仓库，不定期更新。

markdown文档与Linux alias命令或Windows doskey命令联动，可实现终端快捷查询。

## 使用姿势

### 如何在Windows上使用alias

- 创建alias.bat，文件内容如下。

```
@echo off
::Tips
@DOSKEY httpcode=type "D:\Hack Tools\Tips\http_status_code.md"
@DOSKEY versions=type "D:\Hack Tools\Tips\versions.md"
@DOSKEY owasp=type "D:\Hack Tools\Tips\owasp.md"
```

- 注册表打开`计算机\HKEY_CURRENT_USER\Software\Microsoft\Command Processor`。
- 创建字符串值`autorun`，赋值为alias.bat所在位置，例如`D:\Software\alias.bat`。
- 双击alias.bat运行，重启cmd。
- 此时在终端输入httpcode，即可返回文件内容。

![image-20220208090022459](D:\Git\Awesome-Redteam\images\image-20220208090022459.png)

> 解决cmd中文乱码的问题：
>
> 1. 注册表打开`计算机\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Command Processor`。
> 2. 创建字符串值`autorun`，赋值为`chcp 65001`。

### 如何使用浏览器快速查看markdown文档

- 安装插件`Markdown Viewer`。
- 配合Bootstrap可以实现快速部署导航页或文档库。

![image-20220208091030741](D:\Git\Awesome-Redteam\images\image-20220208091030741.png)

