# Awesome-Redteam
轻量化红队知识仓库，不定期更新。

markdown文档与Linux alias命令或Windows doskey命令联动，可实现终端快捷查询。

## 快速导航

### 编码转换

- CyberChef：编解码及加密，可本地部署 https://github.com/gchq/CyberChef
- OK Tools在线工具：https://github.com/wangyiwy/oktools
- CTF在线工具：http://www.hiencode.com/
- Unicode字符表：https://www.52unicode.com/enclosed-alphanumerics-zifu

### 实用工具

- Explain Shell：Shell命令解析 https://explainshell.com/
- 在线正则表达式：https://c.runoob.com/front-end/854/
- Ceye DNS：DNS oob平台 http://ceye.io/
- Webshell Chop：https://webshellchop.chaitin.cn/demo/
- XSS Chop：https://xsschop.chaitin.cn/demo/
- WebShell查杀：https://n.shellpub.com/
- Google Hacking Database：https://www.exploit-db.com/google-hacking-database
- Wayback Machine：网页缓存查询 https://archive.org/web

### IP/域名收集

#### 确认真实IP地址

- IP精准定位：https://www.ipuu.net/#/home
- IP 138：https://site.ip138.com/
- Security Trails：https://securitytrails.com/

#### 多个地点Ping服务器

- Chinaz：https://ping.chinaz.com/
- Host Tracker：https://www.host-tracker.com/
- Webpage Test：https://www.webpagetest.org/
- DNS Check：https://dnscheck.pingdom.com/

#### Whois注册信息反查

- 站长之家 Whois：https://whois.chinaz.com/
- 中国万网 Whois：https://whois.aliyun.com/
- 国际 Whois：https://who.is/

#### DNS数据聚合查询

- Hacker Target：https://hackertarget.com/find-dns-host-records
- DNS Dumpster：https://dnsdumpster.com
- DNS DB：https://dnsdb.io/zh-cn

#### TLS证书信息查询

- Censys：https://censys.io
- Certificate Search：https://crt.sh
- 证书透明度监控：https://developers.facebook.com/tools/ct"

#### IP地址段收集

- CNNIC中国互联网信息中心：http://ipwhois.cnnic.net.cn

### 网络空间搜索

- Fofa：https://fofa.info/
- Shodan：https://www.shodan.io/
- ZoomEye：https://www.zoomeye.org/
- 谛听：https://www.ditecting.com/
- 360网络空间测绘：https://quake.360.cn/quake/#/index

### 威胁情报

- Virustotal：https://www.virustotal.com/gui/home/upload
- 腾讯哈勃分析系统：https://habo.qq.com/tool/index
- 微步在线威胁情报：https://x.threatbook.cn/
- 奇安信威胁情报：https://ti.qianxin.com/
- 360威胁情报：https://ti.360.net/#/homepage
- 安恒威胁情报：https://ti.dbappsecurity.com.cn/
- 火线安全平台：https://www.huoxian.cn

### CTF平台

- CTF Wiki：https://ctf-wiki.org/
- CTF Time：https://ctftime.org/
- CTF Tools：https://github.com/zardus/ctf-tools
- 攻防世界：https://adworld.xctf.org.cn/

### 漏洞平台

- Exploit Database：https://www.exploit-db.com/
- HackerOne：https://www.hackerone.com/
- Vulhub：https://vulhub.org/
- 乌云镜像：http://wooyun.2xss.cc/
- 知道创宇漏洞平台：https://www.seebug.org/

### 信息收集

- AlliN：https://github.com/P1-Team/AlliN
- Kunyu：https://github.com/knownsec/Kunyu
- OneForAll：https://github.com/shmilylty/OneForAll
- ShuiZe：https://github.com/0x727/ShuiZe_0x727
- ksubdomain：https://github.com/knownsec/ksubdomain
- dirsearch：https://github.com/maurosoria/dirsearch
- Fofa Viewer：https://github.com/wgpsec/fofa_viewer

### 开源项目

#### 基础知识

- The art of command line：https://github.com/jlevy/the-art-of-command-line

#### 漏洞整理POC/EXP

- PoCBox：https://github.com/0verSp4ce/PoCBox
- Vulnerability：https://github.com/EdgeSecurityTeam/Vulnerability
- POChouse：https://github.com/DawnFlame/POChouse
- 未授权访问漏洞总结：http://luckyzmj.cn/posts/15dff4d3.html#toc-heading-3

#### Bypass

- PHPFuck：https://github.com/splitline/PHPFuck
- JSFuck：http://www.jsfuck.com/

#### Payload

- PayloadsAllTheThings：https://github.com/swisskyrepo/PayloadsAllTheThings

### 内网渗透

- Responder：https://github.com/SpiderLabs/Responder
- Windows-Exploit-Suggester：https://github.com/AonCyberLabs/Windows-Exploit-Suggester
- Linux_Exploit_Suggester：https://github.com/InteliSecureLabs/Linux_Exploit_Suggester
- CDK：容器渗透 https://github.com/cdk-team/CDK

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

![image-20220208090022459](./images/image-20220208090022459.png)

> 解决cmd中文乱码的问题：
>
> 1. 注册表打开`计算机\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Command Processor`。
> 2. 创建字符串值`autorun`，赋值为`chcp 65001`。

### 如何使用浏览器快速查看markdown文档

- 安装插件`Markdown Viewer`。
- 配合Bootstrap可以实现快速部署导航页或文档库。

![image-20220208091030741](./images/image-20220208091030741.png)

