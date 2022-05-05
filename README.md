# Awesome-Redteam
**【免责声明】本仓库所涉及的技术、思路和工具仅供学习，任何人不得将其用于非法用途和盈利，否则后果自行承担。**

轻量化红队知识仓库，不定期更新。

markdown文档与Linux alias命令或Windows doskey命令联动，可实现终端快捷查询。

## 目录

- [漏洞知识库](#漏洞知识库)
- [仓库导航](#仓库导航)
- [开源导航](#开源导航)
  - [编解码/加密](#编解码加密)
  - [实用工具](#实用工具)
  - [IP/域名收集](#ip域名收集)
    - [确认真实IP地址](#确认真实ip地址)
    - [多个地点Ping服务器](#多个地点ping服务器)
    - [Whois注册信息反查](#whois注册信息反查)
    - [DNS数据聚合查询](#dns数据聚合查询)
    - [TLS证书信息查询](#tls证书信息查询)
    - [IP地址段收集](#ip地址段收集)
  - [网络空间搜索](#网络空间搜索)
  - [威胁情报平台](#威胁情报平台)
  - [CTF平台](#ctf平台)
  - [漏洞平台](#漏洞平台)
  - [专项靶机平台](#专项靶机平台)
  - [综合靶机平台](#综合靶机平台)
  - [公开知识库](#公开知识库)
- [信息收集](#信息收集)
  - [指纹识别](#指纹识别)
  - [扫描/爆破](#扫描爆破)
  - [爆破字典](#爆破字典)
  - [综合信息收集](#综合信息收集)
  - [内网信息收集](#内网信息收集)
- [漏洞研究](#漏洞研究)
  - [漏洞综述](#漏洞综述)
  - [漏洞挖掘](#漏洞挖掘)
  - [开源漏洞库](#开源漏洞库)
  - [POC/EXP](#pocexp)
- [内网渗透](#内网渗透)
  - [Bypass](#bypass)
  - [Payloads](#payloads)
  - [WebShell](#webshell)
  - [内网穿透](#内网穿透)
  - [开源蜜罐](#开源蜜罐)
  - [容器逃逸](#容器逃逸)
  - [其他](#其他)
- [移动端/物联网](#移动端物联网)
- [云服务](#云服务)
- [大数据](#大数据)
- [逆向分析](#逆向分析)
- [工具赋能](#工具赋能)
  - [Metasploit](#metasploit)
  - [Cobaltstrike](#cobaltstrike)
  - [Burpsuite](#burpsuite)
  - [Chrome crx](#chrome-crx)
  - [Xray](#xray)
- [使用姿势](#使用姿势)
  - [如何在Windows上使用alias](#如何在windows上使用alias)
  - [如何使用浏览器快速查看markdown文档](#如何使用浏览器快速查看markdown文档)

## 漏洞知识库

Vulnerability Wiki，一个基于docsify开发的漏洞知识库项目，集成了Vulhub、Peiqi、0sec、Wooyun（待更新）等开源漏洞库。

可以通过docsify自定义部署（推荐docsify部署），也可以通过docker快速部署。

- Vulnerability Wiki：[Threekiii/Vulnerability-Wiki](https://github.com/Threekiii/Vulnerability-Wiki)

![image-20220429163635753](https://typora-notes-1308934770.cos.ap-beijing.myqcloud.com/202204291636876.png)

## 项目导航

- 反弹shell命令速查：[Click Here](https://github.com/Threekiii/Awesome-Redteam/blob/master/tips/%E5%8F%8D%E5%BC%B9shell%E5%91%BD%E4%BB%A4%E9%80%9F%E6%9F%A5.md)
- 重要端口及服务速查：[Click Here](https://github.com/Threekiii/Awesome-Redteam/blob/master/tips/%E9%87%8D%E8%A6%81%E7%AB%AF%E5%8F%A3%E5%8F%8A%E6%9C%8D%E5%8A%A1%E9%80%9F%E6%9F%A5.md)
- 安全厂商及其官网链接速查：[Click Here](https://github.com/Threekiii/Awesome-Redteam/blob/master/tips/%E5%AE%89%E5%85%A8%E5%8E%82%E5%95%86%E5%8F%8A%E5%85%B6%E5%AE%98%E7%BD%91%E9%93%BE%E6%8E%A5%E9%80%9F%E6%9F%A5.txt)
- 红队中易被攻击的一些重点系统漏洞整理（来源：棱角安全团队）：[Click Here](https://github.com/Threekiii/Awesome-Redteam/blob/master/docs/%E7%BA%A2%E9%98%9F%E4%B8%AD%E6%98%93%E8%A2%AB%E6%94%BB%E5%87%BB%E7%9A%84%E4%B8%80%E4%BA%9B%E9%87%8D%E7%82%B9%E7%B3%BB%E7%BB%9F%E6%BC%8F%E6%B4%9E%E6%95%B4%E7%90%86.md)
- Apache项目及漏洞指纹速查：[Click Here](https://github.com/Threekiii/Awesome-Redteam/blob/master/tips/Apache%E9%A1%B9%E7%9B%AE%E5%8F%8A%E6%BC%8F%E6%B4%9E%E6%8C%87%E7%BA%B9%E9%80%9F%E6%9F%A5.md) 

## 开源导航

### 编解码/加密

- CyberChef：编解码及加密，可本地部署 https://github.com/gchq/CyberChef
- OK Tools在线工具：https://github.com/wangyiwy/oktools
- CTF在线工具：http://www.hiencode.com/
- Unicode字符表：https://www.52unicode.com/enclosed-alphanumerics-zifu
- 在线MD5 Hash破解：https://www.somd5.com/
- XSSEE：在线综合编解码工具 https://evilcos.me/lab/xssee/

### 实用工具

- Explain Shell：Shell命令解析 https://explainshell.com/
- 在线正则表达式：https://c.runoob.com/front-end/854/
- Ceye DNS：DNS oob平台 http://ceye.io/
- DNS log：DNS oob平台 http://dnslog.cn/
- Webshell Chop：https://webshellchop.chaitin.cn/demo/
- XSS Chop：https://xsschop.chaitin.cn/demo/
- WebShell查杀：https://n.shellpub.com/
- Google Hacking Database：https://www.exploit-db.com/google-hacking-database
- Wayback Machine：网页缓存查询 https://archive.org/web
- HTML5 Security Cheatsheet：XSS攻击向量学习/参考 https://html5sec.org/
- 在线代码格式标准化：http://web.chacuo.net/formatsh

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

### 威胁情报平台

- Virustotal：https://www.virustotal.com/gui/home/upload
- 腾讯哈勃分析系统：https://habo.qq.com/tool/index
- 微步在线威胁情报：https://x.threatbook.cn/
- 奇安信威胁情报：https://ti.qianxin.com/
- 360威胁情报：https://ti.360.net/#/homepage
- 安恒威胁情报：https://ti.dbappsecurity.com.cn/
- 火线安全平台：https://www.huoxian.cn
- Hacking8安全信息流：https://i.hacking8.com/

### CTF平台

- CTF Wiki：https://ctf-wiki.org/
- CTF Time：https://ctftime.org/
- CTF Tools：https://github.com/zardus/ctf-tools
- 攻防世界：https://adworld.xctf.org.cn/
- Hacker 101：https://www.hacker101.com/

### 漏洞平台

- Exploit Database：https://www.exploit-db.com/
- HackerOne：https://www.hackerone.com/
- Vulhub：https://vulhub.org/
- 乌云镜像：http://wooyun.2xss.cc/
- 知道创宇漏洞平台：https://www.seebug.org/

### 专项靶机平台

- Sqli-labs：SQL注入 https://github.com/Audi-1/sqli-labs
- Xss-labs：XSS注入 https://github.com/do0dl3/xss-labs
- Upload-labs：上传漏洞 https://github.com/c0ny1/upload-labs

### 综合靶机平台

- DVWA：https://github.com/digininja/DVWA
- HackTheBox：https://www.hackthebox.com/
- OWASP Top10：https://owasp.org/www-project-juice-shop/
- WebGoat：https://github.com/WebGoat/WebGoat
- Vulstudy：docker快速搭建共17个漏洞靶场 https://github.com/c0ny1/vulstudy

### 公开知识库

- 零组文库：零组已停运，非官方 https://0-wiki.com/
- 先知社区：https://xz.aliyun.com/
- 狼组公开知识库：https://wiki.wgpsec.org/
- 404星链计划：知道创宇 404 实验室 https://github.com/knownsec/404StarLink
- MITRE ATT＆CK：网络攻击中使用的已知对抗战术和技术 https://attack.mitre.org/matrices/enterprise/

## 信息收集

### 指纹识别

- Wapplyzer：Chrome插件 跨平台网站分析工具 https://github.com/AliasIO/Wappalyzer

- TideFinger：提取了多个开源指纹识别工具的规则库并进行了规则重组 https://github.com/TideSec/TideFinger
- 御剑web指纹识别程序：https://www.webshell.cc/4697.html

- 云悉指纹识别：http://www.yunsee.cn/

### 扫描/爆破

- dirsearch：目录扫描/爆破 https://github.com/maurosoria/dirsearch
- dirmap：目录扫描/爆破 https://github.com/H4ckForJob/dirmap
- Arjun：HTTP参数扫描器 https://github.com/s0md3v/Arjun
- ksubdomain：子域名爆破 https://github.com/knownsec/ksubdomain
- Gobuster：URI/DNS/WEB爆破 https://github.com/OJ/gobuster
- Hydra：弱密码爆破 https://github.com/vanhauser-thc/thc-hydra
- John the Ripper：https://github.com/openwall/john

### 爆破字典

- Dictionary-Of-Pentesting：渗透测试、SRC漏洞挖掘、爆破、Fuzzing等常用字典 https://github.com/insightglacier/Dictionary-Of-Pentesting
- fuzzDicts：Web渗透Fuzz字典 https://github.com/TheKingOfDuck/fuzzDicts
- PentesterSpecialDict：渗透测试工程师精简化字典 https://github.com/ppbibo/PentesterSpecialDict

### 综合信息收集

- AlliN：https://github.com/P1-Team/AlliN
- Kunyu：https://github.com/knownsec/Kunyu
- OneForAll：https://github.com/shmilylty/OneForAll
- ShuiZe：https://github.com/0x727/ShuiZe_0x727
- Fofa Viewer：https://github.com/wgpsec/fofa_viewer

### 内网信息收集

- fscan：内网综合扫描工具 https://github.com/shadow1ng/fscan
- hping3：端口扫描 高速 发包量少 结果准确无蜜罐 https://github.com/antirez/hping
- EHole：红队重点攻击系统指纹探测工具 https://github.com/EdgeSecurityTeam/EHole
- Ladon：用于大型网络渗透的多线程插件化综合扫描工具 https://github.com/k8gege/Ladon

## 漏洞研究

### 漏洞综述

- 未授权访问漏洞总结：http://luckyzmj.cn/posts/15dff4d3.html#toc-heading-3

### 漏洞挖掘

- Windows-Exploit-Suggester：https://github.com/AonCyberLabs/Windows-Exploit-Suggester
- Linux_Exploit_Suggester：https://github.com/InteliSecureLabs/Linux_Exploit_Suggester

### 开源漏洞库

- Vulhub：https://vulhub.org/
- PeiQi：http://wiki.peiqi.tech/
- Vulnerability：https://github.com/EdgeSecurityTeam/Vulnerability
- POChouse：https://github.com/DawnFlame/POChouse

### POC/EXP

- ysoserial：Java反序列化 https://github.com/frohoff/ysoserial
- Vulmap：漏洞扫描和验证工具 https://github.com/zhzyker/vulmap
- Some-PoC-oR-ExP：各种漏洞PoC、ExP的收集或编写 https://github.com/coffeehb/Some-PoC-oR-ExP
- CMS-Hunter：CMS漏洞测试用例集合 https://github.com/SecWiki/CMS-Hunter
- Penetration_Testing_POC：https://github.com/Mr-xn/Penetration_Testing_POC

## 内网渗透

### Bypass

- PHPFuck：https://github.com/splitline/PHPFuck
- JSFuck：http://www.jsfuck.com/
- Gopherus：生成gopher链接 https://github.com/tarunkant/Gopherus

### Payloads

- PayloadsAllTheThings：https://github.com/swisskyrepo/PayloadsAllTheThings
- java.lang.Runtime.exec() Payload：java Payload在线生成 https://www.bugku.net/runtime-exec-payloads/
- PHP Generic Gadget Chains：PHP反序列化Payload https://github.com/ambionics/phpggc

### WebShell

- Webshell收集项目：https://github.com/tennc/webshell
- Behinder 冰蝎：https://github.com/rebeyond/Behinder
  - Behinder3：`kali + java 11.0.14` 或 `windows10 + java 1.8.0_91`，注意，该环境下Behinder2无法正常运行
  - Behinder2：windows10 + java 1.8.0_91
- Godzilla 哥斯拉：https://github.com/BeichenDream/Godzilla

### 内网穿透

- NPS：通过web端管理，无需配置文件 https://github.com/ehang-io/nps
- FRP：55k star项目 https://github.com/fatedier/frp
- Neo-reGeorg：tunnel快速部署 https://github.com/L-codes/Neo-reGeorg
- Proxifier：windows代理工具 https://www.proxifier.com/
- Proxychains：kali代理工具 https://github.com/haad/proxychains

### 开源蜜罐

- HFish：一款安全、简单可信赖的跨平台蜜罐软件，允许商业和个人用户免费使用 https://github.com/hacklcx/HFish

### 容器逃逸

- CDK：容器渗透 https://github.com/cdk-team/CDK

### 其他

- The art of command line：快速掌握命令行 https://github.com/jlevy/the-art-of-command-line
- Responder：实现获取NTLM Hash等功能 https://github.com/SpiderLabs/Responder
- Impacket：其中的psexec.py通过用户名和密码远程连接到目标服务器 https://github.com/SecureAuthCorp/impacket
- PsTools：PsExec.exe功能同Impacket中的psexec.py https://docs.microsoft.com/en-us/sysinternals/downloads/pstools

## 移动端/物联网

- CrackMinApp：反编译微信小程序 https://github.com/Cherrison/CrackMinApp  
- AppInfoScanner：移动端信息收集 https://github.com/kelvinBen/AppInfoScanner
- wxappUnpacker：小程序解包 https://github.com/xuedingmiaojun/wxappUnpacker
- IoT-vulhub： IoT 版固件漏洞复现环境 https://github.com/firmianay/IoT-vulhub

## 云服务

- aliyun-accesskey-Tools：阿里云accesskey利用工具 https://github.com/mrknow001/aliyun-accesskey-Tools
- cosbrowser：腾讯云COS客户端 https://github.com/TencentCloud/cosbrowser

## 大数据

- DruidCrack：Druid密文解密工具 https://github.com/rabbitmask/DruidCrack

## 逆向分析

- 逆向分析工具集：https://pythonarsenal.com/
- PEiD：查壳工具 https://www.aldeid.com/wiki/PEiD
- Py2exe：Python打包工具 https://www.py2exe.org/
- PyInstaller：Python打包工具 https://github.com/pyinstaller/pyinstaller

## 工具赋能

### Metasploit

- Metasploit：https://github.com/rapid7/metasploit-framework

### Cobaltstrike

- Awesome CobaltStrike：CobaltStrike知识库 https://github.com/zer0yu/Awesome-CobaltStrike

- Erebus：后渗透测试插件 https://github.com/DeEpinGh0st/Erebus
- LSTAR：综合后渗透插件 https://github.com/lintstar/LSTAR
- ElevateKit：提权插件 https://github.com/rsmudge/ElevateKit

### Burpsuite

- HaE：高亮标记与信息提取辅助型插件 https://github.com/gh0stkey/HaE
- Log4j2Scan：Log4j主动扫描 https://github.com/whwlsfb/Log4j2Scan

### Chrome crx

- Proxy SwitchyOmega：快速切换代理 https://github.com/FelisCatus/SwitchyOmega
- Wappalyzer：识别网站技术/框架/语言 https://www.wappalyzer.com/
- EditThisCookie：修改Cookie https://www.editthiscookie.com/
- FindSomething：在网页的源代码或js中寻找有用信息 https://github.com/ResidualLaugh/FindSomething
- Disable JavaScript：禁用JavaScript绕过弹窗 https://github.com/dpacassi/disable-javascript
- Hunter：查找网页暴露邮箱 https://hunter.io/chrome
- Hack Bar：渗透神器No.1 https://github.com/0140454/hackbar

### Xray

- Xray：安全评估工具 https://github.com/chaitin/xray

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

