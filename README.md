# Awesome-Redteam

**【免责声明】本仓库所涉及的技术、思路和工具仅供安全技术研究，任何人不得将其用于非授权渗透测试，不得将其用于非法用途和盈利，否则后果自行承担。**

## 快速导航

- [攻防渗透常用命令](https://github.com/Threekiii/Awesome-Redteam/blob/master/cheatsheets/%E6%94%BB%E9%98%B2%E6%B8%97%E9%80%8F%E5%B8%B8%E7%94%A8%E5%91%BD%E4%BB%A4%E9%80%9F%E6%9F%A5.md)
- [重要端口及服务速查](https://github.com/Threekiii/Awesome-Redteam/blob/master/cheatsheets/%E9%87%8D%E8%A6%81%E7%AB%AF%E5%8F%A3%E5%8F%8A%E6%9C%8D%E5%8A%A1%E9%80%9F%E6%9F%A5.md)

## 目录
- [Awesome-Redteam](#awesome-redteam)
  - [快速导航](#快速导航)
  - [目录](#目录)
  - [项目导航](#项目导航)
    - [速查文档-CheatSheets](#速查文档-cheatsheets)
    - [一些代码-Scripts](#一些代码-scripts)
    - [攻防知识-Tips](#攻防知识-tips)
    - [服务搭建-Docs](#服务搭建-docs)
  - [开源导航](#开源导航)
    - [编解码/加解密综合](#编解码加解密综合)
    - [常见编解码/加解密](#常见编解码/加解密)
    - [实用工具](#实用工具)
    - [威胁情报](#威胁情报)
    - [网络空间搜索](#网络空间搜索)
    - [公开知识库](#公开知识库)
    - [其他](#其他)
  - [信息收集](#信息收集)
    - [IP/域名](#ip域名)
      - [确认真实IP地址](#确认真实ip地址)
      - [多个地点Ping服务器](#多个地点ping服务器)
      - [IP反查域名](#ip反查域名)
      - [Whois注册信息反查](#whois注册信息反查)
      - [DNS数据聚合查询](#dns数据聚合查询)
      - [TLS证书信息查询](#tls证书信息查询)
      - [IP地址段收集](#ip地址段收集)
    - [指纹识别](#指纹识别)
    - [WAF识别](#waf识别)
    - [扫描/爆破](#扫描爆破)
    - [爆破字典](#爆破字典)
    - [信息泄露](#信息泄露)
    - [电子邮箱](#电子邮箱)
    - [综合信息收集](#综合信息收集)
    - [内网信息收集](#内网信息收集)
  - [漏洞研究](#漏洞研究)
    - [SRC](#src)
    - [开源文库](#开源文库)
    - [靶机平台](#靶机平台)
  - [漏洞利用](#漏洞利用)
    - [综合POC](#综合poc)
    - [综合工具](#综合工具)
    - [辅助工具](#辅助工具)
    - [操作系统](#操作系统)
    - [中间件](#中间件)
    - [CMS](#cms)
    - [OA](#oa)
    - [Bypass](#bypass)
  - [内网渗透](#内网渗透)
    - [Payloads](#payloads)
    - [WebShell](#webshell)
    - [Bypass](#bypass-1)
    - [免杀](#免杀)
    - [内网穿透](#内网穿透)
    - [密码提取](#密码提取)
    - [开源蜜罐](#开源蜜罐)
    - [容器安全](#容器安全)
    - [其他](#其他-1)
  - [新一代信息技术](#新一代信息技术)
    - [移动端/物联网](#移动端物联网)
    - [云服务](#云服务)
    - [大数据](#大数据)
    - [逆向分析](#逆向分析)
  - [工具赋能](#工具赋能)
    - [Metasploit](#metasploit)
    - [Yakit](#yakit)
    - [Cobaltstrike](#cobaltstrike)
    - [Burpsuite](#burpsuite)
    - [Chrome crx](#chrome-crx)
  - [其他优秀项目](#其他优秀项目)
  - [使用姿势](#使用姿势)
    - [如何在Windows上使用alias](#如何在windows上使用alias)
    - [如何使用浏览器快速查看markdown文档](#如何使用浏览器快速查看markdown文档)

## 项目导航

### 速查文档-CheatSheets

- 攻防渗透常用命令速查：[Click Here](https://github.com/Threekiii/Awesome-Redteam/blob/master/cheatsheets/%E6%94%BB%E9%98%B2%E6%B8%97%E9%80%8F%E5%B8%B8%E7%94%A8%E5%91%BD%E4%BB%A4%E9%80%9F%E6%9F%A5.md)
- 常见WAF拦截页面速查：[Click Here](https://github.com/Threekiii/Awesome-Redteam/blob/master/cheatsheets/%E5%B8%B8%E8%A7%81WAF%E6%8B%A6%E6%88%AA%E9%A1%B5%E9%9D%A2%E9%80%9F%E6%9F%A5.md)
- 反弹shell命令速查：[Click Here](https://github.com/Threekiii/Awesome-Redteam/blob/master/cheatsheets/%E5%8F%8D%E5%BC%B9shell%E5%91%BD%E4%BB%A4%E9%80%9F%E6%9F%A5.md)
- 重要端口及服务速查：[Click Here](https://github.com/Threekiii/Awesome-Redteam/blob/master/cheatsheets/%E9%87%8D%E8%A6%81%E7%AB%AF%E5%8F%A3%E5%8F%8A%E6%9C%8D%E5%8A%A1%E9%80%9F%E6%9F%A5.md)
- HTTP状态码速查：[Click Here](https://github.com/Threekiii/Awesome-Redteam/blob/master/cheatsheets/HTTP%E7%8A%B6%E6%80%81%E7%A0%81%E9%80%9F%E6%9F%A5.md)
- 安全厂商及官网链接速查：[Click Here](https://github.com/Threekiii/Awesome-Redteam/blob/master/cheatsheets/%E5%AE%89%E5%85%A8%E5%8E%82%E5%95%86%E5%8F%8A%E5%AE%98%E7%BD%91%E9%93%BE%E6%8E%A5%E9%80%9F%E6%9F%A5.txt)
- 主要安全产品及弱口令速查：[Click Here](https://github.com/Threekiii/Awesome-Redteam/blob/master/cheatsheets/%E4%B8%BB%E8%A6%81%E5%AE%89%E5%85%A8%E4%BA%A7%E5%93%81%E5%8F%8A%E5%BC%B1%E5%8F%A3%E4%BB%A4%E9%80%9F%E6%9F%A5.md)
- Apache项目及漏洞指纹速查：[Click Here](https://github.com/Threekiii/Awesome-Redteam/blob/master/cheatsheets/Apache%E9%A1%B9%E7%9B%AE%E5%8F%8A%E6%BC%8F%E6%B4%9E%E6%8C%87%E7%BA%B9%E9%80%9F%E6%9F%A5.md) 
- OWASP TOP10 2017/2021：[Click Here](https://github.com/Threekiii/Awesome-Redteam/blob/master/cheatsheets/OWASP%20TOP10.md) 

### 一些代码-Scripts

- ShellcodeWrapper：[Click Here](https://github.com/Threekiii/Awesome-Redteam/tree/master/scripts/ShellcodeWrapper) 
- AntivirusScanner：杀软进程检测脚本 [Click Here](https://github.com/Threekiii/Awesome-Redteam/tree/master/scripts/AntivirusScanner) 
- runtime-exec-payloads.html：java.lang.Runtime.exec() Payloads生成 [Click Here](https://github.com/Threekiii/Awesome-Redteam/blob/master/scripts/runtime-exec-payloads.html) 

### 攻防知识-Tips

- 内网渗透-免杀：[Click Here](https://github.com/Threekiii/Awesome-Redteam/blob/master/tips/%E5%86%85%E7%BD%91%E6%B8%97%E9%80%8F-%E5%85%8D%E6%9D%80.md)
- 内网渗透-隐藏：[Click Here](https://github.com/Threekiii/Awesome-Redteam/blob/master/tips/%E5%86%85%E7%BD%91%E6%B8%97%E9%80%8F-%E9%9A%90%E8%97%8F.md)
- 红队中易被攻击的一些重点系统漏洞整理（来源：棱角安全团队）：[Click Here](https://github.com/Threekiii/Awesome-Redteam/blob/master/tips/%E7%BA%A2%E9%98%9F%E4%B8%AD%E6%98%93%E8%A2%AB%E6%94%BB%E5%87%BB%E7%9A%84%E4%B8%80%E4%BA%9B%E9%87%8D%E7%82%B9%E7%B3%BB%E7%BB%9F%E6%BC%8F%E6%B4%9E%E6%95%B4%E7%90%86.md)
- 网络攻击与防御图谱：[Click Here](https://github.com/Threekiii/Awesome-Redteam/blob/master/tips/%E7%BD%91%E7%BB%9C%E6%94%BB%E5%87%BB%E4%B8%8E%E9%98%B2%E5%BE%A1%E5%9B%BE%E8%B0%B1.svg) 
- 云上攻防：[Click Here](https://github.com/Threekiii/Awesome-Redteam/blob/master/tips/%E4%BA%91%E4%B8%8A%E6%94%BB%E9%98%B2.md)

### 服务搭建-Docs

- DNS log平台搭建：[Click Here](https://github.com/Threekiii/Awesome-Redteam/blob/master/docs/DNS%20log%E5%B9%B3%E5%8F%B0%E6%90%AD%E5%BB%BA.md) 

## 开源导航

### 编解码/加解密综合

- CyberChef：编解码及加密，可本地部署 https://github.com/gchq/CyberChef
- OK Tools在线工具：https://github.com/wangyiwy/oktools
- CTF在线工具：http://www.hiencode.com/
- XSSEE：在线综合编解码工具 https://evilcos.me/lab/xssee/
- MeTools：在线综合编解码工具 http://www.metools.info/code/quotedprintable231.html

### 常见编解码/加解密

- MD5 Hash：https://www.somd5.com/
- GB2312：http://code.mcdvisa.com/
- Unicode字符表：https://www.52unicode.com/enclosed-alphanumerics-zifu
- Unicode：https://www.compart.com/en/unicode/
- UUencode：http://web.chacuo.net/charsetuuencode
- Escape/Unescape：https://tool.chinaz.com/tools/escape.aspx
- HTML实体编码：https://zh.rakko.tools/tools/21/

### 实用工具

- Explain Shell：Shell命令解析 https://explainshell.com/
- 反弹Shell生成：可本地部署 https://github.com/0dayCTF/reverse-shell-generator
- 在线正则表达式：https://c.runoob.com/front-end/854/
- Webshell Chop：https://webshellchop.chaitin.cn/demo/
- XSS Chop：https://xsschop.chaitin.cn/demo/
- WebShell查杀：https://n.shellpub.com/
- HTML5 Security Cheatsheet：XSS攻击向量学习/参考 https://html5sec.org/
- 在线代码格式标准化：http://web.chacuo.net/formatsh
- 免费接受手机验证码：https://www.supercloudsms.com/en/ 

### 威胁情报

- Virustotal：https://www.virustotal.com/gui/home/upload
- 腾讯哈勃分析系统：https://habo.qq.com/tool/index
- 微步在线威胁情报：https://x.threatbook.cn/
- 奇安信威胁情报：https://ti.qianxin.com/
- 360威胁情报：https://ti.360.net/#/homepage
- 安恒威胁情报：https://ti.dbappsecurity.com.cn/
- 火线安全平台：https://www.huoxian.cn
- 知道创宇漏洞平台：https://www.seebug.org/
- Hacking8安全信息流：https://i.hacking8.com/

### 网络空间搜索

- Fofa：https://fofa.info/
- Shodan：https://www.shodan.io/
- ZoomEye：https://www.zoomeye.org/
- 谛听：https://www.ditecting.com/
- 360网络空间测绘：https://quake.360.cn/quake/#/index
- Google Hacking Database：https://www.exploit-db.com/google-hacking-database

### 公开知识库

- 零组文库：零组已停运，非官方 https://0-wiki.com/
- 先知社区：https://xz.aliyun.com/
- 狼组公开知识库：https://wiki.wgpsec.org/
- 404星链计划：知道创宇 404 实验室 https://github.com/knownsec/404StarLink
- MITRE ATT＆CK：网络攻击中使用的已知对抗战术和技术 https://attack.mitre.org/matrices/enterprise/

### 其他

- Wayback Machine：网页历史缓存 https://archive.org/web

## 信息收集

### IP/域名

#### 确认真实IP地址

- IP精准定位：https://www.ipuu.net/#/home
- IP 138：https://site.ip138.com/
- Security Trails：https://securitytrails.com/

#### 多个地点Ping服务器

- Chinaz：https://ping.chinaz.com/
- Host Tracker：https://www.host-tracker.com/
- Webpage Test：https://www.webpagetest.org/
- DNS Check：https://dnscheck.pingdom.com/

#### IP反查域名

- IP138 https://site.ip138.com/
- 微步在线  https://x.threatbook.cn/

- VirusTotal [https://www.virustotal.com/](https://www.virustotal.com/gui/home/upload)

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

### 指纹识别

- Wapplyzer：Chrome插件 跨平台网站分析工具 https://github.com/AliasIO/Wappalyzer
- TideFinger：提取了多个开源指纹识别工具的规则库并进行了规则重组 https://github.com/TideSec/TideFinger
- fingerprint：各种工具指纹收集分享 https://github.com/r0eXpeR/fingerprint
- Dismap：tcp/udp/tls 协议指纹和 4500+ Web 指纹规则 https://github.com/zhzyker/dismap
- Finger：一款红队在大量的资产中存活探测与重点攻击系统指纹探测工具 https://github.com/EASY233/Finger
- 御剑web指纹识别程序：https://www.webshell.cc/4697.html
- 云悉指纹识别：http://www.yunsee.cn/

### WAF识别

- identYwaf：WAF识别工具 https://github.com/stamparm/identYwaf

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
- Web-Fuzzing-Box：Web 模糊测试字典与Payloads https://github.com/gh0stkey/Web-Fuzzing-Box
- PentesterSpecialDict：渗透测试工程师精简化字典 https://github.com/ppbibo/PentesterSpecialDict
- fuzz：https://github.com/Bo0oM/fuzz.txt
- SuperWordlist：弱口令字典 https://github.com/fuzz-security/SuperWordlist
- top25-parameter：top25参数字典 https://github.com/lutfumertceylan/top25-parameter

### 信息泄露

- GitHack：.git泄露利用脚本 https://github.com/lijiejie/GitHack
- ds_store_exp：.DS_Store 文件泄漏利用脚本 https://github.com/lijiejie/ds_store_exp
- Hawkeye：GitHub 泄露监控系统 https://github.com/0xbug/Hawkeye 

### 电子邮箱

- Hunter：Chrome插件 查找网页暴露邮箱 https://hunter.io/chrome
- Skymem：邮箱地址搜索 https://www.skymem.info/
- 搜邮箱：邮箱域名搜索 https://souyouxiang.com/find-contact/
- gophish：钓鱼邮件 https://github.com/gophish/gophish

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
- ENScan_GO：国内企业信息收集 https://github.com/wgpsec/ENScan_GO
- Ladon：用于大型网络渗透的多线程插件化综合扫描工具 https://github.com/k8gege/Ladon
- HackBrowserData：浏览器数据导出工具 https://github.com/moonD4rk/HackBrowserData

## 漏洞研究

### SRC

- HackerOne：https://www.hackerone.com/

### 开源文库

- cve：收录了几乎所有公开的CVE https://github.com/trickest/cve
- Vulhub：基于Docker的漏洞复现环境 https://vulhub.org/
- PeiQi：面向网络安全从业者的知识文库 http://wiki.peiqi.tech/
- Vulnerability：棱角社区公布漏洞 https://github.com/EdgeSecurityTeam/Vulnerability
- 乌云镜像：http://wooyun.2xss.cc/
- 未授权访问漏洞总结：http://luckyzmj.cn/posts/15dff4d3.html

### 靶机平台

- DVWA：https://github.com/digininja/DVWA
- HackTheBox：https://www.hackthebox.com/
- OWASP Top10：https://owasp.org/www-project-juice-shop/
- WebGoat：https://github.com/WebGoat/WebGoat
- Sqli-labs：SQL注入 https://github.com/Audi-1/sqli-labs
- Xss-labs：XSS注入 https://github.com/do0dl3/xss-labs
- Upload-labs：上传漏洞 https://github.com/c0ny1/upload-labs
- Vulstudy：docker快速搭建共17个漏洞靶场 https://github.com/c0ny1/vulstudy
- Vulfocus：漏洞集成平台 https://github.com/fofapro/vulfocus

## 漏洞利用

### 综合POC

- Exploit Database：https://www.exploit-db.com/
- POChouse：https://github.com/DawnFlame/POChouse
- Some-PoC-oR-ExP：各种漏洞PoC、ExP的收集或编写 https://github.com/coffeehb/Some-PoC-oR-ExP
- Library-POC：基于Pocsuite3、goby编写的漏洞poc&exp存档 https://github.com/luck-ying/Library-POC
- Penetration_Testing_POC：https://github.com/Mr-xn/Penetration_Testing_POC
- PoC-in-GitHub：https://github.com/nomi-sec/PoC-in-GitHub
- 0day：https://github.com/helloexp/0day

### 综合工具

- Xray：安全评估工具 https://github.com/chaitin/xray
- Vulmap：漏洞扫描和验证工具 https://github.com/zhzyker/vulmap
- Artillery：插件化 JAVA 漏洞扫描器 https://github.com/Weik1/Artillery
- Aazhen-v3.1：JavaFX图形化漏洞扫描工具 https://github.com/zangcc/Aazhen-v3.1

### 辅助工具

- ysoserial：Java反序列化 https://github.com/frohoff/ysoserial
- Ceye DNS：在线平台 http://ceye.io/
- Dnslog：在线平台 http://dnslog.cn/
- Fuzz.Red：在线平台 https://github.com/AlphabugX/Alphalog
- DNSLog-GO：自建私有平台 https://github.com/lanyi1998/DNSlog-GO
- JNDI-Injection-Exploit：https://github.com/welk1n/JNDI-Injection-Exploit
- JNDIExploit：功能更强 冰蝎内存马 https://github.com/WhiteHSBG/JNDIExploit

### 操作系统

- Windows-Exploit-Suggester：https://github.com/AonCyberLabs/Windows-Exploit-Suggester
- Linux_Exploit_Suggester：https://github.com/InteliSecureLabs/Linux_Exploit_Suggester

### 中间件

- shiro_attack：https://github.com/j1anFen/shiro_attack
- shiro_rce_tool：https://github.com/wyzxxz/shiro_rce_tool
- ShiroExploit：https://github.com/feihong-cs/ShiroExploit-Deprecated
- ShiroExp：https://github.com/safe6Sec/ShiroExp
- shiro_key：shiro key 收集 目前 1k+ https://github.com/yanm1e/shiro_key
- Struts2VulsTools：https://github.com/shack2/Struts2VulsTools
- ThinkphpGUI：https://github.com/Lotus6/ThinkphpGUI
- thinkphp_gui_tools：https://github.com/bewhale/thinkphp_gui_tools
- WeblogicScan：https://github.com/dr0op/WeblogicScan
- weblogicScanner：https://github.com/0xn0ne/weblogicScanner
- weblogic-framework：https://github.com/sv3nbeast/weblogic-framework
- SpringBootVulExploit：https://github.com/LandGrey/SpringBootVulExploit

### CMS

- CMS-Hunter：CMS漏洞测试用例集合 https://github.com/SecWiki/CMS-Hunter
- 若依CMS https://github.com/thelostworldFree/Ruoyi-All

### OA

- OA综合 https://github.com/achuna33/MYExploit

### Bypass

- CVE-2021-44228-PoC-log4j-bypass-words：https://github.com/Puliczek/CVE-2021-44228-PoC-log4j-bypass-words

## 内网渗透

### Payloads

- PayloadsAllTheThings：https://github.com/swisskyrepo/PayloadsAllTheThings
- java.lang.Runtime.exec() Payload：java Payload在线生成 https://www.bugku.net/runtime-exec-payloads/
- PHP Generic Gadget Chains：PHP反序列化Payload https://github.com/ambionics/phpggc

### WebShell

- Webshell收集项目：https://github.com/tennc/webshell
- TomcatMemShell：Tomcat内存马 https://github.com/ce-automne/TomcatMemShell
- wsMemShell：WebSocket 内存马 https://github.com/veo/wsMemShell
- Behinder 冰蝎：https://github.com/rebeyond/Behinder
  - Behinder4已经发布
  - Behinder3：`kali + java 11.0.14` 或 `windows10 + java 1.8.0_91`，注意，该环境下Behinder2无法正常运行，Behinder3代理经测试php无法成功穿透，jsp可以成功穿透
  - Behinder2：windows10 + java 1.8.0_91
- Godzilla 哥斯拉：https://github.com/BeichenDream/Godzilla
- Skyscorpion：https://github.com/shack2/skyscorpion

### Bypass

- PHPFuck：https://github.com/splitline/PHPFuck
- JSFuck：http://www.jsfuck.com/
- Gopherus：生成gopher链接 https://github.com/tarunkant/Gopherus

### 免杀

- bypassAV：免杀shellcode加载器 过火绒不过360 https://github.com/pureqh/bypassAV
- GolangBypassAV：https://github.com/safe6Sec/GolangBypassAV
- BypassAntiVirus：远控免杀系列文章及配套工具 https://github.com/TideSec/BypassAntiVirus 
  - BypassAntiVirus2022年部分免杀复现：[Threekiii/Awesome-Redteam](https://github.com/Threekiii/Awesome-Redteam/blob/master/tips/%E5%86%85%E7%BD%91%E6%B8%97%E9%80%8F-%E5%85%8D%E6%9D%80.md)

- AV_Evasion_Tool：掩日 - 适用于红队的综合免杀工具 https://github.com/1y0n/AV_Evasion_Tool
- shellcodeloader：Windows平台的shellcode免杀加载器 https://github.com/knownsec/shellcodeloader
- 杀软比对：https://www.shentoushi.top/av/av.php

### 内网穿透

- NPS：通过web端管理，无需配置文件 https://github.com/ehang-io/nps
- FRP：55k star项目 https://github.com/fatedier/frp
- Neo-reGeorg：tunnel快速部署 https://github.com/L-codes/Neo-reGeorg
- Proxifier：windows代理工具 https://www.proxifier.com/
- Proxychains：kali代理工具 https://github.com/haad/proxychains

### 密码提取

- Responder：实现获取NTLM Hash等功能 https://github.com/SpiderLabs/Responder

### 开源蜜罐

- HFish：一款安全、简单可信赖的跨平台蜜罐软件，允许商业和个人用户免费使用 https://github.com/hacklcx/HFish

### 容器安全

- CDK：容器渗透 https://github.com/cdk-team/CDK
- veinmind-tools：容器安全工具集 https://github.com/chaitin/veinmind-tools

### 其他

- Impacket：其中的psexec.py通过用户名和密码远程连接到目标服务器 https://github.com/SecureAuthCorp/impacket
- PsTools：PsExec.exe功能同Impacket中的psexec.py https://docs.microsoft.com/en-us/sysinternals/downloads/pstools

## 新一代信息技术

### 移动端/物联网

- CrackMinApp：反编译微信小程序 https://github.com/Cherrison/CrackMinApp  
- AppInfoScanner：移动端信息收集 https://github.com/kelvinBen/AppInfoScanner
- wxappUnpacker：小程序解包 https://github.com/xuedingmiaojun/wxappUnpacker
- IoT-vulhub： IoT 版固件漏洞复现环境 https://github.com/firmianay/IoT-vulhub

### 云服务

- aliyun-accesskey-Tools：阿里云accesskey利用工具 https://github.com/mrknow001/aliyun-accesskey-Tools
- cosbrowser：腾讯云COS客户端 https://github.com/TencentCloud/cosbrowser

### 大数据

- DruidCrack：Druid密文解密工具 https://github.com/rabbitmask/DruidCrack

### 逆向分析

- 逆向分析工具集：https://pythonarsenal.com/
- PEiD：查壳工具 https://www.aldeid.com/wiki/PEiD
- Py2exe：Python打包工具 https://www.py2exe.org/
- PyInstaller：Python打包工具 https://github.com/pyinstaller/pyinstaller

## 云上攻防

- AWSGoat：https://github.com/ine-labs/AWSGoat
- TerraformGoat：https://github.com/HuoCorp/TerraformGoat
- ATT&CK Cloud矩阵：https://attack.mitre.org/matrices/enterprise/cloud/

## 工具赋能

### Metasploit

- Metasploit：https://github.com/rapid7/metasploit-framework
- https://attack.mitre.org/matrices/enterprise/cloud/

### Yakit

- Yakit：网络安全单兵工具 对标Burpsuite https://github.com/yaklang/yakit

### Cobaltstrike

- Awesome CobaltStrike：CobaltStrike知识库 https://github.com/zer0yu/Awesome-CobaltStrike

- Erebus：后渗透测试插件 https://github.com/DeEpinGh0st/Erebus
- LSTAR：综合后渗透插件 https://github.com/lintstar/LSTAR
- ElevateKit：提权插件 https://github.com/rsmudge/ElevateKit

### Burpsuite

- HaE：高亮标记与信息提取辅助型插件 https://github.com/gh0stkey/HaE
- Log4j2Scan：Log4j主动扫描插件 https://github.com/whwlsfb/Log4j2Scan
- RouteVulScan：检测脆弱路径插件 https://github.com/F6JO/RouteVulScan

### Chrome crx

- Proxy SwitchyOmega：快速切换代理 https://github.com/FelisCatus/SwitchyOmega
- Wappalyzer：识别网站技术/框架/语言 https://www.wappalyzer.com/
- EditThisCookie：修改Cookie https://www.editthiscookie.com/
- FindSomething：在网页的源代码或js中寻找有用信息 https://github.com/ResidualLaugh/FindSomething
- Disable JavaScript：禁用JavaScript绕过弹窗 https://github.com/dpacassi/disable-javascript
- Hack Bar：渗透神器No.1 https://github.com/0140454/hackbar

## 其他优秀项目

- oh my zsh：命令行工具集 好用 推荐 https://github.com/ohmyzsh/ohmyzsh
- The art of command line：快速掌握命令行 https://github.com/jlevy/the-art-of-command-line
- PySimpleGUI：https://github.com/PySimpleGUI/PySimpleGUI
- f8x：红/蓝队环境自动化部署工具 https://github.com/ffffffff0x/f8x
- mate-translate：一个翻译神器 https://gikken.co/mate-translate/

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

![image-20220208090022459](https://typora-notes-1308934770.cos.ap-beijing.myqcloud.com/202205131147745.png)

> 解决cmd中文乱码的问题：
>
> 1. 注册表打开`计算机\HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Command Processor`。
> 2. 创建字符串值`autorun`，赋值为`chcp 65001`。

### 如何使用浏览器快速查看markdown文档

- 安装插件`Markdown Viewer`。
- 配合Bootstrap可以实现快速部署导航页或文档库。

![image-20220519182738441](https://typora-notes-1308934770.cos.ap-beijing.myqcloud.com/202205191827578.png)