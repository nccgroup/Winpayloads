# Winpayloads - Python2.7
Undetectable Windows Payload Generation with extras Running on Python2.7

## As usual, Don't upload payloads to any online virus checkers  
  
  
## Features
* UACBypass - PowerShellEmpire https://github.com/PowerShellEmpire/Empire/raw/master/data/module_source/privesc/Invoke-BypassUAC.ps1 Copyright (c) 2015, Will Schroeder and Justin Warner. All rights reserved.   
* PowerUp - PowerShellEmpire https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1 Copyright (c) 2015, Will Schroeder and Justin Warner. All rights reserved.   
* Invoke-Shellcode https://github.com/PowerShellMafia/PowerSploit/blob/master/CodeExecution/Invoke-Shellcode.ps1 Copyright (c) 2012, Matthew Graeber. All rights reserved.
* Invoke-Mimikatz https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-Mimikatz.ps1 Copyright (c) 2012, Matthew Graeber. All rights reserved.
* Invoke-EventVwrBypass https://github.com/enigma0x3/Misc-PowerShell-Stuff/blob/master/Invoke-EventVwrBypass.ps1 Matt Nelson (@enigma0x3)
* Persistence - Adds payload persistence on reboot   
* Psexec Spray - Spray hashes until successful connection and psexec payload on target   
* Upload to local webserver - Easy deployment
* Powershell stager - allows invoking payloads in memory & more

## Getting Started
1. ```git clone https://github.com/nccgroup/winpayloads.git```
2. ```cd winpayloads```
3. ```./setup.sh``` will setup everything needed for Winpayloads
4. Start Winpayloads ```./Winpayloads.py```  
5. Type 'help' or '?' to get a detailed help page  
  ```setup.sh -r``` will reinstall  

#### Rerun setup.sh on every git pull

![alt tag](https://raw.githubusercontent.com/Charliedean/charliedean.github.io/master/images/2016-02-16%2010_12_29-Kali2%20-%20VMware%20Workstation.png)

# Video and Information on Blog  
https://charliedean.github.io  
