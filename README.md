# Winpayloads - Python2.7
Undetectable Windows Payload Generation with extras Running on Python2.7

## As usual, Don't upload payloads to any online virus checkers  
- Virus Total Detection - Updated 25/01/2019 - 16/68 Detections  
https://www.virustotal.com/#/file/a921ac7540c93bf03a8ed76158b445b5f8780d8f112405811ebbe820c0e3d5c3/detection

## For Fully Undetectable Payloads please use the stager functionality [Youtube Video](https://youtu.be/eRl5H5wHqKY)

## Docker!  
Normal installation is deprecated, Please use docker now.  
`docker pull charliedean07/winpayloads:latest`  
`docker run -e LANG=C.UTF-8 --net=host -it charliedean07/winpayloads`  

  
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
* Anti sandboxing techniques
* Custom shellcode 

## Check out the Wiki for installation and more!
https://github.com/nccgroup/Winpayloads/wiki  

![alt tag](https://raw.githubusercontent.com/Charliedean/charliedean.github.io/master/images/2016-02-16%2010_12_29-Kali2%20-%20VMware%20Workstation.png)

# Video and Information on Blog  (OUTDATED)
https://charliedean.github.io  
