from main import *

print_payloads =(
"""
+ Windows Reverse Shell
- This payload will give the attacker a stageless reverse tcp shell
- A listener will be automatically started using NetCat

+ Windows Reverse Meterpreter
- This payload will give the attacker a staged reverse tcp meterpreter shell
- A listener will be automatically started using Metasploit
- All MODULES are avalible for this payload

+ Windows Bind Meterpreter
- This payload will give the attacker a staged bind tcp meterpreter shell
- Connection to the bind port will be automatically started using Metasploit
- All MODULES are avalible for this payload

+ Windows Reverse Meterpreter HTTPS
- This payload will give the attacker a staged reverse HTTPS meterpreter shell
- A listener will be automatically started using Metasploit
- All MODULES are avalible for this payload

+ Windows Reverse Meterpreter DNS
- This payload will give the attacker a staged reverse tcp meterpreter shell with DNS name resolution
- Good for dynamic ip addresses and persistence payloads
- A listener will be automatically started using Metasploit
- All MODULES are avalible for this payload
""")
print_modules =(
"""
+ UAC Bypass
- This Module only works on Local Administrator Accounts
- Using this module, PowerShellEmpire's UAC Bypass will execute on the target
- This will bypass uac and create another session running as administrator
- https://github.com/PowerShellEmpire/Empire

+ Priv Esc checks
- Using this module, PowerShellEmpire's PowerUp AllChecks will execute on the target
- This will find common privesc vulnerabilities on the target
- https://github.com/PowerShellEmpire/Empire

+ Persistence
- This module will run a powershell script on the target
- Persistence adds registry keys and to the startup folder to automatically run the payload everytime the target boots
""")
print_deployment =(
"""
+ SimpleHTTPServer
- The payload will be hosted locally on a HTTP server

+ Psexec and Spraying
- Spray hashes to find a vulnerable target
- Psexec the payload to the target
- Runs as system
""")


def winpayloads_help():
    print "\n|=------=|"
    print "|" + t.bold_green + "PAYLOADS" + t.normal + "|"
    print "|=------=|"
    print print_modules
    print "\n|=-----=|"
    print "|" + t.bold_green + "MODULES" + t.normal + "|"
    print "|=-----=|"
    print print_payloads
    print "\n|=--------=|"
    print "|" + t.bold_green + "DEPLOYMENT" + t.normal + "|"
    print "|=--------=|"
    print print_deployment
