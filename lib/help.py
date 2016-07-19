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

print_ps_menu =(
"""
+ Powershell Menu
- Powershell payloads that are executed by Powershell

+ Reverse Powershell shell
- Reverse powershell shell over tcp

+ Reverse Watch Screen
- Streams the targets primary screen to your local machine over tcp

+ Ask creds
- Keeps asking the target for their username and password until the correct credentials are entered.
- Credentials are then sent over tcp
""")

print_stager =(
"""
+ Stager
- Listener starts on port 5555 when starting winpayloads
- Using the stager main menu item will print the encoded powershell stager command
- This can then be used in a bat file or executed directly into a cmd prompt
- A secure encrypted socket connection will be made back to winpayloads
- Using the clients menu, you can interact will all the clients and drop into a shell
- When a client has an active connection, all payloads can be executed on the target through the connection
- Payloads will be invoked without touching disk and powershell payloads will be executed through the shell
- Multiple payloads can be used while the client is connected
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
    print "\n|=--------=|"
    print "|" + t.bold_green + " PS MENU  " + t.normal + "|"
    print "|=--------=|"
    print print_ps_menu
    print "\n|=--------=|"
    print "|" + t.bold_green + "  STAGER  " + t.normal + "|"
    print "|=--------=|"
    print print_stager
    return "pass"
