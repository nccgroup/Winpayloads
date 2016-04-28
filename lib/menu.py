from main import *
from payloadextras import *
from startmetasploit import *
from generatepayload import *
from preparepayload import *

def noColourLen(colourString):
    return len(re.compile(r'\x1b[^m]*m').sub('', colourString))

def noColourCenter(colourString):
    return (' '*((t.width / 2) - (noColourLen(colourString) /2))) + colourString

def getAndRunPSMenu():
    psMenu = MenuOptions(psMenuOptions)
    psMenu.runmenu()

def getAndRunMainMenu():
    mainMenu = MenuOptions(mainMenuOptions)
    mainMenu.runmenu()

mainMenuOptions = OrderedDict([
    ('1', {'payloadchoice': SHELLCODE.windows_rev_shell, 'payload': 'Windows_Reverse_Shell', 'extrawork': reversePayloadGeneration, 'availablemodules': None, 'enableshellter': True}),
    ('2', {'payloadchoice': SHELLCODE.windows_met_rev_shell, 'payload': 'Windows_Meterpreter_Reverse_Shell', 'extrawork': reversePayloadGeneration, 'availablemodules': METASPLOIT_Functions['reverse'], 'enableshellter': True}),
    ('3', {'payloadchoice': SHELLCODE.windows_met_bind_shell, 'payload': 'Windows_Meterpreter_Bind_Shell', 'extrawork': bindPayloadGeneration, 'availablemodules': METASPLOIT_Functions['bind'], 'enableshellter': True}),
    ('4', {'payloadchoice': SHELLCODE.windows_met_rev_https_shell, 'payload': 'Windows_Meterpreter_Reverse_HTTPS', 'extrawork': httpsPayloadGeneration, 'availablemodules': METASPLOIT_Functions['https'], 'enableshellter': True}),
    ('5', {'payloadchoice': SHELLCODE.windows_met_rev_shell_dns, 'payload': 'Windows_Meterpreter_Reverse_Dns', 'extrawork': dnsPayloadGeneration, 'availablemodules': METASPLOIT_Functions['dns'], 'enableshellter': True}),
    ('ps', {'payloadchoice': None, 'payload': 'PowerShell Menu', 'extrawork': getAndRunPSMenu}),
    ('back', {'payloadchoice': None, 'payload': 'Main Menu', 'extrawork': getAndRunMainMenu}),
    ('?', {'payloadchoice': None, 'payload': 'Print Detailed Help', 'extrawork': FUNCTIONS().winpayloads_help}),
])

psMenuOptions = OrderedDict([
    ('1', {'payloadchoice': SHELLCODE.windows_ps_rev_shell, 'payload': 'Windows_Interactive_Reverse_Powershell_Shell', 'extrawork': reversePowerShellGeneration}),
    ('2', {'payloadchoice': SHELLCODE.windows_ps_rev_watch_screen, 'payload': 'Windows_Reverse_Powershell_ScreenWatch', 'extrawork': reversePowerShellWatchScreenGeneration}),
    ('back', {'payloadchoice': None, 'payload': 'Main Menu', 'extrawork': getAndRunMainMenu}),
])

class MenuOptions(object):
    def __init__(self, choices):
        self.choices = choices

    def _choose(self, n):
        if self.choices.has_key(n):
            return (True, self.choices[n]['payloadchoice'], self.choices[n]['payload'], self.choices[n]['extrawork'])
        else:
            print t.bold_red + '[*] Wrong Selection' + t.normal
            return (False, None, None, None)

    def runmenu(self):
        self.printMenues()
        while True:
            user_choice = raw_input('>')
            success, payloadchoice, payload, extrawork = self._choose(user_choice)

            if not success:
                continue
            if extrawork:
                if payloadchoice:
                    extrawork(payloadchoice,payload)
                else:
                    extrawork()
            if user_choice != "?":
                break

    def printMenues(self):
        Splash()
        print '=' * (t.width / 2 - 3) + "-MENU-" + '=' * (t.width / 2 - 3)
        maxlen = 0
        arr = []
        for i in self.choices.iterkeys():
            menuPrintString = t.bold_yellow + str(i) + ': ' + t.normal + str(self.choices[i]['payload'])
            try:
                if self.choices[i]['enableshellter'] == True:
                    menuPrintString += t.bold_red + ' [shellter] ' + t.normal
                menuPrintString += t.bold_green + str(self.choices[i]['availablemodules'].keys()).replace('\'','').replace('normal, ','') + t.normal
            except:
                pass

            nocolourlen = noColourLen(menuPrintString)
            if nocolourlen > maxlen:
                maxlen = nocolourlen
            arr.append(menuPrintString)
        for i in arr:
            print (' '*((t.width / 2) - (maxlen / 2))) + i + (' '*((t.width / 2) - (maxlen / 2)))
        print '='*t.width

def Splash():
    print t.clear + t.bold_red
    print noColourCenter("_       ___       ____              __                __")
    print noColourCenter("  | |     / (_)___  / __ \____ ___  __/ /___  ____ _____/ /____")
    print noColourCenter("  | | /| / / / __ \/ /_/ / __ `/ / / / / __ \/ __ `/ __  / ___/")
    print noColourCenter(" | |/ |/ / / / / / ____/ /_/ / /_/ / / /_/ / /_/ / /_/ (__  )")
    print noColourCenter(" |__/|__/_/_/ /_/_/    \__,_/\__, /_/\____/\__,_/\__,_/____/")
    print noColourCenter("              /____/Charlie Dean" + t.normal)
