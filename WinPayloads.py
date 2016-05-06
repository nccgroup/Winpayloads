#!/usr/bin/python
from lib.main import *
from lib.payloadextras import *
from lib.startmetasploit import *
from lib.menu import *

try:
    from lib.psexecspray import *
except:
    print t.bold_red + "[!] Rerun the setup.sh" + t.normal

if not re.search('winpayloads', os.getcwd().lower()):
    print t.bold_red + "[!!] Please Run From Winpayloads Dir" + t.normal
    sys.exit(1)

try:
    os.mkdir('/etc/winpayloads')
except OSError:
    pass


try:
    getAndRunMainMenu()
except KeyboardInterrupt:
    print t.bold_green + '\n[*] Cleaning Up\n' + t.normal
    subprocess.call(['rm *.rc'], shell=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.call(['rm *.ps1'], shell=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    subprocess.call(['rm logdict*'], shell=True,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    sys.exit()
