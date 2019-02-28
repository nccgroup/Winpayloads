#
#   Minimum Registry size checker (default: 55 MB), Python
#   Module written by Brandon Arvanaghi
#   Website: arvanaghi.com
#   Twitter: @arvanaghi
#	Edited for use in winpayloads

import sys
import win32com
from win32com.client import GetObject

*minRegistrySizeMB* = $55$

regObjects = GetObject("winmgmts:").ExecQuery("SELECT CurrentSize FROM Win32_Registry")

for regObject in regObjects:
	if int(regObject.Properties_('CurrentSize')) > minRegistrySizeMB:
		pass
	else:
		sys.exit()
