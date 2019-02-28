#
#
#   Module written by Brandon Arvanaghi
#   Website: arvanaghi.com
#   Twitter: @arvanaghi
#	Edited for use in winpayloads

import sys
import getpass

*username* = $'administrator'$

if getpass.getuser().lower() == username.lower():
    pass
else:
    sys.exit()
