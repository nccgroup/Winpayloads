#
#
#   Module written by Brandon Arvanaghi
#   Website: arvanaghi.com
#   Twitter: @arvanaghi
#	Edited for use in winpayloads

*$username* = $'administrator'$

if ($env:username.ToLower() -eq $username) {
  $a = 1
} else {
  exit
}
