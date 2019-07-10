#
#   Waits until N mouse clicks occur before executing (default: 10), Python
#   Module written by Brandon Arvanaghi
#   Website: arvanaghi.com
#   Twitter: @arvanaghi
#	Edited for use in winpayloads

import win32api
import sys

count = 0
*minClicks* = $10$

while count < minClicks:
	new_state_left_click = win32api.GetAsyncKeyState(1)
	new_state_right_click = win32api.GetAsyncKeyState(2)

	if new_state_left_click % 2 == 1:
		count += 1
	if new_state_right_click % 2 == 1:
		count += 1
