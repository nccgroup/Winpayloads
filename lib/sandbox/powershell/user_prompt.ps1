#
#   Prompts user with dialog box and waits for response before executing, PowerShell
#   Module written by Brandon Arvanaghi
#   Website: arvanaghi.com
#   Twitter: @arvanaghi
#	  Edited for use in winpayloads

$dialogBoxTitle = "Update Complete"
$dialogBoxMessage = "Press OK to Continue"

if ($Args.count -eq 2) {
	$dialogBoxTitle = $($args[0])
	$dialogBoxMessage = $($args[1])
}

$messageBox = New-Object -COMObject WScript.Shell
[void]$messageBox.Popup($dialogBoxMessage,0,$dialogBoxTitle,0)
