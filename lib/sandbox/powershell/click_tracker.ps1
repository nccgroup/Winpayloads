#
#   Waits until N mouse clicks occur before executing (default: 10), PowerShell
#   Module written by Brandon Arvanaghi
#   Website: arvanaghi.com
#   Twitter: @arvanaghi
#	  Edited for use in winpayloads

*$minClicks* = $10$
$count = 0

$getAsyncKeyProto = @'
[DllImport("user32.dll", CharSet=CharSet.Auto, ExactSpelling=true)]
public static extern short GetAsyncKeyState(int virtualKeyCode);
'@

$getAsyncKeyState = Add-Type -MemberDefinition $getAsyncKeyProto -Name "Win32GetState" -Namespace Win32Functions -PassThru

while ($count -lt $minClicks) {
    Start-Sleep 1
    $leftClick = $getAsyncKeyState::GetAsyncKeyState(1)
    $rightClick = $getAsyncKeyState::GetAsyncKeyState(2)

    if ($leftClick) {
        $count += 1
    }

    if ($rightClick) {
        $count += 1
    }
}
