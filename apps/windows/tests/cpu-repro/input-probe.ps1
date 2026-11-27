param([string]$Exe, [string]$Mode)
Add-Type -AssemblyName UIAutomationClient, UIAutomationTypes
$AE = [System.Windows.Automation.AutomationElement]; $TS = [System.Windows.Automation.TreeScope]
Add-Type -Namespace Win -Name N -MemberDefinition '[DllImport("user32.dll")] public static extern bool SetForegroundWindow(System.IntPtr h); [DllImport("user32.dll")] public static extern void keybd_event(byte vk, byte scan, uint flags, System.UIntPtr extra); [DllImport("user32.dll")] public static extern bool SetCursorPos(int x, int y); [DllImport("user32.dll")] public static extern void mouse_event(uint f, uint dx, uint dy, uint d, System.UIntPtr e); [DllImport("user32.dll")] public static extern System.IntPtr GetForegroundWindow(); [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(System.IntPtr h, System.IntPtr pid); [DllImport("kernel32.dll")] public static extern uint GetCurrentThreadId(); [DllImport("user32.dll")] public static extern bool AttachThreadInput(uint a, uint b, bool attach); [DllImport("user32.dll")] public static extern bool BringWindowToTop(System.IntPtr h); [DllImport("user32.dll")] public static extern void SwitchToThisWindow(System.IntPtr h, bool altTab);'
# Take the foreground even while another app holds it (a plain SetForegroundWindow is refused then).
function Front($hw) { for ($k = 0; $k -lt 10 -and [Win.N]::GetForegroundWindow() -ne $hw; $k++) { [Win.N]::keybd_event(0x12,0,0,[UIntPtr]::Zero); [Win.N]::keybd_event(0x12,0,2,[UIntPtr]::Zero); $tid = [Win.N]::GetWindowThreadProcessId([Win.N]::GetForegroundWindow(), [IntPtr]::Zero); $me = [Win.N]::GetCurrentThreadId(); [void][Win.N]::AttachThreadInput($me, $tid, $true); [void][Win.N]::BringWindowToTop($hw); [void][Win.N]::SetForegroundWindow($hw); [void][Win.N]::AttachThreadInput($me, $tid, $false); if ($k -ge 4) { [Win.N]::SwitchToThisWindow($hw, $true) }; Start-Sleep -Milliseconds 300 } }
function Cpu($p) { $p.Refresh(); $a = $p.TotalProcessorTime.TotalMilliseconds; Start-Sleep 2; $p.Refresh(); [int](($p.TotalProcessorTime.TotalMilliseconds - $a) / 20) }
function Center($el) { $r = $el.Current.BoundingRectangle; @([int]($r.X + $r.Width/2), [int]($r.Y + $r.Height/2)) }
function Click() { [Win.N]::mouse_event(2,0,0,0,[UIntPtr]::Zero); Start-Sleep -Milliseconds 60; [Win.N]::mouse_event(4,0,0,0,[UIntPtr]::Zero) }
[void][Win.N]::SetCursorPos(5, 5)
$p = Start-Process $Exe -PassThru
try {
  do { Start-Sleep -Milliseconds 300; $win = $AE::RootElement.FindFirst($TS::Children, (New-Object System.Windows.Automation.PropertyCondition($AE::ProcessIdProperty, $p.Id))) } while (-not $win)
  Start-Sleep 3
  Front ([IntPtr]$win.Current.NativeWindowHandle); Start-Sleep 1
  $add = $win.FindFirst($TS::Descendants, (New-Object System.Windows.Automation.PropertyCondition($AE::NameProperty, 'Add text')))
  $txt = $win.FindFirst($TS::Descendants, (New-Object System.Windows.Automation.PropertyCondition($AE::NameProperty, 'Hello')))
  $c = Center $add; $t = Center $txt
  switch ($Mode) {
    'invoke-cursor-outside' { }
    'invoke-cursor-over-window' { [void][Win.N]::SetCursorPos($t[0], $t[1]) }
    'invoke-cursor-over-button' { [void][Win.N]::SetCursorPos($c[0], $c[1]) }
    'click-text-then-invoke' { [void][Win.N]::SetCursorPos($t[0], $t[1]); Start-Sleep -Milliseconds 150; Click; Start-Sleep -Milliseconds 300; [void][Win.N]::SetCursorPos(5,5) }
  }
  Start-Sleep -Milliseconds 400
  $before = Cpu $p
  if ($Mode -like 'click-named:*') { $e = $win.FindFirst($TS::Descendants, (New-Object System.Windows.Automation.PropertyCondition($AE::NameProperty, $Mode.Split(':')[1]))); $q = Center $e; [void][Win.N]::SetCursorPos($q[0], $q[1]); Start-Sleep -Milliseconds 150; Click; Start-Sleep -Milliseconds 200; [void][Win.N]::SetCursorPos(5,5) }
  elseif ($Mode -like 'click-named-esc:*') {   # open a flyout or overflow, then close it with Esc before measuring
    $e = $win.FindFirst($TS::Descendants, (New-Object System.Windows.Automation.PropertyCondition($AE::NameProperty, $Mode.Split(':')[1])))
    if ($null -eq $e) { "element not found: $($Mode.Split(':')[1])"; return }
    $q = Center $e; [void][Win.N]::SetCursorPos($q[0], $q[1]); Start-Sleep -Milliseconds 150; Click; Start-Sleep -Milliseconds 800
    [Win.N]::keybd_event(0x1B,0,0,[UIntPtr]::Zero); [Win.N]::keybd_event(0x1B,0,2,[UIntPtr]::Zero); Start-Sleep -Milliseconds 300; [void][Win.N]::SetCursorPos(5,5) }
  elseif ($Mode -eq 'click-button') { [void][Win.N]::SetCursorPos($c[0], $c[1]); Start-Sleep -Milliseconds 150; Click }
  elseif ($Mode -eq 'click-button-then-move-out') { [void][Win.N]::SetCursorPos($c[0], $c[1]); Start-Sleep -Milliseconds 150; Click; Start-Sleep -Milliseconds 200; [void][Win.N]::SetCursorPos(5,5) }
  else { $add.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke() }
  Start-Sleep 1
  $after = Cpu $p
  "{0,-30} before change={1,3}%  after change={2,3}%" -f $Mode, $before, $after
} finally { if (-not $p.HasExited) { $p.Kill() } }
