$logfile = 'C:\UnattendLogs\Specialize.log';

try {
    &amp; "C:\Windows\Setup\Scripts\RemovePackages.ps1" *>> $logfile 2>&amp;1
    &amp; "C:\Windows\Setup\Scripts\RemoveCapabilities.ps1" *>> $logfile 2>&amp;1
    &amp; "C:\Windows\Setup\Scripts\RemoveFeatures.ps1" *>> $logfile 2>&amp;1
} catch {
    "Specialize error: $($_.Exception.Message)" | Out-File -FilePath $logfile -Append -Encoding utf8
}
    
&amp; "C:\Windows\Setup\Scripts\RemovePackages.ps1" *>> $logfile 2&gt;&amp;1
&amp; "C:\Windows\Setup\Scripts\RemoveCapabilities.ps1" *>> $logfile 2&gt;&amp;1
&amp; "C:\Windows\Setup\Scripts\RemoveFeatures.ps1" *>> $logfile 2&gt;&amp;1
"Specialize error: $($_.Exception.Message)" | Out-File -FilePath $logfile -Append -Encoding utf8
$scripts = @(
{
reg.exe add "HKLM\SYSTEM\Setup\MoSetup" /v AllowUpgradesWithUnsupportedTPMOrCPU /t REG_DWORD /d 1 /f;
};
{
Remove-Item -LiteralPath 'C:\Users\Default\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk', 'C:\Windows\System32\OneDriveSetup.exe', 'C:\Windows\SysWOW64\OneDriveSetup.exe' -ErrorAction 'Continue';
};
{
Remove-Item -LiteralPath 'Registry::HKLM\Software\Microsoft\WindowsUpdate\Orchestrator\UScheduler_Oobe\OutlookUpdate' -Force -ErrorAction 'SilentlyContinue';
};
{
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Communications" /v ConfigureChatAutoInstall /t REG_DWORD /d 0 /f;
};
{
&amp; 'C:\Windows\Setup\Scripts\RemovePackages.ps1';
};
{
&amp; 'C:\Windows\Setup\Scripts\RemoveCapabilities.ps1';
};
{
&amp; 'C:\Windows\Setup\Scripts\RemoveFeatures.ps1';
};
{
net.exe accounts /maxpwage:UNLIMITED;
};
{
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\CI\Policy" /v VerifiedAndReputablePolicyState /t REG_DWORD /d 0 /f;
};
{
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f;
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components" /v ServiceEnabled /t REG_DWORD /d 0 /f;
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components" /v NotifyMalicious /t REG_DWORD /d 0 /f;
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components" /v NotifyPasswordReuse /t REG_DWORD /d 0 /f;
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\WTDS\Components" /v NotifyUnsafeApp /t REG_DWORD /d 0 /f;
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" /v HideSystray /t REG_DWORD /d 1 /f;
};
{
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 0 /f
};
{
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v LongPathsEnabled /t REG_DWORD /d 1 /f
};
{
Remove-Item -LiteralPath 'C:\Users\Public\Desktop\Microsoft Edge.lnk' -ErrorAction 'SilentlyContinue' -Verbose;
};
{
auditpol.exe /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:enable /failure:enable;
};
{
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f;
};
{
Set-ExecutionPolicy -Scope 'LocalMachine' -ExecutionPolicy 'RemoteSigned' -Force;
};
{
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v HiberbootEnabled /t REG_DWORD /d 0 /f;
};
{
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Dsh" /v AllowNewsAndInterests /t REG_DWORD /d 0 /f;
};
{
reg.exe add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsConsumerFeatures" /t REG_DWORD /d 1 /f;
};
{
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\BitLocker" /v "PreventDeviceEncryption" /t REG_DWORD /d 1 /f;
};
{
reg.exe add "HKLM\Software\Policies\Microsoft\Edge" /v HideFirstRunExperience /t REG_DWORD /d 1 /f;
};
{
reg.exe add "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v BackgroundModeEnabled /t REG_DWORD /d 0 /f;
reg.exe add "HKLM\Software\Policies\Microsoft\Edge\Recommended" /v StartupBoostEnabled /t REG_DWORD /d 0 /f;
};
{
&amp; 'C:\Windows\Setup\Scripts\SetStartPins.ps1';
};
{
try {
$bytes = &amp; 'C:\Windows\Setup\Scripts\GetWallpaper.ps1';
[System.IO.File]::WriteAllBytes( 'C:\Windows\Setup\Scripts\Wallpaper', $bytes );
} catch {
$_;
}
};
{
try {
$bytes = &amp; 'C:\Windows\Setup\Scripts\GetLockScreenImage.ps1';
[System.IO.File]::WriteAllBytes( 'C:\Windows\Setup\Scripts\LockScreenImage', $bytes );
reg.exe add "HKLM\Software\Microsoft\Windows\CurrentVersion\PersonalizationCSP" /v LockScreenImagePath /t REG_SZ /d "C:\Windows\Setup\Scripts\LockScreenImage" /f;
} catch {
$_;
}
};
{
&amp; 'C:\Windows\Setup\Scripts\unattend-01.ps1';
};
{
reg.exe import "C:\Windows\Setup\Scripts\unattend-02.reg";
};
&amp; {
[float] $complete = 0;
[float] $increment = 100 / $scripts.Count;
foreach( $script in $scripts ) {
Write-Progress -Activity 'Running scripts to customize your Windows installation. Do not close this window.' -PercentComplete $complete;
'*** Will now execute command &#xAB;{0}&#xBB;.' -f $(
$str = $script.ToString().Trim() -replace '\s+', ' ';
$max = 100;
if( $str.Length -le $max ) {
$str;
} else {
$str.Substring( 0, $max - 1 ) + '&#x2026;';
}
);
$start = [datetime]::Now;
&amp; $script;
'*** Finished executing command after {0:0} ms.' -f [datetime]::Now.Subtract( $start ).TotalMilliseconds;
"`r`n" * 3;
$complete += $increment;
}
} *&gt;&amp;1 | Out-String -Width 1KB -Stream &gt;&gt; "C:\Windows\Setup\Scripts\Specialize.log";
