$logfile = 'C:\UnattendLogs\UserOnce.log';

try {
    # 1. Check Winget
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        $wingetUrl = "https://github.com/microsoft/winget-cli/releases/latest/download/Microsoft.DesktopAppInstaller_8wekyb3d8bbwe.msixbundle"
        Invoke-WebRequest -Uri $wingetUrl -OutFile "$env:TEMP\winget.msixbundle" -UseBasicParsing *>> $logfile 2>&amp;1
        Add-AppxPackage -Path "$env:TEMP\winget.msixbundle" *>> $logfile 2>&amp;1
    }

    # 2. Via Winget
    $apps = @('7zip.7zip', 'Brave.Brave', 'Google.Chrome', 'Mozilla.Firefox.Nightly', 'RARLab.WinRAR')
    foreach ($app in $apps) {
        winget install --id $app --silent --accept-package-agreements --accept-source-agreements *>> $logfile 2>&amp;1
    }

    # 3. Visual C++ Redistributable
    Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile "$env:TEMP\vc_redist.x64.exe" -UseBasicParsing *>> $logfile 2>&amp;1
    Start-Process -FilePath "$env:TEMP\vc_redist.x64.exe" -ArgumentList "/quiet /norestart" -Wait *>> $logfile 2>&amp;1

    # 4. Windows Terminal
    $termUrl = "https://github.com/microsoft/terminal/releases/latest/download/Microsoft.WindowsTerminal_Win11.msixbundle"
    Invoke-WebRequest -Uri $termUrl -OutFile "$env:TEMP\terminal.msixbundle" -UseBasicParsing *>> $logfile 2>&amp;1
    Add-AppxPackage -Path "$env:TEMP\terminal.msixbundle" *>> $logfile 2>&amp;1

    # 5. ViVeTool
    $vivetoolUrl = (Invoke-RestMethod "https://api.github.com/repos/thebookisclosed/ViVe/releases/latest").assets.browser_download_url | Where-Object {$_ -like "*zip"}
    Invoke-WebRequest -Uri $vivetoolUrl -OutFile "$env:TEMP\ViVeTool.zip" -UseBasicParsing *>> $logfile 2>&amp;1
    
    $vivetoolPath = "$env:ProgramFiles\ViVeTool"
    Expand-Archive -Path "$env:TEMP\ViVeTool.zip" -DestinationPath $vivetoolPath -Force *>> $logfile 2>&amp;1

    # 6. ViVeTool IDs
    $ids = @(
        49402389, 49221331, 58988972, 59265307, 47205210, 58989002, 
        48433719, 57118881, 58381341, 58527096, 57156807, 57259990, 
        41118774, 55805655, 58778013, 58383338, 59270880, 59203365, 57703775
    )
    foreach ($id in $ids) {
        &amp; "$vivetoolPath\vivetool.exe" /enable /id:$id *>> $logfile 2>&amp;1
    }

    # 7. Reatart
    Restart-Computer -Force *>> $logfile 2>&amp;1

} catch {
    "UserOnce error: $($_.Exception.Message)" | Out-File -FilePath $logfile -Append -Encoding utf8
}
    
Invoke-WebRequest -Uri $wingetUrl -OutFile "$env:TEMP\winget.msixbundle" -UseBasicParsing *>> $logfile 2&gt;&amp;1
Add-AppxPackage -Path "$env:TEMP\winget.msixbundle" *>> $logfile 2&gt;&amp;1
winget install --id $app --silent --accept-package-agreements --accept-source-agreements *>> $logfile 2&gt;&amp;1
Invoke-WebRequest -Uri "https://aka.ms/vs/17/release/vc_redist.x64.exe" -OutFile "$env:TEMP\vc_redist.x64.exe" -UseBasicParsing *>> $logfile 2&gt;&amp;1
Start-Process -FilePath "$env:TEMP\vc_redist.x64.exe" -ArgumentList "/quiet /norestart" -Wait *>> $logfile 2&gt;&amp;1
Invoke-WebRequest -Uri $termUrl -OutFile "$env:TEMP\terminal.msixbundle" -UseBasicParsing *>> $logfile 2&gt;&amp;1
Add-AppxPackage -Path "$env:TEMP\terminal.msixbundle" *>> $logfile 2&gt;&amp;1
Invoke-WebRequest -Uri $vivetoolUrl -OutFile "$env:TEMP\ViVeTool.zip" -UseBasicParsing *>> $logfile 2&gt;&amp;1
Expand-Archive -Path "$env:TEMP\ViVeTool.zip" -DestinationPath $vivetoolPath -Force *>> $logfile 2&gt;&amp;1
&amp; "$vivetoolPath\vivetool.exe" /enable /id:$id *>> $logfile 2&gt;&amp;1
Restart-Computer -Force *>> $logfile 2&gt;&amp;1
$scripts = @(
{
Set-WinHomeLocation -GeoId 137;
};
{
Get-AppxPackage -Name 'Microsoft.Windows.Ai.Copilot.Provider' | Remove-AppxPackage;
};
{
@(
Get-ChildItem -LiteralPath $env:USERPROFILE -Force -Recurse -Depth 2;
) | Where-Object -FilterScript {
$_.Attributes.HasFlag( [System.IO.FileAttributes]::ReparsePoint );
} | Remove-Item -Force -Recurse -Verbose;
};
{
Remove-Item -LiteralPath "${env:USERPROFILE}\Desktop\Microsoft Edge.lnk" -ErrorAction 'SilentlyContinue' -Verbose;
};
{
Set-ItemProperty -LiteralPath 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name 'LaunchTo' -Type 'DWord' -Value 1;
};
{
Set-ItemProperty -LiteralPath 'Registry::HKCU\Software\Microsoft\Windows\CurrentVersion\Search' -Name 'SearchboxTaskbarMode' -Type 'DWord' -Value 1;
};
{
New-Item -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Force;
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Name '{5399e694-6ce5-4d6c-8fce-1d8870fdcba0}' -Value 1 -Type 'DWord';
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Name '{b4bfcc3a-db2c-424c-b029-7fe99a87c641}' -Value 1 -Type 'DWord';
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Name '{a8cdff1c-4878-43be-b5fd-f8091c1c60d0}' -Value 1 -Type 'DWord';
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Name '{374de290-123f-4565-9164-39c4925e467b}' -Value 1 -Type 'DWord';
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Name '{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}' -Value 1 -Type 'DWord';
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Name '{f874310e-b6b7-47dc-bc84-b9e6b38f5903}' -Value 1 -Type 'DWord';
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Name '{1cf1260c-4dd0-4ebb-811f-33c572699fde}' -Value 1 -Type 'DWord';
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Name '{f02c1a0d-be21-4350-88b0-7367fc96ef3c}' -Value 1 -Type 'DWord';
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Name '{3add1653-eb32-4cb0-bbd7-dfa0abb5acca}' -Value 1 -Type 'DWord';
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Name '{645ff040-5081-101b-9f08-00aa002f954e}' -Value 0 -Type 'DWord';
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Name '{20d04fe0-3aea-1069-a2d8-08002b30309d}' -Value 0 -Type 'DWord';
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -Value 1 -Type 'DWord';
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\ClassicStartMenu' -Name '{a0953c92-50dc-43bf-be83-3742fed03c9c}' -Value 1 -Type 'DWord';
New-Item -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Force;
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{5399e694-6ce5-4d6c-8fce-1d8870fdcba0}' -Value 1 -Type 'DWord';
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{b4bfcc3a-db2c-424c-b029-7fe99a87c641}' -Value 1 -Type 'DWord';
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{a8cdff1c-4878-43be-b5fd-f8091c1c60d0}' -Value 1 -Type 'DWord';
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{374de290-123f-4565-9164-39c4925e467b}' -Value 1 -Type 'DWord';
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}' -Value 1 -Type 'DWord';
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{f874310e-b6b7-47dc-bc84-b9e6b38f5903}' -Value 1 -Type 'DWord';
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{1cf1260c-4dd0-4ebb-811f-33c572699fde}' -Value 1 -Type 'DWord';
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{f02c1a0d-be21-4350-88b0-7367fc96ef3c}' -Value 1 -Type 'DWord';
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{3add1653-eb32-4cb0-bbd7-dfa0abb5acca}' -Value 1 -Type 'DWord';
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{645ff040-5081-101b-9f08-00aa002f954e}' -Value 0 -Type 'DWord';
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{20d04fe0-3aea-1069-a2d8-08002b30309d}' -Value 0 -Type 'DWord';
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{59031a47-3f72-44a7-89c5-5595fe6b30ee}' -Value 1 -Type 'DWord';
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel' -Name '{a0953c92-50dc-43bf-be83-3742fed03c9c}' -Value 1 -Type 'DWord';
};
{
Set-ItemProperty -Path 'Registry::HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Start' -Name 'VisiblePlaces' -Value $( [convert]::FromBase64String('ztU0LVr6Q0WC8iLm6vd3PC+zZ+PeiVVDv85h83sYqTe8JIoUDNaJQqCAbtm7okiCIAYLsFF/MkyqHjTMVH9zFUSBdf4NCK5Ci9o07Ze2Y5RKsL10SvloT4vWQ5gHHai8oAc/OArogEywWobbhF28TYYIc1KqUUNCn3sndlhGWdTFpbNChn30QoCkk/rKeoi1') ) -Type 'Binary';
};
{
&amp; 'C:\Windows\Setup\Scripts\SetColorTheme.ps1';
};
{
&amp; 'C:\Windows\Setup\Scripts\SetWallpaper.ps1';
};
{
Get-Process -Name 'explorer' -ErrorAction 'SilentlyContinue' | Where-Object -FilterScript {
$_.SessionId -eq ( Get-Process -Id $PID ).SessionId;
} | Stop-Process -Force;
};
&amp; {
[float] $complete = 0;
[float] $increment = 100 / $scripts.Count;
foreach( $script in $scripts ) {
Write-Progress -Activity 'Running scripts to configure this user account. Do not close this window.' -PercentComplete $complete;
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
} *&gt;&amp;1 | Out-String -Width 1KB -Stream &gt;&gt; "$env:TEMP\UserOnce.log";
