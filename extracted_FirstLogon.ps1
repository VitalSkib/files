$logfile = 'C:\UnattendLogs\FirstLogon.log';
try {
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 38 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "AutoRestartShell" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "DisableDomainCreds" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "EveryoneIncludesAnonymous" /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LimitBlankPasswordUse" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v "NTLMMinClientSec" /t REG_DWORD /d 536870912 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v "NTLMMinServerSec" /t REG_DWORD /d 536870912 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "EnablePlainTextPassword" /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DontDisplayLastUserName" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "LegalNoticeCaption" /t REG_SZ /d "" /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "LegalNoticeText" /t REG_SZ /d "" /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "scforceoption" /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ShutdownWithoutLogon" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "undockwithoutlogon" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowClipboardHistory" /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShortcutArrow" /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MessagingService" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wlpasvc" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RetailDemo" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2>&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WalletService" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2>&amp;1
# (rest of FirstLogon reg and commands appended verbatim from original)
} catch {
    "FirstLogon error: $($_.Exception.Message)" | Out-File -FilePath $logfile -Append -Encoding utf8
}
$scripts = @(
    {
        Set-ItemProperty -LiteralPath 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoLogonCount' -Type 'DWord' -Force -Value 0;
    };
    {
        @(
            Get-ChildItem -LiteralPath 'C:\' -Force;
            Get-ChildItem -LiteralPath 'C:\Users' -Force;
            Get-ChildItem -LiteralPath 'C:\Users\Default' -Force -Recurse -Depth 2;
            Get-ChildItem -LiteralPath 'C:\Users\Public' -Force -Recurse -Depth 2;
            Get-ChildItem -LiteralPath 'C:\ProgramData' -Force;
        ) | Where-Object -FilterScript {
            $_.Attributes.HasFlag( [System.IO.FileAttributes]::ReparsePoint );
        } | Remove-Item -Force -Recurse -Verbose;
    };
    {
        cmd.exe /c "rmdir C:\Windows.old";
    };
    {
        &amp; 'C:\Windows\Setup\Scripts\unattend-03.ps1';
    };
    {
        Remove-Item -LiteralPath @(
          'C:\Windows\Panther\unattend.xml';
          'C:\Windows\Panther\unattend-original.xml';
          'C:\Windows\Setup\Scripts\Wifi.xml';
        ) -Force -ErrorAction 'SilentlyContinue' -Verbose;
    };
);

&amp; {
  [float] $complete = 0;
  [float] $increment = 100 / $scripts.Count;
  foreach( $script in $scripts ) {
    Write-Progress -Activity 'Running scripts to finalize your Windows installation. Do not close this window.' -PercentComplete $complete;
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
} *>&amp;1 | Out-String -Width 1KB -Stream >> "C:\Windows\Setup\Scripts\FirstLogon.log";
    
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\PriorityControl" /v "Win32PrioritySeparation" /t REG_DWORD /d 38 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v "AutoRestartShell" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "VerboseStatus" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "DisableDomainCreds" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "EveryoneIncludesAnonymous" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "LimitBlankPasswordUse" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v "NTLMMinClientSec" /t REG_DWORD /d 536870912 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v "NTLMMinServerSec" /t REG_DWORD /d 536870912 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "EnablePlainTextPassword" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "EnableSecuritySignature" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v "RequireSecuritySignature" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "DontDisplayLastUserName" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "LegalNoticeCaption" /t REG_SZ /d "" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "LegalNoticeText" /t REG_SZ /d "" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "scforceoption" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "ShutdownWithoutLogon" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "undockwithoutlogon" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WinDefend" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "AllowClipboardHistory" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Power" /v "HibernateEnabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShortcutArrow" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\GraphicsPerfSvc" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MessagingService" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wlpasvc" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RetailDemo" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WalletService" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\wisvc" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\OneSyncSvc_*" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\MessagingService_*" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\ReserveManager" /v "ShippedWithReserves" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNgsc" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteRegistry" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteAssistance" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableInventory" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v "DisableUAR" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d 100 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v "SmartScreenEnabled" /t REG_SZ /d "Off" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControlEnabled" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\SmartScreen" /v "ConfigureAppInstallControl" /t REG_SZ /d "Anywhere" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableIOAVProtection" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "PublishUserActivities" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TextInput" /v "AllowLinguisticDataCollection" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableSensors" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\FindMyDevice" /v "AllowFindMyDevice" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /v "AllowSuggestedAppsInWindowsInkWorkspace" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" /v "AllowWindowsInkWorkspace" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\PenWorkspace" /v "PenWorkspaceButtonDesiredVisibility" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\dmwappushservice" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DiagTrack" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSync" /t REG_DWORD /d 2 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\SettingSync" /v "DisableSettingSyncUserOverride" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableLibrariesDefaultSaveToOneDrive" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSync" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender Security Center\Systray" /v "HideSystray" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userAccountInformation" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisallowShaking" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "EnableBalloonTips" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v "AllowGameDVR" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XblAuthManager" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XblGameSave" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\xboxgip" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoUseStoreOpenWith" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoNewAppAlert" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoStartMenuRecommendations" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "HidePeopleBar" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "AllowOnlineTips" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Network Connections" /v "NC_ShowSharedAccessUI" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingDataSharing" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\TabletPC" /v "PreventHandwritingErrorReports" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" /v "DisabledByGroupPolicy" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EnhancedStorageDevices" /v "TCGSecurityActivationDisabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\OneSettings" /v "EnableSync" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DeviceCompatibility" /v "DisableRemoteAssistance" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo" /t REG_DWORD /d 2 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCalendar" /t REG_DWORD /d 2 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory" /t REG_DWORD /d 2 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera" /t REG_DWORD /d 2 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts" /t REG_DWORD /d 2 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail" /t REG_DWORD /d 2 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation" /t REG_DWORD /d 2 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging" /t REG_DWORD /d 2 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMicrophone" /t REG_DWORD /d 2 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMotion" /t REG_DWORD /d 2 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessNotifications" /t REG_DWORD /d 2 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessPhone" /t REG_DWORD /d 2 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios" /t REG_DWORD /d 2 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTrustedDevices" /t REG_DWORD /d 2 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsGetDiagnosticInfo" /t REG_DWORD /d 2 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsRunInBackground" /t REG_DWORD /d 2 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices" /t REG_DWORD /d 2 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTasks" /t REG_DWORD /d 2 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Biometrics" /v "Enabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredUI" /v "DisablePasswordReveal" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WebClient" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userNotificationListener" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCall" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\userDataTasks" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" /v "ScenarioExecutionEnabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDelay" /t REG_DWORD /d 60 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisableLastAccessUpdate" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\OneDrive" /v "DisableFileSyncNgsc" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\OneDrive" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
taskkill /f /im OneDrive.exe *>> $logfile 2&gt;&amp;1
%SystemRoot%\SysWOW64\OneDriveSetup.exe /uninstall *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\RemoteAssistance" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WpnUserService_*" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WpnService" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{67144949-5132-4859-8036-a737b43825d8}" /v "EnabledScenarioExecutionLevel" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" /v "DisableWpad" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\WinHttpAutoProxySvc" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\DriverSearching" /v "SearchOrderConfig" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\ScheduledDiagnostics" /v "EnabledExecution" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "EnableQueryRemoteServer" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\ScriptedDiagnosticsProvider\Policy" /v "DisableQueryRemoteServer" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\diagsvc" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Services\DusmSvc" /v "Start" /t REG_DWORD /d 4 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{3af8b24a-4a18-4f1d-87ef-94494e8b092b}" /v "ScenarioExecutionEnabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{5c23dec4-4e8e-4bdb-b0cf-851126b148a0}" /v "ScenarioExecutionEnabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{67144949-5132-4859-8036-a737b43825d8}" /v "ScenarioExecutionEnabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{6c28c7e5-4269-4dc3-9b92-5ee84a7a1bc4}" /v "ScenarioExecutionEnabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{86432a0b-3c7d-4ddf-a89c-172faa90485d}" /v "ScenarioExecutionEnabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{8af052f9-3da0-4d8f-a228-7ace8c3b1034}" /v "ScenarioExecutionEnabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{9c5a40da-b965-4fc3-8781-88dd50a6299d}" /v "ScenarioExecutionEnabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{c295fbdf-34a7-49a7-ace5-3f3ab456d558}" /v "ScenarioExecutionEnabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{ebc25cf6-9120-4283-b972-0e5520d0000E}" /v "ScenarioExecutionEnabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WDI\{ebc25cf6-9120-4283-b972-0e5520d0000F}" /v "ScenarioExecutionEnabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\WindowsMitigation" /v "UserPreference" /t REG_DWORD /d 3 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettings" /t REG_DWORD /d 3 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d 3 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d 3 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "CompositionPolicy" /t REG_DWORD /d 2 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "ColorizationGlassAttribute" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "EnableAeroPeek" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "EnableWindowColorization" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\Dwm" /v "AccentColor" /t REG_DWORD /d 4282927692 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Accent" /v "AccentPalette" /t REG_BINARY /d 6B6B6BFF5A5A5AFF4D4D4DFF3A3A3AFF2D2D2DFF1F1F1FFF0F0F0FFF090909FF /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Accent" /v "AccentColorMenu" /t REG_DWORD /d 4281545523 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Accent" /v "StartColorMenu" /t REG_DWORD /d 4281150758 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "EnableTransparency" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableAcrylicBackgroundOnLogon" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "PlatformSupportMiracast" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "DxgKrnlVersion" /t REG_DWORD /d 4354 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "MinDxgKrnlVersion" /t REG_DWORD /d 20483 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\GraphicsDrivers" /v "TdrDdiDelay" /t REG_DWORD /d 60 /f *>> $logfile 2&gt;&amp;1
"FirstLogon error: $($_.Exception.Message)" | Out-File -FilePath $logfile -Append -Encoding utf8
{
Set-ItemProperty -LiteralPath 'Registry::HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name 'AutoLogonCount' -Type 'DWord' -Force -Value 0;
};
{
@(
Get-ChildItem -LiteralPath 'C:\' -Force;
Get-ChildItem -LiteralPath 'C:\Users' -Force;
Get-ChildItem -LiteralPath 'C:\Users\Default' -Force -Recurse -Depth 2;
Get-ChildItem -LiteralPath 'C:\Users\Public' -Force -Recurse -Depth 2;
Get-ChildItem -LiteralPath 'C:\ProgramData' -Force;
) | Where-Object -FilterScript {
$_.Attributes.HasFlag( [System.IO.FileAttributes]::ReparsePoint );
} | Remove-Item -Force -Recurse -Verbose;
};
{
cmd.exe /c "rmdir C:\Windows.old";
};
{
&amp; 'C:\Windows\Setup\Scripts\unattend-03.ps1';
};
{
Remove-Item -LiteralPath @(
'C:\Windows\Panther\unattend.xml';
'C:\Windows\Panther\unattend-original.xml';
'C:\Windows\Setup\Scripts\Wifi.xml';
) -Force -ErrorAction 'SilentlyContinue' -Verbose;
};
} *&gt;&amp;1 | Out-String -Width 1KB -Stream &gt;&gt; "C:\Windows\Setup\Scripts\FirstLogon.log";
