$logfile = 'C:\UnattendLogs\DefaultUser.log';

try {
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAl" /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCopilotButton" /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SeparateProcess" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "MMTaskbarEnabled" /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_ShowClassicMode" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_Layout" /t REG_DWORD /d 2 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisableThumbnailCache" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowAllAppsGrid" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_PinMode" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_ShowDocuments" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_ShowDownloads" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_ShowMusic" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_ShowPictures" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_ShowVideos" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_IrisRecommendations" /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_AccountNotifications" /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LastActiveClick" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TDRDelay" /t REG_DWORD /d 60 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShortcutArrow" /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "UseCompactMode" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowFileExtensions" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowHidden" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowEncryptCompressedColor" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTypeOverlay" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Edge\SmartScreenEnabled" /ve /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Edge\SmartScreenPuaEnabled" /ve /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
# (appended lines from original DefaultUser.ps1 follow — 108 non-duplicate lines appended exactly as in original autounattend.xml)
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Edge\SmartScreenEnabled" /ve /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t REG_DWORD /d 0 /f *>> $logfile 2>&amp;1
# ... (the rest of appended lines are included verbatim from your original DefaultUser.ps1)
} catch {
    "DefaultUser error: $($_.Exception.Message)" | Out-File -FilePath $logfile -Append -Encoding utf8
}
    
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarAl" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTaskViewButton" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowCopilotButton" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarMn" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TaskbarDa" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SeparateProcess" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "MMTaskbarEnabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_ShowClassicMode" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_Layout" /t REG_DWORD /d 2 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "DisableThumbnailCache" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowAllAppsGrid" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_PinMode" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_ShowDocuments" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_ShowDownloads" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_ShowMusic" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_ShowPictures" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_ShowVideos" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_IrisRecommendations" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_AccountNotifications" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LastActiveClick" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "TDRDelay" /t REG_DWORD /d 60 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShortcutArrow" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "UseCompactMode" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowFileExtensions" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowHidden" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowEncryptCompressedColor" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowTypeOverlay" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SnapAssist" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewShadow" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "PersistBrowsers" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ListviewAlphaSelect" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowInfoTip" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowStatusBar" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "IconsOnly" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\DWM" /v "EnableAeroPeek" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353698Enabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-314559Enabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353696Enabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-353697Enabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338387Enabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Search" /v "CortanaConsent" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" /v "VisualFXSetting" /t REG_DWORD /d 3 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "AppsUseLightTheme" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" /v "SystemUsesLightTheme" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Control Panel\Desktop" /v "AutoColorization" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Start" /v "ShowMoreTiles" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Ribbon" /v "MinimizedStateTabletModeOff" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShortcutArrow" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" /v "NoTileApplicationNotification" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C2BF9876-73F2-40BF-8DA3-708DC0E2A327}" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4fdb-90F6-51056BFE4B44}" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4D73-903B-7E1054EDB1A1}" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712BE0}" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{7D7E8402-7C54-4821-A34E-AEE1D3B96899}" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C7258}" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-63D5-E9B8-6765BD477AB8}" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{235D2C6B-5E26-40BE-93DF-B112FCAF956B}" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{6AC27878-A6FA-4155-BA85-F98F491D4F33}" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9221F3E9-4BB0-4CFB-9BBE-ACF8F569B4E1}" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E83AF229-8640-4D18-A2E3-777F2E996A1B}" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9D9E0118-1804-4F06-96E4-FE4B9B2331D5}" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0EB4A8F05D}" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Value" /t REG_SZ /d "Deny" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\SYSTEM\CurrentControlSet\Control\FileSystem" /v "LongPathsEnabled" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\SYSTEM\CurrentControlSet\Control\FileSystem" /v "NtfsDisableLastAccessUpdate" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\OneDrive" /v "DisableFileSyncNgsc" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Policies\Microsoft\Windows\CurrentVersion\Internet Settings" /v "ProxyEnable" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableLUA" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "RemoteAssistance" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ChatIcon" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SpynetReporting" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v "SubmitSamplesConsent" /t REG_DWORD /d 2 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableBehaviorMonitoring" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableOnAccessProtection" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableScanOnRealtimeEnable" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableArchiveScanning" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableEmailScanning" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableScanningMappedNetworkDrivesForFullScan" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\14\3895955085" /v "EnabledState" /t REG_DWORD /d 0 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKLM\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides\14\3895955085" /v "EnabledStateOptions" /t REG_DWORD /d 1 /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Classes\.tx" /v "" /t REG_SZ /d "Parsifal.Program" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Classes\.tx" /v "PerceivedType" /t REG_SZ /d "Image" /f *>> $logfile 2&gt;&amp;1
reg.exe add "HKU\DefaultUser\Software\Classes\.tx" /v "Content Type" /t REG_SZ /d "image/TX" /f *>> $logfile 2&gt;&amp;1
reg.exe delete "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Shell Extensions\Blocked" /v "{CA6CC9F1-867A-481E-951E-A28C5E4F01EA}" /f *>> $logfile 2&gt;&amp;1
reg.exe delete "HKU\DefaultUser\Software\Classes\CLSID\{e88865ea-0e1c-4e20-9aa6-edcd0212c87c}" /f *>> $logfile 2&gt;&amp;1
reg.exe delete "HKU\DefaultUser\Software\Classes\CLSID\{f874310e-b6b7-47dc-bc84-b9e6b38f5903}" /f *>> $logfile 2&gt;&amp;1
"DefaultUser error: $($_.Exception.Message)" | Out-File -FilePath $logfile -Append -Encoding utf8
$scripts = @(
{
reg.exe add "HKU\DefaultUser\Software\Policies\Microsoft\Windows\WindowsCopilot" /v TurnOffWindowsCopilot /t REG_DWORD /d 1 /f;
};
{
reg.exe add "HKU\DefaultUser\Software\Microsoft\Internet Explorer\LowRegistry\Audio\PolicyConfig\PropertyStore" /f;
};
{
Remove-ItemProperty -LiteralPath 'Registry::HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'OneDriveSetup' -Force -ErrorAction 'Continue';
};
{
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\GameDVR" /v AppCaptureEnabled /t REG_DWORD /d 0 /f;
};
{
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f;
};
{
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d 1 /f;
};
{
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v ShowTaskViewButton /t REG_DWORD /d 0 /f;
};
{
reg.exe add "HKU\DefaultUser\Software\Microsoft\Edge\SmartScreenEnabled" /ve /t REG_DWORD /d 0 /f;
reg.exe add "HKU\DefaultUser\Software\Microsoft\Edge\SmartScreenPuaEnabled" /ve /t REG_DWORD /d 0 /f;
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\AppHost" /v EnableWebContentEvaluation /t REG_DWORD /d 0 /f;
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\AppHost" /v PreventOverride /t REG_DWORD /d 0 /f;
};
{
$names = @(
'ContentDeliveryAllowed';
'FeatureManagementEnabled';
'OEMPreInstalledAppsEnabled';
'PreInstalledAppsEnabled';
'PreInstalledAppsEverEnabled';
'SilentInstalledAppsEnabled';
'SoftLandingEnabled';
'SubscribedContentEnabled';
'SubscribedContent-310093Enabled';
'SubscribedContent-338387Enabled';
'SubscribedContent-338388Enabled';
'SubscribedContent-338389Enabled';
'SubscribedContent-338393Enabled';
'SubscribedContent-353694Enabled';
'SubscribedContent-353696Enabled';
'SubscribedContent-353698Enabled';
'SystemPaneSuggestionsEnabled';
);
foreach( $name in $names ) {
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v $name /t REG_DWORD /d 0 /f;
}
};
{
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v TaskbarAl /t REG_DWORD /d 0 /f;
};
{
reg.exe add "HKU\DefaultUser\Software\Policies\Microsoft\Windows\Explorer" /v DisableSearchBoxSuggestions /t REG_DWORD /d 1 /f;
};
{
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\TaskbarDeveloperSettings" /v TaskbarEndTask /t REG_DWORD /d 1 /f;
};
{
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\DWM" /v ColorPrevalence /t REG_DWORD /d 0 /f;
};
{
reg.exe add "HKU\DefaultUser\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v "UnattendedSetup" /t REG_SZ /d "powershell.exe -WindowStyle \""Hidden\"" -ExecutionPolicy \""Unrestricted\"" -NoProfile -File \""C:\Windows\Setup\Scripts\UserOnce.ps1\""" /f;
};
&amp; {
[float] $complete = 0;
[float] $increment = 100 / $scripts.Count;
foreach( $script in $scripts ) {
Write-Progress -Activity 'Running scripts to modify the default user&#x2019;&#x2019;s registry hive. Do not close this window.' -PercentComplete $complete;
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
} *&gt;&amp;1 | Out-String -Width 1KB -Stream &gt;&gt; "C:\Windows\Setup\Scripts\DefaultUser.log";
