#Requires -RunAsAdministrator

$filename = "after-windows-installation.ps1"

function instalace
{
	$computername = Read-Host -Prompt 'Enter a new name for your computer to rename'
	Rename-Computer -NewName $computername -LocalCredential RemoteComputerAdminUser

	# allow choloatey
	Set-ExecutionPolicy AllSigned

	# install chocolatey
	Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
	
	choco install -y chocolatey-core.extension
	choco install -y googlechrome
	choco install -y vlc
	choco install -y winrar
	choco install -y vscode
	choco install -y wget
	choco install -y deluge
	choco install -y virtualbox
	choco install -y obs-studio
	choco install -y nmap
	choco install -y discord
	choco install -y nano
	choco install -y hwmonitor
	choco install -y microsoft-windows-terminal
	choco install -y spotify
	choco install -y anydesk
	choco install -y rufus
	choco install -y sublimetext3
	choco install -y winscp
	choco install -y 7zip
	choco install -y lightshot

	choco install -y steam-client
	choco install -y minecraft-launcher
	choco install -y livesplit

	#choco install git.install
	#choco install jre8
	#choco install nodejs.install
	#choco install vim
	#choco install ffmpeg
	#choco install imagemagick
	#choco install pip
	#choco install composer
	#choco install mongodb
	#choco install mariadb
	#choco install apache-httpd
	#choco install dotnetcore-sdk
	#choco install -y python3

	# Tools
	choco install vcredist140

	mkdir $home\tmp
	cd $home\tmp
	wget -O python-3.9.2.exe https://www.python.org/ftp/python/3.9.2/python-3.9.2-amd64.exe
	Start-Process python-3.9.2.exe -Wait

	wget -O cz-linux.zip https://github.com/filiprojek/czech-linux-keyboard-for-windows/archive/master.zip
	7z x .\cz-linux.zip
	cd czech-linux-keyboard-for-windows-master
	cd cz-linux
	Start-Process setup.exe -Wait

	cd $home
	Remove-Item -LiteralPath $home\tmp -Force -Recurse
	Set-ExecutionPolicy unrestricted
	echo "Done!"
}
function wslinstall
{
	Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
	dism.exe /online /enable-feature /featurename:Microsoft-Windows-Subsystem-Linux /all /norestart
	dism.exe /online /enable-feature /featurename:VirtualMachinePlatform /all /norestart
	$command = "powershell $home\Desktop\$filename wslupdate"
	$command | Add-Content -Path "$home\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\wslupdate.bat"
	Restart-Computer -Force
}
function wslupdate
{
	rm "$home\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\wslupdate.bat"
	mkdir $home\Desktop\tmp
	cd $home\Desktop\tmp
	wget -O wsl_update.msi https://wslstorestorage.blob.core.windows.net/wslblob/wsl_update_x64.msi
	Start-Process wsl_update.msi -Wait
	wsl --set-default-version 2
	cd ..
	Remove-Item -LiteralPath $home\Desktop\tmp -Force -Recurse
	echo "Done!"
}
function fedora33
{
	$hexfolder = "53f066403b8d54093629d2f1a6ba8db67a1aa7b8b8e01e45d86f37cfbd38c844"
	mkdir $home\tmp
	cd $home\tmp
	wget -O fedora33-x86_64.tar.xz https://kojipkgs.fedoraproject.org//packages/Fedora-Container-Base/33/20210227.0/images/Fedora-Container-Base-33-20210227.0.x86_64.tar.xz
	7z x .\fedora33-x86_64.tar.xz
	7z x .\fedora33-x86_64.tar -y
	cd $hexfolder
	mv layer.tar fedora-33.tar
	mkdir $HOME\wsl\Fedora-33
	#wsl --import Fedora-33 $HOME\wsl\Fedora-33 $home\tmp\$hexfolder\fedora-33.tar
	cd $home
	Remove-Item -LiteralPath $home\tmp -Force -Recurse

	echo "Done!"
}
function debloat {
    Write-Host "Creating Restore Point incase something bad happens"
    Enable-ComputerRestore -Drive "C:\"
    Checkpoint-Computer -Description "RestorePoint1" -RestorePointType "MODIFY_SETTINGS"

	Write-Host "Running O&O Shutup with Recommended Settings"
    Import-Module BitsTransfer		choco install shutup10 -y
	Start-BitsTransfer -Source "https://raw.githubusercontent.com/ChrisTitusTech/win10script/master/ooshutup10.cfg" -Destination ooshutup10.cfg		OOSU10 ooshutup10.cfg /quiet
	Start-BitsTransfer -Source "https://dl5.oo-software.com/files/ooshutup10/OOSU10.exe" -Destination OOSU10.exe	
	./OOSU10.exe ooshutup10.cfg /quiet

    Write-Host "Disabling Telemetry..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Application Experience\ProgramDataUpdater" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Autochk\Proxy" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" | Out-Null

    Write-Host "Disabling Application suggestions..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "ContentDeliveryAllowed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "OemPreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "PreInstalledAppsEverEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SilentInstalledAppsEnabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338387Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338388Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-338389Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SubscribedContent-353698Enabled" -Type DWord -Value 0
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" -Name "SystemPaneSuggestionsEnabled" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableWindowsConsumerFeatures" -Type DWord -Value 1

    Write-Host "Disabling Activity History..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "EnableActivityFeed" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "UploadUserActivities" -Type DWord -Value 0

    Write-Host "Disabling Location Tracking..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" -Name "Value" -Type String -Value "Deny"
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0

    Write-Host "Disabling automatic Maps updates..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\Maps" -Name "AutoUpdateEnabled" -Type DWord -Value 0

    Write-Host "Disabling Feedback..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "DoNotShowFeedbackNotifications" -Type DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClient" -ErrorAction SilentlyContinue | Out-Null
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Feedback\Siuf\DmClientOnScenarioDownload" -ErrorAction SilentlyContinue | Out-Null

    Write-Host "Disabling Tailored Experiences..."
	If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent")) {
		New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CloudContent" -Name "DisableTailoredExperiencesWithDiagnosticData" -Type DWord -Value 1

    Write-Host "Disabling Advertising ID..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo" -Name "DisabledByGroupPolicy" -Type DWord -Value 1

    Write-Host "Disabling Error reporting..."
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Type DWord -Value 1
	Disable-ScheduledTask -TaskName "Microsoft\Windows\Windows Error Reporting\QueueReporting" | Out-Null

    Write-Host "Restricting Windows Update P2P only to local network..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config")) {
		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1

    Write-Host "Stopping and disabling Diagnostics Tracking Service..."
	Stop-Service "DiagTrack" -WarningAction SilentlyContinue
	Set-Service "DiagTrack" -StartupType Disabled

    Write-Host "Stopping and disabling WAP Push Service..."
	Stop-Service "dmwappushservice" -WarningAction SilentlyContinue
	Set-Service "dmwappushservice" -StartupType Disabled

    Write-Host "Enabling F8 boot menu options..."
	bcdedit /set `{current`} bootmenupolicy Legacy | Out-Null

    Write-Host "Stopping and disabling Home Groups services..."
	Stop-Service "HomeGroupListener" -WarningAction SilentlyContinue
	Set-Service "HomeGroupListener" -StartupType Disabled
	Stop-Service "HomeGroupProvider" -WarningAction SilentlyContinue
	Set-Service "HomeGroupProvider" -StartupType Disabled

    Write-Host "Disabling Remote Assistance..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Type DWord -Value 0

    Write-Host "Disabling Storage Sense..."
	Remove-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" -Recurse -ErrorAction SilentlyContinue

    Write-Host "Stopping and disabling Superfetch service..."
	Stop-Service "SysMain" -WarningAction SilentlyContinue
	Set-Service "SysMain" -StartupType Disabled

    Write-Host "Setting BIOS time to UTC..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\TimeZoneInformation" -Name "RealTimeIsUniversal" -Type DWord -Value 1

#    Write-Host "Disabling Hibernation..."
#	Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Session Manager\Power" -Name "HibernteEnabled" -Type Dword -Value 0
#	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings")) {
#		New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" | Out-Null
#	}
#	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\FlyoutMenuSettings" -Name "ShowHibernateOption" -Type Dword -Value 0

    Write-Host "Showing task manager details..."
	$taskmgr = Start-Process -WindowStyle Hidden -FilePath taskmgr.exe -PassThru
	Do {
		Start-Sleep -Milliseconds 100
		$preferences = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -ErrorAction SilentlyContinue
	} Until ($preferences)
	Stop-Process $taskmgr
	$preferences.Preferences[28] = 0
	Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\TaskManager" -Name "Preferences" -Type Binary -Value $preferences.Preferences

    Write-Host "Showing file operations details..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\OperationStatusManager" -Name "EnthusiastMode" -Type DWord -Value 1

	Write-Host "Show seconds in taskbar"
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowSecondsInSystemClock" -Type DWord -Value 1

	Write-Host "Enable clipboard history"
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\Clipboard" -Name "EnableClipboardHistory" -Type DWord -Value 1

#   Write-Host "Hiding Task View button..."
#	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0

    Write-Host "Hiding People icon..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" -Name "PeopleBand" -Type DWord -Value 0

#    Write-Host "Showing all tray icons..."
#	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" -Name "EnableAutoTray" -Type DWord -Value 0

	Write-Host "Enabling NumLock after startup..."
	If (!(Test-Path "HKU:")) {
		New-PSDrive -Name HKU -PSProvider Registry -Root HKEY_USERS | Out-Null
	}
	Set-ItemProperty -Path "HKU:\.DEFAULT\Control Panel\Keyboard" -Name "InitialKeyboardIndicators" -Type DWord -Value 2147483650
	Add-Type -AssemblyName System.Windows.Forms
	If (!([System.Windows.Forms.Control]::IsKeyLocked('NumLock'))) {
		$wsh = New-Object -ComObject WScript.Shell
		$wsh.SendKeys('{NUMLOCK}')
	}

	#disable cortana
    Write-Host "Disabling Cortana..."
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
	If (!(Test-Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore")) {
		New-Item -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Force | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Type DWord -Value 0

	# disable onedrive
    Write-Host "Disabling OneDrive..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive")) {
		New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" | Out-Null
	}
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OneDrive" -Name "DisableFileSyncNGSC" -Type DWord -Value 1
    Write-Host "Uninstalling OneDrive..."
	Stop-Process -Name "OneDrive" -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	$onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
	If (!(Test-Path $onedrive)) {
		$onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
	}
	Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
	Start-Sleep -s 2
	Stop-Process -Name "explorer" -ErrorAction SilentlyContinue
	Start-Sleep -s 2
	Remove-Item -Path "$env:USERPROFILE\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse -ErrorAction SilentlyContinue
	If (!(Test-Path "HKCR:")) {
		New-PSDrive -Name HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT | Out-Null
	}
	Remove-Item -Path "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue
	Remove-Item -Path "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -ErrorAction SilentlyContinue

	# darkmode
    Write-Host "Enabling Dark Mode"
	Set-ItemProperty -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Themes\Personalize -Name AppsUseLightTheme -Value 0

    Write-Host "Changing default Explorer view to This PC..."
	Set-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1
	
    Write-Host "Hiding 3D Objects icon from This PC..."
	Remove-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\MyComputer\NameSpace\{0DB7E03F-FC29-4DC6-9020-FF41B59E513A}" -Recurse -ErrorAction SilentlyContinue

	$Bloatware = @(

	        #Unnecessary Windows 10 AppX Apps
	        "Microsoft.3DBuilder"
	        "Microsoft.AppConnector"
		    "Microsoft.BingFinance"
		    "Microsoft.BingNews"
		    "Microsoft.BingSports"
		    "Microsoft.BingTranslator"
		    "Microsoft.BingWeather"
	        "Microsoft.GetHelp"
	        "Microsoft.Getstarted"
	        "Microsoft.Messaging"
	        "Microsoft.Microsoft3DViewer"
	        "Microsoft.MicrosoftSolitaireCollection"
	        "Microsoft.NetworkSpeedTest"
	        "Microsoft.News"
	        "Microsoft.Office.Lens"
	        "Microsoft.Office.Sway"
	        "Microsoft.OneConnect"
	        "Microsoft.People"
	        "Microsoft.Print3D"
	        "Microsoft.SkypeApp"
	        "Microsoft.StorePurchaseApp"
	        "Microsoft.Wallet"
	        "Microsoft.Whiteboard"
	        "Microsoft.WindowsAlarms"
	        "microsoft.windowscommunicationsapps"
	        "Microsoft.WindowsFeedbackHub"
	        "Microsoft.WindowsMaps"
	        "Microsoft.WindowsSoundRecorder"
	        "Microsoft.ZuneMusic"
	        "Microsoft.ZuneVideo"

	        #Sponsored Windows 10 AppX Apps
	        #Add sponsored/featured apps to remove in the "*AppName*" format
	        "*EclipseManager*"
	        "*ActiproSoftwareLLC*"
	        "*AdobeSystemsIncorporated.AdobePhotoshopExpress*"
	        "*Duolingo-LearnLanguagesforFree*"
	        "*PandoraMediaInc*"
	        "*CandyCrush*"
	        "*BubbleWitch3Saga*"
	        "*Wunderlist*"
	        "*Flipboard*"
	        "*Twitter*"
	        "*Facebook*"
	        "*Royal Revolt*"
	        "*Sway*"
	        "*Speed Test*"
	        "*Dolby*"
	        "*Viber*"
	        "*ACGMediaPlayer*"
	        "*Netflix*"
	        "*OneCalendar*"
	        "*LinkedInforWindows*"
	        "*HiddenCityMysteryofShadows*"
	        "*Hulu*"
	        "*HiddenCity*"
	        "*AdobePhotoshopExpress*"
	                     
	        #Optional: Typically not removed but you can if you need to for some reason
	        #"*Microsoft.Advertising.Xaml_10.1712.5.0_x64__8wekyb3d8bbwe*"
	        #"*Microsoft.Advertising.Xaml_10.1712.5.0_x86__8wekyb3d8bbwe*"
	        #"*Microsoft.BingWeather*"
	        #"*Microsoft.MSPaint*"
	        #"*Microsoft.MicrosoftStickyNotes*"
	        #"*Microsoft.Windows.Photos*"
	        #"*Microsoft.WindowsCalculator*"
	        #"*Microsoft.WindowsStore*"
	    )
	    foreach ($Bloat in $Bloatware) {
	        Get-AppxPackage -Name $Bloat| Remove-AppxPackage
	        Get-AppxProvisionedPackage -Online | Where-Object DisplayName -like $Bloat | Remove-AppxProvisionedPackage -Online
	        Write-Host "Trying to remove $Bloat."
	    }

	# Tohle je disabled protoze se zde script sekne
	#   Write-Host "Installing Windows Media Player..."
	#	Enable-WindowsOptionalFeature -Online -FeatureName "WindowsMediaPlayer" -NoRestart -WarningAction SilentlyContinue | Out-Null

    #Stops edge from taking over as the default .PDF viewer    
    Write-Host "Stopping Edge from taking over as the default .PDF viewer"
	# Identify the edge application class 
	$Packages = "HKCU:SOFTWARE\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages" 
	$edge = Get-ChildItem $Packages -Recurse -include "MicrosoftEdge" 
		
	# Specify the paths to the file and URL associations 
	$FileAssocKey = Join-Path $edge.PSPath Capabilities\FileAssociations 
	$URLAssocKey = Join-Path $edge.PSPath Capabilities\URLAssociations 
		
	# get the software classes for the file and URL types that Edge will associate 
	$FileTypes = Get-Item $FileAssocKey 
	$URLTypes = Get-Item $URLAssocKey 
		
	$FileAssoc = Get-ItemProperty $FileAssocKey 
	$URLAssoc = Get-ItemProperty $URLAssocKey 
		
	$Associations = @() 
	$Filetypes.Property | foreach {$Associations += $FileAssoc.$_} 
	$URLTypes.Property | foreach {$Associations += $URLAssoc.$_} 
		
	# add registry values in each software class to stop edge from associating as the default 
	foreach ($Association in $Associations) 
			{ 
			$Class = Join-Path HKCU:SOFTWARE\Classes $Association 
			#if (Test-Path $class) 
			#   {write-host $Association} 
			# Get-Item $Class 
			Set-ItemProperty $Class -Name NoOpenWith -Value "" 
			Set-ItemProperty $Class -Name NoStaticDefaultVerb -Value "" 
			} 
            
    
    #Removes Paint3D stuff from context menu
	$Paint3Dstuff = @(
	        "HKCR:\SystemFileAssociations\.3mf\Shell\3D Edit"
		"HKCR:\SystemFileAssociations\.bmp\Shell\3D Edit"
		"HKCR:\SystemFileAssociations\.fbx\Shell\3D Edit"
		"HKCR:\SystemFileAssociations\.gif\Shell\3D Edit"
		"HKCR:\SystemFileAssociations\.jfif\Shell\3D Edit"
		"HKCR:\SystemFileAssociations\.jpe\Shell\3D Edit"
		"HKCR:\SystemFileAssociations\.jpeg\Shell\3D Edit"
		"HKCR:\SystemFileAssociations\.jpg\Shell\3D Edit"
		"HKCR:\SystemFileAssociations\.png\Shell\3D Edit"
		"HKCR:\SystemFileAssociations\.tif\Shell\3D Edit"
		"HKCR:\SystemFileAssociations\.tiff\Shell\3D Edit"
	    )
    #Rename reg key to remove it, so it's revertible
    foreach ($Paint3D in $Paint3Dstuff) {
        If (Test-Path $Paint3D) {
	    $rmPaint3D = $Paint3D + "_"
	    Set-Item $Paint3D $rmPaint3D
		}
    }
    
	#$wshell.Popup("Operation Completed",0,"Done",0x0)
	echo "Operation Completed"
}
function help
{
	echo "0 - Pro pomoc -> help"
	echo "1 - Pro debloat Windows 10 -> debloat"
	echo "2 - Pro instalaci zakladnich programu -> installapps"
	echo "3 - Pro instalaci WSL -> wsl"
	echo "4 - Pro aktualizaci WSL na verzi 2 -> wslupdate"
	echo "5 - Pro instalaci distribuce Fedora 33 -> fedora33"
	echo ""
	$output = Read-Host -Prompt 'Enter number: '
	menu $output
}
function test
{
	$computername = Read-Host -Prompt 'Enter a new name for your computer to rename'
	echo $computername
}


function menu
{
	If ($output -ne $null)
	{
		$arguments = $output
	}
	else
	{
		$arguments = $args[0]
	}
	switch ($arguments)
	{
		0 { help }
		1 { debloat }
		2 { instalace }
		3 { wslinstall }
		4 { wslupdate }
		5 { fedora33 }
		'help' { help }
		'test' { test }
		default { help }
	}
}

menu



