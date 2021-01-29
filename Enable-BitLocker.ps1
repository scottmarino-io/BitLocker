#Check BitLocker prerequisites
$TPMNotEnabled = Get-WmiObject win32_tpm -Namespace root\cimv2\security\microsofttpm | where {$_.IsEnabled_InitialValue -eq $false} -ErrorAction SilentlyContinue
$TPMEnabled = Get-WmiObject win32_tpm -Namespace root\cimv2\security\microsofttpm | where {$_.IsEnabled_InitialValue -eq $true} -ErrorAction SilentlyContinue
$WindowsVer = Get-WmiObject -Query 'select * from Win32_OperatingSystem where (Version like "6.2%" or Version like "6.3%" or Version like "10.0%") and ProductType = "1"' -ErrorAction SilentlyContinue
$BitLockerReadyDrive = Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction SilentlyContinue
$BitLockerDecrypted = Get-BitLockerVolume -MountPoint $env:SystemDrive | where {$_.VolumeStatus -eq "FullyDecrypted"} -ErrorAction SilentlyContinue
$BLVS = Get-BitLockerVolume | Where-Object {$_.KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'}} -ErrorAction SilentlyContinue
$TPM = Get-TPM

#Check if volume is already encrypted. If so exit, if not continue
if ($BLVS.VolumeStatus -eq 'FullyEncrypted')
{
  Write-Host "Volume is already Fully Encrypted... Exiting."
  $TPM 
  Exit
}

else {
  
#Step 1 - Check if TPM is enabled and initialise if required
if ($WindowsVer -and !$TPMNotEnabled) 
{
Initialize-Tpm -AllowClear -AllowPhysicalPresence -ErrorAction SilentlyContinue
}

#Step 2 - Check if BitLocker volume is provisioned and partition system drive for BitLocker if required
if ($WindowsVer -and $TPMEnabled -and !$BitLockerReadyDrive) 
{
Get-Service -Name defragsvc -ErrorAction SilentlyContinue | Set-Service -Status Running -ErrorAction SilentlyContinue
BdeHdCfg -target $env:SystemDrive shrink -quiet
}

#Step 3 - Check BitLocker AD Key backup Registry values exist and if not, create them.
$BitLockerRegLoc = 'HKLM:\SOFTWARE\Policies\Microsoft'
if (Test-Path "$BitLockerRegLoc\FVE")
{
  Write-Verbose '$BitLockerRegLoc\FVE Key already exists' -Verbose
}
else
{
  New-Item -Path "$BitLockerRegLoc" -Name 'FVE'
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'ActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'RequireActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'ActiveDirectoryInfoToStore' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'EncryptionMethodNoDiffuser' -Value '00000003' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'EncryptionMethodWithXtsOs' -Value '00000006' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'EncryptionMethodWithXtsFdv' -Value '00000006' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'EncryptionMethodWithXtsRdv' -Value '00000003' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'EncryptionMethod' -Value '00000003' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSRecovery' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSManageDRA' -Value '00000000' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSRecoveryPassword' -Value '00000002' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSRecoveryKey' -Value '00000002' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSHideRecoveryPage' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSActiveDirectoryInfoToStore' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSRequireActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSAllowSecureBootForIntegrity' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'OSEncryptionType' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVRecovery' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVManageDRA' -Value '00000000' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVRecoveryPassword' -Value '00000002' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVRecoveryKey' -Value '00000002' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVHideRecoveryPage' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVActiveDirectoryInfoToStore' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVRequireActiveDirectoryBackup' -Value '00000001' -PropertyType DWORD
  New-ItemProperty -Path "$BitLockerRegLoc\FVE" -Name 'FDVEncryptionType' -Value '00000001' -PropertyType DWORD
}

#Step 4 - If all prerequisites are met, then enable BitLocker
if ($WindowsVer -and $TPMEnabled -and $BitLockerReadyDrive -and $BitLockerDecrypted) 
{
Add-BitLockerKeyProtector -MountPoint $env:SystemDrive -TpmProtector
Enable-BitLocker -MountPoint $env:SystemDrive -RecoveryPasswordProtector -SkipHardwareTest -ErrorAction SilentlyContinue
}

#Step 5 - Backup BitLocker recovery passwords to AD
if ($BLVS) 
{
ForEach ($BLV in $BLVS) 
{
$Key = $BLV | Select-Object -ExpandProperty KeyProtector | Where-Object {$_.KeyProtectorType -eq 'RecoveryPassword'}
ForEach ($obj in $key)
{ 
Backup-BitLockerKeyProtector -MountPoint $BLV.MountPoint -KeyProtectorID $obj.KeyProtectorId
}
}
}

<#
#Step 6 - Prompt user to reboot with postponment options of 1 hour and 4 hours
Function Create-GetSchedTime {   
    Param(   
    $SchedTime   
    )
          $script:StartTime = (Get-Date).AddSeconds($TotalTime)
          $RestartDate = ((get-date).AddSeconds($TotalTime)).AddMinutes(-5)
          $RDate = (Get-Date $RestartDate -f 'MM.dd.yyyy') -replace "\.","/"      # 03/16/2016
          $RTime = Get-Date $RestartDate -f 'HH:mm'                                    # 09:31
          &schtasks /delete /tn "Post Maintenance Restart" /f
          &schtasks /create /sc once /tn "Post Maintenance Restart" /tr "'C:\Windows\system32\cmd.exe' /c shutdown -r -f -t 300" /SD $RDate /ST $RTime /f
    }
    [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms") | Out-Null
    [System.Reflection.Assembly]::LoadWithPartialName( "Microsoft.VisualBasic") | Out-Null
    $Title = "Inspire Brands - BitLocker Encryption - Reboot Notification"
    $Message = "Your computer will automatically restart in :"
    $Button1Text = "Restart now"
    $Button2Text = "Postpone for 1 hour"
    $Button3Text = "Postpone for 4 hours"
    $Form = $null
    $Button1 = $null
    $Button2 = $null
    $Label = $null
    $TextBox = $null
    $Result = $null
    $timerUpdate = New-Object 'System.Windows.Forms.Timer'
    $TotalTime = 900 #in seconds
    Create-GetSchedTime -SchedTime $TotalTime
    $timerUpdate_Tick={
          # Define countdown timer
          [TimeSpan]$span = $script:StartTime - (Get-Date)
          # Update the display
          $hours = "{0:00}" -f $span.Hours
          $mins = "{0:00}" -f $span.Minutes
        $secs = "{0:00}" -f $span.Seconds
        $labelTime.Text = "{0}:{1}:{2}" -f $hours, $mins, $secs
          $timerUpdate.Start()
          if ($span.TotalSeconds -le 0)
          {
                $timerUpdate.Stop()
                &schtasks /delete /tn "Post Maintenance Restart" /f
                shutdown -r -f /t 0
          }
    }
    $Form_StoreValues_Closing=
          {
                #Store the control values
          }
          
    $Form_Cleanup_FormClosed=
          {
                #Remove all event handlers from the controls
                try
                {
                      $Form.remove_Load($Form_Load)
                      $timerUpdate.remove_Tick($timerUpdate_Tick)
                      #$Form.remove_Load($Form_StateCorrection_Load)
                      $Form.remove_Closing($Form_StoreValues_Closing)
                      $Form.remove_FormClosed($Form_Cleanup_FormClosed)
                }
                catch [Exception]
                { }
          }
          
    # Form
    $Form = New-Object -TypeName System.Windows.Forms.Form
    $Form.Text = $Title
    $Form.Size = New-Object -TypeName System.Drawing.Size(407,205)
    $Form.StartPosition = "CenterScreen"
    $Form.Topmost = $true
    $Form.KeyPreview = $true
    $Form.ShowInTaskbar = $Formalse
    $Form.FormBorderStyle = "FixedDialog"
    $Form.MaximizeBox = $Formalse
    $Form.MinimizeBox = $Formalse
    $Icon = [system.drawing.icon]::ExtractAssociatedIcon("c:\Windows\System32\UserAccountControlSettings.exe")
    $Form.Icon = $Icon
     
    # Button One (Reboot/Shutdown Now)
    $Button1 = New-Object -TypeName System.Windows.Forms.Button
    $Button1.Size = New-Object -TypeName System.Drawing.Size(90,25)
    $Button1.Location = New-Object -TypeName System.Drawing.Size(10,135)
    $Button1.Text = $Button1Text
    $Button1.Font = 'Tahoma, 10pt'
    $Button1.Add_Click({
          &schtasks /delete /tn "Post Maintenance Restart" /f
          shutdown -r -f /t 0
          $Form.Close()
    })
    $Form.Controls.Add($Button1)
    # Button Two (Postpone for 1 Hour)
    $Button2 = New-Object -TypeName System.Windows.Forms.Button
    $Button2.Size = New-Object -TypeName System.Drawing.Size(133,25)
    $Button2.Location = New-Object -TypeName System.Drawing.Size(105,135)
    $Button2.Text = $Button2Text
    $Button2.Font = 'Tahoma, 10pt'
    $Button2.Add_Click({
          $Button2.Enabled = $False
          $timerUpdate.Stop()
          $TotalTime = 3600
          Create-GetSchedTime -SchedTime $TotalTime
          $timerUpdate.add_Tick($timerUpdate_Tick)
          $timerUpdate.Start()
    })
    $Form.Controls.Add($Button2)
     
    # Button Three (Postpone for 4 Hours)
    $Button3 = New-Object -TypeName System.Windows.Forms.Button
    $Button3.Size = New-Object -TypeName System.Drawing.Size(140,25)
    $Button3.Location = New-Object -TypeName System.Drawing.Size(243,135)
    $Button3.Text = $Button3Text
    $Button3.Font = 'Tahoma, 10pt'
    $Button3.Add_Click({
          $Button2.Enabled = $False
          $timerUpdate.Stop()
          $TotalTime = 14400
          Create-GetSchedTime -SchedTime $TotalTime
          $timerUpdate.add_Tick($timerUpdate_Tick)
          $timerUpdate.Start()
    })
    $Form.Controls.Add($Button3)
    
    # Label
    $Label = New-Object -TypeName System.Windows.Forms.Label
    $Label.Size = New-Object -TypeName System.Drawing.Size(330,25)
    $Label.Location = New-Object -TypeName System.Drawing.Size(10,15)
    $Label.Text = $Message
    $label.Font = 'Tahoma, 10pt'
    $Form.Controls.Add($Label)
    
    # Label2
    $Label2 = New-Object -TypeName System.Windows.Forms.Label
    $Label2.Size = New-Object -TypeName System.Drawing.Size(355,30)
    $Label2.Location = New-Object -TypeName System.Drawing.Size(10,100)
    $Label2.Text = $Message2
    $label2.Font = 'Tahoma, 10pt'
    $Form.Controls.Add($Label2)
    
    # labelTime
    $labelTime = New-Object 'System.Windows.Forms.Label'
    $labelTime.AutoSize = $True
    $labelTime.Font = 'Arial, 26pt, style=Bold'
    $labelTime.Location = '120, 60'
    $labelTime.Name = 'labelTime'
    $labelTime.Size = '43, 15'
    $labelTime.TextAlign = 'MiddleCenter'
    $Form.Controls.Add($labelTime)
     
    #Start the timer
    $timerUpdate.add_Tick($timerUpdate_Tick)
    $timerUpdate.Start()
    # Show
    $Form.Add_Shown({$Form.Activate()})
    #Clean up the control events
    $Form.add_FormClosed($Form_Cleanup_FormClosed)
    #Store the control values when form is closing
    $Form.add_Closing($Form_StoreValues_Closing)
    #Show the Form
    $Form.ShowDialog() | Out-Null
</#>
}
