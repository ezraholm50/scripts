# Names of VMs to backup separated by semicolon (Mandatory)
$VMNames = "en0ch_se","goodstart.techandme.se","lousynlig.eu","magnusace.com","NGINX","rmtechnology_net","techandme.se","solve-it.se"

# Name of vCenter or standalone host VMs to backup reside on (Mandatory)
$HostName = "192.168.3.10"

# Desired compression level (Optional; Possible values: 0 - None, 4 - Dedupe-friendly, 5 - Optimal, 6 - High, 9 - Extreme) 
$CompressionLevel = "5"

# Quiesce VM when taking snapshot (Optional; VMware Tools are required; Possible values: $True/$False)
$EnableQuiescence = $True

# Protect resulting backup with encryption key (Optional; $True/$False)
$EnableEncryption = $False

# Encryption Key (Optional; path to a secure string)
$EncryptionKey = ""

# Retention settings (Optional; By default, VeeamZIP files are not removed and kept in the specified location for an indefinite period of time. 
# Possible values: Never , Tonight, TomorrowNight, In3days, In1Week, In2Weeks, In1Month)
$Retention = "In1Week"

##################################################################
#                   Notification Settings
##################################################################

# Enable notification (Optional)
$EnableNotification = $True

# Email SMTP server
$SMTPServer = "mail.citynetwork.se"

# Email FROM
$EmailFrom = "no-reply@techandme.se" 

# Email TO
$EmailTo = "daniel@techandme.se"

# Email subject
$EmailSubject = "VEEAMZIP"

##################################################################
#                   Email formatting 
##################################################################

$style = "<style>BODY{font-family: Arial; font-size: 10pt;}"
$style = $style + "TABLE{border: 1px solid black; border-collapse: collapse;}"
$style = $style + "TH{border: 1px solid black; background: #dddddd; padding: 5px; }"
$style = $style + "TD{border: 1px solid black; padding: 5px; }"
$style = $style + "</style>"

##################################################################
#                   Mount PSDrive
##################################################################
$username = "VEEAM"
$PlainPassword = "SECUREP@SSWORD"
$SecurePassword = $PlainPassword | ConvertTo-SecureString -AsPlainText -Force 
$Directory = "\\Qnap-backup\VEEAM" # For instance, \\1.2.3.4\backup
$Cred = new-object System.Management.Automation.PSCredential -argumentlist $username, $SecurePassword
# Remove old drive
If ((Get-PSDrive [a-z]) -Match 'Z') {
Remove-PSDrive Z; "Removed Z: drive first"
}

# Use a new drive
$used  = Get-PSDrive | Select-Object -Expand Name |
         Where-Object { $_.Length -eq 1 }
$drive = 90..65 | ForEach-Object { [string][char]$_ } |
         Where-Object { $used -notcontains $_ } |
         Select-Object -First 1

# Create new drive
New-PSDrive –Name $drive -PSProvider Microsoft.Powershell.core\Filesystem  -Root $Directory -Credential $Cred


# Testing
# net use J: \\192.168.1.115\veeam /user:veeam SECUREP@SSWORD
# net use O: \\Qnap-backup\VEEAM SECUREP@SSWORD /user:veeam
# $Directory = "O:\"

#################### DO NOT MODIFY PAST THIS LINE ################
Asnp VeeamPSSnapin

$Server = Get-VBRServer -name $HostName
$MesssagyBody = @()

foreach ($VMName in $VMNames)
{
  $VM = Find-VBRViEntity -Name $VMName -Server $Server
  
  If ($EnableEncryption)
  {
    $EncryptionKey = Add-VBREncryptionKey -Password (cat $EncryptionKey | ConvertTo-SecureString)
    $ZIPSession = Start-VBRZip -Entity $VM -Folder $Directory -Compression $CompressionLevel -DisableQuiesce:(!$EnableQuiescence) -AutoDelete $Retention -EncryptionKey $EncryptionKey
  }
  
  Else 
  {
    $ZIPSession = Start-VBRZip -Entity $VM -Folder $Directory -Compression $CompressionLevel -DisableQuiesce:(!$EnableQuiescence) -AutoDelete $Retention
  }
  
  If ($EnableNotification) 
  {
    $TaskSessions = $ZIPSession.GetTaskSessions().logger.getlog().updatedrecords
    $FailedSessions =  $TaskSessions | where {$_.status -eq "EWarning" -or $_.Status -eq "EFailed"}
  
  if ($FailedSessions -ne $Null)
  {
    $netMesssagyBody = $MesssagyBody + ($ZIPSession | Select-Object @{n="Name";e={($_.name).Substring(0, $_.name.LastIndexOf("("))}} ,@{n="Start Time";e={$_.CreationTime}},@{n="End Time";e={$_.EndTime}},Result,@{n="Details";e={$FailedSessions.Title}})
  }
   
  Else
  {
    $MesssagyBody = $MesssagyBody + ($ZIPSession | Select-Object @{n="Name";e={($_.name).Substring(0, $_.name.LastIndexOf("("))}} ,@{n="Start Time";e={$_.CreationTime}},@{n="End Time";e={$_.EndTime}},Result,@{n="Details";e={($TaskSessions | sort creationtime -Descending | select -first 1).Title}})
  }
  
  }   
}
If ($EnableNotification)
{
$Message = New-Object System.Net.Mail.MailMessage $EmailFrom, $EmailTo
$Message.Subject = $EmailSubject
$Message.IsBodyHTML = $True
$message.Body = $MesssagyBody | ConvertTo-Html -head $style | Out-String
$SMTP = New-Object Net.Mail.SmtpClient($SMTPServer)
$SMTP.Send($Message)
}
