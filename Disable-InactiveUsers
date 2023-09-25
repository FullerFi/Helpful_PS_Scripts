$T = New-JobTrigger -Daily -At "11:30 PM" -DaysInterval 3
Register-ScheduledJob -Name AD_Housekeeping -ScriptBlock {
#Our parent OU#
$parentOU = 'DC=ACCU,DC=LOCAL'
#OU for Disabled Users#
$UsersOU = "OU=Disabled Users,OU=Accu-Users,DC=ACCU,DC=LOCAL"
#OU for Disabled Computers#
$ComputersOU = "OU=Disabled Computers,OU=ACCU,DC=ACCU,DC=LOCAL"
#Inactivity threshhold - 90 days#
$Inactivity = "90.00:00:00"
$Date = Get-Date -Format "MM/dd/yyyy"

#Creating Disabled Users OU if it don't exist#
if (Get-ADOrganizationalUnit -Filter "distinguishedName -eq '$UsersOU'") { Write-Host "$UsersOU already exists."} else { New-ADOrganizationalUnit -Name $UsersOU -Path $parentOU}
#Creating Disabled Computers OU if it don't exist#
if (Get-ADOrganizationalUnit -Filter "distinguishedName -eq '$ComputersOU'") { Write-Host "$ComputersOU already exists."} else { New-ADOrganizationalUnit -Name $ComputersOU -Path $parentOU}

$DisabledUsers = Search-ADAccount -AccountInactive -TimeSpan $Inactivity -UsersOnly
foreach ($DisabledUser in $DisabledUsers){
$sam=$DisabledUser.samaccountname
$dn=$DisabledUser.distinguishedName
#Checking whether account is already in Disabled
if ($dn -notmatch $UsersOU){
#Disabling User Accounts#
$DisabledUser|Disable-ADAccount
#Moving Accounts to Disabled OU#
$DisabledUser| Move-ADObject -TargetPath $UsersOU
Set-ADUser $sam -Description ("Moved from: " + $dn + "Disabled due to inactivity on " + $Date)
}
}

$DisabledComputers = Search-ADAccount -AccountInactive -TimeSpan $Inactivity -ComputersOnly
foreach ($DisabledComputer in $DisabledComputers){
$sam=$DisabledComputer.samaccountname
$dn=$DisabledComputer.distinguishedName
#Checking whether account is already in Disabled
if ($dn -notmatch $ComputersOU){
#Disabling Computer Accounts#
$DisabledComputer|Disable-ADAccount
#Moving Computer Accounts to Disabled OU#
$DisabledComputer| Move-ADObject -TargetPath $ComputersOU
Set-ADComputer $sam -Description ("Moved from: " + $dn + "Disabled due to inactivity on " + $Date)
}
}
} -Trigger $T
