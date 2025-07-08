funtion Get-ADAccountLockoutDetails {
    [CmdletBinding(DefaultParameterSetName='ByName')]
    param (
        [Parameter(Mandatory=$true)]
        [string]$UserName,
        [int]$HoursBack = 24
    )

    Import-Module ActiveDirectory -ErrorAction Stop

    Write-Host "Searching for lockout events for user '$UserName' in the last $HoursBack hours.."

    $DomainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name
    $LockoutEvents = @()

    foreach ($DC in $DomainControllers) {
        Write-Verbose "Querying $DC for Event ID 4740 for $UserName..."
        try {
            $Events = Get-WinEvent -ComputerName $DC -FilterHashtable @{
                LogName   = 'Security'
                ID        = 4740
                StartTime = (Get-Date).AddHours(-$HoursBack)
            } | Where-Object { $_.Properties[0].Value -eq $UserName }

            if ($Events) {
                foreach ($Event in $Events) {
                    $LockoutEvents += [PSCustomObject]@{
                        TimeOccurred     = $Event.TimeCreated
                        DomainController = $DC
                        LockedAccount    = $Event.Properties[0].Value
                        CallerComputer   = $Event.Properties[1].Value
                    }
                }
            }
        }
        catch {
            Write-Warning "Failed to query events from $DC: $($_.Exception.Message)"
        }
    }

    if ($LockoutEvents.Count -eq 0) {
        Write-Host "No lockout events found for '$UserName' in the last $HoursBack hours."
    }
    else {
        Write-Host "Found $($LockoutEvents.Count) lockout events for '$UserName'."
        $LockoutEvents | Sort-Object TimeOccurred | Format-Table -AutoSize

        # Optionally, go deeper in the Caller Computer's logs
        $UniqueCallerComputers = $LockoutEvents | Select-Object -ExpandProperty CallerComputer -Unique

        foreach ($Caller in $UniqueCallerComputers) {
            Write-Host "`nInvestigating Event ID 4625 on Caller Computer: $Caller"
            try {
                Get-WinEvent -ComputerName $Caller -FilterHashtable @{
                    LogName   = 'Security'
                    ID        = 4625
                    StartTime = (Get-Date).AddHours(-$HoursBack)
                } | Where-Object { $_.Properties[5].Value -eq $UserName  } | # Properties[5].Value is TargetAccountName
                Select-Object TimeCreated, @{N='Target Account':E={$_.Properties[5].Value}}, @{N='Logon Type':E={$_.Properties[8].Value}}, Message | 
                Format-List
            }
            catch {
                Write-Warning "Failed to retrieve Event ID 4625 from $Caller: $($_.Exception.Message)"
            }
        }
    }
}
