
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.DirectoryServices

# Create the main form
$form = New-Object System.Windows.Forms.Form
$form.Text = "AD Pro Tool"
$form.Size = New-Object System.Drawing.Size(800, 1020)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false

# Create tab control
$tabs = New-Object System.Windows.Forms.TabControl
$tabs.Size = New-Object System.Drawing.Size(780, 980)
$tabs.Location = New-Object System.Drawing.Point(10, 10)


#### --- TAB 1: ACCOUNT STATUS --- #############################################################

$tabStatus = New-Object System.Windows.Forms.TabPage
$tabStatus.Text = "Account Status"

# Input label
$lblUser2 = New-Object System.Windows.Forms.Label
$lblUser2.Text = "Username:"
$lblUser2.Location = '10,20'
$tabStatus.Controls.Add($lblUser2)

# Input textbox
$txtUser2 = New-Object System.Windows.Forms.TextBox
$txtUser2.Location = '120,20'
$txtUser2.Size = '200,20'
$tabStatus.Controls.Add($txtUser2)

# Output TextBox
$txtStatusOutput = New-Object System.Windows.Forms.TextBox
$txtStatusOutput.Location = New-Object System.Drawing.Point(10,90)
$txtStatusOutput.Size = New-Object System.Drawing.Size(760,800)
$txtStatusOutput.Multiline = $true
$txtStatusOutput.ScrollBars = "Vertical"
$txtStatusOutput.ReadOnly = $true
$txtStatusOutput.BackColor = [System.Drawing.Color]::Black
$txtStatusOutput.ForeColor = [System.Drawing.Color]::LightGreen
$txtStatusOutput.Font = New-Object System.Drawing.Font("Consolas", 9)
$tabStatus.Controls.Add($txtStatusOutput)

# Search button
$btnCheckStatus = New-Object System.Windows.Forms.Button
$btnCheckStatus.Text = "Check"
$btnCheckStatus.Location = '120,50'
$tabStatus.Controls.Add($btnCheckStatus)

$btnCheckStatus.Add_Click({
    $accountName = $txtUser2.Text
    try {
        $user = Get-ADUser -Identity $accountName -Properties PwdLastSet, LastLogonTimestamp, Enabled, MemberOf, DistinguishedName
        if ($user) {
            $pwdLastSet = [DateTime]::FromFileTime($user.PwdLastSet)
            $lastLogon = [DateTime]::FromFileTime($user.LastLogonTimestamp)
            $status = if ($user.Enabled) { "Enabled" } else { "Disabled" }
            $groups = $user.MemberOf -join [Environment]::NewLine
            $ou = $user.DistinguishedName
            $txtStatusOutput.Text = "User: $accountName" + [Environment]::NewLine +
                                    "Status: $status" + [Environment]::NewLine +
                                    "Last Password Change: $pwdLastSet" + [Environment]::NewLine +
                                    "Last Logon: $lastLogon" + [Environment]::NewLine +
                                    "------------------------" + [Environment]::NewLine +
                                    "Groups:" + [Environment]::NewLine + $groups + [Environment]::NewLine +
                                    "------------------------" + [Environment]::NewLine +
                                    "Location in AD:" + [Environment]::NewLine + $ou
        } else {
            $txtStatusOutput.Text = "Account not found or error retrieving data."
        }
    }
    catch {
        $txtStatusOutput.Text = "Error retrieving account status: $($_.Exception.Message)"
    }
})


#### --- TAB 2: LOCKOUT INVESTIGATOR --- #######################################################################

$tabLockout = New-Object System.Windows.Forms.TabPage
$tabLockout.Text = "Lockout Investigator"

$lblUsername = New-Object System.Windows.Forms.Label
$lblUsername.Location = New-Object System.Drawing.Point(10, 20)
$lblUsername.Size = New-Object System.Drawing.Size(100, 20)
$lblUsername.Text = "Username:"
$tabLockout.Controls.Add($lblUsername)

$txtUsername = New-Object System.Windows.Forms.TextBox
$txtUsername.Location = New-Object System.Drawing.Point(120, 18)
$txtUsername.Size = New-Object System.Drawing.Size(200, 20)
$tabLockout.Controls.Add($txtUsername)

$lblHours = New-Object System.Windows.Forms.Label
$lblHours.Location = New-Object System.Drawing.Point(340, 20)
$lblHours.Size = New-Object System.Drawing.Size(140, 20)
$lblHours.Text = "Time Range (hours):"
$tabLockout.Controls.Add($lblHours)

$numHours = New-Object System.Windows.Forms.NumericUpDown
$numHours.Location = New-Object System.Drawing.Point(480, 18)
$numHours.Size = New-Object System.Drawing.Size(60, 20)
$numHours.Minimum = 1
$numHours.Maximum = 168
$numHours.Value = 96
$tabLockout.Controls.Add($numHours)

$btnSearch = New-Object System.Windows.Forms.Button
$btnSearch.Location = New-Object System.Drawing.Point(550, 16)
$btnSearch.Size = New-Object System.Drawing.Size(80, 25)
$btnSearch.Text = "Search"
$tabLockout.Controls.Add($btnSearch)

$btnExport = New-Object System.Windows.Forms.Button
$btnExport.Location = New-Object System.Drawing.Point(550, 50)
$btnExport.Size = New-Object System.Drawing.Size(110, 25)
$btnExport.Text = "Export CSV"
$btnExport.Enabled = $false
$tabLockout.Controls.Add($btnExport)

$btnTest = New-Object System.Windows.Forms.Button
$btnTest.Location = New-Object System.Drawing.Point(650, 16)
$btnTest.Size = New-Object System.Drawing.Size(50, 25)
$btnTest.Text = "Test"
$tabLockout.Controls.Add($btnTest)

$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Location = New-Object System.Drawing.Point(10, 50)
$lblStatus.Size = New-Object System.Drawing.Size(750, 20)
$lblStatus.Text = "Ready to search..."
$lblStatus.ForeColor = [System.Drawing.Color]::Blue
$tabLockout.Controls.Add($lblStatus)

$dgvResults = New-Object System.Windows.Forms.DataGridView
$dgvResults.Location = New-Object System.Drawing.Point(10, 80)
$dgvResults.Size = New-Object System.Drawing.Size(760, 200)
$dgvResults.AllowUserToAddRows = $false
$dgvResults.ReadOnly = $true
$dgvResults.SelectionMode = "FullRowSelect"
$dgvResults.AutoSizeColumnsMode = "Fill"
$tabLockout.Controls.Add($dgvResults)

$lblFailedLogons = New-Object System.Windows.Forms.Label
$lblFailedLogons.Location = New-Object System.Drawing.Point(10, 290)
$lblFailedLogons.Size = New-Object System.Drawing.Size(200, 20)
$lblFailedLogons.Text = "Failed Logon Attempts:"
$lblFailedLogons.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9, [System.Drawing.FontStyle]::Bold)
$tabLockout.Controls.Add($lblFailedLogons)

$dgvFailedLogons = New-Object System.Windows.Forms.DataGridView
$dgvFailedLogons.Location = New-Object System.Drawing.Point(10, 315)
$dgvFailedLogons.Size = New-Object System.Drawing.Size(760, 130)
$dgvFailedLogons.AllowUserToAddRows = $false
$dgvFailedLogons.ReadOnly = $true
$dgvFailedLogons.SelectionMode = "FullRowSelect"
$dgvFailedLogons.AutoSizeColumnsMode = "Fill"
$tabLockout.Controls.Add($dgvFailedLogons)

$lblDebug = New-Object System.Windows.Forms.Label
$lblDebug.Location = New-Object System.Drawing.Point(10, 455)
$lblDebug.Size = New-Object System.Drawing.Size(200, 20)
$lblDebug.Text = "Debug Output:"
$lblDebug.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9, [System.Drawing.FontStyle]::Bold)
$tabLockout.Controls.Add($lblDebug)

$txtDebug = New-Object System.Windows.Forms.TextBox
$txtDebug.Location = New-Object System.Drawing.Point(10, 480)
$txtDebug.Size = New-Object System.Drawing.Size(760, 460)
$txtDebug.Multiline = $true
$txtDebug.ScrollBars = "Vertical"
$txtDebug.ReadOnly = $true
$txtDebug.BackColor = [System.Drawing.Color]::Black
$txtDebug.ForeColor = [System.Drawing.Color]::LightGreen
$txtDebug.Font = New-Object System.Drawing.Font("Consolas", 8)
$tabLockout.Controls.Add($txtDebug)

# Global variable to store results
$Global:LockoutData = @()
$Global:FailedLogonData = @()

# Function to add debug output
function Add-DebugOutput {
    param([string]$Message)
    $timestamp = Get-Date -Format "HH:mm:ss"
    $txtDebug.AppendText("[$timestamp] $Message`r`n")
    $txtDebug.ScrollToCaret()
    $form.Refresh()
}

# Test function to check basic functionality
function Test-BasicFunctionality {
    $txtDebug.Clear()
    Add-DebugOutput "=== BASIC FUNCTIONALITY TEST ==="
    
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        Add-DebugOutput "✓ ActiveDirectory module imported successfully"
        
        $DCs = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name
        Add-DebugOutput "✓ Found $($DCs.Count) Domain Controllers: $($DCs -join ', ')"
        
        $cutoffTime = (Get-Date).AddHours(-96)
        $lockedAccounts = Search-ADAccount -LockedOut -UsersOnly

        $recentLockedAccounts = $lockedAccounts | Where-Object {
            $user = Get-ADUser $_.SamAccountName -Properties LockoutTime
            $user.LockoutTime -gt 0 -and ([datetime]::FromFileTime($user.LockoutTime) -gt $cutoffTime)
        }

        Add-DebugOutput "✓ Found $($recentLockedAccounts.Count) accounts locked out in the last 96 hours"
        if ($recentLockedAccounts.Count -gt 0) {
            $recentLockedAccounts | ForEach-Object {
                Add-DebugOutput "  - $($_.SamAccountName) ($($_.Name))"
            }
        }

        $firstDC = $DCs[0]
        Add-DebugOutput "Testing event log access on $firstDC..."
        
        $recentEvents = Get-WinEvent -ComputerName $firstDC -FilterHashtable @{
            LogName = 'Security'
            ID = 4740
            StartTime = (Get-Date).AddHours(-168)
        } -MaxEvents 10 -ErrorAction Stop
        
        Add-DebugOutput "✓ Found $($recentEvents.Count) recent lockout events on $firstDC"
        
        if ($recentEvents.Count -gt 0) {
            Add-DebugOutput "Recent lockout events:"
            $recentEvents | ForEach-Object {
                $lockedUser = $_.Properties[0].Value
                $callerComputer = $_.Properties[1].Value
                Add-DebugOutput "  - $($_.TimeCreated): $lockedUser from $callerComputer"
            }
        }
    }
    catch {
        Add-DebugOutput "✗ ERROR: $($_.Exception.Message)"
    }

    Add-DebugOutput "=== TEST COMPLETE ==="
}

$btnTest.Add_Click({ Test-BasicFunctionality })

# Function to add debug output to the debug box
function Add-DebugOutput {
    param([string]$Message)
    $timestamp = Get-Date -Format "HH:mm:ss"
    $txtDebug.AppendText("[$timestamp] $Message`r`n")
    $txtDebug.ScrollToCaret()
    [System.Windows.Forms.Application]::DoEvents()
}

# Function to search for lockout events and failed logons
function Search-LockoutEvents {
    $username = $txtUsername.Text.Trim()
    $hoursBack = [int]$numHours.Value

    if ([string]::IsNullOrEmpty($username)) {
        [System.Windows.Forms.MessageBox]::Show("Please enter a username.", "Error", "OK", "Error")
        return
    }

    $lblStatus.Text = "Searching for lockout events..."
    $lblStatus.ForeColor = [System.Drawing.Color]::Blue
    $btnSearch.Enabled = $false
    $btnExport.Enabled = $false
    $txtDebug.Clear()

    # Clear previous results
    $dgvResults.DataSource = $null
    $dgvFailedLogons.DataSource = $null
    $Global:LockoutData = @()
    $Global:FailedLogonData = @()

    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $DomainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name
        Add-DebugOutput "✓ Found $($DomainControllers.Count) Domain Controllers: $($DomainControllers -join ', ')"

        foreach ($DC in $DomainControllers) {
            $lblStatus.Text = "Querying $DC..."
            Add-DebugOutput "Querying $DC for lockout events..."
            [System.Windows.Forms.Application]::DoEvents()

            try {
                $Events = Get-WinEvent -ComputerName $DC -FilterHashtable @{
                    LogName   = 'Security'
                    ID        = 4740
                    StartTime = (Get-Date).AddHours(-$hoursBack)
                } -ErrorAction SilentlyContinue

                foreach ($Event in $Events) {
                    $eventUser = $Event.Properties[0].Value
                    $callerComputer = $Event.Properties[1].Value

                    if ($eventUser.ToLower() -eq $username.ToLower()) {
                        $Global:LockoutData += [PSCustomObject]@{
                            TimeOccurred     = $Event.TimeCreated
                            DomainController = $DC
                            LockedAccount    = $eventUser
                            CallerComputer   = $callerComputer
                        }
                        Add-DebugOutput "Lockout: $eventUser on $DC from $callerComputer at $($Event.TimeCreated)"
                    }
                }
            }
            catch {
                Add-DebugOutput "⚠ Failed to query $DC ${($_.Exception.Message)}"
            }
        }

        if ($Global:LockoutData.Count -eq 0) {
            $lblStatus.Text = "No lockout events found for '$username' in the last $hoursBack hours."
            $lblStatus.ForeColor = [System.Drawing.Color]::Orange
            Add-DebugOutput "No lockout events found."
        }
        else {
            $dgvResults.DataSource = $Global:LockoutData | Sort-Object TimeOccurred
            $lblStatus.Text = "Found $($Global:LockoutData.Count) lockout events. Investigating failed logons..."
            $lblStatus.ForeColor = [System.Drawing.Color]::Green
            [System.Windows.Forms.Application]::DoEvents()

            $UniqueCallerComputers = $Global:LockoutData | Select-Object -ExpandProperty CallerComputer -Unique
            foreach ($Caller in $UniqueCallerComputers) {
                $lblStatus.Text = "Investigating failed logons on $Caller..."
                Add-DebugOutput "Investigating failed logons on $Caller..."
                [System.Windows.Forms.Application]::DoEvents()

                try {
                    $FailedLogons = Get-WinEvent -ComputerName $Caller -FilterHashtable @{
                        LogName   = 'Security'
                        ID        = 4625
                        StartTime = (Get-Date).AddHours(-$hoursBack)
                    } -ErrorAction SilentlyContinue | Where-Object {
                        $_.Properties[5].Value -eq $username
                    } | Select-Object -First 50

                    foreach ($logon in $FailedLogons) {
                        $Global:FailedLogonData += [PSCustomObject]@{
                            TimeCreated    = $logon.TimeCreated
                            TargetAccount  = $logon.Properties[5].Value
                            LogonType      = $logon.Properties[8].Value
                            SourceIP       = $logon.Properties[19].Value
                            Workstation    = $logon.Properties[13].Value
                            CallerComputer = $Caller
                        }
                        Add-DebugOutput "Failed logon: $($logon.Properties[5].Value) from $Caller at $($logon.TimeCreated)"
                    }
                }
                catch {
                    Add-DebugOutput "⚠ Failed to query failed logons from $Caller ${($_.Exception.Message)}"
                }
            }

            if ($Global:FailedLogonData.Count -gt 0) {
                $dgvFailedLogons.DataSource = $Global:FailedLogonData | Sort-Object TimeCreated
            }

            $lblStatus.Text = "Investigation complete. Found $($Global:LockoutData.Count) lockouts and $($Global:FailedLogonData.Count) failed logon attempts."
            $lblStatus.ForeColor = [System.Drawing.Color]::Green
            $btnExport.Enabled = $true
        }
    }
    catch {
        $errorMsg = $_.Exception.Message
        $lblStatus.Text = "Error: $errorMsg"
        $lblStatus.ForeColor = [System.Drawing.Color]::Red
        Add-DebugOutput "FATAL ERROR: $errorMsg"
    }
    finally {
        $btnSearch.Enabled = $true
        Add-DebugOutput "Search operation completed"
    }
}

# Wire the Search button to the function
$btnSearch.Add_Click({ Search-LockoutEvents })


#### --- TAB 3: CRED CHECKER --- ######################################################################

$tabCred = New-Object System.Windows.Forms.TabPage
$tabCred.Text = "Cred Checker"

# Username label
$userLabel = New-Object System.Windows.Forms.Label
$userLabel.Text = "Username:"
$userLabel.Location = New-Object System.Drawing.Point(10, 20)
$userLabel.Size = New-Object System.Drawing.Size(280, 20)
$tabCred.Controls.Add($userLabel)

# Username textbox
$userBox = New-Object System.Windows.Forms.TextBox
$userBox.Location = New-Object System.Drawing.Point(10, 40)
$userBox.Size = New-Object System.Drawing.Size(280, 20)
$tabCred.Controls.Add($userBox)

# Password label
$passLabel = New-Object System.Windows.Forms.Label
$passLabel.Text = "Password:"
$passLabel.Location = New-Object System.Drawing.Point(10, 70)
$passLabel.Size = New-Object System.Drawing.Size(280, 20)
$tabCred.Controls.Add($passLabel)

# Password textbox
$passBox = New-Object System.Windows.Forms.TextBox
$passBox.Location = New-Object System.Drawing.Point(10, 90)
$passBox.Size = New-Object System.Drawing.Size(280, 20)
$passBox.UseSystemPasswordChar = $true
$tabCred.Controls.Add($passBox)

# Output label
$outputLabel = New-Object System.Windows.Forms.Label
$outputLabel.Text = ""
$outputLabel.Location = New-Object System.Drawing.Point(10, 150)
$outputLabel.Size = New-Object System.Drawing.Size(280, 40)
$outputLabel.ForeColor = 'DarkRed'
$tabCred.Controls.Add($outputLabel)

# Submit button
$loginButton = New-Object System.Windows.Forms.Button
$loginButton.Text = "Check"
$loginButton.Location = New-Object System.Drawing.Point(110, 120)
$tabCred.Controls.Add($loginButton)

# Button click event
$loginButton.Add_Click({
    $username = "alsac.local\\" + $userBox.Text
    $password = $passBox.Text
    try {
        $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://alsac.local", $username, $password)
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($entry)
        $searcher.Filter = "(samAccountName=$($userBox.Text))"
        $result = $searcher.FindOne()

        if ($result -ne $null) {
            $outputLabel.ForeColor = 'DarkGreen'
            $outputLabel.Text = "✅ Password is correct."
        } else {
            throw "Invalid credentials or user not found."
        }
    } catch {
        $outputLabel.ForeColor = 'DarkRed'
        $outputLabel.Text = "❌ Invalid credentials or error."
    }
})

#### --- TAB 4: Group Policy & Permissions Checker --- #####################################################

$tabGPO = New-Object System.Windows.Forms.TabPage
$tabGPO.Text = "GPO & Permissions"

# Group/User input label
$lblGroupInput = New-Object System.Windows.Forms.Label
$lblGroupInput.Text = "Group or Username:"
$lblGroupInput.Location = New-Object System.Drawing.Point(10, 20)
$lblGroupInput.Size = New-Object System.Drawing.Size(160, 20)
$tabGPO.Controls.Add($lblGroupInput)

# Input textbox
$txtGroupInput = New-Object System.Windows.Forms.TextBox
$txtGroupInput.Location = New-Object System.Drawing.Point(200, 20)
$txtGroupInput.Size = New-Object System.Drawing.Size(200, 20)
$tabGPO.Controls.Add($txtGroupInput)

# Search button
$btnGroupSearch = New-Object System.Windows.Forms.Button
$btnGroupSearch.Text = "Search"
$btnGroupSearch.Location = New-Object System.Drawing.Point(200, 50)
$btnGroupSearch.Size = New-Object System.Drawing.Size(80, 25)
$tabGPO.Controls.Add($btnGroupSearch)

# Output box
$txtGroupOutput = New-Object System.Windows.Forms.TextBox
$txtGroupOutput.Location = New-Object System.Drawing.Point(10, 90)
$txtGroupOutput.Size = New-Object System.Drawing.Size(760, 800)
$txtGroupOutput.Multiline = $true
$txtGroupOutput.ScrollBars = "Vertical"
$txtGroupOutput.ReadOnly = $true
$txtGroupOutput.BackColor = [System.Drawing.Color]::Black
$txtGroupOutput.ForeColor = [System.Drawing.Color]::LightGreen
$txtGroupOutput.Font = New-Object System.Drawing.Font("Consolas", 9)
$tabGPO.Controls.Add($txtGroupOutput)

# Search logic
$btnGroupSearch.Add_Click({
    $inputName = $txtGroupInput.Text.Trim()
    $txtGroupOutput.Clear()

    if ([string]::IsNullOrEmpty($inputName)) {
        $txtGroupOutput.Text = "Please enter a group or username."
        return
    }

    try {
        # Try to get group
        $group = Get-ADGroup -Identity $inputName -ErrorAction SilentlyContinue
        $user = Get-ADUser -Identity $inputName -ErrorAction SilentlyContinue

        if ($group) {
            $txtGroupOutput.AppendText("=== Group Membership ===`r`n")
            $members = Get-ADGroupMember -Identity $inputName | Select-Object Name, SamAccountName, ObjectClass
            foreach ($member in $members) {
                $txtGroupOutput.AppendText("Name: $($member.Name), SAM: $($member.SamAccountName), Type: $($member.ObjectClass)`r`n")
            }
        }

        if ($group -or $user) {
            $txtGroupOutput.AppendText("`r`n=== Linked Group Policies ===`r`n")
            $GPOs = Get-GPO -All | Where-Object {
                ($_ | Get-GPOReport -ReportType Xml) -match $inputName
            }
            foreach ($gpo in $GPOs) {
                $txtGroupOutput.AppendText("GPO: $($gpo.DisplayName), ID: $($gpo.Id)`r`n")
            }

            $txtGroupOutput.AppendText("`r`n=== Delegated Permissions on OUs ===`r`n")
            $OUs = Get-ADOrganizationalUnit -Filter *
            foreach ($OU in $OUs) {
                $ACLs = Get-Acl -Path ("AD:\" + $OU.DistinguishedName)
                foreach ($ACE in $ACLs.Access) {
                    if ($ACE.IdentityReference -match $inputName) {
                        $txtGroupOutput.AppendText("OU: $($OU.Name)`r`n")
                        $txtGroupOutput.AppendText("Permission: $($ACE.AccessControlType) - $($ACE.ActiveDirectoryRights)`r`n")
                    }
                }
            }

            $txtGroupOutput.AppendText("`r`n=== ACLs on Shared Resources ===`r`n")
            $Shares = Get-SmbShare | Where-Object {$_.Name -notlike "IPC$"}
            foreach ($Share in $Shares) {
                $Path = $Share.Path
                if (Test-Path $Path) {
                    $ACL = Get-Acl -Path $Path
                    foreach ($ACE in $ACL.Access) {
                        if ($ACE.IdentityReference -match $inputName) {
                            $txtGroupOutput.AppendText("Share: $($Share.Name)`r`n")
                            $txtGroupOutput.AppendText("Path: $Path`r`n")
                            $txtGroupOutput.AppendText("Permission: $($ACE.FileSystemRights)`r`n")
                        }
                    }
                }
            }
        } else {
            $txtGroupOutput.Text = "No group or user found with the name '$inputName'."
        }
    }
    catch {
        $txtGroupOutput.Text = "Error: $($_.Exception.Message)"
    }
})


# Add tabs
$tabs.TabPages.AddRange(@($tabStatus, $tabLockout, $tabCred, $tabGPO))
$form.Controls.Add($tabs)

# Show the form
$form.Topmost = $true
$form.Add_Shown({ $form.Activate() })
[void]$form.ShowDialog()
