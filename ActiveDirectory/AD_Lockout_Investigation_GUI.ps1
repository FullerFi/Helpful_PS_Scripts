Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Create the main form
$form = New-Object System.Windows.Forms.Form
$form.Text = "AD Account Lockout Investigator"
$form.Size = New-Object System.Drawing.Size(800, 600)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false

# Username input
$lblUsername = New-Object System.Windows.Forms.Label
$lblUsername.Location = New-Object System.Drawing.Point(10, 20)
$lblUsername.Size = New-Object System.DrawAdd-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Create the main form
$form = New-Object System.Windows.Forms.Form
$form.Text = "AD Account Lockout Investigator"
$form.Size = New-Object System.Drawing.Size(800, 600)
$form.StartPosition = "CenterScreen"
$form.FormBorderStyle = "FixedDialog"
$form.MaximizeBox = $false

# Username input
$lblUsername = New-Object System.Windows.Forms.Label
$lblUsername.Location = New-Object System.Drawing.Point(10, 20)
$lblUsername.Size = New-Object System.Drawing.Size(100, 20)
$lblUsername.Text = "Username:"
$form.Controls.Add($lblUsername)

$txtUsername = New-Object System.Windows.Forms.TextBox
$txtUsername.Location = New-Object System.Drawing.Point(120, 18)
$txtUsername.Size = New-Object System.Drawing.Size(200, 20)
$form.Controls.Add($txtUsername)

# Hours back input
$lblHours = New-Object System.Windows.Forms.Label
$lblHours.Location = New-Object System.Drawing.Point(340, 20)
$lblHours.Size = New-Object System.Drawing.Size(140, 20)
$lblHours.Text = "Time Range (hours):"
$form.Controls.Add($lblHours)

$numHours = New-Object System.Windows.Forms.NumericUpDown
$numHours.Location = New-Object System.Drawing.Point(480, 18)
$numHours.Size = New-Object System.Drawing.Size(60, 20)
$numHours.Minimum = 1
$numHours.Maximum = 168
$numHours.Value = 24
$form.Controls.Add($numHours)

# Search button
$btnSearch = New-Object System.Windows.Forms.Button
$btnSearch.Location = New-Object System.Drawing.Point(550, 16)
$btnSearch.Size = New-Object System.Drawing.Size(80, 25)
$btnSearch.Text = "Search"
$form.Controls.Add($btnSearch)

# Export button
$btnExport = New-Object System.Windows.Forms.Button
$btnExport.Location = New-Object System.Drawing.Point(640, 16)
$btnExport.Size = New-Object System.Drawing.Size(80, 25)
$btnExport.Text = "Export CSV"
$btnExport.Enabled = $false
$form.Controls.Add($btnExport)

# Status label
$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Location = New-Object System.Drawing.Point(10, 50)
$lblStatus.Size = New-Object System.Drawing.Size(750, 20)
$lblStatus.Text = "Ready to search..."
$lblStatus.ForeColor = [System.Drawing.Color]::Blue
$form.Controls.Add($lblStatus)

# Results DataGridView
$dgvResults = New-Object System.Windows.Forms.DataGridView
$dgvResults.Location = New-Object System.Drawing.Point(10, 80)
$dgvResults.Size = New-Object System.Drawing.Size(760, 200)
$dgvResults.AllowUserToAddRows = $false
$dgvResults.ReadOnly = $true
$dgvResults.SelectionMode = "FullRowSelect"
$dgvResults.AutoSizeColumnsMode = "Fill"
$form.Controls.Add($dgvResults)

# Failed logon attempts DataGridView
$lblFailedLogons = New-Object System.Windows.Forms.Label
$lblFailedLogons.Location = New-Object System.Drawing.Point(10, 290)
$lblFailedLogons.Size = New-Object System.Drawing.Size(200, 20)
$lblFailedLogons.Text = "Failed Logon Attempts:"
$lblFailedLogons.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($lblFailedLogons)

$dgvFailedLogons = New-Object System.Windows.Forms.DataGridView
$dgvFailedLogons.Location = New-Object System.Drawing.Point(10, 315)
$dgvFailedLogons.Size = New-Object System.Drawing.Size(760, 220)
$dgvFailedLogons.AllowUserToAddRows = $false
$dgvFailedLogons.ReadOnly = $true
$dgvFailedLogons.SelectionMode = "FullRowSelect"
$dgvFailedLogons.AutoSizeColumnsMode = "Fill"
$form.Controls.Add($dgvFailedLogons)

# Global variable to store results
$Global:LockoutData = @()
$Global:FailedLogonData = @()

# Search function
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
    
    # Clear previous results
    $dgvResults.DataSource = $null
    $dgvFailedLogons.DataSource = $null
    $Global:LockoutData = @()
    $Global:FailedLogonData = @()
    
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $DomainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name
        
        foreach ($DC in $DomainControllers) {
            $lblStatus.Text = "Querying $DC..."
            $form.Refresh()
            
            try {
                $Events = Get-WinEvent -ComputerName $DC -FilterHashtable @{
                    LogName   = 'Security'
                    ID        = 4740
                    StartTime = (Get-Date).AddHours(-$hoursBack)
                } -ErrorAction SilentlyContinue | Where-Object { $_.Properties[0].Value -eq $username }
                
                if ($Events) {
                    foreach ($Event in $Events) {
                        $Global:LockoutData += [PSCustomObject]@{
                            TimeOccurred     = $Event.TimeCreated
                            DomainController = $DC
                            LockedAccount    = $Event.Properties[0].Value
                            CallerComputer   = $Event.Properties[1].Value
                        }
                    }
                }
            }
            catch {
                Write-Warning "Failed to query $DC"
            }
        }
        
        if ($Global:LockoutData.Count -eq 0) {
            $lblStatus.Text = "No lockout events found for '$username' in the last $hoursBack hours."
            $lblStatus.ForeColor = [System.Drawing.Color]::Orange
        }
        else {
            $dgvResults.DataSource = $Global:LockoutData | Sort-Object TimeOccurred
            $lblStatus.Text = "Found $($Global:LockoutData.Count) lockout events. Investigating failed logons..."
            $lblStatus.ForeColor = [System.Drawing.Color]::Green
            $form.Refresh()
            
            # Get failed logon attempts
            $UniqueCallerComputers = $Global:LockoutData | Select-Object -ExpandProperty CallerComputer -Unique
            
            foreach ($Caller in $UniqueCallerComputers) {
                $lblStatus.Text = "Investigating failed logons on $Caller..."
                $form.Refresh()
                
                try {
                    $FailedLogons = Get-WinEvent -ComputerName $Caller -FilterHashtable @{
                        LogName   = 'Security'
                        ID        = 4625
                        StartTime = (Get-Date).AddHours(-$hoursBack)
                    } -ErrorAction SilentlyContinue | Where-Object { $_.Properties[5].Value -eq $username } | Select-Object -First 50
                    
                    if ($FailedLogons) {
                        foreach ($logon in $FailedLogons) {
                            $Global:FailedLogonData += [PSCustomObject]@{
                                TimeCreated = $logon.TimeCreated
                                TargetAccount = $logon.Properties[5].Value
                                LogonType = $logon.Properties[8].Value
                                SourceIP = $logon.Properties[19].Value
                                Workstation = $logon.Properties[13].Value
                                CallerComputer = $Caller
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "Failed to query failed logons from $Caller"
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
        $lblStatus.Text = "Error: $($_.Exception.Message)"
        $lblStatus.ForeColor = [System.Drawing.Color]::Red
    }
    finally {
        $btnSearch.Enabled = $true
    }
}

# Export function
function Export-Results {
    if ($Global:LockoutData.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No data to export.", "Info", "OK", "Information")
        return
    }
    
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "CSV files (*.csv)|*.csv"
    $saveDialog.FileName = "LockoutInvestigation_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    
    if ($saveDialog.ShowDialog() -eq "OK") {
        try {
            $Global:LockoutData | Export-Csv -Path $saveDialog.FileName -NoTypeInformation
            if ($Global:FailedLogonData.Count -gt 0) {
                $failedLogonFile = $saveDialog.FileName -replace '\.csv$', '_FailedLogons.csv'
                $Global:FailedLogonData | Export-Csv -Path $failedLogonFile -NoTypeInformation
            }
            [System.Windows.Forms.MessageBox]::Show("Data exported successfully!", "Success", "OK", "Information")
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)", "Error", "OK", "Error")
        }
    }
}

# Event handlers
$btnSearch.Add_Click({ Search-LockoutEvents })
$btnExport.Add_Click({ Export-Results })
$txtUsername.Add_KeyDown({
    if ($_.KeyCode -eq "Enter") {
        Search-LockoutEvents
    }
})

# Show the form
$form.ShowDialog()ing.Size(100, 20)
$lblUsername.Text = "Username:"
$form.Controls.Add($lblUsername)

$txtUsername = New-Object System.Windows.Forms.TextBox
$txtUsername.Location = New-Object System.Drawing.Point(120, 18)
$txtUsername.Size = New-Object System.Drawing.Size(200, 20)
$form.Controls.Add($txtUsername)

# Hours back input
$lblHours = New-Object System.Windows.Forms.Label
$lblHours.Location = New-Object System.Drawing.Point(340, 20)
$lblHours.Size = New-Object System.Drawing.Size(80, 20)
$lblHours.Text = "Hours Back:"
$form.Controls.Add($lblHours)

$numHours = New-Object System.Windows.Forms.NumericUpDown
$numHours.Location = New-Object System.Drawing.Point(430, 18)
$numHours.Size = New-Object System.Drawing.Size(60, 20)
$numHours.Minimum = 1
$numHours.Maximum = 168
$numHours.Value = 24
$form.Controls.Add($numHours)

# Search button
$btnSearch = New-Object System.Windows.Forms.Button
$btnSearch.Location = New-Object System.Drawing.Point(520, 16)
$btnSearch.Size = New-Object System.Drawing.Size(80, 25)
$btnSearch.Text = "Search"
$form.Controls.Add($btnSearch)

# Export button
$btnExport = New-Object System.Windows.Forms.Button
$btnExport.Location = New-Object System.Drawing.Point(610, 16)
$btnExport.Size = New-Object System.Drawing.Size(80, 25)
$btnExport.Text = "Export CSV"
$btnExport.Enabled = $false
$form.Controls.Add($btnExport)

# Status label
$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Location = New-Object System.Drawing.Point(10, 50)
$lblStatus.Size = New-Object System.Drawing.Size(750, 20)
$lblStatus.Text = "Ready to search..."
$lblStatus.ForeColor = [System.Drawing.Color]::Blue
$form.Controls.Add($lblStatus)

# Results DataGridView
$dgvResults = New-Object System.Windows.Forms.DataGridView
$dgvResults.Location = New-Object System.Drawing.Point(10, 80)
$dgvResults.Size = New-Object System.Drawing.Size(760, 200)
$dgvResults.AllowUserToAddRows = $false
$dgvResults.ReadOnly = $true
$dgvResults.SelectionMode = "FullRowSelect"
$dgvResults.AutoSizeColumnsMode = "Fill"
$form.Controls.Add($dgvResults)

# Failed logon attempts DataGridView
$lblFailedLogons = New-Object System.Windows.Forms.Label
$lblFailedLogons.Location = New-Object System.Drawing.Point(10, 290)
$lblFailedLogons.Size = New-Object System.Drawing.Size(200, 20)
$lblFailedLogons.Text = "Failed Logon Attempts:"
$lblFailedLogons.Font = New-Object System.Drawing.Font("Microsoft Sans Serif", 9, [System.Drawing.FontStyle]::Bold)
$form.Controls.Add($lblFailedLogons)

$dgvFailedLogons = New-Object System.Windows.Forms.DataGridView
$dgvFailedLogons.Location = New-Object System.Drawing.Point(10, 315)
$dgvFailedLogons.Size = New-Object System.Drawing.Size(760, 220)
$dgvFailedLogons.AllowUserToAddRows = $false
$dgvFailedLogons.ReadOnly = $true
$dgvFailedLogons.SelectionMode = "FullRowSelect"
$dgvFailedLogons.AutoSizeColumnsMode = "Fill"
$form.Controls.Add($dgvFailedLogons)

# Global variable to store results
$Global:LockoutData = @()
$Global:FailedLogonData = @()

# Search function
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
    
    # Clear previous results
    $dgvResults.DataSource = $null
    $dgvFailedLogons.DataSource = $null
    $Global:LockoutData = @()
    $Global:FailedLogonData = @()
    
    try {
        Import-Module ActiveDirectory -ErrorAction Stop
        $DomainControllers = Get-ADDomainController -Filter * | Select-Object -ExpandProperty Name
        
        foreach ($DC in $DomainControllers) {
            $lblStatus.Text = "Querying $DC..."
            $form.Refresh()
            
            try {
                $Events = Get-WinEvent -ComputerName $DC -FilterHashtable @{
                    LogName   = 'Security'
                    ID        = 4740
                    StartTime = (Get-Date).AddHours(-$hoursBack)
                } -ErrorAction SilentlyContinue | Where-Object { $_.Properties[0].Value -eq $username }
                
                if ($Events) {
                    foreach ($Event in $Events) {
                        $Global:LockoutData += [PSCustomObject]@{
                            TimeOccurred     = $Event.TimeCreated
                            DomainController = $DC
                            LockedAccount    = $Event.Properties[0].Value
                            CallerComputer   = $Event.Properties[1].Value
                        }
                    }
                }
            }
            catch {
                Write-Warning "Failed to query $DC"
            }
        }
        
        if ($Global:LockoutData.Count -eq 0) {
            $lblStatus.Text = "No lockout events found for '$username' in the last $hoursBack hours."
            $lblStatus.ForeColor = [System.Drawing.Color]::Orange
        }
        else {
            $dgvResults.DataSource = $Global:LockoutData | Sort-Object TimeOccurred
            $lblStatus.Text = "Found $($Global:LockoutData.Count) lockout events. Investigating failed logons..."
            $lblStatus.ForeColor = [System.Drawing.Color]::Green
            $form.Refresh()
            
            # Get failed logon attempts
            $UniqueCallerComputers = $Global:LockoutData | Select-Object -ExpandProperty CallerComputer -Unique
            
            foreach ($Caller in $UniqueCallerComputers) {
                $lblStatus.Text = "Investigating failed logons on $Caller..."
                $form.Refresh()
                
                try {
                    $FailedLogons = Get-WinEvent -ComputerName $Caller -FilterHashtable @{
                        LogName   = 'Security'
                        ID        = 4625
                        StartTime = (Get-Date).AddHours(-$hoursBack)
                    } -ErrorAction SilentlyContinue | Where-Object { $_.Properties[5].Value -eq $username } | Select-Object -First 50
                    
                    if ($FailedLogons) {
                        foreach ($logon in $FailedLogons) {
                            $Global:FailedLogonData += [PSCustomObject]@{
                                TimeCreated = $logon.TimeCreated
                                TargetAccount = $logon.Properties[5].Value
                                LogonType = $logon.Properties[8].Value
                                SourceIP = $logon.Properties[19].Value
                                Workstation = $logon.Properties[13].Value
                                CallerComputer = $Caller
                            }
                        }
                    }
                }
                catch {
                    Write-Warning "Failed to query failed logons from $Caller"
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
        $lblStatus.Text = "Error: $($_.Exception.Message)"
        $lblStatus.ForeColor = [System.Drawing.Color]::Red
    }
    finally {
        $btnSearch.Enabled = $true
    }
}

# Export function
function Export-Results {
    if ($Global:LockoutData.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show("No data to export.", "Info", "OK", "Information")
        return
    }
    
    $saveDialog = New-Object System.Windows.Forms.SaveFileDialog
    $saveDialog.Filter = "CSV files (*.csv)|*.csv"
    $saveDialog.FileName = "LockoutInvestigation_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    
    if ($saveDialog.ShowDialog() -eq "OK") {
        try {
            $Global:LockoutData | Export-Csv -Path $saveDialog.FileName -NoTypeInformation
            if ($Global:FailedLogonData.Count -gt 0) {
                $failedLogonFile = $saveDialog.FileName -replace '\.csv$', '_FailedLogons.csv'
                $Global:FailedLogonData | Export-Csv -Path $failedLogonFile -NoTypeInformation
            }
            [System.Windows.Forms.MessageBox]::Show("Data exported successfully!", "Success", "OK", "Information")
        }
        catch {
            [System.Windows.Forms.MessageBox]::Show("Export failed: $($_.Exception.Message)", "Error", "OK", "Error")
        }
    }
}

# Event handlers
$btnSearch.Add_Click({ Search-LockoutEvents })
$btnExport.Add_Click({ Export-Results })
$txtUsername.Add_KeyDown({
    if ($_.KeyCode -eq "Enter") {
        Search-LockoutEvents
    }
})

# Show the form
$form.ShowDialog()
