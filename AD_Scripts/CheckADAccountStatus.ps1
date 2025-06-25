Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$form = New-Object System.Windows.Forms.Form
$form.Text = "AD Account Status Checker"
$form.Size = New-Object System.Drawing.Size(400,450)

$label = New-Object System.Windows.Forms.Label
$label.Text = "Enter Account Name:"
$label.Location = New-Object System.Drawing.Point(10,20)
$form.Controls.Add($label)

$textbox = New-Object System.Windows.Forms.TextBox
$textbox.Location = New-Object System.Drawing.Point(150,18)
$form.Controls.Add($textbox)

$button = New-Object System.Windows.Forms.Button
$button.Text = "Check Status"
$button.Location = New-Object System.Drawing.Point(150,50)
$button.Size = New-Object System.Drawing.Size(100,30)
$form.Controls.Add($button)

$output = New-Object System.Windows.Forms.TextBox
$output.Location = New-Object System.Drawing.Point(10,80)
$output.Size = New-Object System.Drawing.Size(380,300)
$output.Multiline = $true
$output.ReadOnly = $true
$output.ScrollBars = "Vertical"
$form.Controls.Add($output)

$button.Add_Click({
    $accountName = $textbox.Text
    $user = Get-ADUser -Identity $accountName -Properties PwdLastSet, LastLogonTimestamp, Enabled, MemberOf, DistinguishedName
    if ($user) {
        $pwdLastSet = [DateTime]::FromFileTime($user.PwdLastSet)
        $LastLogonTimestamp = [DateTime]::FromFileTime($user.LastLogonTimestamp)
        $status = if ($user.Enabled) { "Enabled" } else { "Disabled" }
        $groups = $user.MemberOf -join [Environment]::NewLine
        $ou = $user.DistinguishedName
        $output.Text = "User: $accountName" + [Environment]::NewLine +
                       "Status: $status" + [Environment]::NewLine +
                       "Last Password Change: $pwdLastSet" + [Environment]::NewLine +
                       "Last Logon: $LastLogonTimestamp" + [Environment]::NewLine +
                       "------------------------" + [Environment]::NewLine +
                       "Groups:" + [Environment]::NewLine + $groups + [Environment]::NewLine +
                       "------------------------" + [Environment]::NewLine +
                       "Location in AD:" + [Environment]::NewLine + $ou
    } else {
        $output.Text = "Account not found or error retrieving data."
    }
})

[void]$form.ShowDialog()
