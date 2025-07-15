## Make sure to add the domain you're working within on line 53 ##

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.DirectoryServices

# Create the form
$form = New-Object System.Windows.Forms.Form
$form.Text = "Cred Checker"
$form.Size = New-Object System.Drawing.Size(350,220)
$form.StartPosition = "CenterScreen"

# Username label and textbox
$userLabel = New-Object System.Windows.Forms.Label
$userLabel.Text = "Username:"
$userLabel.Location = New-Object System.Drawing.Point(10,20)
$userLabel.Size = New-Object System.Drawing.Size(280,20)
$form.Controls.Add($userLabel)

$userBox = New-Object System.Windows.Forms.TextBox
$userBox.Location = New-Object System.Drawing.Point(10,40)
$userBox.Size = New-Object System.Drawing.Size(280,20)
$form.Controls.Add($userBox)

# Password label and textbox
$passLabel = New-Object System.Windows.Forms.Label
$passLabel.Text = "Password:"
$passLabel.Location = New-Object System.Drawing.Point(10,70)
$passLabel.Size = New-Object System.Drawing.Size(280,20)
$form.Controls.Add($passLabel)

$passBox = New-Object System.Windows.Forms.TextBox
$passBox.Location = New-Object System.Drawing.Point(10,90)
$passBox.Size = New-Object System.Drawing.Size(280,20)
$passBox.UseSystemPasswordChar = $true
$form.Controls.Add($passBox)

# Output label
$outputLabel = New-Object System.Windows.Forms.Label
$outputLabel.Text = ""
$outputLabel.Location = New-Object System.Drawing.Point(10,150)
$outputLabel.Size = New-Object System.Drawing.Size(280,40)
$outputLabel.ForeColor = 'DarkRed'
$form.Controls.Add($outputLabel)

# Submit button
$loginButton = New-Object System.Windows.Forms.Button
$loginButton.Text = "Check"
$loginButton.Location = New-Object System.Drawing.Point(110,120)
$loginButton.Add_Click({
    $username = "alsac.local\" + $userBox.Text
    $password = $passBox.Text

    try {
        $entry = New-Object System.DirectoryServices.DirectoryEntry("LDAP://ADD DOMAIN HERE", $username, $password)
        $null = $entry.NativeObject  # Force bind
        $outputLabel.ForeColor = 'DarkGreen'
        $outputLabel.Text = "✅ Password is correct."
    } catch {
        $outputLabel.ForeColor = 'DarkRed'
        $outputLabel.Text = "❌ Invalid credentials or error."
    }
})
$form.Controls.Add($loginButton)

# Show the form
$form.Topmost = $true
$form.Add_Shown({ $form.Activate() })
[void]$form.ShowDialog()
