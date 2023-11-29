Add-Type -AssemblyName System.Windows.Forms

# Function to get the current domain name
function Get-CurrentDomainName {
    try {
        $currentDomain = (Get-WmiObject Win32_ComputerSystem).Domain
        return $currentDomain
    } catch {
        throw "Failed to retrieve the current domain name. Error: $_"
    }
}
function Compare-Domain {
    param (
        [string]$DomainName
    )

    # Define the regex pattern for a domain name
    $domainRegex = "^[a-zA-Z0-9-]+(\.[a-zA-Z]{2,})+$"

    # Compare the input string to the regex pattern
    if ($DomainName -match $domainRegex) {
        return $True
    } else {
        return $False
    }
}
function Convert-ToNetBiosName {
    param (
        [string]$domainName
    )

    # Remove invalid characters from the domain name
    $cleanedName = $domainName -replace '[^a-zA-Z0-9]', ''

    # Ensure the length does not exceed NetBIOS limit (15 characters)
    $netBiosName = $cleanedName.Substring(0, [Math]::Min(15, $cleanedName.Length))

    return $netBiosName
}
$Form1 = New-Object System.Windows.Forms.Form
$Form1.Text = " Domain Rename Tool"
$Form1.Size = New-Object System.Drawing.Size(600,400)
$Form1.ShowInTaskbar = $false
$Form1.StartPosition = "CenterScreen"
$Form1.MinimizeBox = $true
$Form1.MaximizeBox = $false
$Form1.ControlBox = $true
$Form1.FormBorderStyle = 3
$Form1.Opacity = 1
$Form1.UseWaitCursor = $false
$Form1.AutoScroll = $false
$Form1.HorizontalScroll.Enabled = $false
$Form1.VerticalScroll.Enabled = $false
$Form1.VerticalScroll.Visible = $false
$Form1.Topmost = $true
$Form1.MaximumSize = "600,400" 
$Form1.MinimumSize = "600,400"
$Form1.SizeGripStyle = 2
$Form1.Capture = $false
$Form1.KeyPreview = $false
$Form1.AllowTransparency = $false
$Form1.AllowDrop = $false
$Form1.Icon = New-Object System.Drawing.Icon "$PSScriptRoot\S1_Logo_Shield_RGB_PURP.ico"

# Create label
$labelPrompt = New-Object System.Windows.Forms.Label
$labelPrompt.Text = "Enter the new domain name:"
$labelPrompt.AutoSize = $true
$labelPrompt.Location = New-Object System.Drawing.Point(20,30)

# Create textbox
$textbox = New-Object System.Windows.Forms.TextBox
$textbox.Location = New-Object System.Drawing.Point(20,60)
$textbox.Size = New-Object System.Drawing.Size(250,20)

# Add picture
$imagePath = "$PSScriptRoot\S1_Logo_Shield_RGB_PURP.png"
$picturebox = New-Object Windows.Forms.PictureBox
$picturebox.ImageLocation = $imagePath
$picturebox.SizeMode = [Windows.Forms.PictureBoxSizeMode]::Zoom
$picturebox.Location = New-Object Drawing.Point(480, 25)

# Create LabelResult0
$labelResult0 = New-Object System.Windows.Forms.Label
$labelResult0.Location = New-Object System.Drawing.Point(20,120)
$labelResult0.Font = New-Object Drawing.Font("Microsoft Sans Serif", 9)
$labelResult0.Size = New-Object System.Drawing.Size(500,25)
$labelResult0.BorderStyle = [System.Windows.Forms.BorderStyle]::None

# Create LabelResult1
$labelResult1 = New-Object System.Windows.Forms.Label
$labelResult1.Location = New-Object System.Drawing.Point(20,180)
$labelResult1.Font = New-Object Drawing.Font("Microsoft Sans Serif", 9)
$labelResult1.Size = New-Object System.Drawing.Size(500,25)
$labelResult1.BorderStyle = [System.Windows.Forms.BorderStyle]::None

# Create OK button
$okButton = New-Object System.Windows.Forms.Button
$okButton.Location = New-Object System.Drawing.Point(20,90)
$okButton.Size = New-Object System.Drawing.Size(75,23)
$okButton.Cursor = [System.Windows.Forms.Cursors]::Hand
$okButton.Text = "OK"
$okButton.DialogResult = 0
$okButton.Add_Click({
    $current_name = Get-CurrentDomainName
    $newDomainName = $textbox.Text
    if (Compare-Domain $newDomainName) {
        $labelResult0.ForeColor = "DarkViolet"
        $labelResult0.Text = "Changing domain name, and will restart after it... (from $current_name to : $newDomainName)"
        $Form1.Controls.Add($labelResult0)

        # Create progress bar
        $progressBar = New-Object System.Windows.Forms.ProgressBar
        $progressBar.Location = New-Object System.Drawing.Point(20,150)
        $progressBar.Size = New-Object System.Drawing.Size(500, 20)
        $progressBar.ForeColor = "DarkViolet"
        $progressBar.MarqueeAnimationSpeed = 30 # You can adjust the speed (milliseconds)
        $progressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
        $Form1.Controls.Add($progressBar)

        # Simulate a progress bar
        $progressBar.Value = 0

        # New DNS zone
        Add-DnsServerPrimaryZone -Name $newDomainName -ReplicationScope "Domain" –PassThru

        # Define paths to tools
        $rendomPath = "$env:SystemRoot\System32\rendom.exe"
        $netdomPath = "$env:SystemRoot\System32\netdom.exe"
        $gpfixupPath = "$env:SystemRoot\System32\gpfixup.exe"

        $progressBar.Value = 10
        # Perform a dry run to check for potential issues
        Set-Location $PSScriptRoot
        Start-Process "$rendomPath" -ArgumentList " /list"
        $progressBar.Value = 15
        Start-Sleep 2
        $NetBIOS = Convert-ToNetBiosName -domainName $newDomainName
        $xml_content = Get-Content "$PSScriptRoot\Domainlist.xml"
        $new_xml_content = $xml_content.Replace($current_name, $newDomainName).Replace('S1',$NetBIOS)
        $new_xml_content | Set-Content -Path "$PSScriptRoot\Domainlist.xml"
        Start-Process "$rendomPath" -ArgumentList " /showforest"
        Start-Sleep 2
        $progressBar.Value = 25
        Start-Process "$rendomPath" -ArgumentList " /upload"
        Start-Sleep 2
        $progressBar.Value = 40
        Start-Process "$netdomPath" -ArgumentList " query fsmo"
        Start-Sleep 2
        $progressBar.Value = 50
        Start-Process "$rendomPath" -ArgumentList " /prepare"
        Start-Sleep 2
        $progressBar.Value = 60
        Start-Process "$rendomPath" -ArgumentList " /execute"
        Start-Sleep 2
        $progressBar.Value = 75
        Start-Process "$gpfixupPath" -ArgumentList "  /olddns:$current_name /newdns:$newDomainName"
        Start-Process "$gpfixupPath" -ArgumentList " /oldnb:S1 /newnb:$newDomainName"
        Start-Sleep 2
        $progressBar.Value = 85
        Start-Process "$netdomPath" -ArgumentList " computername $env:COMPUTERNAME.$current_name /add:$env:COMPUTERNAME.$newDomainName"
        Start-Process "$netdomPath" -ArgumentList " computername $env:COMPUTERNAME.$current_name /makeprimary:$env:COMPUTERNAME.$newDomainName"
        Start-Sleep 2
        $progressBar.Value = 95
        $labelResult1.ForeColor = "Green"
        $labelResult1.Text = "Domain name changed successfully (RESTART IN 10s), wait 25 seconds after login."
        $Form1.Controls.Add($labelResult1)
        Start-Sleep 10
        $progressBar.Value = 100
        # Restart the computer
        Restart-Computer -Force
               
    } elseif (($newDomainName -eq $null) -or ($newDomainName -eq "")) {
        $Form1.Controls.Remove($labelResult0)
        $Form1.Controls.Remove($labelResult1)
        $Form1.Controls.Remove($progressBar)
        $Form1.Update()
        $labelResult1.Text = "Cannot change domain name, you have to enter a domain name in the text box." 
        $labelResult1.ForeColor = "Red"
        $Form1.Controls.Add($labelResult1)
    } else {
        $Form1.Controls.Remove($labelResult0)
        $Form1.Controls.Remove($labelResult1)
        $Form1.Controls.Remove($progressBar)
        $Form1.Update()
        $labelResult1.Text = "Cannot change domain name from $current_name to $newDomainName because it is not a valid domain name." 
        $labelResult1.ForeColor = "Red"
        $Form1.Controls.Add($labelResult1)
    }
})

# Create Cancel button
$cancelButton = New-Object System.Windows.Forms.Button
$cancelButton.Location = New-Object System.Drawing.Point(110,90)
$cancelButton.Size = New-Object System.Drawing.Size(75,23)
$cancelButton.Text = "Cancel"
$cancelButton.DialogResult = 1
$cancelButton.Cursor = [System.Windows.Forms.Cursors]::Hand
$cancelButton.Add_Click({
    $labelResult1.Text = "Operation canceled."
    $labelResult1.ForeColor = "Red"
})

# Add controls to form
$Form1.Controls.Add($labelPrompt)
$Form1.Controls.Add($textbox)
$Form1.Controls.Add($okButton)
$Form1.Controls.Add($cancelButton)
$Form1.Controls.Add($picturebox)

# Display form
$Form1.ShowDialog()

# Dispose of the form
$Form1.Dispose()
