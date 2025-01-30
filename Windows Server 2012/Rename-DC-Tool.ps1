<#
.DESCRIPTION
    Can rename a classic computer and a DC as well (using Rename-DC-Tool.ps1) Is able to configure WinRM over HTTPS & Enable LDAPS and rename some SPNs.
.NOTES
    By Samuel PAGES 
    Done : June 27th 2024
    Rewritten : October 30th 2024 
    Change launch.ps1 to launch this script
    Find the script : https://github.com/SentinelSamuel/Rename-Computer-Tool
#>
if (!(Test-Path "C:\old_computername.txt")) {
    # Define the path to the .psm1 file (adjust the path accordingly)
    $modulePath = "$PSScriptRoot\DC-Modules.psm1"

    # Import modules
    Import-Module -Name $modulePath -ErrorAction Stop
    # Verify that the module was imported successfully
    if (Get-Module -Name "DC-Modules") {
        Write-Host "[+] Module imported successfully." -ForegroundColor Green
    } else {
        Write-Host "[-] Failed to import the module file." -ForegroundColor Red
    }

    $CurrentName = $env:COMPUTERNAME

    Add-Type -AssemblyName System.Windows.Forms

    $Form1 = New-Object System.Windows.Forms.Form
    $Form1.Text = "Machine Rename Tool"
    $Form1.Size = New-Object System.Drawing.Size(600, 430)
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
    $Form1.MaximumSize = "600,430"
    $Form1.MinimumSize = "600,430"
    $Form1.SizeGripStyle = 2
    $Form1.Capture = $false
    $Form1.KeyPreview = $false
    $Form1.AllowTransparency = $false
    $Form1.AllowDrop = $false
    $Form1.Icon = New-Object System.Drawing.Icon "$PSScriptRoot\S1_Logo_Shield_RGB_PURP.ico"

    # Create label
    $labelPrompt = New-Object System.Windows.Forms.Label
    $labelPrompt.Text = "To make this Environment useable by all the SEs, you must change the machine name. Please enter the computer name right here:"
    $labelPrompt.Size = New-Object System.Drawing.Size(250, 50)
    $labelPrompt.AutoSize = $false
    $labelPrompt.Location = New-Object System.Drawing.Point(20, 25)

    # Create textbox
    $textbox = New-Object System.Windows.Forms.TextBox
    $textbox.Location = New-Object System.Drawing.Point(20, 90)
    $textbox.Size = New-Object System.Drawing.Size(250, 20)

    # Create checkbox to Disable WinRM over HTTP
    $checkboxWinRMHTTP = New-Object System.Windows.Forms.CheckBox
    $checkboxWinRMHTTP.Location = New-Object System.Drawing.Point(20, 120)
    $checkboxWinRMHTTP.Size = New-Object System.Drawing.Size(20, 20)
    # Text to Disable WinRM over HTTP
    $LabelCheckboxWinRMHTTP = New-Object System.Windows.Forms.Label
    $LabelCheckboxWinRMHTTP.Text = "Disable WinRM over HTTP"
    $LabelCheckboxWinRMHTTP.Location = New-Object System.Drawing.Point(40, 123)
    $LabelCheckboxWinRMHTTP.Size = New-Object System.Drawing.Size(250, 25)
    $LabelCheckboxWinRMHTTP.AutoSize = $false

    # Create checkbox to Enable WinRM over HTTPS 
    $checkboxWinRMHTTPS = New-Object System.Windows.Forms.CheckBox
    $checkboxWinRMHTTPS.Location = New-Object System.Drawing.Point(20, 150)
    $checkboxWinRMHTTPS.Size = New-Object System.Drawing.Size(20, 20)
    # Text to Enable WinRM over HTTPS
    $LabelCheckboxWinRMHTTPS = New-Object System.Windows.Forms.Label
    $LabelCheckboxWinRMHTTPS.Text = "Enable WinRM over HTTPS"
    $LabelCheckboxWinRMHTTPS.Location = New-Object System.Drawing.Point(40, 153)
    $LabelCheckboxWinRMHTTPS.Size = New-Object System.Drawing.Size(250, 25)
    $LabelCheckboxWinRMHTTPS.AutoSize = $false

    # Create checkbox to Disable LDAP
    $checkboxLDAP = New-Object System.Windows.Forms.CheckBox
    $checkboxLDAP.Location = New-Object System.Drawing.Point(20, 180)
    $checkboxLDAP.Size = New-Object System.Drawing.Size(20, 20)
    # Text to Disable LDAP
    $LabelCheckboxLDAP = New-Object System.Windows.Forms.Label
    $LabelCheckboxLDAP.Text = "Disable LDAP"
    $LabelCheckboxLDAP.Location = New-Object System.Drawing.Point(40, 183)
    $LabelCheckboxLDAP.Size = New-Object System.Drawing.Size(250, 25)
    $LabelCheckboxLDAP.AutoSize = $false

    # Create checkbox to Enable LDAPS
    $checkboxLDAPS = New-Object System.Windows.Forms.CheckBox
    $checkboxLDAPS.Location = New-Object System.Drawing.Point(20, 210)
    $checkboxLDAPS.Size = New-Object System.Drawing.Size(20, 20)
    # Text to Enable LDAPS
    $LabelCheckboxLDAPS = New-Object System.Windows.Forms.Label
    $LabelCheckboxLDAPS.Text = "Enable LDAPS"
    $LabelCheckboxLDAPS.Location = New-Object System.Drawing.Point(40, 213)
    $LabelCheckboxLDAPS.Size = New-Object System.Drawing.Size(250, 25)
    $LabelCheckboxLDAPS.AutoSize = $false

    # Add picture
    $imagePath = "$PSScriptRoot\S1_Logo_Shield_RGB_PURP.png"
    $picturebox = New-Object Windows.Forms.PictureBox
    $picturebox.ImageLocation = $imagePath
    $picturebox.SizeMode = [Windows.Forms.PictureBoxSizeMode]::Zoom
    $picturebox.Location = New-Object Drawing.Point(480, 25)

    # Create LabelResult0
    $labelResult0 = New-Object System.Windows.Forms.Label
    $labelResult0.Location = New-Object System.Drawing.Point(310, 120)
    $labelResult0.Font = New-Object Drawing.Font("Microsoft Sans Serif", 9)
    $labelResult0.Size = New-Object System.Drawing.Size(200, 70)
    $labelResult0.BorderStyle = [System.Windows.Forms.BorderStyle]::None

    # Create LabelResult1
    $labelResult1 = New-Object System.Windows.Forms.Label
    $labelResult1.Location = New-Object System.Drawing.Point(20, 280)
    $labelResult1.Font = New-Object Drawing.Font("Microsoft Sans Serif", 9)
    $labelResult1.Size = New-Object System.Drawing.Size(500, 50)
    $labelResult1.BorderStyle = [System.Windows.Forms.BorderStyle]::None

    # Create OK button
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(20, 325)
    $okButton.Size = New-Object System.Drawing.Size(75, 23)
    $okButton.Cursor = [System.Windows.Forms.Cursors]::Hand
    $okButton.Text = "OK"
    $okButton.DialogResult = 0
    $okButton.Add_Click({
        $NewMachineName = $textbox.Text
        Start-Transcript -Path "$PSScriptRoot\Rename-DC.log" -Force
        if ($PSVersionTable.PSVersion.Major -eq 5 -and $PSVersionTable.PSVersion.Minor -eq 1) {
            Write-Host "[+] Supported PowerShell Version $($PSVersionTable.PSVersion.Major).$($PSVersionTable.PSVersion.Minor)" -ForegroundColor Green
            if (Test-ValidMachineName -MachineName $NewMachineName) {
                if (($checkboxLDAP.checked) -and (-not $checkboxLDAPS.checked)) {
                    $Form1.Controls.Remove($labelResult1)
                    $Form1.Controls.Remove($progressBar)
                    $Form1.Update()
                    $labelResult1.ForeColor = "Red"
                    $labelResult1.Text = "You cannot disable LDAP if you don't enable LDAPS"
                    $Form1.Controls.Add($labelResult1)
                } else {
                    Set-Content "C:\old_computername.txt" -Value $CurrentName
                    $labelResult0.ForeColor = "DarkViolet"
                    $labelResult0.Text = "Changing computer name, and will restart after it... (from $CurrentName to $NewMachineName)"
                    $Form1.Controls.Add($labelResult0)

                    # Create progress bar
                    $progressBar = New-Object System.Windows.Forms.ProgressBar
                    $progressBar.Location = New-Object System.Drawing.Point(20, 250)
                    $progressBar.Size = New-Object System.Drawing.Size(500, 20)
                    $progressBar.ForeColor = "DarkViolet"
                    $progressBar.MarqueeAnimationSpeed = 30 # Animation Speed
                    $progressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
                    $Form1.Controls.Add($progressBar)
                    
                    # Simulate a progress bar
                    $progressBar.Value = 0
                    $DomainName = (Get-ADDomain).DNSRoot
                    $DnsName = "$NewMachineName.$DomainName"

                    # Remove old Certificates
                    Remove-CertificatesByComputerName -ComputerName $CurrentName
                    $progressBar.Value = 10

                    # Fully disable WinRM configuration
                    Clear-WinRMConfiguration
                    $progressBar.Value = 20

                    # Enable WinRM over HTTPS if checkbox is checked
                    if ($checkboxWinRMHTTPS.Checked) {
                        $WinRM_HTTPS_CERT = Join-Path -Path $PSScriptRoot -ChildPath "WinRM-HTTPS-Cert.txt"
                        Enable-WinRMHTTPS -DnsName $DnsName -ExportPath $PSScriptRoot -CertFileName "WinRMCert" -PasswordFilePath $WinRM_HTTPS_CERT
                    }
                    $progressBar.Value = 30
                    
                    # Disable WinRM over HTTP
                    if ($checkboxWinRMHTTP.Checked) {
                        Disable-WinRMHTTP
                    }
                    $progressBar.Value = 50

                    # Rename a specific topology AD object 
                    Rename-DFSRTopology -OldComputerName $CurrentName -NewComputerName $NewMachineName
                    $progressBar.Value = 60

                    # Rename SPNs with the computer name
                    Rename-SPNs -NewComputerName $NewMachineName
                    $progressBar.Value = 70

                    # Enable LDAPS
                    if ($checkboxLDAPS.Checked) {
                        $LDAPS_CERT = Join-Path -Path $PSScriptRoot -ChildPath "LDAPS-Cert.txt"
                        Enable-LDAPS -DnsName $DnsName -ExportPath $PSScriptRoot -FilePath $LDAPS_CERT
                    }
                    $progressBar.Value = 80

                    # Disable LDAP
                    if ($checkboxLDAP.Checked) {
                        Disable-LDAP
                    }
                    $progressBar.Value = 90

                    # Restart the computer
                    #Rename-Computer -NewName $NewMachineName -PassThru -Restart
                    $progressBar.Value = 100
                    Stop-Transcript
                    
                    $labelResult1.ForeColor = "Green"
                    $labelResult1.Text = "Machine name changed successfully."
                    $Form1.Controls.Add($labelResult1)
                }

            } elseif (($NewMachineName -eq $null) -or ($NewMachineName -eq "")) {
                $Form1.Controls.Remove($labelResult0)
                $Form1.Controls.Remove($labelResult1)
                $Form1.Controls.Remove($progressBar)
                $Form1.Update()
                $labelResult1.ForeColor = "Red"
                $labelResult1.Text = "Cannot change computer name, you have to enter a computer name in the text box." 
                $Form1.Controls.Add($labelResult1)
            } else {
                $Form1.Controls.Remove($labelResult0)
                $Form1.Controls.Remove($labelResult1)
                $Form1.Controls.Remove($progressBar)
                $Form1.Update()
                $labelResult1.ForeColor = "Red"
                $labelResult1.Text = "Cannot change computer name from $CurrentName to $NewMachineName because it is not a valid computer name (no more than 15 characters)." 
                $Form1.Controls.Add($labelResult1)
            }
        } else {
            $Form1.Controls.Remove($labelResult0)
            $Form1.Controls.Remove($labelResult1)
            $Form1.Controls.Remove($progressBar)
            $Form1.Update()
            $labelResult1.ForeColor = "Red"
            $labelResult1.Text = "The PowerShell Version is not working with this script, please use a newer version" 
            $Form1.Controls.Add($labelResult1)
        }
    })

    # Create Cancel button
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(110, 325)
    $cancelButton.Size = New-Object System.Drawing.Size(75, 23)
    $cancelButton.Text = "Cancel"
    $cancelButton.DialogResult = 1
    $cancelButton.Cursor = [System.Windows.Forms.Cursors]::Hand
    $cancelButton.Add_Click({
        $labelResult1.ForeColor = "Red"
        $labelResult1.Text = "Operation canceled."
    })

    # Add controls to form
    $Form1.Controls.Add($labelPrompt)
    $Form1.Controls.Add($textbox)
    $Form1.Controls.Add($checkboxWinRMHTTP)
    $Form1.Controls.Add($LabelCheckboxWinRMHTTP)
    $Form1.Controls.Add($checkboxWinRMHTTPS)
    $Form1.Controls.Add($LabelCheckboxWinRMHTTPS)
    $Form1.Controls.Add($checkboxLDAPS)
    $Form1.Controls.Add($LabelCheckboxLDAPS)
    $Form1.Controls.Add($checkboxLDAP)
    $Form1.Controls.Add($LabelCheckboxLDAP)
    $Form1.Controls.Add($okButton)
    $Form1.Controls.Add($cancelButton)
    $Form1.Controls.Add($picturebox)

    # Display form
    $Form1.ShowDialog()

    # Dispose of the form
    $Form1.Dispose()
}
