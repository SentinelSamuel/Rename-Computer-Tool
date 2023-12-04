# By Samuel PAGES 
# Done : December 4th 2023

if(!(Test-Path "C:\old_computername.txt")) {

    function Test-ValidMachineName {
        param (
            [string]$MachineName
        )

        # Define the regex pattern for a valid machine name
        $machineNameRegex = "^[a-zA-Z0-9-]+$"

        # Check if the input string matches the regex pattern
        if ($MachineName -match $machineNameRegex) {
            return $true
        } else {
            return $false
        }
    }

    $CurrentName = $env:COMPUTERNAME

    Add-Type -AssemblyName System.Windows.Forms

    $Form1 = New-Object System.Windows.Forms.Form
    $Form1.Text = " Machine Rename Tool"
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
    $Form1.Icon = New-Object System.Drawing.Icon ".\S1_Logo_Shield_RGB_PURP.ico"

    # Create label
    $labelPrompt = New-Object System.Windows.Forms.Label
    $labelPrompt.Text = "To make this Environment useable by all the SEs, you must change the machine name, enter the computer name right here :"
    $labelPrompt.Size = New-Object System.Drawing.Size(250,40)
    $labelPrompt.AutoSize = $false
    $labelPrompt.Location = New-Object System.Drawing.Point(20,25)

    # Create textbox
    $textbox = New-Object System.Windows.Forms.TextBox
    $textbox.Location = New-Object System.Drawing.Point(20,70)
    $textbox.Size = New-Object System.Drawing.Size(250,20)

    # Add picture
    $imagePath = ".\S1_Logo_Shield_RGB_PURP.png"
    $picturebox = New-Object Windows.Forms.PictureBox
    $picturebox.ImageLocation = $imagePath
    $picturebox.SizeMode = [Windows.Forms.PictureBoxSizeMode]::Zoom
    $picturebox.Location = New-Object Drawing.Point(480, 25)

    # Create LabelResult0
    $labelResult0 = New-Object System.Windows.Forms.Label
    $labelResult0.Location = New-Object System.Drawing.Point(20,130)
    $labelResult0.Font = New-Object Drawing.Font("Microsoft Sans Serif", 9)
    $labelResult0.Size = New-Object System.Drawing.Size(500,25)
    $labelResult0.BorderStyle = [System.Windows.Forms.BorderStyle]::None

    # Create LabelResult1
    $labelResult1 = New-Object System.Windows.Forms.Label
    $labelResult1.Location = New-Object System.Drawing.Point(20,190)
    $labelResult1.Font = New-Object Drawing.Font("Microsoft Sans Serif", 9)
    $labelResult1.Size = New-Object System.Drawing.Size(500,25)
    $labelResult1.BorderStyle = [System.Windows.Forms.BorderStyle]::None

    # Create OK button
    $okButton = New-Object System.Windows.Forms.Button
    $okButton.Location = New-Object System.Drawing.Point(20,100)
    $okButton.Size = New-Object System.Drawing.Size(75,23)
    $okButton.Cursor = [System.Windows.Forms.Cursors]::Hand
    $okButton.Text = "OK"
    $okButton.DialogResult = 0
    $okButton.Add_Click({    
        $NewMachineName = $textbox.Text
        if (Test-ValidMachineName -MachineName $NewMachineName) {
            Set-Content "C:\old_computername.txt" -Value $CurrentName
            $labelResult0.ForeColor = "DarkViolet"
            $labelResult0.Text = "Changing computer name, and will restart after it... (from $CurrentName to $NewMachineName)"
            $Form1.Controls.Add($labelResult0)

            # Create progress bar
            $progressBar = New-Object System.Windows.Forms.ProgressBar
            $progressBar.Location = New-Object System.Drawing.Point(20,160)
            $progressBar.Size = New-Object System.Drawing.Size(500, 20)
            $progressBar.ForeColor = "DarkViolet"
            $progressBar.MarqueeAnimationSpeed = 30 # You can adjust the speed (milliseconds)
            $progressBar.Style = [System.Windows.Forms.ProgressBarStyle]::Continuous
            $Form1.Controls.Add($progressBar)

            # Simulate a progress bar
            $progressBar.Value = 0
            $progressBar.Value = 50
            Rename-Computer -NewName $NewMachineName -PassThru -Restart
            $progressBar.Value = 100
            $labelResult1.ForeColor = "Green"
            $labelResult1.Text = "Machine name changed successfully."
            $Form1.Controls.Add($labelResult1)
               
        } elseif (($NewMachineName -eq $null) -or ($NewMachineName -eq "")) {
            $Form1.Controls.Remove($labelResult0)
            $Form1.Controls.Remove($labelResult1)
            $Form1.Controls.Remove($progressBar)
            $Form1.Update()
            $labelResult1.Text = "Cannot change computer name, you have to enter a computer name in the text box." 
            $labelResult1.ForeColor = "Red"
            $Form1.Controls.Add($labelResult1)
        } else {
            $Form1.Controls.Remove($labelResult0)
            $Form1.Controls.Remove($labelResult1)
            $Form1.Controls.Remove($progressBar)
            $Form1.Update()
            $labelResult1.Text = "Cannot change computer name from $CurrentName to $NewMachineName because it is not a valid computer name." 
            $labelResult1.ForeColor = "Red"
            $Form1.Controls.Add($labelResult1)
        }
    })

    # Create Cancel button
    $cancelButton = New-Object System.Windows.Forms.Button
    $cancelButton.Location = New-Object System.Drawing.Point(110,100)
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
}
