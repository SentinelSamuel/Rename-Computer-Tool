# By Samuel PAGES 
# Done : June 27th 2024

if(!(Test-Path "C:\old_computername.txt")) {

	function Test-ValidMachineName {
		param (
			[string]$MachineName
		)

		# Define the regex pattern for a valid machine name
		$machineNameRegex = "^[a-zA-Z0-9-]+$"

		# Check if the input string matches the regex pattern and is 15 characters or less
		if ($MachineName -match $machineNameRegex -and $MachineName.Length -le 15) {
			return $true
		} else {
			return $false
		}
	}

    # Function to update DNS entries for a new computer name based on current IP address
    function Update-DnsForNewComputerName {
        param (
            [string]$NewComputerName
        )

        try {
            # Retrieve current IP address
            $newIp = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "Ethernet").IPAddress

            # Get the domain name from Active Directory configuration
            $domain = (Get-ADDomain).DNSRoot

            # Construct the DNS zone names
            $forwardZoneName = $domain
            $reverseZoneName = "$($domain -replace '\.', '.').in-addr.arpa"

            # Get DNS entries matching the current IP address in forward lookup zone
            $currentForwardEntries = Get-DnsServerResourceRecord -ZoneName $forwardZoneName -ErrorAction SilentlyContinue |
                                     Where-Object { $_.RecordType -eq "A" -and $_.RecordData.IPv4Address -eq $newIp }

            if ($currentForwardEntries) {
                foreach ($entry in $currentForwardEntries) {
                    # Remove DNS entry matching the current IP address from forward lookup zone
                    Remove-DnsServerResourceRecord -ZoneName $forwardZoneName -InputObject $entry -Force
                    Write-Host "Removed DNS entry for IP $($entry.RecordData.IPv4Address): $($entry.Name)"
                }
            } else {
                Write-Host "No existing DNS entries found for IP $newIp in forward lookup zone $forwardZoneName."
            }

            # Get DNS entries matching the current IP address in reverse lookup zone
            $currentReverseEntries = Get-DnsServerResourceRecord -ZoneName $reverseZoneName -ErrorAction SilentlyContinue |
                                     Where-Object { $_.RecordType -eq "PTR" -and $_.RecordData.IPv4Address -eq $newIp }

            if ($currentReverseEntries) {
                foreach ($entry in $currentReverseEntries) {
                    # Remove DNS entry matching the current IP address from reverse lookup zone
                    Remove-DnsServerResourceRecord -ZoneName $reverseZoneName -InputObject $entry -Force
                    Write-Host "Removed DNS PTR entry for IP $($entry.RecordData.IPv4Address): $($entry.Name)"
                }
            } else {
                Write-Host "No existing DNS PTR entries found for IP $newIp in reverse lookup zone $reverseZoneName."
            }

            # Add new DNS entry for the new computer name in forward lookup zone
            Add-DnsServerResourceRecordA -ZoneName $forwardZoneName -Name $NewComputerName -IPv4Address $newIp -ErrorAction Stop
            Write-Host "Added new DNS entry: $NewComputerName with IP $newIp"

            # Add new PTR DNS entry for the new computer name in reverse lookup zone
            $ptrName = "$newIp.Split('.')[3].in-addr.arpa"
            Add-DnsServerResourceRecordPtr -ZoneName $reverseZoneName -Name $ptrName -PtrDomainName $NewComputerName -ErrorAction Stop
            Write-Host "Added new PTR DNS entry: $ptrName for $NewComputerName"

        }
        catch {
            Write-Error "Failed to update DNS entries. $_"
        }
    }

    
    function Remove-DnsEntries {
        param (
            [string]$ComputerName
        )
        try {
            # Construct the DNS zone name based on the domain name
            $domain = (Get-ADDomain).DNSRoot
            $forwardZoneName = $domain

            # Get current IP address
            $newIp = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -like "10.*" }).IPAddress

            if (-not $newIp) {
                Write-Warning "No interface found with an IP address starting with '10.'."
                return
            }

            # Get all A records from the current zone that match the IP address and computer name
            $recordsToRemove = Get-DnsServerResourceRecord -ZoneName $forwardZoneName -RRType A | Where-Object { $_.RecordData.IPv4Address -eq $newIp -and $_.HostName -eq $ComputerName }

            if ($recordsToRemove) {
                foreach ($record in $recordsToRemove) {
                    Remove-DnsServerResourceRecord -ZoneName $forwardZoneName -InputObject $record -Force
                    Write-Host "Removed DNS entry from forward lookup zone '$forwardZoneName': $($record.HostName) with IP $($record.RecordData.IPv4Address)"
                }
            } else {
                Write-Host "No DNS entry found in forward lookup zone '$forwardZoneName' for IP address $newIp and computer name $ComputerName."
            }
        }
        catch {
            Write-Error "Failed to remove DNS entries. $_"
        }
    }

    function Rename-SPNs {
        param (
            [Parameter(Mandatory=$true)]
            [string]$NewComputerName
        )

        # Get current computer name
        $CurrentComputerName = $env:COMPUTERNAME

        try {
            # Retrieve all SPNs associated with the current computer
            $spns = Get-ADComputer $CurrentComputerName -Properties servicePrincipalName | Select-Object -ExpandProperty servicePrincipalName

            if ($spns -eq $null) {
                Write-Warning "No SPNs found for computer '$CurrentComputerName'."
                return
            }

            foreach ($spn in $spns) {
                # Construct new SPN with the updated computer name
                $newSpn = $spn -replace "$CurrentComputerName", "$NewComputerName"

                # Update the SPN
                if ($spn -ne $newSpn) {
                    Set-ADComputer $CurrentComputerName -Remove @{servicePrincipalName=$spn}
                    Set-ADComputer $CurrentComputerName -Add @{servicePrincipalName=$newSpn}
                    Write-Output "Renamed SPN from '$spn' to '$newSpn'."
                }
            }

            Write-Output "All SPNs renamed successfully."
        }
        catch {
            Write-Error "Failed to rename SPNs. $_"
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
    $Form1.Icon = New-Object System.Drawing.Icon "$PSScriptRoot\S1_Logo_Shield_RGB_PURP.ico"

    # Create label
    $labelPrompt = New-Object System.Windows.Forms.Label
    $labelPrompt.Text = "To make this Environment useable by all the SEs, you must change the machine name. Please enter the computer name right here :"
    $labelPrompt.Size = New-Object System.Drawing.Size(250,40)
    $labelPrompt.AutoSize = $false
    $labelPrompt.Location = New-Object System.Drawing.Point(20,25)

    # Create textbox
    $textbox = New-Object System.Windows.Forms.TextBox
    $textbox.Location = New-Object System.Drawing.Point(20,70)
    $textbox.Size = New-Object System.Drawing.Size(250,20)

    # Add picture
    $imagePath = "$PSScriptRoot\S1_Logo_Shield_RGB_PURP.png"
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
    $labelResult1.Size = New-Object System.Drawing.Size(500,50)
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

            # Update new DNS computer Name 
            Update-DnsForNewComputerName -NewComputerName $NewMachineName
            $progressBar.Value = 25
            # Rename Spns with the computer name
            Rename-SPNs -NewComputerName $NewMachineName
            $progressBar.Value = 50
            # Remove old DNS Entries
            Remove-DnsEntries -ComputerName $CurrentName
            $progressBar.Value = 75
            # Restart the computer
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
            $labelResult1.Text = "Cannot change computer name from $CurrentName to $NewMachineName because it is not a valid computer name (no more than 15 caracters)." 
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
