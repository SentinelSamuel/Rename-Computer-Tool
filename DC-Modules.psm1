# Validate the new Machine Name
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
        $currentForwardEntries = Get-DnsServerResourceRecord -ZoneName $forwardZoneName -ErrorAction SilentlyContinue `
        | Where-Object { $_.RecordType -eq "A" -and $_.RecordData.IPv4Address -eq $newIp }

        if ($currentForwardEntries) {
            foreach ($entry in $currentForwardEntries) {
                # Remove DNS entry matching the current IP address from forward lookup zone
                Remove-DnsServerResourceRecord -ZoneName $forwardZoneName -InputObject $entry -Force
                Write-Host "[i] Removed DNS entry for IP $($entry.RecordData.IPv4Address): $($entry.Name)" -ForegroundColor Blue
            }
        } else {
            Write-Host "[i] No existing DNS entries found for IP $newIp in forward lookup zone $forwardZoneName." -ForegroundColor Blue
        }

        # Get DNS entries matching the current IP address in reverse lookup zone
        $currentReverseEntries = Get-DnsServerResourceRecord -ZoneName $reverseZoneName -ErrorAction SilentlyContinue `
        | Where-Object { $_.RecordType -eq "PTR" -and $_.RecordData.IPv4Address -eq $newIp }

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
        Write-Host "[+] Added new DNS entry: $NewComputerName with IP $newIp" -ForegroundColor Green

        # Add new PTR DNS entry for the new computer name in reverse lookup zone
        $ptrName = "$newIp.Split('.')[3].in-addr.arpa"
        Add-DnsServerResourceRecordPtr -ZoneName $reverseZoneName -Name $ptrName -PtrDomainName $NewComputerName -ErrorAction Stop
        Write-Host "[+] Added new PTR DNS entry: $ptrName for $NewComputerName" -ForegroundColor Green

    }
    catch {
        Write-Error "Failed to update DNS entries. $_"
    }
}

# Removes DNS Entries of the DC
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
                Write-Host "[i] Removed DNS entry from forward lookup zone '$forwardZoneName': $($record.HostName) with IP $($record.RecordData.IPv4Address)" -ForegroundColor Blue
            }
        } else {
            Write-Host "[i] No DNS entry found in forward lookup zone '$forwardZoneName' for IP address $newIp and computer name $ComputerName." -ForegroundColor Blue
        }
    }
    catch {
        Write-Error "Failed to remove DNS entries. $_"
    }
}

# Remove Certificates using computer name to filter
function Remove-CertificatesByComputerName {
    param (
        [Parameter(Mandatory = $true)]
        [string]$ComputerName
    )

    # Define all possible certificate store locations
    $certStores = @(
        "Cert:\LocalMachine\My",
        "Cert:\LocalMachine\CA",
        "Cert:\LocalMachine\TrustedPeople",
        "Cert:\LocalMachine\TrustedPublisher",
        "Cert:\LocalMachine\Root",
        "Cert:\CurrentUser\My",
        "Cert:\CurrentUser\CA",
        "Cert:\CurrentUser\TrustedPeople",
        "Cert:\CurrentUser\TrustedPublisher",
        "Cert:\CurrentUser\Root"
    )

    try {
        $deletedCertsCount = 0

        # Loop through each certificate store
        foreach ($certStore in $certStores) {
            # Get certificates from the current store
            $certificates = Get-ChildItem -Path $certStore -ErrorAction SilentlyContinue

            if ($certificates -ne $null) {
                foreach ($cert in $certificates) {
                    # Check if the certificate subject, issuer, or name contains the computer name
                    if ($cert.Subject -like "*$ComputerName*" -or $cert.Issuer -like "*$ComputerName*" -or $cert.FriendlyName -like "*$ComputerName*") {
                        Write-Host "Removing certificate from '$certStore': Subject = $($cert.Subject), Issuer = $($cert.Issuer), Thumbprint = $($cert.Thumbprint)" -ForegroundColor Yellow
                        
                        # Remove the certificate
                        Remove-Item -Path "$certStore\$($cert.Thumbprint)" -Force
                        $deletedCertsCount++
                    }
                }
            } else {
                Write-Host "No certificates found in store '$certStore'." -ForegroundColor Blue
            }
        }

        # Provide feedback
        if ($deletedCertsCount -gt 0) {
            Write-Host "[+] $deletedCertsCount certificate(s) containing '$ComputerName' were removed." -ForegroundColor Green
        } else {
            Write-Host "[i] No certificates containing '$ComputerName' were found in any store." -ForegroundColor Blue
        }

    } catch {
        Write-Error "An error occurred while attempting to remove certificates. $_"
    }
}
# Configure WinRM over HTTPS by creating a certificate
function Edit-WinRMHttps {
    param (
        [Parameter(Mandatory=$true, HelpMessage="Enter the DNS name for the certificate.")]
        [string]$DnsName,

        [Parameter(Mandatory=$false, HelpMessage="Specify the export path for the certificate. Default is C:\Temp.")]
        [string]$ExportPath = "C:\Temp",

        [Parameter(Mandatory=$false, HelpMessage="Specify the path to save the password. Default is C:\WinRMHTTPS_passwd.txt.")]
        [string]$PasswordFilePath = "C:\WinRMHTTPS_passwd.txt"
    )
    # Function to generate a random password
    function Get-RandomPassword {
        param (
            [int]$length = 20
        )
        # Define characters for the password
        $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-='
        # Generate password
        $password = -join ((1..$length) | ForEach-Object { $characters | Get-Random })
        return $password
    }
    # Verify if a certificate with the given DNS name already exists
    $existingCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*$DnsName*" }
    if ($existingCert) {
        Write-Host "[-] A certificate with DNS name '$DnsName' already exists. Please remove it or choose a different DNS name." -ForegroundColor Red
        return
    }
    # Check if the DNS name is valid
    if (-not $DnsName -or $DnsName.Length -gt 255 -or $DnsName -match '[^\w.-]') {
        Write-Host "[-] The DNS name provided is invalid. It must not be empty, should be less than 256 characters, and should not contain special characters." -ForegroundColor Red
        return
    }
    # Generate random password
    $randomPassword = Get-RandomPassword -length 20
    # Convert random password to SecureString
    $CertPassword = ConvertTo-SecureString -String $randomPassword -Force -AsPlainText
    # Save the generated password to a file (not as a SecureString, just plain text)
    $randomPassword | Out-File -FilePath $PasswordFilePath -Force
    Write-Host "[+] Random password generated and saved to: $PasswordFilePath" -ForegroundColor Yellow
    # Create a self-signed certificate
    try {
        $cert = New-SelfSignedCertificate -DnsName $DnsName -CertStoreLocation Cert:\LocalMachine\My -ErrorAction Stop
        $thumbprint = $cert.Thumbprint

        # Verify the certificate creation
        if ($cert) {
            Write-Host "[+] Certificate with DNS name '$DnsName' created successfully." -ForegroundColor Green
        } else {
            Write-Host "[-] Certificate creation failed." -ForegroundColor Red
            return
        }
    } catch {
        Write-Host "[-] Error creating certificate: $_" -ForegroundColor Red
        return
    }
    # Export the certificate
    $certPath = "Cert:\LocalMachine\My\$thumbprint"
    # Ensure the export directory exists
    if (-Not (Test-Path -Path $ExportPath)) {
        try {
            New-Item -Path $ExportPath -ItemType Directory -ErrorAction Stop
        } catch {
            Write-Host "[-] Failed to create export directory: $_" -ForegroundColor Red
            return
        }
    }
    # Check if the export path is writable
    if (-Not (Test-Path -Path $ExportPath -PathType Container) -or -Not (Test-Path -Path $ExportPath -PathType Leaf)) {
        Write-Host "[-] The export path is not writable or does not exist." -ForegroundColor Red
        return
    }
    # Export the certificate to a .pfx file using the secure password
    try {
        Export-PfxCertificate -Cert $certPath -FilePath "$ExportPath\winrm.pfx" -Password $CertPassword -ErrorAction Stop
        Write-Host "[+] Certificate exported to: $ExportPath\winrm.pfx" -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to export the certificate: $_" -ForegroundColor Red
        return
    }
    # Check if the firewall rule already exists
    $firewallRuleName = "WinRM HTTPS"
    $existingRule = Get-NetFirewallRule -Name $firewallRuleName -ErrorAction SilentlyContinue
    if (-not $existingRule) {
        # Open the firewall port for WinRM HTTPS
        try {
            New-NetFirewallRule -Name $firewallRuleName -DisplayName "WinRM over HTTPS" -Enabled $true -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow -ErrorAction Stop
            Write-Host "[+] Firewall rule '$firewallRuleName' created successfully." -ForegroundColor Green
        } catch {
            Write-Host "[-] Failed to create firewall rule: $_" -ForegroundColor Red
            return
        }
    } else {
        Write-Host "[+] Firewall rule '$firewallRuleName' already exists." -ForegroundColor Yellow
    }
    # Configure the WinRM service
    winrm quickconfig -q
    # Create the WinRM listener
    try {
        winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname=`"$DnsName`";CertificateThumbprint=`"$thumbprint`"}"
    } catch {
        Write-Host "[-] Failed to create WinRM listener: $_" -ForegroundColor Red
        return
    }

    # Verify the WinRM listener configuration
    winrm enumerate winrm/config/listener
    Write-Host "[+] WinRM over HTTPS has been configured successfully." -ForegroundColor Green
}

# Rename SPNs if there is
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

# Enable LDAPS
function Enable-LDAPS {
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Enter the DNS name for the certificate.")]
        [string]$DnsName,

        [Parameter(Mandatory = $false, HelpMessage = "Specify the export path for the certificate. Default is C:\Temp.")]
        [string]$ExportPath = "C:\Temp",

        [Parameter(Mandatory = $false, HelpMessage = "Specify the path to save the password. Default is C:\LDAPS_CERT.txt.")]
        [string]$PasswordFilePath = "C:\LDAPS_CERT.txt",

        [Parameter(Mandatory = $false, HelpMessage = "Specify whether to disable LDAP (port 389). Default is false.")]
        [bool]$DisableLDAP = $false
    )

    # Function to generate a random password
    function Get-RandomPassword {
        param ([int]$length = 20)
        $characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-='
        $password = -join ((1..$length) | ForEach-Object { $characters | Get-Random })
        return $password
    }

    try {
        Write-Host "[+] Starting LDAPS configuration process..." -ForegroundColor Yellow

        # Check if a certificate with the same DNS name already exists
        $existingCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -match $DnsName }
        if ($existingCert) {
            Write-Host "[i] Certificate with DNS name $DnsName already exists. Skipping certificate creation." -ForegroundColor Blue
            $cert = $existingCert
        } else {
            # Generate a self-signed certificate for LDAPS
            Write-Host "[+] Creating a self-signed certificate for $DnsName..." -ForegroundColor Yellow
            $cert = New-SelfSignedCertificate -DnsName $DnsName -CertStoreLocation Cert:\LocalMachine\My -KeySpec KeyExchange

            # Export the certificate if needed
            $thumbprint = $cert.Thumbprint
            $certPath = "Cert:\LocalMachine\My\$thumbprint"
            $randomPassword = Get-RandomPassword -length 20
            $CertPassword = ConvertTo-SecureString -String $randomPassword -Force -AsPlainText

            # Ensure the export directory exists
            if (-Not (Test-Path -Path $ExportPath)) {
                New-Item -Path $ExportPath -ItemType Directory
            }

            # Export the certificate to a .pfx file using the secure password
            Export-PfxCertificate -Cert $certPath -FilePath "$ExportPath\ldaps.pfx" -Password $CertPassword
            Write-Host "[+] Certificate exported to: $ExportPath\ldaps.pfx" -ForegroundColor Green

            # Save the generated password to a file
            $randomPassword | Out-File -FilePath $PasswordFilePath -Force
            Write-Host "[+] Password saved to: $PasswordFilePath" -ForegroundColor Green
        }

        # Bind the certificate to LDAPS (port 636) if not already bound
        $bindingCheck = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "ldapsslport" -ErrorAction SilentlyContinue
        if ($bindingCheck) {
            Write-Host "[i] LDAPS is already bound to port 636. Skipping binding." -ForegroundColor Blue
        } else {
            Write-Host "[+] Binding the certificate to LDAPS (port 636)..." -ForegroundColor Yellow
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "ldapsslport" -Value 636 -PropertyType Dword -Force
            Write-Host "[+] Certificate bound to LDAPS (port 636)" -ForegroundColor Green
        }

        # Check if the firewall rule for LDAPS already exists
        $existingRule = Get-NetFirewallRule -DisplayName "LDAPS" -ErrorAction SilentlyContinue
        if ($existingRule) {
            Write-Host "[i] Firewall rule for LDAPS (port 636) already exists." -ForegroundColor Blue
        } else {
            # Open the firewall port for LDAPS
            Write-Host "[+] Opening firewall port for LDAPS (port 636)..." -ForegroundColor Yellow
            New-NetFirewallRule -Name "LDAPS Port 636" -DisplayName "LDAPS" -Enabled True -Direction Inbound -Protocol TCP -LocalPort 636 -Action Allow

            # Verify the firewall rule
            $firewallRule = Get-NetFirewallRule -DisplayName "LDAPS" -ErrorAction SilentlyContinue
            if ($firewallRule) {
                Write-Host "[+] Firewall rule created for LDAPS (port 636)" -ForegroundColor Green
            } else {
                Write-Error "[!] Failed to create firewall rule for LDAPS."
            }
        }

        # Optionally disable LDAP (port 389)
        if ($DisableLDAP) {
            $ldapPort = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "ldapport" -ErrorAction SilentlyContinue
            if ($ldapPort -and $ldapPort.ldapport -eq 0) {
                Write-Host "[i] LDAP (port 389) is already disabled." -ForegroundColor Blue
            } else {
                Write-Host "[+] Disabling regular LDAP (port 389)..." -ForegroundColor Yellow
                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "ldapport" -Value 0 -PropertyType Dword -Force
                Write-Host "[+] Regular LDAP (port 389) has been disabled." -ForegroundColor Green
            }
        }

        Write-Host "[+] LDAPS configuration completed successfully." -ForegroundColor Green
    }
    catch {
        Write-Error "An error occurred: $_"
    }
}
