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
        # Retrieve the first active network interface with an IPv4 address (excluding loopback)
        $newIp = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch "Loopback" -and $_.IPAddress }).IPAddress
        
        if (-not $newIp) {
            Write-Error "No active IPv4 address found. Cannot update DNS."
            return
        }

        # Get the domain name from Active Directory configuration
        $domain = (Get-ADDomain).DNSRoot

        # Construct the DNS zone names
        $forwardZoneName = $domain
        $reverseZoneName = "$($domain -replace '\.', '.').in-addr.arpa"

        # Get DNS entries matching the current IP address in the forward lookup zone
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

        # Get DNS entries matching the current IP address in the reverse lookup zone
        $currentReverseEntries = Get-DnsServerResourceRecord -ZoneName $reverseZoneName -ErrorAction SilentlyContinue `
        | Where-Object { $_.RecordType -eq "PTR" -and $_.RecordData.IPv4Address -eq $newIp }

        if ($currentReverseEntries) {
            foreach ($entry in $currentReverseEntries) {
                # Remove DNS entry matching the current IP address from reverse lookup zone
                Remove-DnsServerResourceRecord -ZoneName $reverseZoneName -InputObject $entry -Force
                Write-Host "[i] Removed DNS PTR entry for IP $($entry.RecordData.IPv4Address): $($entry.Name)" -ForegroundColor Blue
            }
        } else {
            Write-Host "[i] No existing DNS PTR entries found for IP $newIp in reverse lookup zone $reverseZoneName." -ForegroundColor Blue
        }

        # Add new DNS entry for the new computer name in the forward lookup zone
        Add-DnsServerResourceRecordA -ZoneName $forwardZoneName -Name $NewComputerName -IPv4Address $newIp -ErrorAction Stop
        Write-Host "[+] Added new DNS entry: $NewComputerName with IP $newIp" -ForegroundColor Green

        # Add new PTR DNS entry for the new computer name in reverse lookup zone
        $ptrName = "$($newIp.Split('.')[3]).in-addr.arpa"
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

# Configure WinRM over HTTPS by creating a certificate
function Edit-WinRMHttps {
    param (
        [Parameter(Mandatory=$true, HelpMessage="Enter the DNS name for the certificate.")]
        [string]$DnsName,

        [Parameter(Mandatory=$false, HelpMessage="Specify the export path for the certificate.")]
        [string]$ExportPath,

        [Parameter(Mandatory=$false, HelpMessage="Specify the path to save the password. Default is .\WinRMHTTPS_passwd.txt.")]
        [string]$PasswordFilePath = "$PSScriptRoot\WinRMHTTPS_passwd.txt"
    )

    # Ensure the export path is provided
    if (-not $ExportPath) {
        Write-Host "[-] You must specify an export path for the certificate." -ForegroundColor Red
        return
    }

    # Check if a certificate with the given DNS name already exists if it is, remove it
    if (Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -like "*$DnsName*" }) {
        Remove-Item $_
    }

    # Function to generate a random password
    function Get-RandomPassword {
        param (
            [Parameter(Mandatory)]
            [int] $length
        )
        
        $charSet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.ToCharArray()
        
        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $bytes = New-Object byte[]($length)
        
        $rng.GetBytes($bytes)
        
        $result = New-Object char[]($length)
        
        for ($i = 0 ; $i -lt $length ; $i++) {
            $result[$i] = $charSet[$bytes[$i]%$charSet.Length]
        }
        
        return -join $result
    }

    # Generate a random password for the certificate
    $randomPassword = Get-RandomPassword -length 20
    # Convert random password to SecureString
    $CertPassword = ConvertTo-SecureString -String $randomPassword -Force -AsPlainText
    # Save the generated password to a file
    $randomPassword | Out-File -FilePath $PasswordFilePath -Force
    Write-Host "[+] Password saved to : $PasswordFilePath" -ForegroundColor Green

    # Generate a self-signed certificate
    try {
        $cert = New-SelfSignedCertificate -DnsName $DnsName -CertStoreLocation Cert:\LocalMachine\My -ErrorAction Stop
        Write-Host "[+] Certificate with DNS name '$DnsName' created successfully." -ForegroundColor Green
    } catch {
        Write-Host "[-] Error creating certificate: $_" -ForegroundColor Red
        return
    }

    # Export the certificate to a .pfx file
    try {
        Export-PfxCertificate -Cert $cert -FilePath "$ExportPath\winrm.pfx" -Password $CertPassword -ErrorAction Stop
        Write-Host "[+] Certificate exported to: $ExportPath\winrm.pfx" -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to export the certificate: $_ ($ExportPath\winrm.pfx)" -ForegroundColor Red
        return
    }

    # Disable WinRM over HTTP if it exists
    try {
        $httpListener = winrm enumerate winrm/config/listener | Where-Object { $_ -like "*Transport=HTTP*" }
        if ($httpListener) {
            winrm delete winrm/config/Listener?Address=*+Transport=HTTP
            Write-Host "[+] WinRM over HTTP has been disabled." -ForegroundColor Green
        } else {
            Write-Host "[i] No existing WinRM HTTP listener found, nothing to disable." -ForegroundColor Blue
        }
    } catch {
        Write-Host "[-] Failed to disable WinRM over HTTP: $_" -ForegroundColor Red
        return
    }

    # Create or update the firewall rule for WinRM HTTPS
    $firewallRuleName = "WinRM HTTPS"
    $existingRule = Get-NetFirewallRule -Name $firewallRuleName -ErrorAction SilentlyContinue

    if ($existingRule) {
        try {
            Remove-NetFirewallRule -Name $firewallRuleName -ErrorAction Stop
            Write-Host "[+] Existing firewall rule '$firewallRuleName' removed." -ForegroundColor Green
        } catch {
            Write-Host "[-] Failed to remove existing firewall rule: $_" -ForegroundColor Red
            return
        }
    }

    try {
        # Create the firewall rule without specifying `-Enabled`
        $firewallRule = New-NetFirewallRule -Name $firewallRuleName -DisplayName "WinRM over HTTPS" -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow -ErrorAction Stop
    
        # Explicitly set the Enabled status afterwards
        Set-NetFirewallRule -Name $firewallRuleName -Enabled "True" -ErrorAction Stop

        Write-Host "[+] Firewall rule '$firewallRuleName' created and enabled successfully." -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to create or enable the firewall rule: $_" -ForegroundColor Red
        return
    }


    # Configure the WinRM service
    try {
        winrm quickconfig -q
        Write-Host "[+] WinRM service configured." -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to configure WinRM service: $_" -ForegroundColor Red
        return
    }

    # Create the WinRM listener
    try {
        winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname=`"$DnsName`";CertificateThumbprint=`"$($cert.Thumbprint)`"}"
        Write-Host "[+] WinRM HTTPS listener created successfully." -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to create WinRM listener: $_" -ForegroundColor Red
        return
    }

    # Verify the WinRM listener configuration
    winrm enumerate winrm/config/listener
    Write-Host "[+] WinRM over HTTPS has been configured successfully." -ForegroundColor Green
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

        [Parameter(Mandatory = $false, HelpMessage = "Specify the export path for the certificate. Default is '.\'")]
        [string]$ExportPath,

        [Parameter(Mandatory = $false, HelpMessage = "Specify the path to save the password. Default is .\LDAPS_CERT.txt.")]
        [string]$PasswordFilePath = "$PSScriptRoot\LDAPS_CERT.txt",

        [Parameter(Mandatory = $false, HelpMessage = "Specify whether to disable LDAP (port 389). Default is false.")]
        [bool]$DisableLDAP = $false
    )

    # Function to generate a random password
    function Get-RandomPassword {
        param (
            [Parameter(Mandatory)]
            [int] $length
        )
        
        $charSet = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'.ToCharArray()
        
        $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
        $bytes = New-Object byte[]($length)
        
        $rng.GetBytes($bytes)
        
        $result = New-Object char[]($length)
        
        for ($i = 0 ; $i -lt $length ; $i++) {
            $result[$i] = $charSet[$bytes[$i]%$charSet.Length]
        }
        
        return -join $result
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
            # Disable the LDAP TCP and UDP firewall rules
            $ldapTcpRule = Get-NetFirewallRule -DisplayName "Active Directory Domain Controller - LDAP (TCP-In)" -ErrorAction SilentlyContinue
            $ldapUdpRule = Get-NetFirewallRule -DisplayName "Active Directory Domain Controller - LDAP (UDP-In)" -ErrorAction SilentlyContinue
            
            if ($ldapTcpRule -and $ldapTcpRule.Enabled) {
                Disable-NetFirewallRule -Name $ldapTcpRule.Name
                Write-Host "[+] Disabled LDAP (TCP port 389) firewall rule." -ForegroundColor Green
            } else {
                Write-Host "[i] LDAP (TCP port 389) firewall rule is already disabled." -ForegroundColor Blue
            }

            if ($ldapUdpRule -and $ldapUdpRule.Enabled) {
                Disable-NetFirewallRule -Name $ldapUdpRule.Name
                Write-Host "[+] Disabled LDAP (UDP port 389) firewall rule." -ForegroundColor Green
            } else {
                Write-Host "[i] LDAP (UDP port 389) firewall rule is already disabled." -ForegroundColor Blue
            }

            # Disable regular LDAP (port 389) in NTDS settings
            $ldapPort = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "ldapport" -ErrorAction SilentlyContinue
            if ($ldapPort -and $ldapPort.ldapport -eq 0) {
                Write-Host "[i] LDAP (port 389) is already disabled in NTDS settings." -ForegroundColor Blue
            } else {
                Write-Host "[+] Disabling regular LDAP (port 389) in NTDS settings..." -ForegroundColor Yellow
                New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "ldapport" -Value 0 -PropertyType Dword -Force
                Write-Host "[+] Regular LDAP (port 389) has been disabled in NTDS settings." -ForegroundColor Green
            }
        }

        Write-Host "[+] LDAPS configuration completed successfully." -ForegroundColor Green
    }
    catch {
        Write-Error "An error occurred: $_"
    }
}
