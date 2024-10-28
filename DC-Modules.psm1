<#
.DESCRIPTION
    Validate the new Machine Name
#>
function Test-ValidMachineName {
    param (
        [string]$MachineName
    )
    # Define the regex pattern for a valid machine name
    $machineNameRegex = "^[a-zA-Z0-9-]+$"
    
    # Get the current computer name (use [Environment]::MachineName or $env:COMPUTERNAME if Get-ComputerInfo is not available)
    $currentComputerName = (Get-ComputerInfo).CsName
    
    # Check if the input string matches the regex pattern, is 15 characters or less, and is different from the current computer name
    if ($MachineName -match $machineNameRegex -and $MachineName.Length -le 15 -and $MachineName -ne $currentComputerName) {
        return $true
    } else {
        return $false
    }
}

<#
.DESCRIPTION
    Function to Rename DNS entries for a new computer name based on current IP address 
#>
function Rename-DnsForNewComputerName {
    param (
        [string]$NewComputerName
    )
    try {
        # Retrieve the first active network interface with an IPv4 address (excluding loopback)
        $newIp = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch "Loopback" -and $_.IPAddress }).IPAddress
        
        if (-not $newIp) {
            Write-Host "[-] No active IPv4 address found. Cannot Rename DNS entries." -ForegroundColor Red
            return
        }
        # Get the domain name from Active Directory configuration
        $domain = (Get-ADDomain).DNSRoot
        # Construct the DNS zone names
        $forwardZoneName = $domain
        $reverseZoneName = "$($domain -replace '\.', '.').in-addr.arpa"
        # Get DNS entries matching the current IP address in the forward lookup zone
        $currentForwardEntries = Get-DnsServerResourceRecord -ZoneName $forwardZoneName -ErrorAction SilentlyContinue | Where-Object { $_.RecordType -eq "A" -and $_.RecordData.IPv4Address -eq $newIp }
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
        $currentReverseEntries = Get-DnsServerResourceRecord -ZoneName $reverseZoneName -ErrorAction SilentlyContinue | Where-Object { $_.RecordType -eq "PTR" -and $_.RecordData.IPv4Address -eq $newIp }
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
        Write-Host "[-] Failed to Rename DNS entries. $_" -ForegroundColor Red
    }
}

<#
.DESCRIPTION
    Removes DNS Entries of the DC
#>
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
        Write-Error "[-] Failed to remove DNS entries. $_"
    }
}

<#
.DESCRIPTION
    Rename the DFSR topology object in AD
#>
function Rename-DFSRTopology {
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Enter the current (old) computer name.")]
        [string]$OldComputerName,

        [Parameter(Mandatory = $true, HelpMessage = "Enter the new computer name.")]
        [string]$NewComputerName
    )
    try {
        # Import the Active Directory module
        Import-Module ActiveDirectory -ErrorAction Stop
        # Get the domain DN dynamically
        $domainDN = ([System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()).GetDirectoryEntry().DistinguishedName
        $dfsrDN = "CN=DFSR-GlobalSettings,CN=System,$domainDN"
        Write-Host "[+] Using DFSR path: $dfsrDN" -ForegroundColor Yellow
        # Find the DFSR computer object with the old name in the topology
        $oldDFSRObject = Get-ADObject -Filter { Name -eq $OldComputerName } -SearchBase $dfsrDN -ErrorAction Stop
        if ($oldDFSRObject) {
            # Rename the DFSR object with the new name
            Rename-ADObject -Identity $oldDFSRObject -NewName $NewComputerName -ErrorAction Stop
            Write-Host "[+] DFSR topology object renamed from '$OldComputerName' to '$NewComputerName' successfully." -ForegroundColor Green
        } else {
            Write-Host "[-] DFSR topology object with name '$OldComputerName' was not found." -ForegroundColor Red
        }
    }
    catch {
        Write-Error "[-] An error occurred: $_"
    }
}

<#
.DESCRIPTION
    Configure WinRM over HTTPS by creating a certificate & Disable WinRM over HTTP
#>
function Edit-WinRMHttps {
    param (
        [Parameter(Mandatory=$true, HelpMessage="Enter the DNS name for the certificate.")]
        [string]$DnsName,

        [Parameter(Mandatory=$false, HelpMessage="Specify the export path for the certificate.")]
        [string]$ExportPath,

        [Parameter(Mandatory=$false, HelpMessage="Specify the path to save the password. Default is .\WinRMHTTPS_passwd.txt.")]
        [string]$FilePath = "$PSScriptRoot\WinRMHTTPS_passwd.txt"
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
    $randomPassword | Out-File -FilePath $FilePath -Force
    Write-Host "[+] Password saved to : $FilePath" -ForegroundColor Green
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
    # Forcefully disable WinRM over HTTP if it exists
    $maxRetries = 3
    $retryCount = 0
    while ($retryCount -lt $maxRetries) {
        try {
            # Attempt to delete the HTTP listener
            winrm delete winrm/config/Listener?Address=*+Transport=HTTP
            Write-Host "[+] Attempted to disable WinRM over HTTP." -ForegroundColor Green
            # Verify HTTP listener is gone
            $httpListenerExists = winrm enumerate winrm/config/listener | Where-Object { $_ -like "*Transport=HTTP*" }
            if (-not $httpListenerExists) {
                Write-Host "[+] WinRM HTTP listener successfully disabled." -ForegroundColor Green
                break
            } else {
                Write-Host "[!] HTTP listener still present. Retrying..." -ForegroundColor Yellow
            }
        } catch {
            Write-Host "[-] Error disabling WinRM HTTP listener: $_" -ForegroundColor Red
        }
        $retryCount++
        Start-Sleep -Seconds 2
    }
    # Check if the HTTP listener still exists after retries
    if ($httpListenerExists) {
        Write-Host "[-] HTTP listener could not be disabled after multiple attempts. Manual intervention may be required." -ForegroundColor Red
    } else {
        Write-Host "[+] Confirmed: WinRM is configured for HTTPS only." -ForegroundColor Green
    }
}

<#
.DESCRIPTION
    Remove Certificates using computer name to filter
#>
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
        Write-Error " [-] An error occurred while attempting to remove certificates. $_"
    }
}

<#
.DESCRIPTION
    Rename SPNs if there is
#>
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
        Write-Error "[-] Failed to rename SPNs. $_"
    }
}

<#
.DESCRIPTION
    Enable LDAPS & is able to disable LDAP
#>
function Enable-LDAPS {
    param (
        [Parameter(Mandatory = $true, HelpMessage = "Enter the DNS name for the certificate.")]
        [string]$DnsName,

        [Parameter(Mandatory = $true, HelpMessage = "Specify the export path for the certificate.")]
        [string]$ExportPath,

        [Parameter(Mandatory = $true, HelpMessage = "Specify the path to save the password.")]
        [string]$FilePath,

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
            Write-Host "[i] Certificate with DNS name $DnsName already exists. Removing existing certificate..." -ForegroundColor Blue
            Remove-Item -Path "Cert:\LocalMachine\My\$($existingCert.Thumbprint)" -Force
            Write-Host "[+] Existing certificate removed." -ForegroundColor Green
        }
        # Generate a new self-signed certificate for LDAPS
        Write-Host "[+] Creating a self-signed certificate for $DnsName..." -ForegroundColor Yellow
        $cert = New-SelfSignedCertificate -DnsName $DnsName -CertStoreLocation Cert:\LocalMachine\My -KeySpec KeyExchange
        # Export the certificate to a .pfx file using a secure password
        $thumbprint = $cert.Thumbprint
        $certPath = "Cert:\LocalMachine\My\$thumbprint"
        $randomPassword = Get-RandomPassword -length 20
        $CertPassword = ConvertTo-SecureString -String $randomPassword -Force -AsPlainText
        # Ensure the export directory exists
        if (-Not (Test-Path -Path $ExportPath)) {
            New-Item -Path $ExportPath -ItemType Directory | Out-Null
        }
        # Define the file path for the exported certificate
        $exportFilePath = Join-Path -Path $ExportPath -ChildPath "ldaps.pfx"
        Export-PfxCertificate -Cert $certPath -FilePath $exportFilePath -Password $CertPassword
        Write-Host "[+] Certificate exported to: $exportFilePath" -ForegroundColor Green
        # Verify if the certificate file exists
        if (Test-Path -Path $exportFilePath) {
            Write-Host "[+] Certificate file created successfully at $exportFilePath." -ForegroundColor Green
        } else {
            Write-Host "[-] Certificate file was not created successfully." -ForegroundColor Red
            return
        }
        # Save the generated password to the specified file
        $randomPassword | Out-File -FilePath $FilePath -Force
        Write-Host "[+] Password saved to: $FilePath" -ForegroundColor Green
        # Verify if the password file exists
        if (Test-Path -Path $FilePath) {
            Write-Host "[+] Password file created successfully at $FilePath." -ForegroundColor Green
        } else {
            Write-Host "[-] Password file was not created successfully." -ForegroundColor Red
            return
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
                Write-Error "[-] Failed to create firewall rule for LDAPS."
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
        Write-Error "[-] An error occurred: $_"
    }
}
