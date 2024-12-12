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
.SYNOPSIS
    Reset WinRM Configuration
#>
function Clear-WinRMConfiguration {
    # Attempt to remove all WinRM listeners
    try {
        # Enumerate all listeners and attempt to delete each one
        $listeners = (winrm enumerate winrm/config/listener)
        foreach ($listener in $listeners) {
            if ($listener -match 'Listener:Address=([^;]+);Transport=([^;]+)') {
                $address = $matches[1]
                $transport = $matches[2]
                $listenerUri = "winrm/config/Listener?Address=$address+Transport=$transport"
                Write-Host "Attempting to delete listener at URI: $listenerUri" -ForegroundColor Yellow
                winrm delete $listenerUri
            }
        }
        Write-Host "[+] All WinRM listeners have been deleted." -ForegroundColor Green
    } catch {
        Write-Host "[-] Error occurred while attempting to delete WinRM listeners: $_" -ForegroundColor Red
    }

    # Reset WinRM to its default configuration, which will remove any additional custom settings
    try {
        winrm invoke Restore winrm/config
        Write-Host "[+] WinRM configuration has been reset to its default state." -ForegroundColor Green
    } catch {
        Write-Host "[-] Failed to reset WinRM configuration: $_" -ForegroundColor Red
    }
}

<#
.SYNOPSIS
    Creates a self-signed certificate for WinRM over HTTPS, configures the HTTPS listener, and exports the certificate and password.
.DESCRIPTION
    This script generates a self-signed certificate for the provided DNS name, creates a WinRM HTTPS listener, and exports the certificate and password. And removes WinRM HTTP listeners
#>
function Enable-WinRMHTTPS {
    param (
        [Parameter(Mandatory=$true, HelpMessage="Enter the DNS name for the certificate.")]
        [string]$DnsName,

        [Parameter(Mandatory=$true, HelpMessage="Specify the export path for the certificate.")]
        [string]$ExportPath,

        [Parameter(Mandatory=$true, HelpMessage="Specify the filename for the exported certificate (without extension).")]
        [string]$CertFileName,

        [Parameter(Mandatory=$true, HelpMessage="Specify the path to save the password.")]
        [string]$PasswordFilePath
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
    # Generate a random password for the certificate
    $randomPassword = Get-RandomPassword -length 20
    $CertPassword = ConvertTo-SecureString -String $randomPassword -Force -AsPlainText

    # Save the generated password to a file
    $randomPassword | Out-File -FilePath $PasswordFilePath -Force
    if (Test-Path $PasswordFilePath) {
        Write-Host "[+] Password saved to: $PasswordFilePath" -ForegroundColor Green
    } else {
        Write-Host "[-] Failed to save Password to: $PasswordFilePath" -ForegroundColor Red
    }

    # Generate a self-signed certificate
    try {
        $cert = New-SelfSignedCertificate -DnsName $DnsName -CertStoreLocation Cert:\LocalMachine\My -KeyExportPolicy Exportable -NotAfter (Get-Date).AddYears(5)
        Write-Host "[+] Self-signed certificate created with DNS name: $DnsName" -ForegroundColor Green
    }
    catch {
        Write-Host "[-] Error creating certificate: $_" -ForegroundColor Red
        return
    }
    
    # Add the certificate to the Trusted Root Certification Authorities store
    try {
        $trustedRootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
        $trustedRootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $trustedRootStore.Add($cert)
        $trustedRootStore.Close()
        Write-Host "[+] Certificate added to Trusted Root Certification Authorities." -ForegroundColor Green
    }
    catch {
        Write-Host "[-] Error adding certificate to Trusted Root: $_" -ForegroundColor Red
    }

    # Export the certificate to a .pfx file
    $CertFilePath = Join-Path -Path $ExportPath -ChildPath "$CertFileName.pfx"
    try {
        Export-PfxCertificate -Cert $cert -FilePath $CertFilePath -Password $CertPassword
        Write-Host "[+] Certificate exported to: $CertFilePath" -ForegroundColor Green
    }
    catch {
        Write-Host "[-] Failed to export the certificate: $_" -ForegroundColor Red
        return
    }

    # Ensure WinRM service is configured
    try {
        winrm quickconfig -q
        Write-Host "[+] WinRM service configured." -ForegroundColor Green
    }
    catch {
        Write-Host "[-] Failed to configure WinRM service: $_" -ForegroundColor Red
        return
    }

    # Create the WinRM HTTPS listener
    try {
        winrm create winrm/config/Listener?Address=*+Transport=HTTPS "@{Hostname=`"$DnsName`";CertificateThumbprint=`"$($cert.Thumbprint)`"}"
        Write-Host "[+] WinRM HTTPS listener created with DNS name: $DnsName" -ForegroundColor Green
    }
    catch {
        Write-Host "[-] Failed to create WinRM HTTPS listener: $_" -ForegroundColor Red
    }
    # Check for existing firewall rule for WinRM HTTPS (port 5986), and add it if not present
    try {
        $firewallRule = (Get-NetFirewallRule | Where-Object {($_.LocalPorts -contains '5986')}) -or (Get-NetFirewallRule -DisplayName "WinRM HTTPS" -ErrorAction SilentlyContinue)
        if (-not $firewallRule) {
            New-NetFirewallRule -DisplayName "WinRM HTTPS" -Direction Inbound -Protocol TCP -LocalPort 5986 -Action Allow
            Write-Host "[+] Firewall rule for WinRM HTTPS created." -ForegroundColor Green
        } else {
            Write-Host "[i] Firewall rule for WinRM HTTPS already exists." -ForegroundColor Blue
        }
    }
    catch {
        Write-Host "[-] Error checking or creating firewall rule: $_" -ForegroundColor Red
    }
}

function Disable-WinRMHTTP {
    winrm delete winrm/config/Listener?Address=*+Transport=HTTP
    Write-Host "[+] WinRM Over HTTP Disabled" -ForegroundColor Green

    # Remove firewall rule for WinRM over HTTP if it exists
    try {
        $httpFirewallRule = Get-NetFirewallRule | Where-Object {($_.LocalPorts -contains '5985')}
        if ($httpFirewallRule) {
            Remove-NetFirewallRule -InputObject $httpFirewallRule
            Write-Host "[+] Firewall rule for WinRM over HTTP has been removed." -ForegroundColor Green
        } else {
            Write-Host "[i] No firewall rule for WinRM over HTTP found." -ForegroundColor Blue
        }
    } catch {
        Write-Host "[-] Error occurred while checking or removing firewall rule for WinRM over HTTP: $_" -ForegroundColor Red
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
        [string]$FilePath
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
        Write-Host "[i] Starting LDAPS configuration process..." -ForegroundColor Blue
        # Check for an existing certificate in the Personal store
        $existingCert = Get-ChildItem Cert:\LocalMachine\My | Where-Object { $_.Subject -match $DnsName }
        if ($existingCert) {
            Write-Host "[i] Certificate with DNS name $DnsName already exists in the Personal store. Removing existing certificate..." -ForegroundColor Blue
            Remove-Item -Path "Cert:\LocalMachine\My\$($existingCert.Thumbprint)" -Force
            Write-Host "[+] Existing certificate removed from Personal store." -ForegroundColor Green
        }

        # Check for an existing certificate in the Trusted Root store
        $trustedRootCert = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Subject -match $DnsName }
        if ($trustedRootCert) {
            Write-Host "[i] Certificate with DNS name $DnsName already exists in the Trusted Root store. Removing existing certificate..." -ForegroundColor Blue
            Remove-Item -Path "Cert:\LocalMachine\Root\$($trustedRootCert.Thumbprint)" -Force
            Write-Host "[+] Existing certificate removed from Trusted Root store." -ForegroundColor Green
        }
        # Generate a new self-signed certificate for LDAPS
        Write-Host "[i] Creating a self-signed certificate for $DnsName..." -ForegroundColor Blue
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

        # Add the certificate to the Trusted Root Certification Authorities store
        try {
            $trustedRootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "LocalMachine")
            $trustedRootStore.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
            $trustedRootStore.Add($cert)
            $trustedRootStore.Close()
            Write-Host "[+] Certificate added to Trusted Root Certification Authorities." -ForegroundColor Green
        }
        catch {
            Write-Host "[-] Error adding certificate to Trusted Root: $_" -ForegroundColor Red
        }

        # Define the file path for the exported certificate
        $exportFilePath = Join-Path -Path $ExportPath -ChildPath "ldaps.pfx"
        Export-PfxCertificate -Cert $certPath -FilePath $exportFilePath -Password $CertPassword
        # Verify if the certificate file exists
        if (Test-Path -Path $exportFilePath) {
            Write-Host "[+] Certificate file created successfully at $exportFilePath." -ForegroundColor Green
        } else {
            Write-Host "[-] Certificate file was not created successfully." -ForegroundColor Red
        }
        # Save the generated password to the specified file
        $randomPassword | Out-File -FilePath $FilePath -Force
        # Verify if the password file exists
        if (Test-Path -Path $FilePath) {
            Write-Host "[+] Password file created successfully at $FilePath." -ForegroundColor Green
        } else {
            Write-Host "[-] Password file was not created successfully." -ForegroundColor Red
        }
        # Bind the certificate to LDAPS (port 636) if not already bound
        $bindingCheck = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "ldapsslport" -ErrorAction SilentlyContinue
        if ($bindingCheck) {
            Write-Host "[i] LDAPS is already bound to port 636. Skipping binding." -ForegroundColor Blue
        } else {
            Write-Host "[i] Binding the certificate to LDAPS (port 636)..." -ForegroundColor Blue
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "ldapsslport" -Value 636 -PropertyType Dword -Force
            Write-Host "[+] Certificate bound to LDAPS (port 636)" -ForegroundColor Green
        }
        # Check if the firewall rule for LDAPS already exists
        $existingRule = Get-NetFirewallRule -DisplayName "LDAPS" -ErrorAction SilentlyContinue
        if ($existingRule) {
            Write-Host "[i] Firewall rule for LDAPS (port 636) already exists." -ForegroundColor Blue
        } else {
            # Open the firewall port for LDAPS
            Write-Host "[i] Opening firewall port for LDAPS (port 636)..." -ForegroundColor Blue
            New-NetFirewallRule -Name "LDAPS Port 636" -DisplayName "LDAPS" -Enabled True -Direction Inbound -Protocol TCP -LocalPort 636 -Action Allow
            # Verify the firewall rule
            $firewallRule = Get-NetFirewallRule -DisplayName "LDAPS" -ErrorAction SilentlyContinue
            if ($firewallRule) {
                Write-Host "[+] Firewall rule created for LDAPS (port 636)" -ForegroundColor Green
            } else {
                Write-Error "[-] Failed to create firewall rule for LDAPS."
            }
        }
        Write-Host "[+] LDAPS configuration completed successfully." -ForegroundColor Green
    }
    catch {
        Write-Error "[-] An error occurred: $_"
    }
}

# Disable LDAP
function Disable-LDAP {
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
            Write-Host "[i] Disabling regular LDAP (port 389) in NTDS settings..." -ForegroundColor Blue
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "ldapport" -Value 0 -PropertyType Dword -Force
            Write-Host "[+] Regular LDAP (port 389) has been disabled in NTDS settings." -ForegroundColor Green
        }
    }
}
