Start-Sleep -Seconds 60

Invoke-Command -computername dc -Credential (new-object pscredential("windomain\vagrant",(ConvertTo-SecureString -AsPlainText -Force -String "vagrant"))) -ScriptBlock {

    Write-Host "$('[{0:HH:mm}]' -f (Get-Date)) [$env:computername] Installing the ATA Lightweight gateway on DC..."

    # Enable web requests to endpoints with invalid SSL certs (like self-signed certs)
    if (-not("SSLValidator" -as [type])) {
        add-type -TypeDefinition @"
    using System;
    using System.Net;
    using System.Net.Security;
    using System.Security.Cryptography.X509Certificates;

    public static class SSLValidator {
        public static bool ReturnTrue(object sender,
            X509Certificate certificate,
            X509Chain chain,
            SslPolicyErrors sslPolicyErrors) { return true; }

        public static RemoteCertificateValidationCallback GetDelegate() {
            return new RemoteCertificateValidationCallback(SSLValidator.ReturnTrue);
        }
    }
"@
    }
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = [SSLValidator]::GetDelegate()

    If (-not (Test-Path "$env:temp\gatewaysetup.zip"))
    {
        Write-Host "[$env:computername] ATA Gateway not yet downloaded. Downloading now..."
        Invoke-WebRequest -uri https://wef/api/management/softwareUpdates/gateways/deploymentPackage -UseBasicParsing -OutFile "$env:temp\gatewaysetup.zip" -Credential (new-object pscredential("wef\vagrant",(convertto-securestring -AsPlainText -Force -String "vagrant")))
        Expand-Archive -Path "$env:temp\gatewaysetup.zip" -DestinationPath "$env:temp\gatewaysetup" -Force
    }
    else
    {
        Write-Host "[$env:computername] Gateway setup already downloaded. Moving On."
    }
    if (-not (Test-Path "C:\Program Files\Microsoft Advanced Threat Analytics"))
    {
        Write-Host "[$env:computername] ATA Gateway not yet installed. Attempting to install now..."
        Set-Location "$env:temp\gatewaysetup"
        Start-Process -Wait -FilePath ".\Microsoft ATA Gateway Setup.exe" -ArgumentList "/q NetFrameworkCommandLineArguments=`"/q`" ConsoleAccountName=`"wef\vagrant`" ConsoleAccountPassword=`"vagrant`""
        Write-Host "[$env:computername] ATA Gateway installation complete!"
    }
    else
    {
        Write-Host "[$env:computername] ATA Gateway already installed. Moving On."
    }
    Write-Host "[$env:computername] Waiting for the ATA Gateway service to start..."
    (Get-Service ATAGateway).WaitForStatus('Running', '00:10:00')
    If ((Get-Service "ATAGateway").Status -ne "Running")
    {
        throw "ATA Gateway service failed to start on DC"
    }
    # Disable invalid web requests to endpoints with invalid SSL certs again
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
}

# Enable web requests to endpoints with invalid SSL certs (like self-signed certs)
if (-not("SSLValidator" -as [type])) {
    add-type -TypeDefinition @"
using System;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

public static class SSLValidator {
    public static bool ReturnTrue(object sender,
        X509Certificate certificate,
        X509Chain chain,
        SslPolicyErrors sslPolicyErrors) { return true; }

    public static RemoteCertificateValidationCallback GetDelegate() {
        return new RemoteCertificateValidationCallback(SSLValidator.ReturnTrue);
    }
}
"@
}
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = [SSLValidator]::GetDelegate()

# set DC as domain synchronizer
$config = Invoke-RestMethod -Uri "https://localhost/api/management/systemProfiles/gateways" -UseDefaultCredentials -UseBasicParsing
$config[0].Configuration.DirectoryServicesResolverConfiguration.UpdateDirectoryEntityChangesConfiguration.IsEnabled = $true

Invoke-RestMethod -Uri "https://localhost/api/management/systemProfiles/gateways/$($config[0].Id)" -UseDefaultCredentials -UseBasicParsing -Method Post -ContentType "application/json" -Body ($config[0] | convertto-json -depth 99)

# Disable invalid web requests to endpoints with invalid SSL certs again
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = $null
