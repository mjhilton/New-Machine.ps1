[CmdletBinding()]
param ()

$ErrorActionPreference = 'Stop';

$IsAdmin = (New-Object System.Security.Principal.WindowsPrincipal([System.Security.Principal.WindowsIdentity]::GetCurrent())).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $IsAdmin) {
    throw "You need to run this script elevated"
}

Write-Progress -Activity "Setting execution policy"
Set-ExecutionPolicy RemoteSigned

Write-Progress -Activity "Ensuring PS profile exists"
if (-not (Test-Path $PROFILE)) {
    New-Item $PROFILE -Force
}

Write-Progress "Hiding desktop icons"
if ((Get-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\).HideIcons -ne 1) {
    Set-ItemProperty HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\ -Name HideIcons -Value 1
    Get-Process explorer | Stop-Process
}

Write-Progress "Making c:\code"
if (-not (Test-Path c:\code)) {
    New-Item c:\code -ItemType Directory
}

Write-Progress "Making c:\temp"
if (-not (Test-Path c:\temp)) {
    New-Item c:\temp -ItemType Directory
}

Write-Progress "Symlinking Outlook Signatures to OneDrive:\Documents\Outlook\Signatures"
if (Test-Path HKCU:\Software\Microsoft\Office\16.0) {
    if (Test-Path "$($Env:AppData)\Microsoft\Signatures") {
        Write-Warning "Signatures already exist. Not gonna do that."
    }
    else
    {
        New-Item -ItemType SymbolicLink -Path "$($Env:AppData)\Microsoft\Signatures" -Value "$($Env:UserProfile)\OneDrive\Documents\Outlook\Signatures"
    }
}
else {
    Write-Warning "Couldn't find a compatible install of Office"
}

Write-Progress "Enabling Windows Subsystem for Linux"
Enable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux

Write-Progress -Activity "Reloading PS profile"
. $PROFILE
