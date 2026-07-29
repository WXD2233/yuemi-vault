param(
  [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$MinimumNodeVersion = [version]"22.13.0"

function Write-Step {
  param([string]$Message)
  Write-Host ""
  Write-Host "==> $Message" -ForegroundColor Cyan
}

function Get-InstalledNodeVersion {
  $nodeCommand = Get-Command node.exe -ErrorAction SilentlyContinue
  if (-not $nodeCommand) {
    $nodeCommand = Get-Command node -ErrorAction SilentlyContinue
  }
  if (-not $nodeCommand) {
    return $null
  }

  try {
    $versionText = (& $nodeCommand.Source --version).Trim().TrimStart("v")
    return [version]$versionText
  } catch {
    return $null
  }
}

function Refresh-ProcessPath {
  $machinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
  $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
  $env:Path = "$machinePath;$userPath"
}

function Install-NodeLts {
  $wingetCommand = Get-Command winget.exe -ErrorAction SilentlyContinue
  if (-not $wingetCommand) {
    throw "Node.js 22.13.0 or newer is required. Install Node.js LTS from https://nodejs.org and run install.cmd again."
  }

  Write-Step "Installing or updating Node.js LTS"
  $commonArguments = @(
    "--id", "OpenJS.NodeJS.LTS",
    "--exact",
    "--source", "winget",
    "--accept-package-agreements",
    "--accept-source-agreements",
    "--disable-interactivity"
  )

  $currentVersion = Get-InstalledNodeVersion
  if ($currentVersion) {
    & $wingetCommand.Source upgrade @commonArguments
    if ($LASTEXITCODE -ne 0) {
      & $wingetCommand.Source install @commonArguments
    }
  } else {
    & $wingetCommand.Source install @commonArguments
  }

  if ($LASTEXITCODE -ne 0) {
    throw "Node.js installation did not complete. Install Node.js LTS manually and run install.cmd again."
  }

  Refresh-ProcessPath
}

function Invoke-Npm {
  param([string[]]$Arguments)

  $npmCommand = Get-Command npm.cmd -ErrorAction SilentlyContinue
  if (-not $npmCommand) {
    $npmCommand = Get-Command npm -ErrorAction SilentlyContinue
  }
  if (-not $npmCommand) {
    throw "npm was not found after Node.js setup. Restart Windows and run install.cmd again."
  }

  & $npmCommand.Source @Arguments
  if ($LASTEXITCODE -ne 0) {
    throw "npm $($Arguments -join ' ') failed with exit code $LASTEXITCODE."
  }
}

try {
  Set-Location -LiteralPath $PSScriptRoot

  Write-Step "Checking Node.js"
  $nodeVersion = Get-InstalledNodeVersion
  if (-not $nodeVersion -or $nodeVersion -lt $MinimumNodeVersion) {
    Install-NodeLts
    $nodeVersion = Get-InstalledNodeVersion
  }

  if (-not $nodeVersion -or $nodeVersion -lt $MinimumNodeVersion) {
    throw "Node.js $MinimumNodeVersion or newer is required. Close this window, restart Windows if Node.js was just installed, and run install.cmd again."
  }
  Write-Host "Node.js v$nodeVersion is ready." -ForegroundColor Green

  Write-Step "Installing project dependencies"
  Invoke-Npm -Arguments @("ci", "--no-audit", "--no-fund")

  if (-not $SkipBuild) {
    Write-Step "Building Yuemi Vault"
    Invoke-Npm -Arguments @("run", "build")
  }

  Write-Step "Installation complete"
  Write-Host "Run start.cmd to start the local application." -ForegroundColor Green
  Write-Host "First-login password: 12345678" -ForegroundColor Yellow
  exit 0
} catch {
  Write-Host ""
  Write-Host "Installation failed: $($_.Exception.Message)" -ForegroundColor Red
  exit 1
}
