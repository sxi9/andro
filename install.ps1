# Android Sentinel installer — Windows (PowerShell).
#   .\install.ps1            install to $HOME\android-sentinel
#   .\install.ps1 -Demo      install, then start demo mode right away
param(
    [string]$Dir = "$HOME\android-sentinel",
    [switch]$Demo
)
$ErrorActionPreference = "Stop"
$Repo = "https://github.com/sxi9/andro"
$Branch = "claude/youthful-goldberg-01npzu"

function Say($msg) { Write-Host "==> $msg" -ForegroundColor Cyan }

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "git is required: https://git-scm.com/download/win"
}
$py = Get-Command python -ErrorAction SilentlyContinue
if (-not $py) { throw "Python 3.10+ is required: https://www.python.org/downloads/" }

# Use this checkout if the script lives inside one.
if (Test-Path (Join-Path $PSScriptRoot "sentinel\__main__.py")) {
    $Dir = $PSScriptRoot
    Say "using existing checkout: $Dir"
} elseif (Test-Path (Join-Path $Dir ".git")) {
    Say "updating existing install: $Dir"
    git -C $Dir fetch origin $Branch
    git -C $Dir checkout $Branch
    git -C $Dir pull --ff-only origin $Branch
} else {
    Say "cloning $Repo ($Branch) -> $Dir"
    git clone -b $Branch $Repo $Dir
}

Say "creating virtualenv"
python -m venv (Join-Path $Dir ".venv")
$pip = Join-Path $Dir ".venv\Scripts\pip.exe"
$python = Join-Path $Dir ".venv\Scripts\python.exe"
& $pip install --quiet --upgrade pip
Say "installing dependencies"
& $pip install --quiet -r (Join-Path $Dir "requirements.txt")

if (Get-Command adb -ErrorAction SilentlyContinue) {
    Say "adb found"
} else {
    Write-Host @"
NOTE: adb (Android platform-tools) is not installed. Sentinel needs it for a
real device (demo mode works without it). Get it:
  winget install Google.PlatformTools
  or download: https://developer.android.com/tools/releases/platform-tools
"@ -ForegroundColor Yellow
}

Say "done."
Write-Host @"

Run it:
  $python -m sentinel --demo     # simulated device, try the UI
  $python -m sentinel            # phone on USB debugging
  $python -m sentinel -s IP:PORT # wireless debugging

Dashboard: http://127.0.0.1:8765  (local-only by design)
"@

if ($Demo) {
    Say "starting demo mode"
    & $python -m sentinel --demo
}
