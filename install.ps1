# Android Sentinel installer - Windows (PowerShell).
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

# Python refuses to create a venv in a path containing ';' (the PATH
# separator). Fall back to a safe location while the code stays put.
$VenvRoot = $Dir
if ($Dir -match ';') {
    $VenvRoot = Join-Path $env:LOCALAPPDATA "android-sentinel"
    New-Item -ItemType Directory -Force -Path $VenvRoot | Out-Null
    Say "checkout path contains ';' - venv goes to $VenvRoot instead"
}
Say "creating virtualenv"
python -m venv (Join-Path $VenvRoot ".venv")
$pip = Join-Path $VenvRoot ".venv\Scripts\pip.exe"
$python = Join-Path $VenvRoot ".venv\Scripts\python.exe"
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

Run it (from the checkout folder; run.cmd also installs anything a
`git pull` added to requirements.txt before starting):
  cd "$Dir"
  run.cmd --demo        # simulated device, try the UI
  run.cmd               # phone on USB debugging
  run.cmd -s IP:PORT    # wireless debugging
  (same thing by hand: & "$python" -m sentinel ...)

Dashboard: http://127.0.0.1:8765  (local-only by design)
"@

if ($Demo) {
    Say "starting demo mode"
    Set-Location $Dir
    & $python -m sentinel --demo
}
