<#
  Downloads the official 3proxy Windows build and drops 3proxy.exe into res\
  so the resource compiler can embed it.

  3proxy is redistributed under its BSD-style license, which permits binary
  redistribution as long as the copyright notice travels with it — that notice
  lives in THIRD-PARTY.txt and in the exe's version resource.
#>
[CmdletBinding()]
param(
    [string]$Version = "1.0.0",
    [ValidateSet("x64", "x86", "arm64")]
    [string]$Arch    = "x64",
    [string]$OutDir  = (Join-Path $PSScriptRoot "..\res")
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$zipName = "3proxy-$Version-$Arch.zip"
$url     = "https://github.com/3proxy/3proxy/releases/download/$Version/$zipName"
$tmp     = Join-Path $env:TEMP "modlink-3proxy"
$zip     = Join-Path $tmp $zipName

New-Item -ItemType Directory -Force -Path $tmp, $OutDir | Out-Null

Write-Host "  downloading $url"
Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing

Write-Host "  extracting"
$ext = Join-Path $tmp "x"
if (Test-Path $ext) { Remove-Item $ext -Recurse -Force }
Expand-Archive -Path $zip -DestinationPath $ext -Force

$exe = Get-ChildItem -Path $ext -Filter "3proxy.exe" -Recurse | Select-Object -First 1
if (-not $exe) { throw "3proxy.exe not found inside $zipName" }

Copy-Item $exe.FullName (Join-Path $OutDir "3proxy.exe") -Force
$size = [math]::Round((Get-Item (Join-Path $OutDir "3proxy.exe")).Length / 1KB, 1)
Write-Host "  ok: res\3proxy.exe ($size KB)" -ForegroundColor Green

# Record the exact upstream build that got embedded.
@"
3proxy $Version ($Arch)
source: $url
fetched: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
"@ | Set-Content (Join-Path $OutDir "3proxy.version.txt") -Encoding UTF8
