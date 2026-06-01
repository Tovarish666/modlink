# modlink — deploy script for Windows 10
# Run: PowerShell -ExecutionPolicy Bypass -File deploy-win.ps1
#
# What it does:
#   1. Checks/installs Python 3
#   2. pip install flask
#   3. Downloads sing-box (Windows amd64)
#   4. Generates self-signed TLS cert via openssl
#   5. Creates C:\modlink\  with configs
#   6. Launches panel at http://localhost:5000

$ErrorActionPreference = "Stop"
$MODLINK_DIR  = "C:\modlink"
$CONF_DIR     = "$env:ProgramData\modlink"
$PANEL_PORT   = 5000
$REPO_RAW     = "https://raw.githubusercontent.com/Tovarish666/modlink/main"

function Info  { param($m) Write-Host "  $m" -ForegroundColor Cyan   }
function Ok    { param($m) Write-Host "  $m" -ForegroundColor Green  }
function Warn  { param($m) Write-Host "  $m" -ForegroundColor Yellow }
function Abort { param($m) Write-Host "`n  ERROR: $m" -ForegroundColor Red; exit 1 }

Write-Host "`n=== modlink deploy (Windows) ===`n" -ForegroundColor Cyan

# ── 1. Python ──────────────────────────────────────────────────────────────
Info "Проверяю Python…"
$py = $null
foreach ($cmd in @("python","python3","py")) {
    try {
        $v = & $cmd --version 2>&1
        if ($v -match "Python 3") { $py = $cmd; break }
    } catch {}
}

if (-not $py) {
    Warn "Python 3 не найден — устанавливаю через winget…"
    try {
        winget install --id Python.Python.3.12 -e --silent --accept-package-agreements --accept-source-agreements
        $env:PATH = [System.Environment]::GetEnvironmentVariable("PATH","Machine") + ";" + $env:PATH
        $py = "python"
    } catch {
        Abort "Не удалось установить Python. Установи вручную: https://python.org"
    }
}
Ok "Python: $( & $py --version 2>&1 )"

# ── 2. Зависимости ────────────────────────────────────────────────────────
# panel.py использует только stdlib — pip не нужен
Ok "зависимости: только stdlib (pip не нужен)"

# ── 3. Директории ──────────────────────────────────────────────────────────
Info "Создаю директории…"
New-Item -ItemType Directory -Force -Path $MODLINK_DIR | Out-Null
New-Item -ItemType Directory -Force -Path $CONF_DIR    | Out-Null
New-Item -ItemType Directory -Force -Path "$CONF_DIR\certs" | Out-Null
Ok "$MODLINK_DIR  +  $CONF_DIR"

# ── 4. sing-box ────────────────────────────────────────────────────────────
$sbExe = "$MODLINK_DIR\sing-box.exe"
if (-not (Test-Path $sbExe)) {
    Info "Скачиваю sing-box…"
    try {
        # получить последний тег через GitHub API
        $rel     = Invoke-RestMethod "https://api.github.com/repos/SagerNet/sing-box/releases/latest"
        $tag     = $rel.tag_name                          # например v1.10.0
        $ver     = $tag.TrimStart("v")
        $zipName = "sing-box-${ver}-windows-amd64.zip"
        $url     = "https://github.com/SagerNet/sing-box/releases/download/${tag}/${zipName}"
        $tmp     = "$env:TEMP\sing-box.zip"
        Invoke-WebRequest $url -OutFile $tmp -UseBasicParsing
        $ext = "$env:TEMP\sb-extract"
        Expand-Archive $tmp -DestinationPath $ext -Force
        $found = Get-ChildItem $ext -Filter "sing-box.exe" -Recurse | Select-Object -First 1
        if (-not $found) { Abort "sing-box.exe не найден в архиве" }
        Copy-Item $found.FullName $sbExe -Force
        Remove-Item $tmp, $ext -Recurse -Force
    } catch {
        Abort "Не удалось скачать sing-box: $_"
    }
    Ok "sing-box: $( & $sbExe version 2>&1 | Select-Object -First 1 )"
} else {
    Ok "sing-box уже есть: $sbExe"
}

# ── 5. TLS сертификат ──────────────────────────────────────────────────────
$certFile = "$CONF_DIR\certs\cert.pem"
$keyFile  = "$CONF_DIR\certs\key.pem"

if (-not (Test-Path $certFile)) {
    Info "Генерирую TLS сертификат…"

    # ищем openssl: в PATH, Git for Windows, Windows встроенный
    $openssl = $null
    foreach ($candidate in @(
        "openssl",
        "C:\Program Files\Git\usr\bin\openssl.exe",
        "C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
        "$env:SystemRoot\System32\openssl.exe"
    )) {
        if (Get-Command $candidate -ErrorAction SilentlyContinue) { $openssl = $candidate; break }
    }

    if ($openssl) {
        & $openssl req -x509 -newkey rsa:2048 -nodes `
            -keyout $keyFile -out $certFile `
            -days 3650 -subj "/CN=modlink" 2>&1 | Out-Null
        Ok "TLS: openssl"
    } else {
        # PowerShell PKI + ExportPkcs8PrivateKey (.NET 4.7.2+, Win10 1709+)
        Info "openssl не найден — использую PowerShell PKI (.NET)…"
        try {
            $cert = New-SelfSignedCertificate `
                -DnsName "modlink" `
                -CertStoreLocation "Cert:\CurrentUser\My" `
                -NotAfter (Get-Date).AddYears(10) `
                -KeyAlgorithm RSA -KeyLength 2048 `
                -KeyExportPolicy Exportable

            # cert → PEM
            $certB64 = [Convert]::ToBase64String($cert.RawData, "InsertLineBreaks")
            "-----BEGIN CERTIFICATE-----`n$certB64`n-----END CERTIFICATE-----" |
                Set-Content $certFile -Encoding ASCII

            # private key → PKCS8 PEM (ExportPkcs8PrivateKey доступен с .NET 4.7.2)
            $rsa      = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
            $keyBytes = $rsa.ExportPkcs8PrivateKey()
            $keyB64   = [Convert]::ToBase64String($keyBytes, "InsertLineBreaks")
            "-----BEGIN PRIVATE KEY-----`n$keyB64`n-----END PRIVATE KEY-----" |
                Set-Content $keyFile -Encoding ASCII

            Ok "TLS: PowerShell PKI (.NET) — cert.pem + key.pem готовы"
        } catch {
            Warn "Не удалось создать TLS сертификат: $_"
            Warn "Установи Git for Windows (openssl внутри) и перезапусти скрипт."
        }
    }
} else {
    Ok "TLS сертификат уже есть"
}

# ── 6. Скачать panel.py и server.py ───────────────────────────────────────
Info "Скачиваю panel.py…"
Invoke-WebRequest "$REPO_RAW/panel.py"  -OutFile "$MODLINK_DIR\panel.py"  -UseBasicParsing
Invoke-WebRequest "$REPO_RAW/server.py" -OutFile "$MODLINK_DIR\server.py" -UseBasicParsing
Ok "panel.py  server.py"

# ── 7. modems.conf ────────────────────────────────────────────────────────
$modemsConf = "$CONF_DIR\modems.conf"
if (-not (Test-Path $modemsConf)) {
    "# N  password" | Out-File $modemsConf -Encoding UTF8
    Ok "Создан пустой modems.conf — добавь модемы через панель"
}

# ── 8. Ярлык ручного запуска ──────────────────────────────────────────────
$startBat = "$MODLINK_DIR\start.bat"
@"
@echo off
title modlink panel
cd /d $MODLINK_DIR
start "" http://localhost:$PANEL_PORT
$py panel.py --port $PANEL_PORT
pause
"@ | Out-File $startBat -Encoding ASCII
Ok "Ярлык: $startBat"

# ── 9. Автозапуск через Task Scheduler ────────────────────────────────────
$TASK_NAME = "modlink-panel"
$pyPath    = (Get-Command $py -ErrorAction SilentlyContinue).Source

if ($pyPath) {
    Info "Регистрирую задачу автозапуска '$TASK_NAME'…"
    try {
        # Удалить старую задачу если есть
        Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false -ErrorAction SilentlyContinue

        $action   = New-ScheduledTaskAction `
                        -Execute $pyPath `
                        -Argument "$MODLINK_DIR\panel.py --port $PANEL_PORT --host 127.0.0.1 --no-browser" `
                        -WorkingDirectory $MODLINK_DIR
        $trigger  = New-ScheduledTaskTrigger -AtStartup
        $settings = New-ScheduledTaskSettingsSet `
                        -ExecutionTimeLimit 0 `
                        -RestartCount 3 `
                        -RestartInterval (New-TimeSpan -Minutes 1)
        $principal = New-ScheduledTaskPrincipal `
                        -UserId "SYSTEM" `
                        -LogonType ServiceAccount `
                        -RunLevel Highest

        Register-ScheduledTask `
            -TaskName $TASK_NAME `
            -Action $action `
            -Trigger $trigger `
            -Settings $settings `
            -Principal $principal | Out-Null

        Ok "Задача '$TASK_NAME' зарегистрирована (запуск при старте системы)"
    } catch {
        Warn "Не удалось зарегистрировать задачу: $_"
        Warn "Используй $startBat для ручного запуска"
    }
} else {
    Warn "Путь к Python не определён — автозапуск не настроен. Используй $startBat"
}

# ── Итог ──────────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "=== Готово ===" -ForegroundColor Green
Write-Host "  Директория:   $MODLINK_DIR"
Write-Host "  Конфиги:      $CONF_DIR"
Write-Host "  Автозапуск:   Task Scheduler → '$TASK_NAME'"
Write-Host "  Ручной запуск: $startBat"
Write-Host "  Панель:       http://localhost:$PANEL_PORT"
Write-Host ""
Write-Host "  Управление сервисом:"
Write-Host "    Старт:  Start-ScheduledTask  -TaskName '$TASK_NAME'"
Write-Host "    Стоп:   Stop-ScheduledTask   -TaskName '$TASK_NAME'"
Write-Host "    Статус: Get-ScheduledTask    -TaskName '$TASK_NAME' | Select-Object TaskName,State"
Write-Host ""

$ans = Read-Host "Запустить панель сейчас? [Y/n]"
if ($ans -notmatch "^[nN]") {
    # Запустить через планировщик (или напрямую если планировщик не сработал)
    try {
        Start-ScheduledTask -TaskName $TASK_NAME -ErrorAction Stop
        Start-Sleep -Seconds 2
        Start-Process "http://localhost:$PANEL_PORT"
        Ok "Панель запущена через планировщик → http://localhost:$PANEL_PORT"
    } catch {
        Start-Process "http://localhost:$PANEL_PORT"
        & $py "$MODLINK_DIR\panel.py" --port $PANEL_PORT
    }
}
