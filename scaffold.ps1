$ErrorActionPreference = "Stop"

$files = @(
    "README.md", "THREAT_MODEL.md", "docker-compose.yml",
    "backend\api\router.go", "backend\api\devices.go", "backend\api\scans.go",
    "backend\api\vulnerabilities.go", "backend\api\firmware.go", "backend\api\alerts.go", "backend\api\risks.go",
    "backend\db\db.go",
    "backend\db\migrations\001_create_devices.sql", "backend\db\migrations\002_create_scans.sql",
    "backend\db\migrations\003_create_vulnerabilities.sql", "backend\db\migrations\004_create_firmware.sql",
    "backend\db\migrations\005_create_alerts.sql",
    "backend\scanner\nmap.go", "backend\scanner\ports.go", "backend\scanner\credentials.go",
    "backend\scanner\protocols.go", "backend\scanner\tls.go",
    "backend\risk\scorer.go",
    "backend\alerts\engine.go",
    "backend\kev\updater.go",
    "backend\models\device.go", "backend\models\scan.go", "backend\models\vulnerability.go",
    "backend\models\firmware.go", "backend\models\alert.go",
    "firmware-analyzer\Dockerfile", "firmware-analyzer\requirements.txt", "firmware-analyzer\main.py",
    "firmware-analyzer\entropy.py", "firmware-analyzer\cve_lookup.py", "firmware-analyzer\binwalk_runner.py",
    "frontend\src\main.tsx", "frontend\src\App.tsx",
    "frontend\src\api\client.ts",
    "frontend\src\components\DeviceInventory.tsx", "frontend\src\components\VulnScanner.tsx",
    "frontend\src\components\FirmwarePanel.tsx", "frontend\src\components\RiskScore.tsx",
    "frontend\src\components\AlertFeed.tsx", "frontend\src\components\NetworkMap.tsx",
    "frontend\src\pages\Dashboard.tsx", "frontend\src\pages\Devices.tsx",
    "frontend\src\pages\Vulnerabilities.tsx", "frontend\src\pages\Firmware.tsx"
)

foreach ($f in $files) {
    $d = Split-Path $f -Parent
    if ($d -and !(Test-Path $d)) { New-Item -ItemType Directory -Force $d | Out-Null }
    if (!(Test-Path $f)) {
        if ($f.EndsWith(".go")) {
            $pkg = Split-Path $d -Leaf
            Set-Content -Path $f -Value "package $pkg`n"
        } else {
            New-Item -ItemType File -Force $f | Out-Null
        }
    }
}

if (!(Test-Path "frontend\package.json")) { Set-Content -Path "frontend\package.json" -Value "{}" }
if (!(Test-Path "frontend\tsconfig.json")) { Set-Content -Path "frontend\tsconfig.json" -Value "{}" }

Write-Host "File tree scaffolded successfully."
