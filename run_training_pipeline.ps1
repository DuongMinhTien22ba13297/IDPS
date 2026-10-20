$ErrorActionPreference = "Stop"
$ProjectDir = "c:\IDPS"
Set-Location -Path $ProjectDir

# Tao thu muc logs neu chua co
if (!(Test-Path -Path "$ProjectDir\logs")) {
    New-Item -ItemType Directory -Path "$ProjectDir\logs" | Out-Null
}

$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$LogFile = "$ProjectDir\logs\training_pipeline_log_$Timestamp.txt"

# Bat dau ghi log
Start-Transcript -Path $LogFile -Force

Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host "  ZERO-TOUCH IDPS -- FULL TRAINING PIPELINE" -ForegroundColor Cyan
Write-Host "  Thoi gian bat dau: $(Get-Date)" -ForegroundColor Cyan
Write-Host "======================================================================" -ForegroundColor Cyan
Write-Host ""

try {
    Write-Host "[1/5] CHAY EXTRACT_PCAP_FEATURES.PY..." -ForegroundColor Yellow
    python src\extract_pcap_features.py
    if ($LASTEXITCODE -ne 0) { throw "extract_pcap_features.py that bai!" }
    Write-Host ""

    Write-Host "[2/5] CHAY LABEL_FLOWS.PY..." -ForegroundColor Yellow
    python src\label_flows.py
    if ($LASTEXITCODE -ne 0) { throw "label_flows.py that bai!" }
    Write-Host ""

    Write-Host "[3/5] CHAY SPLIT_TRAIN_TEST.PY..." -ForegroundColor Yellow
    python datasets\split_train_test.py
    if ($LASTEXITCODE -ne 0) { throw "split_train_test.py that bai!" }
    Write-Host ""

    Write-Host "[4/5] CHAY DATA_PREPROCESSING.PY..." -ForegroundColor Yellow
    python src\data_preprocessing.py
    if ($LASTEXITCODE -ne 0) { throw "data_preprocessing.py that bai!" }
    Write-Host ""

    Write-Host "[5/5] CHAY OFFLINE_TRAINING.PY..." -ForegroundColor Yellow
    python src\offline_training.py
    if ($LASTEXITCODE -ne 0) { throw "offline_training.py that bai!" }
    Write-Host ""

    Write-Host "======================================================================" -ForegroundColor Green
    Write-Host "  HOAN TAT TOAN BO PIPELINE THANH CONG!" -ForegroundColor Green
    Write-Host "  Thoi gian ket thuc: $(Get-Date)" -ForegroundColor Green
    Write-Host "======================================================================" -ForegroundColor Green

} catch {
    Write-Host "`n[!] LOI XAY RA TRONG QUA TRINH CHAY PIPELINE: $_" -ForegroundColor Red
} finally {
    Stop-Transcript
    Write-Host "`nKet qua duoc luu tai: $LogFile" -ForegroundColor Cyan
    Write-Host "Nhan phim bat ky de thoat..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}
