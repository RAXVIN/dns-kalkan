# DNS Kalkan .exe derleme ve paylaşım paketi (c) 2026 WESAR
# Kullanım: powershell -ExecutionPolicy Bypass -File paket\derle.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$pk = Join-Path $root "paket"
$g = Join-Path $root "gorseller"
$work = Join-Path $pk "_derleme"
$dist = Join-Path $pk "_cikti"
Remove-Item $work, $dist -Recurse -Force -ErrorAction SilentlyContinue

$add = @("--add-data", "$g\simge.ico;gorseller", "--add-data", "$g\simge;gorseller\simge")
foreach ($p in 100, 125, 150, 175, 200) { $add += @("--add-data", "$g\arka_plan@$p.png;gorseller") }

python -m PyInstaller --noconfirm --clean --windowed --name "DNS Kalkan" `
    --icon "$g\simge.ico" --version-file "$pk\surum_bilgisi.txt" `
    --distpath $dist --workpath $work --specpath $work `
    --exclude-module numpy --exclude-module PIL @add "$root\dns_kalkan.py"
if ($LASTEXITCODE -ne 0) { throw "PyInstaller hatası" }

$app = Join-Path $dist "DNS Kalkan"
Copy-Item "$pk\kurtarma.bat" $app
Copy-Item "$pk\BENIOKU.txt" $app
$zip = Join-Path $root "DNS_Kalkan_v2.1_WESAR.zip"
Remove-Item $zip -ErrorAction SilentlyContinue
Compress-Archive -Path $app -DestinationPath $zip -CompressionLevel Optimal
"Paket hazır: $zip  ({0:N1} MB)" -f ((Get-Item $zip).Length / 1MB)
