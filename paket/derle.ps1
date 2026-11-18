# DNS Kalkan .exe derleme ve paylaşım paketi (c) 2026 RAXVIN
# Kullanım: powershell -ExecutionPolicy Bypass -File paket\derle.ps1
# Tek dosyalık .exe üretir: nereye kopyalanırsa kopyalansın tek başına çalışır.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$pk = Join-Path $root "paket"
$g = Join-Path $root "gorseller"
$work = Join-Path $pk "_derleme"
$dist = Join-Path $pk "_cikti"
Remove-Item $work, $dist -Recurse -Force -ErrorAction SilentlyContinue

$ver = (Select-String -Path "$root\dns_kalkan.py" -Pattern '^VERSION = "(.+)"').Matches[0].Groups[1].Value
$add = @("--add-data", "$g\simge.ico;gorseller", "--add-data", "$g\simge;gorseller\simge")
foreach ($p in 100, 125, 150, 175, 200) { $add += @("--add-data", "$g\arka_plan@$p.png;gorseller") }

python -m PyInstaller --noconfirm --clean --onefile --windowed --name "DNS Kalkan" `
    --icon "$g\simge.ico" --version-file "$pk\surum_bilgisi.txt" `
    --distpath "$dist\bin" --workpath $work --specpath $work `
    --exclude-module numpy --exclude-module PIL @add "$root\dns_kalkan.py"
if ($LASTEXITCODE -ne 0) { throw "PyInstaller hatası" }

$app = Join-Path $dist "DNS Kalkan"
New-Item -ItemType Directory -Force $app | Out-Null
Move-Item "$dist\bin\DNS Kalkan.exe" $app
Remove-Item "$dist\bin" -Recurse -Force
Copy-Item "$pk\kurtarma.bat" $app
Copy-Item "$pk\BENIOKU.txt" $app
Remove-Item (Join-Path $root "DNS_Kalkan_v*_RAXVIN.zip") -ErrorAction SilentlyContinue
$zip = Join-Path $root "DNS_Kalkan_v${ver}_RAXVIN.zip"
Compress-Archive -Path $app -DestinationPath $zip -CompressionLevel Optimal
"Paket hazır: $zip  ({0:N1} MB)" -f ((Get-Item $zip).Length / 1MB)
