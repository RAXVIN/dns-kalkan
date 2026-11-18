# DNS Kalkan (c) 2026 Raxvin
# arka_plan_orijinal.png dosyasından, her ekran ölçeği için pencereye uygun
# karartılmış arka plan görselleri üretir (arka_plan@100.png, @125, @150, @175, @200).
# Başka bir görsel kullanmak istersen arka_plan_orijinal.png'yi değiştirip bu betiği çalıştır.
Add-Type -AssemblyName System.Drawing
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$src = [Drawing.Image]::FromFile((Join-Path $dir "arka_plan_orijinal.png"))
$BG = [Drawing.Color]::FromArgb(255, 11, 13, 20)

function C([int]$a) { [Drawing.Color]::FromArgb($a, 11, 13, 20) }

function Grad($g, [float]$x, [float]$y, [float]$w, [float]$h, [float]$angle, $stops) {
    $rect = New-Object Drawing.RectangleF($x, $y, $w, $h)
    $br = New-Object Drawing.Drawing2D.LinearGradientBrush($rect, (C 0), (C 0), $angle)
    $cb = New-Object Drawing.Drawing2D.ColorBlend($stops.Count)
    $cb.Positions = [float[]]($stops | % { $_[0] })
    $cb.Colors = [Drawing.Color[]]($stops | % { C $_[1] })
    $br.InterpolationColors = $cb
    $br.WrapMode = [Drawing.Drawing2D.WrapMode]::TileFlipXY
    $g.FillRectangle($br, $rect)
    $br.Dispose()
}

foreach ($pct in 100, 125, 150, 175, 200) {
    $s = $pct / 100.0
    $W = [int][math]::Round(440 * $s); $H = [int][math]::Round(738 * $s)
    $bmp = New-Object Drawing.Bitmap($W, $H)
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.InterpolationMode = [Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $g.SmoothingMode = [Drawing.Drawing2D.SmoothingMode]::HighQuality
    $g.Clear($BG)
    $k = 0.4955 * $s
    $iw = $src.Width * $k; $ih = $src.Height * $k
    $dx = $W - $iw + 32 * $s; $dy = 16 * $s
    $g.DrawImage($src, [float]$dx, [float]$dy, [float]$iw, [float]$ih)
    # görselin alt kenarını zemine erit
    Grad $g 0 ($dy + $ih - 128 * $s) $W (128 * $s) 90 @(@(0, 0), @(1, 255))
    $g.FillRectangle((New-Object Drawing.SolidBrush($BG)), 0, [float]($dy + $ih - 1), $W, [float]($H))
    # genel karartma: üst hafif, alt koyu
    Grad $g 0 0 $W $H 90 @(@(0, 77), @(0.30, 46), @(0.50, 140), @(0.75, 217), @(1, 242))
    # sol üst: başlık okunabilirliği
    Grad $g 0 0 ($W * 0.7) (88 * $s) 0 @(@(0, 140), @(1, 0))
    $out = Join-Path $dir ("arka_plan@{0}.png" -f $pct)
    $bmp.Save($out, [Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    "{0}  {1}x{2}  {3:N0} KB" -f (Split-Path $out -Leaf), $W, $H, ((Get-Item $out).Length / 1KB)
}
$src.Dispose()
