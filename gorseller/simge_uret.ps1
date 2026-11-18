# DNS Kalkan simgesi (c) 2026 RAXVIN
# Mor-turkuaz degrade kalkan + koyu iç kalkan + parlayan "R". Her boyut ayrı çizilir (net görünüm için).
Add-Type -AssemblyName System.Drawing
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$out = Join-Path $dir "simge"
New-Item -ItemType Directory -Force $out | Out-Null

function ShieldPath([float]$x, [float]$y, [float]$w, [float]$h) {
    $p = New-Object Drawing.Drawing2D.GraphicsPath
    $pt = { param($u, $v) New-Object Drawing.PointF(($x + $u * $w), ($y + $v * $h)) }
    $p.StartFigure()
    $p.AddBezier((& $pt 0.50 0.00), (& $pt 0.64 0.08), (& $pt 0.80 0.12), (& $pt 0.97 0.13))
    $p.AddLine((& $pt 0.97 0.13), (& $pt 0.97 0.46))
    $p.AddBezier((& $pt 0.97 0.46), (& $pt 0.97 0.74), (& $pt 0.76 0.90), (& $pt 0.50 1.00))
    $p.AddBezier((& $pt 0.50 1.00), (& $pt 0.24 0.90), (& $pt 0.03 0.74), (& $pt 0.03 0.46))
    $p.AddLine((& $pt 0.03 0.46), (& $pt 0.03 0.13))
    $p.AddBezier((& $pt 0.03 0.13), (& $pt 0.20 0.12), (& $pt 0.36 0.08), (& $pt 0.50 0.00))
    $p.CloseFigure()
    return $p
}

$VIOLET = [Drawing.Color]::FromArgb(255, 139, 92, 246)
$CYAN = [Drawing.Color]::FromArgb(255, 34, 211, 238)

foreach ($s in 16, 20, 24, 32, 40, 48, 64, 96, 128, 256) {
    $bmp = New-Object Drawing.Bitmap($s, $s, [Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $g = [Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = [Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.TextRenderingHint = [Drawing.Text.TextRenderingHint]::AntiAliasGridFit
    $g.Clear([Drawing.Color]::Transparent)
    $big = $s -ge 48
    $m = if ($big) { $s * 0.07 } else { $s * 0.02 }       # parıltı için kenar payı
    $sw = $s - 2 * $m; $sh = $sw * 1.04
    if ($sh -gt $s - 2 * $m) { $sh = $s - 2 * $m; $sw = $sh / 1.04 }
    $sx = ($s - $sw) / 2; $sy = ($s - $sh) / 2

    # dış parıltı (büyük boyutlar)
    if ($big) {
        foreach ($i in 6, 5, 4, 3, 2, 1) {
            $gp = ShieldPath $sx $sy $sw $sh
            $pen = New-Object Drawing.Pen([Drawing.Color]::FromArgb([int](14 + (6 - $i) * 6), 120, 110, 255), [float]($s * 0.012 * $i))
            $pen.LineJoin = [Drawing.Drawing2D.LineJoin]::Round
            $g.DrawPath($pen, $gp); $pen.Dispose(); $gp.Dispose()
        }
    }
    # degrade dış kalkan
    $outer = ShieldPath $sx $sy $sw $sh
    $rect = New-Object Drawing.RectangleF($sx, $sy, $sw, $sh)
    $br = New-Object Drawing.Drawing2D.LinearGradientBrush($rect, $VIOLET, $CYAN, [float]55)
    $g.FillPath($br, $outer); $br.Dispose()

    # koyu iç kalkan
    $k = if ($s -le 24) { 0.16 } else { 0.11 }
    $ix = $sx + $sw * $k; $iy = $sy + $sh * ($k * 0.9); $iw = $sw * (1 - 2 * $k); $ih = $sh * (1 - 2 * $k)
    $inner = ShieldPath $ix $iy $iw $ih
    $ir = New-Object Drawing.RectangleF($ix, $iy, $iw, $ih)
    $ib = New-Object Drawing.Drawing2D.LinearGradientBrush($ir, [Drawing.Color]::FromArgb(255, 24, 22, 52), [Drawing.Color]::FromArgb(255, 10, 14, 26), [float]90)
    $g.FillPath($ib, $inner); $ib.Dispose()

    # iç kalkanın üst parlaması
    if ($s -ge 32) {
        $hr = New-Object Drawing.RectangleF($ix, $iy, $iw, [float]($ih * 0.46)); $hl = New-Object Drawing.Drawing2D.LinearGradientBrush($hr, [Drawing.Color]::FromArgb(60, 167, 139, 250), [Drawing.Color]::FromArgb(0, 167, 139, 250), [float]90)
        $g.SetClip($inner); $g.FillRectangle($hl, $ix, $iy, $iw, [float]($ih * 0.45)); $g.ResetClip(); $hl.Dispose()
    }

    # "R"
    $fs = [float]($ih * 0.58)
    $font = New-Object Drawing.Font("Segoe UI Black", $fs, [Drawing.FontStyle]::Bold, [Drawing.GraphicsUnit]::Pixel)
    $fmt = New-Object Drawing.StringFormat
    $fmt.Alignment = [Drawing.StringAlignment]::Center; $fmt.LineAlignment = [Drawing.StringAlignment]::Center
    $tr = New-Object Drawing.RectangleF($ix, ($iy + $ih * 0.02), $iw, ($ih * 0.86))
    $tp = New-Object Drawing.Drawing2D.GraphicsPath
    $tp.AddString("R", $font.FontFamily, [int][Drawing.FontStyle]::Bold, $fs, $tr, $fmt)
    if ($big) {  # harf parıltısı
        foreach ($i in 3, 2, 1) {
            $gpen = New-Object Drawing.Pen([Drawing.Color]::FromArgb(40, 34, 211, 238), [float]($s * 0.014 * $i))
            $gpen.LineJoin = [Drawing.Drawing2D.LineJoin]::Round
            $g.DrawPath($gpen, $tp); $gpen.Dispose()
        }
    }
    $wb = New-Object Drawing.Drawing2D.LinearGradientBrush($tr, [Drawing.Color]::White, [Drawing.Color]::FromArgb(255, 165, 243, 252), [float]90)
    $g.FillPath($wb, $tp); $wb.Dispose()

    $f = Join-Path $out ("simge_{0}.png" -f $s)
    $bmp.Save($f, [Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
}
"tamam: " + ((Get-ChildItem $out -Filter simge_*.png).Name -join ", ")
