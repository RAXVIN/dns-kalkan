"""simge/simge_*.png dosyalarını tek bir çok boyutlu simge.ico dosyasında birleştirir (PNG sıkıştırmalı ICO)."""
import os
import struct

here = os.path.dirname(os.path.abspath(__file__))
sizes = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256]
blobs = [open(os.path.join(here, "simge", f"simge_{s}.png"), "rb").read() for s in sizes]
head = struct.pack("<HHH", 0, 1, len(sizes))
offset = 6 + 16 * len(sizes)
entries = b""
for s, data in zip(sizes, blobs):
    b = 0 if s >= 256 else s
    entries += struct.pack("<BBBBHHII", b, b, 0, 0, 1, 32, len(data), offset)
    offset += len(data)
with open(os.path.join(here, "simge.ico"), "wb") as f:
    f.write(head + entries + b"".join(blobs))
print("simge.ico", os.path.getsize(os.path.join(here, "simge.ico")), "bayt")
