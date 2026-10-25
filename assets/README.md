The desktop and browser extension share `password-manager.svg` as their icon
source. The desktop shortcut embeds the SVG; its window embeds 64 × 64 RGBA
pixels to avoid adding an image decoder dependency. The extension uses PNGs.
Windows shortcuts can use `password-manager.ico`, which contains sizes from
16 × 16 through 256 × 256 pixels.

After editing the SVG, regenerate the derived assets from the repository root
with `rsvg-convert` (librsvg) and `magick` (ImageMagick):

```bash
for size in 16 32 48 128; do
  rsvg-convert -w "$size" -h "$size" assets/password-manager.svg \
    -o "extension/icons/icon${size}.png"
done
rsvg-convert -w 64 -h 64 assets/password-manager.svg | \
  magick png:- -depth 8 rgba:assets/password-manager-64.rgba
rsvg-convert -w 256 -h 256 assets/password-manager.svg | \
  magick png:- -define icon:auto-resize=256,128,64,48,32,24,16 assets/password-manager.ico
```
