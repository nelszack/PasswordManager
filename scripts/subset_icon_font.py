"""Regenerate assets/material-icons.ttf and src/gui/icon_chars.rs.

Usage (needs fontTools: pip install fonttools):
    python3 scripts/subset_icon_font.py MaterialIcons-Regular.ttf \
        MaterialIcons-Regular.codepoints assets/material-icons.ttf src/gui/icon_chars.rs

Both inputs come from https://github.com/google/material-design-icons (font/).
Add a name to `names` below to include another icon.
"""
import sys
from fontTools import subset
from fontTools.ttLib import TTFont
src, codepoints_file, out_font, out_rs = sys.argv[1:5]
names = """content_copy visibility visibility_off edit delete delete_forever star star_border lock
add search refresh settings build password autorenew help_outline open_in_new close sync
check restore history file_download file_upload language health_and_safety
warning info arrow_back tune key backup shield""".split()
points = {}
for line in open(codepoints_file):
    name, hexcode = line.split()
    points[name] = int(hexcode, 16)
chosen = {n: points[n] for n in names}
options = subset.Options()
options.layout_features = []          # codepoints only, no ligatures
options.name_IDs = ["*"]
options.notdef_outline = True
font = TTFont(src, recalcTimestamp=False)  # same bytes on every run
sub = subset.Subsetter(options)
sub.populate(unicodes=sorted(chosen.values()))
sub.subset(font)
font.save(out_font)
with open(out_rs, "w") as rs:
    rs.write("//! Generated from Material Icons (Apache 2.0, see assets/LICENSE-material-icons.txt).\n")
    rs.write("//! Each constant is the icon's character in the bundled subset font\n")
    rs.write("//! (assets/material-icons.ttf). To add an icon, add its name to\n")
    rs.write("//! scripts/subset_icon_font.py and regenerate both files with it.\n")
    for name in names:
        rs.write(f"pub const {name.upper()}: char = '\\u{{{chosen[name]:x}}}';\n")
print(len(names), "icons")
