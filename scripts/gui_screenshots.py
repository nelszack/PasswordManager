#!/usr/bin/env python3
"""Render every desktop GUI screen offscreen and compare it with a baseline.

The GUI render tests (src/gui/render_tests.rs) draw each synthetic screen with
the real Iced software renderer in several window sizes, scales and themes.
This script exports those renders as PNGs, optionally renders a baseline git
revision the same way, and writes an HTML gallery with side-by-side pictures and
diff images for every screen that changed.

    python3 scripts/gui_screenshots.py                     # gallery of the working tree
    python3 scripts/gui_screenshots.py --baseline main     # compare with main; exit 1 on changes
    python3 scripts/gui_screenshots.py --against DIR       # compare with an earlier --out DIR

Baselines are rendered on the same machine rather than committed: text is drawn
with system fonts, so pixels differ between machines but not between runs.
Only synthetic fixtures are rendered; no vault is read.
"""
import argparse
import html
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import zlib

ROOT = Path(__file__).resolve().parent.parent
TEST_FILTER = "gui::render_tests"


def render(source, destination, target_dir):
    """Run the render tests in `source`, exporting PPM renders into `destination`."""
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True)
    env = dict(os.environ, PM_GUI_REVIEW_DIR=str(destination), CARGO_TARGET_DIR=str(target_dir))
    print(f"Rendering {source} ...", flush=True)
    result = subprocess.run(["cargo", "test", "--locked", "--bin", "pm", TEST_FILTER, "--", "--quiet"],
                            cwd=source, env=env)
    if result.returncode != 0:
        sys.exit(f"render tests failed in {source} (exit {result.returncode})")
    for ppm in destination.glob("*.ppm"):
        width, height, pixels = read_ppm(ppm)
        write_png(ppm.with_suffix(".png"), width, height, pixels)
        ppm.unlink()
    count = len(list(destination.glob("*.png")))
    if not count:
        sys.exit(f"no renders were exported from {source}")
    print(f"  {count} screens")


def read_ppm(path):
    data = path.read_bytes()
    parts = data.split(maxsplit=4)
    if parts[0] != b"P6" or parts[3] != b"255":
        raise ValueError(f"{path} is not an 8-bit binary PPM")
    width, height = int(parts[1]), int(parts[2])
    pixels = parts[4]
    if len(pixels) != width * height * 3:
        raise ValueError(f"{path} has {len(pixels)} bytes for {width}x{height}")
    return width, height, pixels


def read_png(path):
    """Decode the 8-bit RGB, filter-0 PNGs that write_png produces."""
    data = path.read_bytes()
    position, idat, width, height = 8, b"", 0, 0
    while position < len(data):
        length, tag = struct.unpack(">I4s", data[position:position + 8])
        body = data[position + 8:position + 8 + length]
        if tag == b"IHDR":
            width, height = struct.unpack(">II", body[:8])
        elif tag == b"IDAT":
            idat += body
        position += 12 + length
    raw = zlib.decompress(idat)
    stride = width * 3
    rows = (raw[y * (stride + 1) + 1:(y + 1) * (stride + 1)] for y in range(height))
    return width, height, b"".join(rows)


def write_png(path, width, height, pixels):
    stride = width * 3
    raw = b"".join(b"\x00" + pixels[y * stride:(y + 1) * stride] for y in range(height))

    def chunk(tag, body):
        return struct.pack(">I", len(body)) + tag + body + struct.pack(">I", zlib.crc32(tag + body) & 0xFFFFFFFF)

    path.write_bytes(b"\x89PNG\r\n\x1a\n"
                     + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
                     + chunk(b"IDAT", zlib.compress(raw, 6)) + chunk(b"IEND", b""))


def diff(baseline, current, output):
    """Write a diff image (changed pixels red over a faded copy); return the changed pixel count."""
    width, height, before = read_png(baseline)
    current_width, current_height, after = read_png(current)
    if (width, height) != (current_width, current_height):
        return None
    out = bytearray(len(after))
    changed = 0
    for index in range(0, len(after), 3):
        if before[index:index + 3] != after[index:index + 3]:
            changed += 1
            out[index:index + 3] = b"\xff\x00\x00"
        else:
            gray = (after[index] + after[index + 1] + after[index + 2]) // 3
            out[index:index + 3] = bytes((gray // 3 + 170,) * 3)
    write_png(output, width, height, bytes(out))
    return changed


def gallery(out, current, baseline):
    names = sorted(p.name for p in current.glob("*.png"))
    base_names = set(p.name for p in baseline.glob("*.png")) if baseline else set()
    changed, unchanged, added = [], [], []
    removed = sorted(base_names - set(names)) if baseline else []
    diffs = out / "diff"
    diffs.mkdir(exist_ok=True)
    for name in names:
        if not baseline:
            unchanged.append((name, None))
        elif name not in base_names:
            added.append((name, None))
        elif (baseline / name).read_bytes() == (current / name).read_bytes():
            unchanged.append((name, None))
        else:
            pixels = diff(baseline / name, current / name, diffs / name)
            changed.append((name, "size changed" if pixels is None else f"{pixels:,} pixels changed"))

    def rel(path):
        return html.escape(os.path.relpath(path, out))

    def figure(label, path):
        return (f'<figure><figcaption>{label}</figcaption><a href="{rel(path)}">'
                f'<img loading="lazy" src="{rel(path)}" alt="{label}"></a></figure>')

    sections = []
    if changed:
        rows = []
        for name, note in changed:
            figures = figure("baseline", baseline / name) + figure("current", current / name)
            if (diffs / name).exists():
                figures += figure("diff", diffs / name)
            rows.append(f'<section class="change"><h3>{html.escape(name)} <small>{html.escape(note)}</small></h3>'
                        f'<div class="row">{figures}</div></section>')
        sections.append(f"<h2>Changed ({len(changed)})</h2>" + "".join(rows))
    if added:
        sections.append(f"<h2>New ({len(added)})</h2><div class=grid>"
                        + "".join(figure(html.escape(n), current / n) for n, _ in added) + "</div>")
    if removed:
        sections.append(f"<h2>Removed ({len(removed)})</h2><ul>"
                        + "".join(f"<li>{html.escape(n)}</li>" for n in removed) + "</ul>")
    title = "Unchanged" if baseline else "Screens"
    sections.append(f"<details {'open' if not baseline else ''}><summary><h2>{title} ({len(unchanged)})</h2></summary>"
                    "<div class=grid>" + "".join(figure(html.escape(n), current / n) for n, _ in unchanged)
                    + "</div></details>")
    summary = (f"{len(changed)} changed, {len(added)} new, {len(removed)} removed, {len(unchanged)} unchanged"
               if baseline else f"{len(unchanged)} screens")
    page = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>GUI screens</title>
<style>
:root{{--bg:#f6f7f9;--fg:#1d232c;--muted:#5d6775;--card:#fff;--line:#d7dce3}}
@media (prefers-color-scheme:dark){{:root{{--bg:#14181d;--fg:#e6e9ee;--muted:#9aa4b2;--card:#1d232b;--line:#2c343f}}}}
body{{margin:0;padding:16px;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,sans-serif}}
h1{{font-size:20px;margin:0 0 4px}} h2{{font-size:16px;display:inline}} p{{color:var(--muted)}}
h3{{font-size:14px;margin:16px 0 8px}} small{{color:var(--muted);font-weight:normal}}
.row{{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:12px;margin-top:12px}}
figure{{margin:0;background:var(--card);border:1px solid var(--line);border-radius:8px;padding:8px}}
figcaption{{font-size:12px;color:var(--muted);margin-bottom:6px;overflow-wrap:anywhere}}
img{{width:100%;height:auto;display:block;border-radius:4px}} section,details{{margin-top:20px}}
summary{{cursor:pointer}}
</style></head><body><h1>Desktop GUI screens</h1><p>{summary}. Names are screen-width-scale%.</p>
{''.join(sections)}</body></html>"""
    (out / "index.html").write_text(page)
    return changed, added, removed


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=ROOT / "target" / "gui-screenshots")
    parser.add_argument("--baseline", metavar="REF", help="git revision to render and compare against")
    parser.add_argument("--against", type=Path, metavar="DIR",
                        help="compare against the 'current' renders of an earlier --out directory")
    args = parser.parse_args()
    if args.baseline and args.against:
        parser.error("use --baseline or --against, not both")
    out = args.out.resolve()
    out.mkdir(parents=True, exist_ok=True)
    target = Path(os.environ.get("CARGO_TARGET_DIR", ROOT / "target")).resolve()

    baseline = None
    if args.against:
        baseline = args.against.resolve() / "current"
        if not baseline.is_dir():
            parser.error(f"{baseline} does not exist")
        if baseline.parent == out:
            kept = out / "previous"
            if kept.exists():
                shutil.rmtree(kept)
            shutil.copytree(baseline, kept)
            baseline = kept
    elif args.baseline:
        # A fixed location keeps the baseline's incremental build valid between runs.
        worktree = target / "gui-baseline" / "src"
        # Switching an existing checkout only touches files that differ.
        commit = subprocess.run(["git", "rev-parse", "--verify", f"{args.baseline}^{{commit}}"], cwd=ROOT,
                                check=True, capture_output=True, text=True).stdout.strip()
        if (worktree / ".git").exists():
            subprocess.run(["git", "checkout", "--quiet", "--force", "--detach", commit], cwd=worktree, check=True)
            subprocess.run(["git", "clean", "-fdq"], cwd=worktree, check=True)
        else:
            subprocess.run(["git", "worktree", "prune"], cwd=ROOT, check=True)
            subprocess.run(["git", "worktree", "add", "--detach", "--quiet", str(worktree), commit],
                           cwd=ROOT, check=True)
        baseline = out / "baseline"
        # A separate target directory: Cargo judges freshness by file times, so
        # sharing one with the working tree could reuse the other tree's binary.
        render(worktree, baseline, target / "gui-baseline" / "target")
    render(ROOT, out / "current", target)

    changed, added, removed = gallery(out, out / "current", baseline)
    print(f"Gallery: {out / 'index.html'}")
    if baseline:
        for name, note in changed:
            print(f"  changed  {name} ({note})")
        for name, _ in added:
            print(f"  new      {name}")
        for name in removed:
            print(f"  removed  {name}")
        if changed or added or removed:
            return 1
        print("  no visual changes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
