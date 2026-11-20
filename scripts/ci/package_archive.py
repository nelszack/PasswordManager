"""Write byte-reproducible release archives (.tar.gz or .zip) of one directory.

Entries are sorted, owned by 0:0 with empty names, stamped with SOURCE_DATE_EPOCH,
and given normalized permissions (0755 for directories and executables, 0644
otherwise), so archives depend only on file contents and the commit time.
"""
import argparse
import gzip
import io
import os
from pathlib import Path
import stat
import tarfile
import time
import zipfile

ZIP_MINIMUM_EPOCH = 315532800  # 1980-01-01, the earliest timestamp ZIP can store.


def entries(root):
    """Yield (archive name, path) for root and everything below it, sorted by name."""
    base = root.parent
    paths = [root, *root.rglob("*")]
    for path in sorted(paths, key=lambda path: path.relative_to(base).as_posix()):
        if path.is_symlink():
            raise ValueError(f"Release archives must not contain symbolic links: {path}")
        yield path.relative_to(base).as_posix(), path


def mode(path, executables):
    if path.is_dir():
        return 0o755
    executable = path.name in executables or path.stat().st_mode & stat.S_IXUSR
    return 0o755 if executable else 0o644


def write_tar_gz(root, output, epoch, executables):
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, path in entries(root):
            info = tarfile.TarInfo(name)
            info.mtime = epoch
            info.mode = mode(path, executables)
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            if path.is_dir():
                info.type = tarfile.DIRTYPE
                archive.addfile(info)
            else:
                info.size = path.stat().st_size
                with path.open("rb") as contents:
                    archive.addfile(info, contents)
    # An empty file name and fixed mtime keep the gzip header reproducible.
    with output.open("wb") as raw, gzip.GzipFile(filename="", mode="wb", fileobj=raw,
                                                 mtime=0, compresslevel=9) as compressed:
        compressed.write(buffer.getvalue())


def write_zip(root, output, epoch, executables):
    timestamp = time.gmtime(max(epoch, ZIP_MINIMUM_EPOCH))[:6]
    with zipfile.ZipFile(output, "w") as archive:
        for name, path in entries(root):
            info = zipfile.ZipInfo(name + "/" if path.is_dir() else name, date_time=timestamp)
            info.create_system = 3  # Unix, so the permission bits below are honored.
            file_type = stat.S_IFDIR if path.is_dir() else stat.S_IFREG
            info.external_attr = (file_type | mode(path, executables)) << 16
            if path.is_dir():
                info.external_attr |= 0x10  # MS-DOS directory flag.
                archive.writestr(info, b"")
            else:
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, path.read_bytes(), compresslevel=9)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="Directory to archive as the top-level entry")
    parser.add_argument("output", type=Path, help="Archive path ending in .tar.gz or .zip")
    parser.add_argument("--executable", action="append", default=[],
                        help="File name to mark executable even where the filesystem has no mode bits")
    args = parser.parse_args()
    epoch = int(os.environ["SOURCE_DATE_EPOCH"])
    root = args.directory.resolve()
    if not root.is_dir():
        parser.error(f"{args.directory} is not a directory")
    name = args.output.name
    if name.endswith(".tar.gz"):
        write_tar_gz(root, args.output, epoch, set(args.executable))
    elif name.endswith(".zip"):
        write_zip(root, args.output, epoch, set(args.executable))
    else:
        parser.error("output must end in .tar.gz or .zip")


if __name__ == "__main__":
    main()
