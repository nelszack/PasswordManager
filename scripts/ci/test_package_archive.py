"""Release archives must be identical for identical contents and commit time."""
import os
from pathlib import Path
import tarfile
import tempfile
import time
import unittest
from unittest.mock import patch
import zipfile

import package_archive


class ArchiveTests(unittest.TestCase):
    def build(self, directory, order):
        root = Path(directory) / "pm-v1.0.0-test"
        (root / "docs").mkdir(parents=True)
        files = {"pm": b"binary", "README.md": b"readme", "docs/guide.md": b"guide"}
        for name in order:
            (root / name).write_bytes(files[name])
            os.utime(root / name, (time.time() - order.index(name) * 1000,) * 2)
        os.chmod(root / "pm", 0o700)
        os.chmod(root / "README.md", 0o600)
        return root

    def archive(self, suffix, order):
        with tempfile.TemporaryDirectory() as directory:
            root = self.build(directory, order)
            output = Path(directory) / f"out{suffix}"
            with patch.dict(os.environ, {"SOURCE_DATE_EPOCH": "1700000000"}), \
                    patch("sys.argv", ["package_archive.py", str(root), str(output)]):
                package_archive.main()
            return output.read_bytes()

    def test_archives_are_reproducible_and_normalized(self):
        for suffix in (".tar.gz", ".zip"):
            with self.subTest(suffix=suffix):
                first = self.archive(suffix, ["pm", "README.md", "docs/guide.md"])
                self.assertEqual(first, self.archive(suffix, ["docs/guide.md", "README.md", "pm"]))
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "a.tar.gz"
            path.write_bytes(self.archive(".tar.gz", ["pm", "README.md", "docs/guide.md"]))
            with tarfile.open(path) as archive:
                members = archive.getmembers()
            self.assertEqual([member.name for member in members], [
                "pm-v1.0.0-test", "pm-v1.0.0-test/README.md", "pm-v1.0.0-test/docs",
                "pm-v1.0.0-test/docs/guide.md", "pm-v1.0.0-test/pm"])
            modes = {member.name.rsplit("/", 1)[-1]: member.mode for member in members}
            self.assertEqual((modes["pm"], modes["README.md"], modes["docs"]), (0o755, 0o644, 0o755))
            self.assertTrue(all(member.mtime == 1700000000 and member.uid == 0
                                and member.uname == "" for member in members))
            path = Path(directory) / "a.zip"
            path.write_bytes(self.archive(".zip", ["pm", "README.md", "docs/guide.md"]))
            with zipfile.ZipFile(path) as archive:
                self.assertEqual(archive.getinfo("pm-v1.0.0-test/pm").external_attr >> 16 & 0o777, 0o755)
                self.assertEqual(archive.read("pm-v1.0.0-test/docs/guide.md"), b"guide")


if __name__ == "__main__":
    unittest.main()
