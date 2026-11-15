import gzip
import hashlib
import io
import json
import stat
import subprocess
import sys
import tarfile
import unittest
import warnings
import zipfile
from contextlib import redirect_stderr
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

import jsonschema

from archive_boundary import Limits, inspect_archive
from archive_boundary.cli import main, sarif


class ArchiveTests(unittest.TestCase):
    def setUp(self):
        self.temp = TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def archive(self, names, kind="zip"):
        path = self.root / ("release.zip" if kind == "zip" else "release.tar.gz")
        if kind == "zip":
            with warnings.catch_warnings(), zipfile.ZipFile(path, "w") as archive:
                warnings.simplefilter("ignore", UserWarning)
                for name in names:
                    entry = zipfile.ZipInfo(name)
                    # Windows ZipInfo normalizes backslashes. Preserve the hostile fixture bytes.
                    entry.filename = name
                    archive.writestr(entry, b"x")
        else:
            with tarfile.open(path, "w:gz") as archive:
                for name in names:
                    entry = tarfile.TarInfo(name)
                    entry.type = tarfile.DIRTYPE if name.endswith("/") else tarfile.REGTYPE
                    entry.size = 0 if entry.isdir() else 1
                    archive.addfile(entry, None if entry.isdir() else io.BytesIO(b"x"))
        return path

    def rules(self, path, **limits):
        return {f.rule for f in inspect_archive(path, Limits(**limits)).findings}

    def test_clean_zip_and_tar_and_exact_hash(self):
        for kind in ("zip", "tar"):
            with self.subTest(kind=kind):
                path = self.archive(["release/", "release/src/hello.py", "release/LICENSE"], kind)
                report = inspect_archive(path)
                self.assertEqual(report.status, "pass")
                self.assertEqual(report.sha256, hashlib.sha256(path.read_bytes()).hexdigest())
                self.assertEqual(report.members, 3)
                self.assertEqual(report.declared_bytes, 2 if kind == "tar" else 3)

    def test_traversal_and_absolute_paths_both_formats(self):
        for kind in ("zip", "tar"):
            for name in (
                "../outside",
                "/etc/config",
                "C:/config",
                "a/../../config",
                "\\server\\file",
            ):
                with self.subTest(kind=kind, name=name):
                    self.assertIn("AB001", self.rules(self.archive([name], kind)))
        self.assertFalse((self.root.parent / "outside").exists())

    def test_portability(self):
        for name in (
            "a\\b",
            "dir/a:N",
            "CON.txt",
            "a/NUL",
            "a/LPT¹.txt",
            "a./b",
            "a /b",
            "a\x1b[31m",
            "a?b",
        ):
            with self.subTest(name=name):
                self.assertIn("AB002", self.rules(self.archive([name])))

    def test_duplicate_case_and_unicode_aliases(self):
        for names in (["a", "a"], ["A", "a"], ["café", "cafe\u0301"], ["a/b", "a/./b"]):
            self.assertIn("AB003", self.rules(self.archive(names)))

    def test_clashes_both_orders_and_formats(self):
        for kind in ("zip", "tar"):
            for names in (["a", "a/"], ["a/", "a"], ["a", "a/b/c"], ["a/b/c", "a"]):
                with self.subTest(kind=kind, names=names):
                    self.assertIn("AB004", self.rules(self.archive(names, kind)))

    def test_explicit_parent_after_child_is_valid(self):
        self.assertEqual(inspect_archive(self.archive(["a/b", "a/", "a/"])).status, "pass")

    def test_symlink_zip(self):
        path = self.root / "link.zip"
        with zipfile.ZipFile(path, "w") as archive:
            info = zipfile.ZipInfo("link")
            info.create_system = 3
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(info, "target")
        self.assertIn("AB005", self.rules(path))

    def test_tar_special_members(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE):
            path = self.root / "special.tar"
            with tarfile.open(path, "w") as archive:
                info = tarfile.TarInfo("link")
                info.type, info.linkname = kind, "target"
                archive.addfile(info)
            self.assertIn("AB005", self.rules(path))

    def test_encrypted_zip(self):
        path = self.archive(["a"])
        data = bytearray(path.read_bytes())
        # Set encryption bit in local and central headers of a synthetic ZIP.
        data[6] |= 1
        central = data.index(b"PK\x01\x02")
        data[central + 8] |= 1
        path.write_bytes(data)
        self.assertIn("AB006", self.rules(path))

    def test_declared_size_policy(self):
        path = self.root / "large.zip"
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("a", b"x" * 100)
        self.assertIn("AB007", self.rules(path, member_bytes=50))
        self.assertIn("AB008", self.rules(path, content_bytes=50))

    def test_input_limit_has_no_partial_hash(self):
        report = inspect_archive(self.archive(["a"]), Limits(input_bytes=1))
        self.assertEqual(report.status, "incomplete")
        self.assertIsNone(report.sha256)

    def test_gzip_expansion_budget(self):
        path = self.root / "expanded.tar.gz"
        path.write_bytes(gzip.compress(b"\0" * 100_000))
        report = inspect_archive(path, Limits(tar_bytes=1000))
        self.assertEqual(report.status, "incomplete")
        self.assertIn("AB008", {f.rule for f in report.findings})

    def test_member_name_and_implied_path_budgets(self):
        for names, limits in [
            (["a", "b"], {"members": 1}),
            (["a/b/c/d"], {"members": 2}),
            (["abcd"], {"name_chars": 2}),
            (["a" * 4097], {}),
        ]:
            self.assertEqual(
                inspect_archive(self.archive(names), Limits(**limits)).status, "incomplete"
            )

    def test_finding_budget(self):
        report = inspect_archive(self.archive(["../a", "../b"]), Limits(findings=1))
        self.assertFalse(report.complete)
        self.assertEqual(len(report.findings), 1)

    def test_malformed_missing_and_truncated(self):
        path = self.root / "invalid"
        for data in (b"garbage", b"PK\x03\x04", b"\x1f\x8b\x08", gzip.compress(b"bad tar")):
            path.write_bytes(data)
            self.assertEqual(inspect_archive(path).status, "incomplete")
        self.assertEqual(inspect_archive(self.root / "missing").status, "incomplete")

    def test_json_deterministic_and_exit_codes(self):
        for names, code in [(["a"], 0), (["../a"], 1)]:
            path = self.archive(names)
            args = [sys.executable, "-m", "archive_boundary.cli", "--format", "json", str(path)]
            first = subprocess.run(args, capture_output=True, text=True)
            second = subprocess.run(args, capture_output=True, text=True)
            self.assertEqual(first.returncode, code, first.stderr)
            self.assertEqual(first.stdout, second.stdout)
            self.assertEqual(json.loads(first.stdout)["schema_version"], 1)
        with self.assertRaises(SystemExit) as context:
            with redirect_stderr(io.StringIO()):
                main([str(path), "--members", "0"])
        self.assertEqual(context.exception.code, 2)

    def test_cli_incomplete_and_terminal_escaping(self):
        path = self.archive(["a\x1b[31m"])
        result = subprocess.run(
            [sys.executable, "-m", "archive_boundary.cli", str(path)], capture_output=True
        )
        self.assertNotIn(b"\x1b", result.stdout)
        result = subprocess.run(
            [sys.executable, "-m", "archive_boundary.cli", str(path), "--input-bytes", "1"],
            capture_output=True,
        )
        self.assertEqual(result.returncode, 2)

    def test_sarif_evidence_and_execution_status(self):
        report = inspect_archive(self.archive(["../a"]))
        run = sarif([report])["runs"][0]
        self.assertEqual(run["results"][0]["ruleId"], "AB001")
        self.assertEqual(run["results"][0]["properties"]["sha256"], report.sha256)
        self.assertTrue(run["invocations"][0]["executionSuccessful"])
        report.complete = False
        self.assertFalse(sarif([report])["runs"][0]["invocations"][0]["executionSuccessful"])

    def test_limits_validation(self):
        for value in (0, -1, True, 1.5):
            with self.assertRaises(ValueError):
                Limits(members=value)

    def test_no_extraction_and_root_directory(self):
        for kind in ("zip", "tar"):
            path = self.archive(["./", "./package/a"], kind)
            with (
                patch.object(tarfile.TarFile, "extractall", side_effect=AssertionError),
                patch.object(zipfile.ZipFile, "extractall", side_effect=AssertionError),
            ):
                self.assertEqual(inspect_archive(path).status, "pass")

    def test_json_schema_accepts_all_report_states(self):
        schema = json.loads(
            (Path(__file__).parents[1] / "docs/report.schema.json").read_text(encoding="utf-8")
        )
        jsonschema.Draft202012Validator.check_schema(schema)
        for names in (["a"], ["../a"]):
            for limits in (Limits(), Limits(input_bytes=1)):
                report = inspect_archive(self.archive(names), limits)
                jsonschema.validate({"schema_version": 1, "reports": [report.to_dict()]}, schema)


if __name__ == "__main__":
    unittest.main()
