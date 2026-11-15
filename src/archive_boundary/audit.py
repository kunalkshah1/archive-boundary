"""Inspect archive metadata without extracting members or running package code."""

from __future__ import annotations

import gzip
import hashlib
import io
import re
import stat
import tarfile
import unicodedata
import zipfile
import zlib
from dataclasses import asdict, dataclass, field
from pathlib import Path

RULES = {
    "AB001": "Absolute or parent-traversing path",
    "AB002": "Path is not portable across common filesystems",
    "AB003": "Duplicate or filesystem-equivalent member path",
    "AB004": "A path is both a file and a directory",
    "AB005": "Link or special member requires extraction semantics",
    "AB006": "Encrypted ZIP member cannot be inspected",
    "AB007": "Declared content exceeds inspection policy",
    "AB008": "Inspection budget exhausted",
    "AB009": "Invalid or unsupported archive",
}


@dataclass(frozen=True)
class Limits:
    """Finite budgets; sizes are bytes, name budgets count Unicode characters."""

    input_bytes: int = 32 * 1024 * 1024
    tar_bytes: int = 128 * 1024 * 1024
    members: int = 25_000
    name_chars: int = 4 * 1024 * 1024
    member_bytes: int = 32 * 1024 * 1024
    content_bytes: int = 128 * 1024 * 1024
    findings: int = 500

    def __post_init__(self):
        if any(type(value) is not int or value <= 0 for value in asdict(self).values()):
            raise ValueError("Limits must be positive integers")


@dataclass(frozen=True)
class Finding:
    rule: str
    member: str
    message: str


@dataclass
class Report:
    archive: str
    limits: Limits
    sha256: str | None = None
    format: str | None = None
    complete: bool = True
    members: int = 0
    declared_bytes: int = 0
    findings: list[Finding] = field(default_factory=list)

    @property
    def status(self):
        return "incomplete" if not self.complete else "fail" if self.findings else "pass"

    def to_dict(self):
        return {"schema_version": 1, **asdict(self), "status": self.status}


class _Stop(Exception):
    pass


class _Inspector:
    def __init__(self, report: Report):
        self.report = report
        self.paths: dict[str, tuple[bool, str, bool]] = {}
        self.name_chars = 0

    def finding(self, rule, name, message):
        if len(self.report.findings) >= self.report.limits.findings:
            self.report.complete = False
            raise _Stop
        self.report.findings.append(Finding(rule, name, message))

    def stop(self, message):
        self.report.complete = False
        self.finding("AB008", "", message)
        raise _Stop

    def member(self, name: str, directory: bool, size: int, special=False, encrypted=False):
        report = self.report
        report.members += 1
        self.name_chars += len(name)
        if report.members > report.limits.members or self.name_chars > report.limits.name_chars:
            self.stop("Member count or member-name budget exceeded")
        if len(name) > 4096:
            self.stop("Member path exceeds 4096 characters")
        report.declared_bytes += size
        if size < 0 or size > report.limits.member_bytes:
            self.finding("AB007", name, "Member declared size exceeds policy")
        if report.declared_bytes > report.limits.content_bytes:
            self.stop("Total declared content exceeds policy")
        if encrypted:
            self.finding("AB006", name, RULES["AB006"])
        if special:
            self.finding("AB005", name, RULES["AB005"])
        parts = name.replace("\\", "/").split("/")
        if name.startswith(("/", "\\")) or re.match(r"^[A-Za-z]:", name) or ".." in parts:
            self.finding("AB001", name, RULES["AB001"])
            return
        parts = [part for part in parts if part not in ("", ".")]
        if not parts and directory:
            return
        reserved = re.compile(r"^(CON|PRN|AUX|NUL|COM[1-9¹²³]|LPT[1-9¹²³])(?:\.|$)", re.I)
        if (
            not parts
            or "\\" in name
            or any(ord(char) < 32 or ord(char) == 127 for char in name)
            or any(
                part.endswith((".", " "))
                or any(c in part for c in ':*?"<>|')
                or reserved.match(part)
                for part in parts
            )
        ):
            self.finding("AB002", name, RULES["AB002"])
        if not parts:
            return
        # Include implied parents. Bound these records too, including deeply nested names.
        for index in range(1, len(parts) + 1):
            raw = "/".join(parts[:index])
            key = unicodedata.normalize("NFC", raw).casefold()
            folder = index < len(parts) or directory
            explicit = index == len(parts)
            previous = self.paths.get(key)
            if previous:
                was_folder, original, was_explicit = previous
                if was_folder != folder:
                    self.finding("AB004", name, f"Conflicts with {original!r}")
                elif explicit and was_explicit and not (folder and original == name):
                    self.finding("AB003", name, f"Aliases or duplicates {original!r}")
            else:
                self.name_chars += len(key)
                if (
                    len(self.paths) >= report.limits.members
                    or self.name_chars > report.limits.name_chars
                ):
                    self.stop("Retained path budget exceeded")
            if explicit or previous is None:
                self.paths[key] = (folder, name if explicit else raw, explicit)


def inspect_archive(path: str | Path, limits: Limits | None = None) -> Report:
    """Inspect one local snapshot. A pass covers metadata rules, not trust or extractability."""
    limits = limits or Limits()
    report = Report(Path(path).name, limits)
    inspector = _Inspector(report)
    try:
        with Path(path).open("rb") as source:
            data = source.read(limits.input_bytes + 1)
        if len(data) > limits.input_bytes:
            inspector.stop("Input exceeds byte budget; no digest of the whole input is available")
        report.sha256 = hashlib.sha256(data).hexdigest()
        if data.startswith((b"PK\x03\x04", b"PK\x05\x06")):
            report.format = "zip"
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for entry in archive.infolist():
                    mode = entry.external_attr >> 16
                    kind = stat.S_IFMT(mode)
                    inspector.member(
                        entry.orig_filename,
                        entry.is_dir(),
                        entry.file_size,
                        special=kind not in (0, stat.S_IFREG, stat.S_IFDIR),
                        encrypted=bool(entry.flag_bits & 1),
                    )
        else:
            report.format = "tar.gz" if data.startswith(b"\x1f\x8b") else "tar"
            if report.format == "tar.gz":
                with gzip.GzipFile(fileobj=io.BytesIO(data)) as compressed:
                    data = compressed.read(limits.tar_bytes + 1)
            if len(data) > limits.tar_bytes:
                inspector.stop("Uncompressed tar exceeds byte budget")
            with tarfile.open(fileobj=io.BytesIO(data), mode="r|") as archive:
                for entry in archive:
                    archive.members.clear()
                    inspector.member(
                        entry.name,
                        entry.isdir(),
                        entry.size,
                        special=not (entry.isreg() or entry.isdir()) or entry.issparse(),
                    )
    except _Stop:
        pass
    except (
        OSError,
        EOFError,
        ValueError,
        tarfile.TarError,
        zipfile.BadZipFile,
        zlib.error,
        NotImplementedError,
    ) as exc:
        report.complete = False
        # Parser messages may contain hostile paths. JSON escapes them; terminal output uses repr.
        if len(report.findings) < limits.findings:
            report.findings.append(Finding("AB009", "", f"{type(exc).__name__}: {str(exc)[:300]}"))
    return report
