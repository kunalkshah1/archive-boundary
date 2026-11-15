# archive-boundary

**Catch release archive path hazards before your users unpack them.**

An offline CI gate for ZIP/wheel, tar, and tar.gz archives. It checks member metadata without extracting files, importing package code, or contacting a network service. Runtime dependencies: Python 3.11+ standard library only.

```sh
git clone https://github.com/kunalkshah1/archive-boundary.git
cd archive-boundary
python -m pip install .
archive-boundary dist/package.whl dist/package.tar.gz
archive-boundary --format json dist/package.whl > report.json
archive-boundary --format sarif dist/package.whl > report.sarif
```

A synthetic archive containing a file `package/assets` and another member `package/assets/logo.svg` fails with `AB004`: the second member requires the first path to be a directory. The reverse order also fails. Case and Unicode aliases can create additional conflicts on downstream filesystems.

## Rules

| ID | Check |
| --- | --- |
| AB001 | Absolute paths, drive prefixes, parent traversal |
| AB002 | Backslashes, control characters, Windows reserved names, trailing dots/spaces and forbidden characters |
| AB003 | Duplicate file paths, casefold or NFC Unicode aliases |
| AB004 | File/directory clashes, including implied directories |
| AB005 | Symbolic/hard links, devices, FIFOs and sparse tar members |
| AB006 | Encrypted ZIP entries |
| AB007 | Declared member size exceeds policy |
| AB008 | Input, expansion, name, member, content or finding budget exhausted |
| AB009 | Missing, malformed or unsupported archive |

Repeated identical directory entries are accepted. Links are flagged even when their targets appear local: whether they are acceptable depends on the consumer's extraction policy.

## CI contract

| Exit | Meaning |
| --- | --- |
| 0 | Inspection completed and no configured metadata rule failed |
| 1 | Inspection completed with findings |
| 2 | Inspection incomplete, invalid input, or invalid CLI arguments |

JSON includes `schema_version`, archive basename, exact input SHA-256 when the whole input fits the budget, effective limits, completion state, member count, declared bytes and findings. The [JSON schema](docs/report.schema.json) describes version 1. SARIF 2.1.0 contains stable rule IDs and archive/member/hash properties; `executionSuccessful` is false for incomplete inspection. Reports omit timestamps for reproducible output.

Default budgets: 32 MiB input, 128 MiB decompressed tar, 25,000 member/path records, 4 Mi characters of retained names, 32 MiB per member, 128 MiB total declared content, 500 findings. Paths longer than 4,096 characters stop inspection. All numeric budgets have CLI overrides; keep runner-level time and memory limits too.

A GitHub Actions step after your existing checkout, Python setup and package build:

```yaml
- name: Inspect release archives
  run: |
    python -m pip install ./tools/archive-boundary
    archive-boundary dist/*.whl dist/*.tar.gz
```

Vendor a reviewed version under `tools/archive-boundary`, or install from a reviewed commit of this repository. This package has **not** been uploaded to PyPI. For JSON/SARIF capture, preserve the command's nonzero exit status; redirecting output does not change it. This tool only generates SARIF; uploading it to a code-scanning service is a separate CI step.

## Scope and limitations

This is an initial release, not a security certification. A pass covers these metadata rules; it does not prove that an archive is safe, trustworthy, installable or accepted by a particular extractor. ZIP payloads are not decompressed, so CRCs, actual expansion size and corrupt payloads are not validated. Tar gzip containers are decompressed within a byte cap before metadata inspection. Nested archives are not recursively opened. No malware, secret, signature, dependency, license or build analysis is performed.

Unicode NFC/casefold catches common aliases but does not emulate every filesystem (including macOS ignorable characters, Windows short names and volume-specific normalization). ZIP central-directory parsing and tar extension-header handling occur in Python's standard library before member-level budgets are checked; the input and tar byte caps bound those inputs, not exact process RSS. Use a patched Python and isolate inspection of untrusted artifacts. See [threat model](docs/THREAT_MODEL.md).

## Development

```sh
python -m pip install -e ".[dev]"
python -m unittest discover -s tests -v
ruff check .
ruff format --check .
```

Tests generate archives locally and cover both clash orders, normalized aliases, traversal, links, special members, encryption flags, malformed input, bounded expansion, report determinism, terminal escaping and CLI exit codes. CI exercises Linux, Windows and macOS with Python 3.11 and 3.14.

The initial use case came from [wheelgap #261](https://github.com/wheelgap/wheelgap/issues/261), a maintainer request to avoid answering build questions for archives pip cannot unpack. This project is independent; it does not claim to reproduce pip's extraction rules. [Roadmap](docs/ROADMAP.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · MIT license.
