"""Command line reports with deterministic JSON and SARIF output."""

import argparse
import json
from dataclasses import asdict

from . import __version__
from .audit import RULES, Limits, inspect_archive


def sarif(reports):
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "archive-boundary",
                        "version": __version__,
                        "rules": [
                            {"id": key, "shortDescription": {"text": text}}
                            for key, text in RULES.items()
                        ],
                    }
                },
                "invocations": [{"executionSuccessful": all(r.complete for r in reports)}],
                "results": [
                    {
                        "ruleId": f.rule,
                        "level": "error",
                        "message": {"text": f"{r.archive!r}: {f.member!r}: {f.message}"},
                        "properties": {
                            "archive": r.archive,
                            "member": f.member,
                            "sha256": r.sha256,
                        },
                    }
                    for r in reports
                    for f in r.findings
                ],
            }
        ],
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline ZIP/tar release archive metadata checks")
    parser.add_argument("archives", nargs="+")
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    parser.add_argument("--version", action="version", version=__version__)
    for key, value in asdict(Limits()).items():
        parser.add_argument("--" + key.replace("_", "-"), type=int, default=value)
    args = parser.parse_args(argv)
    try:
        limits = Limits(**{key: getattr(args, key) for key in asdict(Limits())})
    except ValueError as exc:
        parser.error(str(exc))
    reports = [inspect_archive(path, limits) for path in args.archives]
    if args.format == "json":
        print(
            json.dumps({"schema_version": 1, "reports": [r.to_dict() for r in reports]}, indent=2)
        )
    elif args.format == "sarif":
        print(json.dumps(sarif(reports), indent=2))
    else:
        for report in reports:
            print(f"{report.archive!r}: {report.status} ({report.members} members)")
            for finding in report.findings:
                print(f"  {finding.rule} {finding.member!r}: {finding.message!r}")
    return (
        2 if any(not r.complete for r in reports) else 1 if any(r.findings for r in reports) else 0
    )


if __name__ == "__main__":
    raise SystemExit(main())
