# Validation record — 15 November 2026

Initial local verification on macOS arm64, Python 3.14.6:

- 21 unittest tests passed; parametrized subtests cover ZIP and tar variations.
- Ruff 0.17.5 lint and formatting passed.
- Wheel and source distribution built with isolated hatchling 1.33.0.
- Both built artifacts pass archive-boundary's own metadata checks.
- Built-artifact JSON validates against the checked-in version 1 report schema.
- SARIF from both artifacts validates against the SARIF 2.1.0 schema fetched from https://json.schemastore.org/sarif-2.1.0.json (SHA-256 `c96eb2d311c37b0a38cbd18c52d79a68f778bbd2d831abed7412d9850740f785`). Schema validation establishes structural validity, not successful integration with a code-scanning service.
- A separate virtual environment installed the built wheel without dependencies and ran its CLI successfully against both artifacts.

The GitHub CI matrix independently runs tests on Linux, Windows and macOS, Python 3.11 and 3.14. Its live status is available in the Actions tab. A cross-platform CI run is a release gate, not a substitute for fuzzing, external review or production observation.

Not yet measured: peak RSS, parser fuzz coverage, real-release false-positive rate, or extractor-specific compatibility. These remain explicit 1.0 gates in the roadmap.
