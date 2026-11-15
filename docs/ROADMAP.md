# Roadmap and release gates

0.1 supplies a finite offline metadata gate with reproducible reports. No adoption, performance or security-audit claims are made.

Before a stable 1.0:

1. Validate against a licensed corpus of real releases and publish false-positive measurements; keep malformed examples synthetic.
2. Add a Windows/macOS/Linux extractor comparison harness in isolated temporary directories, clearly separating metadata policy from extractor-specific behavior.
3. Fuzz parser entry points under external CPU/RSS limits and publish seeds and reproduction instructions.
4. Add versioned policy configuration and explicit, reviewable exceptions with expiry/reasons. Never silently skip an unsupported member.
5. SARIF output validates against the upstream schema (see VALIDATION.md); exercise an actual upload integration.
6. Measure peak RSS and wall time for budget-boundary inputs and choose production limits from evidence.
7. Independent security review and a documented support/release process.

Potential follow-ups: source/wheel path parity and build provenance integration. These require separate designs; the initial gate remains focused on archive boundaries.
