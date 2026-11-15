# Threat model

Input is a local release artifact whose names, metadata and compressed bytes may be hostile. Inspection must never extract member paths into the filesystem, run package code or fetch external resources. The tool reads one capped snapshot, hashes the same bytes it inspects, and reports evidence using archive basenames and member names.

ZIP parsing inspects central-directory metadata only. Gzip tar parsing first reads at most the tar byte limit plus one byte, then iterates tar headers and clears tarfile's member cache. This deliberately trades bounded memory for a simpler parser boundary. Budgets are policy controls, not exact RSS guarantees. Standard-library parsing, decoded strings, JSON output and temporary buffers add overhead; running in a container with OS resource limits remains appropriate.

Findings are errors under the default conservative policy. A special member may be intentional; evaluate it against the consumer's extractor rather than suppressing it automatically. Incomplete results always exit 2, including a finding budget exhaustion. Never translate an incomplete result to a pass.

JSON uses escaped strings; terminal output represents archive and member names with Python repr and represents parser messages too, preventing embedded terminal escapes/newlines from being interpreted. SARIF consumers must treat member strings as untrusted display data. Neither reports nor tests include file payloads or credentials.

Out of scope: malware detection, archive authenticity, signature verification, content-based secret detection, sandboxing vulnerable decompressors, all extractor behaviors, Unicode equivalence for every filesystem, recursive archives and ZIP CRC/content validation. Python's gzip/zlib/tarfile/zipfile implementation is part of the trusted computing base. Use a supported, patched Python version.
