# Publication secret audit

Reviewed on **2026-10-12** with **Gitleaks 8.30.1**, downloaded from its official release and
verified against the published SHA-256 digest and checksum manifest.

The unfiltered review scanned every reachable Git commit (`--all --full-history`) and a
separate snapshot of the current tracked files, using default rules, ten decoding levels,
three archive levels, and fully redacted reports. Inline `gitleaks:allow` comments and
repository ignore files were disabled for that audit. A planted, synthetic credential-shaped
canary made the scanner fail; the report also confirmed full redaction.

This repository produced **0 credential-shaped findings in each scan**.

Both unfiltered scans returned exit 0 with zero findings. No fixture exclusions were needed.

The review also inspected configuration examples, credential-bearing URL shapes, sample data,
tracked artifact types, private infrastructure references, and reachable history. Runtime
credentials, real account tokens, local databases, environment files, logs, and audit reports
are not publication artifacts. Intentional maintainer authorship metadata remains in Git.

## Ongoing gate

[Secret scan workflow](../.github/workflows/secret-scan.yml) runs on pushes and pull requests,
fetches the full history, uses the default ruleset, rejects inline allow comments, and redacts
output. The scanner archive and checkout action are pinned by checksum/commit. The workflow
needs no provider key or third-party account credential and grants read-only repository access.

Reproduce its scan after installing the same Gitleaks release:

```bash
gitleaks git . --log-opts="--all --full-history" --redact=100 \
  --ignore-gitleaks-allow --max-decode-depth=10 --max-archive-depth=3
```

The [portfolio audit](https://github.com/ashartanveercs-del/ashartanveercs-del/blob/main/docs/SECURITY-AUDIT.md)
records cross-repository scope and fixture decisions. A secret scan is a detection gate,
not proof that every possible private string can be recognized. Publication reviews still
require human inspection of suspicious values and newly added data files.
