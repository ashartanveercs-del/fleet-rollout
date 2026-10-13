# Verification record — 2026-10-12

[README](../README.md) · [Design proof map](PROOF_MAP.md) · [CI workflow](../.github/workflows/ci.yml)

Executed locally on Windows 11 with CPython 3.12.10, from the repository root, using the
existing development virtual environment. Commands exercised fictional agents, temporary
files, SQLite and loopback HTTP; no Docker daemon, SSH endpoint or live fleet was used.
The date is the review's local date (America/Los_Angeles).

| Exact PowerShell command | Observed result |
|---|---|
| `.\.venv\Scripts\python.exe -m pytest -q -ra` | **731 passed, 18 skipped**, 0 failed; 42.97 s. `sh` was absent from the default PATH |
| `$env:Path = 'C:\Program Files\Git\usr\bin;' + $env:Path` followed by `.\.venv\Scripts\python.exe -m pytest -q -ra` | **745 passed, 4 skipped**, 0 failed; 26.81 s. Real-shell executor contract cases executed using Git's bundled `sh` |
| `.\.venv\Scripts\python.exe -m ruff check src tests examples` | All checks passed |
| `.\.venv\Scripts\python.exe examples\rehearse_rollout.py` | Exit 0; all expected intermediate exit codes checked; five-target rollout verified, every target matched golden, unhealthy canary restored and later targets untouched; 15-record ledger chain verified |

The PATH adjustment above was scoped to the verification shell, not a persistent system
setting. With `sh`, the remaining four skips are three real-executor symlink cases and one
execute-bit case, which need a POSIX filesystem. CI is configured for Linux/Python 3.11 and
3.12, where those cases run, plus Windows/Python 3.12, where the drive-path guard test runs.
The Windows workflow adds Git's shell to PATH when present. The Windows-only guard test
skips on Linux; a test count is therefore not a promise that every platform runs every case.

## Fix validated in this review

A lock timestamp without a timezone previously caused a `TypeError` while computing age.
New target-lock and local-lock regressions reproduced the crashes before the fix. An
unusable timestamp now has unknown age and remains held; another run receives `LockHeld`
without changing the file. The focused lock suite reports 13 passed, including malformed
timestamp controls; the final complete suite collects 749 cases.

## What this proves and what remains outside it

Tests cover hostile spec validation, canary ordering, customer consent, stage/read-back/
restore faults, interrupted transaction recovery, preservation of later edits, row-level
SQLite restoration, lock exclusion, health response bodies and nested shell guard parsing.
The fake executor and real adapter share contracts, with the actual target programs run
under local `sh`. No live Docker/SSH transport or production rollout was validated. The
hook does not sandbox arbitrary programs and approvals still rely on filesystem trust.
See [the boundaries](PROOF_MAP.md#boundaries).

## Publication audit

The pre-publication audit inspected 75 tracked files and every reachable historical blob:
7 commits, 112 unique blobs. It checked file inventory and commit subjects, known credential
formats/private-key markers, private fleet names and paths, embedded addresses and URL
hosts. No credential or private infrastructure candidates were found. Fleet hosts use
`example.com`, customer/operator names are fictional, and tickets cover only the bundled
example fleet. Public author attribution is intentional. No publication blocker was found;
no history was rewritten.
