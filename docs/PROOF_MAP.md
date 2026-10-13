# Design claims and their evidence

[README](../README.md) · [Executed verification](VERIFICATION.md)

A rollout is a sequence of independently verified target transactions. It stops on the
first failed target; it is not an all-fleet atomic transaction.

| Claim | Implementation | Evidence |
|---|---|---|
| A patch can name an approved operation, not invent shell code | [spec.py](../src/fleet_rollout/spec.py), [yamlsafe.py](../src/fleet_rollout/yamlsafe.py), [validation.py](../src/fleet_rollout/validation.py) | [test_spec.py](../tests/test_spec.py), [test_yamlsafe.py](../tests/test_yamlsafe.py): traversal, duplicate YAML keys, aliases and forbidden commands |
| Staged and restored bytes are read back before installation | [transaction.py](../src/fleet_rollout/transaction.py), [backup.py](../src/fleet_rollout/backup.py) | [test_transaction.py](../tests/test_transaction.py): lossy transport, tampered backups, symlinked paths and partial restores |
| Recovery preserves later edits and unrelated database rows | [transaction.py](../src/fleet_rollout/transaction.py), [scripts.py](../src/fleet_rollout/scripts.py) | [test_rollout.py](../tests/test_rollout.py), [test_scripts.py](../tests/test_scripts.py): another patch's interrupted transaction, manual edits and real SQLite row restores |
| A 200 response with the wrong body halts the rollout | [health.py](../src/fleet_rollout/health.py), [rollout.py](../src/fleet_rollout/rollout.py) | [test_health.py](../tests/test_health.py), [rehearse_rollout.py](../examples/rehearse_rollout.py): syntactically valid config, unhealthy canary, restoration and untouched later targets |
| Fake executors honor the real adapter's file/command contract | [testing.py](../src/fleet_rollout/testing.py), [container.py](../src/fleet_rollout/executors/container.py) | [test_executor_contract.py](../tests/test_executor_contract.py): the same cases run against the fake and actual scripts under a local `sh` |
| Authorization recognizes nested shell context and write-capable flags | [guard/shell.py](../src/fleet_rollout/guard/shell.py), [guard/classify.py](../src/fleet_rollout/guard/classify.py) | [test_guard.py](../tests/test_guard.py), [test_guard_shell.py](../tests/test_guard_shell.py): SSH wrappers, Docker contexts, redirects, protected paths and computed targets |
| Malformed lock metadata still denies concurrent work | [locks.py](../src/fleet_rollout/locks.py) | [test_locks.py](../tests/test_locks.py): a timestamp without a timezone is held, with unknown age, and never silently broken |

## Boundaries

- No live Docker daemon or SSH endpoint was exercised in the local verification. Real
  on-target shell programs, SQLite operations and loopback HTTP probes are exercised
  without those transports; the public Linux workflow covers POSIX-specific contracts.
- The command hook is not a sandbox. It cannot inspect arbitrary program internals, resolve
  every dynamically constructed target, or substitute for keeping production credentials
  outside an agent's session. See the README's [security notes](../README.md#security-notes).
- Tickets and approvals rely on filesystem access controls; they are not cryptographically
  signed human identities. A hash chain detects interior changes, but detecting truncated
  tails requires pinning the head hash outside the writer's control.
- Restore covers recorded file changes and database row changes. It does not remove created
  directories or undo execute-bit changes. Crash/recovery tests exercise process interruption
  and write faults, not every filesystem or machine power-loss scenario.
- Execution is serial. Already completed targets remain patched when a later target fails.
