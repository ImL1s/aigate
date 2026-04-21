# Perf Regression Fixture

## Fixture choice: `lodash@4.17.21`

The perf-regression test (`test_monorepo_perf_regression.py`) uses
`lodash@4.17.21` as a representative npm workload.

### Why lodash?

| Property | Value |
|---|---|
| Unpacked files | ~650 `.js` files |
| Unpacked size | ~1.5 MB |
| Zero dependencies | Yes — no transitive install noise |
| Reproducible | Version-pinned, no lock file drift |
| openat() calls | ~1300–1800 (file copy + .bin symlink) |

The large file count generates enough `openat()` syscalls that strace
ptrace overhead is measurable (typically 10–40%) without requiring
network access beyond the first warm-up run.

### Preferred alternative (plan §2.7.5)

The plan recommends `create-react-app@5.0.1` for a more realistic
monorepo workload (~45 s clean install).  Use it when:

1. `AIGATE_RUN_PERF_FULL=1` is set in CI (heavier job stage).
2. You need R5 worst-case budget data (45 s × 1.5 = 67.5 s).

The lodash fixture is sufficient for trend detection and is 20–50×
faster to execute.

### npm cache

`npm install --prefer-offline` is used.  The warm-up run populates
`~/.npm` before timing begins, so clean and traced runs both hit
cache.  First-ever run (cold cache, no network) will be skipped by
the `npm install --prefer-offline` fallback:

```
npm ERR! code ENOVERSIONS
```

In that case the test skips with a human-readable message.

### strace flags (mirrors BirdcageBackend)

```
strace -f -e trace=connect,openat,write,execve,clone -o /dev/null -- npm install
```

`-o /dev/null` avoids FIFO I/O skewing timing; the syscall set mirrors
`StraceObserver.argv_prefix()` exactly.

### Acceptance criterion (REV-J)

`t_traced / t_clean ≤ 1.5`

Failure is surfaced as `pytest.skip` with a `coverage.warning`-style
log message, NOT a hard CI fail, until Phase 3 raises the budget.
