# Evidence

Raw records the course project cites, kept as produced. Generated certificates and keys
(`*/pki/`) are not tracked.

| Path | What | Commit |
|---|---|---|
| `2026-11-03_tests_windows.log` | verbose `ctest` run on Windows: every check of every suite | in the file header |
| `2026-11-03_tests_linux.log` | the same on Ubuntu 24.04 in WSL2 | in the file header |
| `2026-11-03_bench_windows/` | **first** Windows benchmark run. Times from accept only. Kept because it showed that accept-to-thread-start dominated every arm; not cited as a result | `69b599e` |
| `2026-11-03_bench_windows_run2/` | second Windows run, with thread start recorded per connection. The Windows result in the document | `c08784d` |
| `2026-11-03_bench_linux/` | Linux run in WSL2, records written to the Linux filesystem. The Linux result in the document | `c08784d` |
| `2026-11-03_bench_linux_attempt1_records_on_9p/` | first Linux attempt. Records went to `/mnt/d` over 9p, flushing stalled the server threads, the connection limit was hit and records were lost. Not analysed | `c08784d` |
| `2026-11-03_micro_windows.txt`, `2026-11-03_micro_linux.txt` | `octet-micro`: the in-memory work detection adds per connection | in the file header |

Each benchmark directory holds `server.csv` (one line per connection, columns in
`meta.json`), `client.csv`, `meta.json` (host, platform, commit, seed, arm order) and
`summary.json` (written by `bench/analyse.py`).

Regenerate the document numbers:

```sh
python bench/analyse.py evidence/2026-11-03_bench_windows_run2 --latex docs/generated/2026-11-03_bench_windows_run2.tex --prefix win
python bench/analyse.py evidence/2026-11-03_bench_linux --latex docs/generated/2026-11-03_bench_linux.tex --prefix lin
python bench/analyse.py evidence/2026-11-03_bench_windows --latex docs/generated/2026-11-03_bench_windows.tex --prefix winfirst
python bench/evidence2tex.py evidence docs/generated/evidence_macros.tex
python bench/plot2tex.py evidence/2026-11-03_bench_windows_run2 evidence/2026-11-03_bench_linux docs/generated/effects_plot.tex
```
