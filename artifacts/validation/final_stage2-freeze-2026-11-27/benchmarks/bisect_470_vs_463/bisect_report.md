# Extended benchmark, ML on (models/isoforest.joblib 3fe74cdd...), no-grace FP drift: bisect

Environment: SIM. Each row is a full extended-benchmark run (`scripts/benchmark_extended.py --model models/isoforest.joblib`, 116 sessions) of that commit in a scratch worktree (read-only: no commit was made from them), same machine, same shipped model. `decisions md5` is the md5 of the decompressed decisions.csv (69,600 per-decision rows).

| code | decisions md5 | v2 no-grace TP / FP / TN / FN | v2 5 s grace TP / FP / TN / FN |
|---|---|---|---|
| committed artifacts/benchmarks_extended (41311fa) | `29a662b74e71` | 9088 / 470 / 42209 / 1133 | 9088 / 39 / 40813 / 1133 |
| 41311fa | `29a662b74e71` | 9088 / 470 / 42209 / 1133 | 9088 / 39 / 40813 / 1133 |
| 444f385 (= eae85e6^) | `29a662b74e71` | 9088 / 470 / 42209 / 1133 | 9088 / 39 / 40813 / 1133 |
| eae85e6 | `db9c672c099f` | 9088 / 463 / 42216 / 1133 | 9088 / 39 / 40813 / 1133 |
| 8605cea | `db9c672c099f` | 9088 / 463 / 42216 / 1133 | 9088 / 39 / 40813 / 1133 |
| 3a10573 | `477a2eb732fe` | 9072 / 462 / 42217 / 1149 | 9072 / 39 / 40813 / 1149 |
| 03e4de9 | `477a2eb732fe` | 9072 / 462 / 42217 / 1149 | 9072 / 39 / 40813 / 1149 |
| 63241a1 | `477a2eb732fe` | 9072 / 462 / 42217 / 1149 | 9072 / 39 / 40813 / 1149 |
| b6d2ab7 | `477a2eb732fe` | 9072 / 462 / 42217 / 1149 | 9072 / 39 / 40813 / 1149 |
| 8e58003 = freeze tag (extended_ml_on) | `477a2eb732fe` | 9072 / 462 / 42217 / 1149 | 9072 / 39 / 40813 / 1149 |

Pairwise per-session diffs (rows that differ between consecutive steps; see `diff_*.txt`):

- committed artifacts/benchmarks_extended (41311fa) -> 41311fa: total differing rows: 0 sessions 116 116 (`diff_committed__41311fa.txt`)
- 41311fa -> 444f385 (= eae85e6^): total differing rows: 0 sessions 116 116 (`diff_41311fa__444f385.txt`)
- 444f385 (= eae85e6^) -> eae85e6: total differing rows: 228 sessions 116 116 (`diff_444f385__eae85e6.txt`)
- eae85e6 -> 8605cea: total differing rows: 0 sessions 116 116 (`diff_eae85e6__8605cea.txt`)
- 8605cea -> 3a10573: total differing rows: 3992 sessions 116 116 (`diff_8605cea__3a10573.txt`)
- 3a10573 -> 03e4de9: total differing rows: 0 sessions 116 116 (`diff_3a10573__03e4de9.txt`)
- 03e4de9 -> 63241a1: total differing rows: 0 sessions 116 116 (`diff_03e4de9__63241a1.txt`)
- 63241a1 -> b6d2ab7: total differing rows: 0 sessions 116 116 (`diff_63241a1__b6d2ab7.txt`)
- b6d2ab7 -> 8e58003 = freeze tag (extended_ml_on): total differing rows: 0 sessions 116 116 (`diff_b6d2ab7__8e58003.txt`)
