<!--
Title: <type>: <summary> (#<issue>)   e.g. fix: treat satellites_visible=255 as unknown (#16)
Rules: AGENTS.md §7–§8. Open as draft while iterating (drafts are not auto-reviewed).
Do not add AI attribution lines. A human approves and merges.
-->

Closes #

## What changed and why

## How it was verified
<!-- Exact commands and their summary lines. Write "not run" for anything you did not run. -->
```text
$ python -m pytest
<last line>
$ ruff check src tests scripts backend
<output>
```
- Frontend (`npm --prefix frontend test` / `run build`): <summary or "not applicable">
- Stage-1 regression (`aegis benchmark --out <scratch> --no-figures`; required if
  `src/aegisflight/{features,detectors,fusion,pipeline.py,sources,mavlink,config.py}`,
  `configs/` or `models/` changed): `TP/FP/TN/FN = … / … / … / …` or "not applicable"

## Contracts and safety
- [ ] No frozen contract changed (`AGENTS.md` §4). If one changed: approval link + `docs/HANDOFF.md` note: …
- [ ] No security boundary weakened (`AGENTS.md` §5): serial receive-only, local-only attack tooling, no `0.0.0.0` default, no secrets
- [ ] Docs updated where behaviour changed (`docs/DEVELOPMENT.md` list)

## Evidence (only if this PR adds or changes a reported number)
| Number | Environment tag | Claim class | Artifact path | Command to regenerate |
|---|---|---|---|---|

## Risks and follow-ups
