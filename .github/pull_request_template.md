## What & why

<!-- One or two sentences. Link the issue or README section this addresses, if relevant. -->

## Detection impact

<!-- Every PR that touches rules, capture, or the catalogue MUST answer this. -->

- [ ] No detection impact, **or** the scorecard is attached / linked below.
- [ ] If recall improved or FP changed, `eval/baseline.json` is updated **in this PR** so the metric move is a reviewable diff (never silent drift).

```
recall:     __ / 10   (baseline: 0.9)
precision:  __
FP count:   __        (baseline: 0)
ruleset:    ET-Open/suricata-7.0.7/<date>
```

## Checklist

- [ ] `docker compose config` passes.
- [ ] No secret committed (gitleaks clean); no key/`.env`/`wg0.conf` staged.
- [ ] Self-referential rules stay in `demo.rules` (never counted as detection).
- [ ] New author rules match generalizable attack traits, not the sim's own paths/strings.
- [ ] CI is green (validate · secrets · unit · rules · sast · containers · detection).
