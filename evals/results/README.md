# Scoreboards

One JSON file per graded run. Keys are sorted and the indent is fixed, so
`git diff` between two files reads as a list of behaviour changes rather than a
reformat.

`baseline-<provider>-<model>.json` is the reference the scheduled workflow
compares a fresh run against. Model-dependent scores get a 0.05 tolerance,
because a temperature-0 request is still not perfectly repeatable across a
provider's own deployments. The deterministic classes get no tolerance.

To refresh a baseline after a deliberate change (new cases, reworded tool
descriptions, a different model), run the harness and commit the output under
the matching name:

```bash
python -m evals.run --all --out evals/results/baseline-<provider>-<model>.json
```

The `run.generated_at` field is the only value expected to change between two
otherwise identical runs.
