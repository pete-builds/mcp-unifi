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

## Committed samples

Two files here are illustrative samples from real runs on 2026-08-21, not
baselines. They exist so a reader can see the format and a first result without
running anything, and nothing compares against them.

`sample-2026-08-21-deterministic-only.json`
: `python -m evals.run --all` with no model credentials configured. Refusal
  16/16, audit fidelity 8/8, and the two model-dependent classes recorded as
  skipped with the reason. This is what CI sees on a fork with no key.

`sample-2026-08-21-groq-llama-3.3-70b-focused.json`
: The focused tier only, against Llama 3.3 70B through a self-hosted LiteLLM
  gateway. 17 of 25 correct, one case answered in prose with no tool call, and
  **seven cases lost to HTTP 429**: the free provider tier ran out of quota
  partway through and put the deployment into an eight-minute cooldown. Of the
  18 cases that got a model response, 17 were correct.

That 429 block is the reason this is a sample and not a baseline. A run that
lost 28% of its cases to throttling is not a number anything should be graded
against, and the harness records it as `error` rather than quietly scoring it as
a miss precisely so the distinction is visible in the file. Committing a
baseline should wait for a provider tier that can complete a full sweep.
