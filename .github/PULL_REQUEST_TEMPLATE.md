## Pull Request

### What does this PR do?

<!-- A clear, concise summary of the change. -->

### Motivation / context

<!-- Why is this change needed? Link a related issue with "Closes #123" if applicable. -->

### Risk level

- [ ] Low (docs / tests / non-functional)
- [ ] Medium (detector logic or heuristics)
- [ ] High (core engine, reporter schema, or CI-critical behavior)

### Type of change

- [ ] Bug fix (non-breaking change that fixes an issue)
- [ ] New detection rule (new CWE or variant)
- [ ] False-positive / false-negative fix
- [ ] Performance improvement
- [ ] Documentation update
- [ ] Other (describe below)

### Validation performed

- [ ] `pytest tests -q --tb=short`
- [ ] `python -m benchmarks.nvd_benchmark --fail-under 90 --quiet`
- [ ] `python -m benchmarks.quality_benchmark --fail-under 100 --quiet`
- [ ] `python -m benchmarks.external_corpus --manifest benchmarks/external_manifest.json --fail-under 100 --quiet`

### Backward compatibility

- [ ] No breaking changes
- [ ] Breaking change (explain migration below)

### Reviewer focus areas

<!-- Optional: point reviewers to high-value files / concerns. -->
- 

### Checklist

- [ ] I have added or updated tests for the change
- [ ] All existing tests pass (`pytest tests/`)
- [ ] The benchmark still passes (`python -m benchmarks.nvd_benchmark --fail-under 90 --quiet`)
- [ ] I have updated `CHANGELOG.md` under `[Unreleased]`
- [ ] For new rules: I have added an entry to the detection-coverage table in `README.md`

### Sample output

<!-- Paste an example of `ansede-static` output that demonstrates the change, if applicable. -->
