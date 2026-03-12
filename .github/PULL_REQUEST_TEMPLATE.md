## Summary

<!-- What does this PR do? 1-3 bullet points. -->

-
-

## Type of change

- [ ] Bug fix (false positive / false negative)
- [ ] New security check
- [ ] CVE database update
- [ ] Documentation
- [ ] CI / tooling
- [ ] Other

## Related issue

Closes #

## Checklist

- [ ] `pytest` passes locally
- [ ] `ruff check pipeguard tests` passes
- [ ] `mypy pipeguard` passes
- [ ] New check has fixtures in `tests/fixtures/` (real workflow examples, no synthetic YAML)
- [ ] README security checks table updated (if new rule added)
- [ ] No secrets, tokens, or API keys in code or fixtures
