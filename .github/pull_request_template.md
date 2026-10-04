## Summary

<!-- What does this change and why? Link the issue: Fixes #123 -->

## Type

- [ ] Bug fix
- [ ] New feature (ecosystem, intel source, output format, console page, …)
- [ ] Documentation
- [ ] Refactoring / tests

## Checklist

- [ ] `python3 -m pytest` passes (offline)
- [ ] `python3 -m pyflakes agent server tests` is clean
- [ ] New behaviour has tests (including a negative / false-positive case for detection rules)
- [ ] Agent is still a single file and imports without side effects
- [ ] New DB columns are nullable; agent ↔ backend contract test still passes
- [ ] Console: no inline scripts, no raw HTML, new menu entries are routed
- [ ] Docs updated (README / `docs/` / CHANGELOG "Unreleased")
- [ ] Live check against the real service done (for new ecosystems/distros/feeds) — describe below

## Testing notes
