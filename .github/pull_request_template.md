## What and why

<!-- One or two sentences. Link the task in docs/PRODUCTION_PLAN.md if there is one. -->

## Checklist

- [ ] `uv run ruff check src tests` and `uv run ruff format --check src tests` pass
- [ ] `uv run mypy src` passes
- [ ] `uv run pytest tests/unit tests/integration` passes
- [ ] No secrets, tokens, or lab credentials in the diff
- [ ] Docs updated (and `CHANGELOG.md` under **Unreleased**) if behaviour changed
- [ ] Safety invariants unchanged (`docs/SECURITY_AND_LIMITATIONS.md`), or the change is explained here
