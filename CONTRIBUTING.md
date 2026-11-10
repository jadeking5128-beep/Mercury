# Contributing

Contributions are welcome. Keep changes focused, documented, tested, and compatible with the Termux-first goal.

## Before opening a pull request

1. Check existing issues to avoid duplicate work.
2. Read [Security and scope](docs/SECURITY.md) before security-sensitive changes.
3. Do not commit secrets, real target data, or provider credentials.
4. Add or update tests for behavior changes.
5. Update relevant documentation and examples.
6. Run:

```bash
python -m pip install -e ".[api,dev]"
pytest -q
ruff check mercury tests
```

## Engineering expectations

- Maintain Python 3.10+ compatibility.
- Use type hints and useful docstrings.
- Use subprocess argument arrays, never shell strings built from user input.
- Apply explicit timeouts and output bounds to network and subprocess operations.
- Revalidate target scope immediately before network activity.
- Do not follow redirects unless every destination is revalidated.
- Keep API secrets out of logs, exceptions, fixtures, screenshots, and commits.
- Document Termux-specific installation constraints.
- Do not describe a tool as integrated when it is only detected by the registry.

## Pull request checklist

- [ ] Clear problem statement and focused scope.
- [ ] Tests cover success, failure, and relevant security boundaries.
- [ ] Documentation and examples are updated.
- [ ] No credentials, personal data, or live target evidence are included.
- [ ] CI passes on the supported Python matrix.
