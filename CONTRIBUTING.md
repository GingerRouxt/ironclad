# Contributing

Use synthetic reproductions and keep credentials, personal reports and private machine details out of issues and commits. Report vulnerabilities through [SECURITY.md](SECURITY.md).

Use mise runtimes and uv for Python. Run `mise exec -- uv run --offline python -m unittest discover -s tests -v` and `node --test tests/model.test.cjs`. Full local validation is documented in [releasing](docs/RELEASING.md). Do not run privileged tests or change services without explicit authorization.

Contributions should explain the problem, resulting behavior, tests and limits. Preserve upstream license notices and add positive, negative and legitimate-workload cases for detection changes.
