# Contributing

Useful contributions:

- A BEC or payee-change pattern the guard misses, with a primary source (FBI IC3, FinCEN, a regulator or a court record) and a made-up example request that shows it.
- IBAN country lengths, with the ISO 13616 registry entry.
- Look-alike cases that slip through, or ordinary domains that are wrongly flagged.

Code changes:

- `ruff check .`, `ruff format --check .`, `python scripts/check.py`, `mypy` and `pytest -q` must pass.
- Every new finding needs a test that fires it and one near miss that does not.
- Use reserved example domains and 555-01xx phone numbers in tests.
