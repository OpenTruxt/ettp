# Contributing to ETTP

Thank you for contributing to the Entity Trust Transfer Protocol.

ETTP is foundational infrastructure. Contributions must preserve protocol
stability, interoperability, security, determinism, and clear separation
between protocol primitives and implementation-specific features.

## Development Environment

ETTP supports Python 3.11 and newer. Use Python 3.13 for the current
development and CI environment.

The project uses:

- uv
- Ruff
- mypy
- pytest
- JSON Schema

Install dependencies with:

```bash
uv sync
```

## Before Opening a Pull Request

Run:

```bash
uv run ruff check .
uv run ruff format --check .
uv run mypy src
uv run pytest
uv run python scripts/validate_schemas.py
```

All checks must pass.

## Protocol Changes

Changes to the protocol surface require particular care.

Do not silently change:

* protocol semantics
* schema structure
* serialization behavior
* identifiers
* decision semantics
* interoperability requirements

Protocol proposals should explain:

1. the problem
2. the proposed change
3. compatibility implications
4. security implications
5. interoperability implications
6. testing requirements

## Dependencies

Do not introduce dependencies without a clear engineering reason.

ETTP core must remain lightweight.

Infrastructure such as web frameworks, databases, queues, cloud SDKs,
or orchestration platforms must not become dependencies of the protocol
core unless explicitly approved.

## Determinism

Protocol behavior must be deterministic wherever the specification
requires deterministic behavior.

Do not introduce an LLM dependency into deterministic protocol evaluation.

## Security

Security-sensitive changes require tests and documentation.

Do not implement cryptographic primitives manually.

Use established cryptographic libraries.

## Tests

New functionality must include appropriate tests.

Security-sensitive behavior should include regression tests.

Protocol changes should include schema/conformance tests where applicable.

## Pull Requests

Pull requests should:

* have a focused purpose
* include tests
* update documentation when behavior changes
* pass CI
* avoid unrelated changes

## Commit Quality

Use clear commit messages describing the change.

Prefer small, reviewable commits over large mixed commits.

## Architectural Rule

Never allow an implementation shortcut to become an accidental protocol
assumption.

ETTP must remain capable of evolving beyond AI agents toward broader
autonomous entities and systems.
