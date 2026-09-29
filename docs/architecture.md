# ETTP Architecture

ETTP separates its language-independent protocol definition from the Python
reference implementation.

## Protocol and implementation boundaries

- JSON Schema defines the protocol wire format under `schemas/ettp/`.
- Python runtime models and validation belong under `src/ettp/`.
- Protocol behavior must not depend on a web framework, database, cloud
  service, or a specific AI-agent framework.
- Schema namespace, protocol version, and Python package version are distinct
  version identifiers.

Sprint 0 establishes this structure without defining protocol objects or
policy behavior. Those are introduced in subsequent sprints.
