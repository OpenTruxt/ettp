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

## Sprint 3 policy evaluation

The policy engine keeps policy evaluation separate from policy storage and
conflict resolution:

```text
Action + Entity
  -> EvaluationContext
  -> PolicyRegistry
  -> PolicyEvaluator
  -> PrecedenceResolver
  -> Decision
```

Condition evaluation is deterministic and uses only protocol-approved dotted
fields. Unsupported roots, private paths, and unknown operators fail closed.

When multiple policies match, precedence is deterministic:

1. Explicit policy `priority`, when present
2. `BLOCK`
3. `REQUIRE_APPROVAL`
4. `REDACT`
5. `ALLOW`

Policies with the same priority and effect are ordered by stable policy ID and
then policy version. Registry registration order is never used for precedence.
