# ETTP Protocol Schemas — v1

This directory contains the version 1 JSON Schema definitions for the
Entity Trust Transfer Protocol.

The protocol wire format is defined using JSON Schema.

Python runtime models must not become the protocol definition.

The schemas in this directory are language-independent and are intended
to be consumable by implementations in Python, TypeScript, Go, Rust,
and other languages.

Protocol version:

0.1

Schema namespace:

v1

## Schema contract

- Every normative schema uses JSON Schema Draft 2020-12.
- Each schema has a canonical `$id` under
	`https://github.com/OpenTruxt/ettp/schemas/ettp/v1/`.
- Root protocol objects are JSON objects with a `title`, `description`, and
	explicit `required` fields.
- Protocol objects reject undeclared fields with `additionalProperties: false`.
- Extensibility is explicit: object schemas may provide an `extensions` object
	for implementation-defined data. Extension values do not redefine protocol
	fields.
- Cross-schema references use canonical schema `$id` URIs. Reference tests
	must load schemas into a registry and verify resolution, not only inspect
	`$ref` strings.
- Identifiers are opaque, non-empty strings. Schemas do not mandate a DID,
	blockchain, URI, or vendor-specific identifier format.
- Timestamps use the JSON Schema `date-time` format and fixtures validate them
	with a format checker.
- JSON Schema is the wire contract; Python models must not become its source of
	truth.

The schema namespace is `v1`; the current protocol version is `0.1`. Those
values are distinct from the Python package version.

## Shared definitions

`common.schema.json` is a definitions-only support document, not an eleventh
protocol object. It provides the shared `Identifier`, `ProtocolVersion`,
`Timestamp`, `EntityReference`, `ResourceReference`, `Metadata`, and
`NonEmptyString` definitions. Object schemas reference these definitions using
the canonical common-schema `$id`.

## Identity schema

`identity.schema.json` defines an entity's stable identifier and identity
metadata, without binding ETTP to a specific identity technology. Its
`entity_type` is an extensible string. Status is the closed set `ACTIVE`,
`SUSPENDED`, `REVOKED`, and `EXPIRED`. Capabilities describe what an entity can
attempt; they do not grant authorization.

Identity keeps identifiers technology-neutral and supports provenance,
creation/expiration timestamps, capabilities, and the defined lifecycle
statuses. `owner`, `issuer`, `provenance`, and `expires_at` are optional in the
current schema; identity ID, version, entity type, capabilities, creation time,
and status are required.

## Entity schema

`entity.schema.json` describes the protocol participant using the Entity fields
listed in this guide. Entity `type` values remain extensible strings rather
than a closed enum. The required `capabilities` field describes what the entity
can attempt, not what it is currently authorized to do. `metadata` is
descriptive; `extensions` is the explicit implementation-defined extension
point. The schema does not implement physical entities or policy behavior.

## Capability schema

`capability.schema.json` follows the guide's named capability form, such as
`{"name": "customer.read"}`. Names are non-empty extensible strings. A
capability describes what an entity can attempt; it does not imply current
authorization. Resource scopes, operation lists, and policy constraints are
not introduced into this schema because the current guide does not define them.

## Resource schema

`resource.schema.json` follows the guide's resource example: `id`, extensible
`type` (such as `database`, `file`, or `API`), `name`, and descriptive
`metadata`. All four fields are required as shown in the example. Unknown
resource types remain representable; this schema does not impose access or
policy semantics.

## Trust Context schema

`trust-context.schema.json` limits the initial context to entity identity,
capability, AI environment, time, operator, and resource. Location, risk,
provenance, and authorization are not made mandatory protocol fields in this
initial AI-focused context. Implementations may use the explicit `extensions`
object for additional attributes without changing protocol semantics.

## Action schema

`action.schema.json` requires an action ID, entity reference, extensible action
type, target, operation, and arguments. The optional `context` references the
Trust Context schema. Argument values remain data; the schema does not execute
or authorize the action.

## Policy schema

`policy.schema.json` stores a versioned effect and condition records. Each
condition has a field, an extensible operator identifier, and a JSON value.
Effects use the defined `ALLOW`, `BLOCK`, `REQUIRE_APPROVAL`, and `REDACT` set.
Sprint 1 only validates this representation; it does not interpret conditions,
resolve precedence, or evaluate policies.

## Decision schema

`decision.schema.json` records an action ID and one of the four closed decision
effects. A reason and policy ID are optional descriptive links; no evaluator is
implemented by the schema.

## Evidence schema

`evidence.schema.json` records an event, timestamp, entity, action, and
decision. Policy ID and execution details are optional, since an action may be
denied before execution or may not be associated with a policy. Storage,
hash-chaining, and verification are outside Sprint 1.

## Error schema

`error.schema.json` defines the machine-readable error codes and requires an
error code, safe message, and protocol version. Request ID and non-sensitive
details are optional. Implementation-specific sensitive details must not be
exposed.
