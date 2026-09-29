# Security Policy

Security is a core design requirement of ETTP.

ETTP is intended to become foundational trust infrastructure for
autonomous systems. Security vulnerabilities may therefore have
significant downstream consequences.

## Reporting a Vulnerability

Please do not disclose security vulnerabilities publicly before the
maintainers have had an opportunity to investigate them.

Use the repository's private security reporting mechanism where available.

## Security Principles

ETTP development follows these principles:

- fail safely
- validate untrusted input
- preserve entity identity
- preserve action identity
- prevent authorization bypass
- maintain deterministic behavior where required
- protect evidence integrity
- avoid unnecessary dependencies
- use established cryptographic primitives
- test adversarial inputs

## Scope

Security testing will progressively cover:

- malformed protocol data
- unexpected types
- oversized payloads
- serialization attacks
- identity mismatches
- capability mismatches
- policy bypasses
- evidence modification
- duplicate events
- recursive structures
- dependency vulnerabilities

Detailed security testing will be introduced in later development sprints.
