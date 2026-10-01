"""Delegation primitives for ETTP authority propagation."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Literal

from pydantic import Field, model_validator

from ettp.protocol import ETTPModel

from .authority import Authority


class Delegation(ETTPModel):
    """A delegated grant of authority with bounded depth and provenance."""

    delegation_id: str = Field(min_length=1)
    grantor: str = Field(min_length=1)
    grantee: str = Field(min_length=1)
    authority: Authority | str
    capabilities: list[str] = Field(default_factory=list)
    constraints: dict[str, Any] = Field(default_factory=dict)
    scope: str | None = Field(default=None, min_length=1)
    issued_at: datetime | None = None
    expires_at: datetime | None = None
    parent_delegation: str | None = Field(default=None, min_length=1)
    depth: int = Field(default=0, ge=0)
    status: Literal["ACTIVE", "REVOKED", "EXPIRED", "PENDING"] = "ACTIVE"
    revocation_reference: str | None = Field(default=None, min_length=1)
    signature: str | None = Field(default=None, min_length=1)
    max_delegation_depth: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_depth_and_timing(self) -> Delegation:
        if self.parent_delegation is not None and self.depth < 1:
            self.depth = 1
        if self.max_delegation_depth is not None and self.depth > self.max_delegation_depth:
            raise ValueError("delegation depth exceeds the configured maximum")
        if (
            self.issued_at is not None
            and self.expires_at is not None
            and self.expires_at < self.issued_at
        ):
            raise ValueError("delegation expiry must be after issuance")
        return self

    def validate_chain(self, known_delegations: list[Delegation] | None = None) -> list[str]:
        """Validate the delegation ancestry and return the root-to-leaf chain."""
        if self.parent_delegation == self.delegation_id:
            raise ValueError("delegation cannot reference itself as parent")

        if known_delegations is None:
            known_delegations = []

        chain = [self.delegation_id]
        current_id = self.parent_delegation
        child = self
        seen: set[str] = set()

        while current_id is not None:
            if current_id in seen:
                raise ValueError("delegation chain contains a cycle")
            seen.add(current_id)
            parent = next(
                (item for item in known_delegations if item.delegation_id == current_id),
                None,
            )
            if parent is None:
                if self.parent_delegation is not None:
                    raise ValueError(f"parent delegation not found: {current_id}")
                break
            if parent.grantee != child.grantor:
                raise ValueError("delegation chain violates the grantor/grantee ancestry contract")
            chain.insert(0, parent.delegation_id)
            child = parent
            current_id = parent.parent_delegation

        if self.max_delegation_depth is not None and len(chain) - 1 > self.max_delegation_depth:
            raise ValueError("delegation depth exceeds the configured maximum")

        return chain

    def attenuated_authority(
        self,
        known_delegations: list[Delegation] | None = None,
    ) -> Authority:
        """Return a grant bounded by this delegation and every known ancestor."""
        known_delegations = known_delegations or []
        parent: Delegation | None = None
        parent_authority: Authority | None = None
        if self.parent_delegation is not None:
            parent = next(
                (
                    item
                    for item in known_delegations
                    if item.delegation_id == self.parent_delegation
                ),
                None,
            )
            if parent is None:
                raise ValueError("parent delegation is required to attenuate child authority")
            if parent.status != "ACTIVE":
                raise ValueError("parent delegation is not active")
            self.validate_chain(known_delegations)
            parent_authority = parent.attenuated_authority(known_delegations)

        if isinstance(self.authority, str):
            authority = Authority(
                id=f"{self.delegation_id}:authority",
                action=self.authority,
                capabilities=list(dict.fromkeys(self.capabilities)),
                constraints=dict(self.constraints),
                scope=self.scope,
                grantor=self.grantor,
                grantee=self.grantee,
            )
        else:
            authority = self.authority.model_copy(deep=True)
            delegated_capabilities = set(self.capabilities)
            authority_capabilities = set(authority.capabilities)
            authority.capabilities = sorted(authority_capabilities & delegated_capabilities)
            authority.constraints = self._attenuate_constraints(
                authority.constraints,
                self.constraints,
            )
            if self.scope is not None:
                if authority.scope is not None and not self._scope_is_within(
                    self.scope, authority.scope
                ):
                    raise ValueError("delegation scope exceeds the parent authority scope")
                authority.scope = self.scope
        if self.grantor is not None and authority.grantor is None:
            authority.grantor = self.grantor
        if self.grantee is not None and authority.grantee is None:
            authority.grantee = self.grantee

        if parent_authority is not None:
            if parent_authority.action is not None and authority.action != parent_authority.action:
                raise ValueError("child delegation attempts to broaden its parent's action scope")
            authority.capabilities = sorted(
                set(authority.capabilities) & set(parent_authority.capabilities)
            )
            authority.constraints = self._attenuate_constraints(
                parent_authority.constraints,
                authority.constraints,
            )
            issued_dates = [
                _as_utc(value)
                for value in (parent_authority.issued_at, authority.issued_at)
                if value is not None
            ]
            expiration_dates = [
                _as_utc(value)
                for value in (parent_authority.expires_at, authority.expires_at)
                if value is not None
            ]
            authority.issued_at = max(issued_dates) if issued_dates else None
            authority.expires_at = min(expiration_dates) if expiration_dates else None
            if parent_authority.scope is not None and (
                authority.scope is None
                or not self._scope_is_within(authority.scope, parent_authority.scope)
            ):
                raise ValueError("child delegation attempts to broaden its parent's scope")
        return authority

    @staticmethod
    def _attenuate_constraints(
        parent: dict[str, Any],
        child: dict[str, Any],
    ) -> dict[str, Any]:
        """Combine known bounds conservatively; never replace a bound with a looser one."""
        constraints = dict(parent)
        for key, value in child.items():
            if key not in constraints:
                constraints[key] = value
            elif key == "max_amount":
                constraints[key] = min(float(constraints[key]), float(value))
            elif key == "min_amount":
                constraints[key] = max(float(constraints[key]), float(value))
            elif key in {"allowed_operations", "allowed_resources", "allowed_targets"}:
                parent_values = set(constraints[key])
                constraints[key] = sorted(parent_values & set(value))
            elif key == "denied_operations":
                constraints[key] = sorted(set(constraints[key]) | set(value))
            elif constraints[key] != value:
                # Unknown constraint semantics cannot safely be relaxed by a child.
                continue
        return constraints

    @staticmethod
    def _scope_is_within(child_scope: str, parent_scope: str) -> bool:
        """Treat exact scope matches and slash-delimited descendants as attenuation."""
        return child_scope == parent_scope or child_scope.startswith(f"{parent_scope.rstrip('/')}/")

    def chain(self) -> list[str]:
        """Return the chain from the root delegation to this delegation."""
        if self.parent_delegation is None:
            return [self.delegation_id]
        return [self.parent_delegation, self.delegation_id]


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
