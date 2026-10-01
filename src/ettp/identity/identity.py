"""ETTP identity model."""

from datetime import datetime
from typing import Any

from pydantic import Field, field_validator

from ettp.protocol import EntityStatus, ETTPModel

from .relationship import EntityRelationship


class Identity(ETTPModel):
    """A stable, technology-independent identity record."""

    id: str = Field(min_length=1)
    eid: str | None = Field(default=None, min_length=1)
    version: str = Field(min_length=1)
    entity_type: str = Field(min_length=1)
    owner: str | None = Field(default=None, min_length=1)
    issuer: str | None = Field(default=None, min_length=1)
    capabilities: list[str]
    provenance: dict[str, Any] | None = None
    created_at: datetime
    expires_at: datetime | None = None
    status: EntityStatus
    relationships: list[EntityRelationship] | None = None
    extensions: dict[str, Any] | None = None

    @property
    def e_id(self) -> str | None:
        """Compatibility alias for the ETTP EID."""
        return self.eid

    @field_validator("capabilities")
    @classmethod
    def validate_unique_capabilities(cls, capabilities: list[str]) -> list[str]:
        if any(not capability for capability in capabilities):
            raise ValueError("capabilities must contain non-empty strings")
        if len(capabilities) != len(set(capabilities)):
            raise ValueError("capabilities must contain unique values")
        return capabilities
