"""ETTP entity model."""

from typing import Any, Literal

from pydantic import Field, field_validator

from ettp.protocol import EntityStatus, ETTPModel

from .relationship import EntityRelationship


class Entity(ETTPModel):
    """An autonomous or human entity participating in ETTP."""

    id: str = Field(min_length=1)
    eid: str | None = Field(default=None, min_length=1)
    type: str = Field(min_length=1)
    name: str = Field(min_length=1)
    version: str = Field(min_length=1)
    issuer: str | None = Field(default=None, min_length=1)
    owner: str | None = Field(default=None, min_length=1)
    capabilities: list[str]
    metadata: dict[str, Any]
    protocol_version: Literal["0.1"]
    status: EntityStatus = EntityStatus.ACTIVE
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
