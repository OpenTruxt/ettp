"""Entity relationship models for ETTP."""

from typing import Any

from pydantic import Field

from ettp.protocol import ETTPModel


class EntityRelationship(ETTPModel):
    """A directional, first-class relationship between ETTP entities."""

    source: str = Field(min_length=1)
    relationship: str = Field(min_length=1)
    target: str = Field(min_length=1)
    metadata: dict[str, Any] | None = None
