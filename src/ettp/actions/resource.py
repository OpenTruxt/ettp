"""ETTP resource model."""

from typing import Any

from pydantic import Field

from ettp.protocol import ETTPModel


class Resource(ETTPModel):
    """A resource that an ETTP action may target."""

    type: str = Field(min_length=1)
    id: str = Field(min_length=1)
    name: str = Field(min_length=1)
    metadata: dict[str, Any]
    extensions: dict[str, Any] | None = None
