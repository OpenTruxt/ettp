"""ETTP capability model."""

from typing import Any

from pydantic import Field

from ettp.protocol import ETTPModel


class Capability(ETTPModel):
    """A named capability an entity can potentially attempt."""

    name: str = Field(min_length=1)
    extensions: dict[str, Any] | None = None
