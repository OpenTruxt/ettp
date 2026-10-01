"""Revocation model for ETTP authority and delegation state."""

from __future__ import annotations

from datetime import datetime

from pydantic import Field

from ettp.protocol import ETTPModel


class Revocation(ETTPModel):
    """A typed revocation record for credential, delegation, authority, or entity state."""

    id: str = Field(min_length=1)
    target_type: str = Field(default="delegation", min_length=1)
    target_id: str = Field(min_length=1)
    action: str = Field(min_length=1)
    reason: str | None = Field(default=None, min_length=1)
    actor: str | None = Field(default=None, min_length=1)
    issued_at: datetime | None = None
    status: str = "ACTIVE"
