"""Authority model for ETTP delegation and enforcement."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import Field, model_validator

from ettp.protocol import ETTPModel


class Authority(ETTPModel):
    """A bounded grant of authority that explains why an action is allowed."""

    id: str = Field(min_length=1)
    action: str | None = Field(default=None, min_length=1)
    capabilities: list[str] = Field(default_factory=list)
    constraints: dict[str, Any] = Field(default_factory=dict)
    scope: str | None = Field(default=None, min_length=1)
    grantor: str | None = Field(default=None, min_length=1)
    grantee: str | None = Field(default=None, min_length=1)
    issued_at: datetime | None = None
    expires_at: datetime | None = None
    metadata: dict[str, Any] | None = None

    @model_validator(mode="after")
    def validate_authority(self) -> Authority:
        if (
            not self.capabilities
            and self.action is None
            and not self.constraints
            and self.scope is None
        ):
            raise ValueError(
                "authority must define at least one action, capability, scope, or constraint"
            )
        if (
            self.issued_at is not None
            and self.expires_at is not None
            and self.expires_at < self.issued_at
        ):
            raise ValueError("authority expiry must be after issuance")
        return self
