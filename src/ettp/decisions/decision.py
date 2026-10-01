"""ETTP decision model."""

from datetime import datetime
from typing import Any

from pydantic import Field

from ettp.protocol import Effect, ETTPModel


class Decision(ETTPModel):
    """A deterministic outcome associated with an ETTP action."""

    id: str = Field(min_length=1)
    action_id: str = Field(min_length=1)
    effect: Effect
    reason: str | None = Field(default=None, min_length=1)
    policy_id: str | None = Field(default=None, min_length=1)
    policy_version: str | None = Field(default=None, min_length=1)
    reason_code: str | None = Field(default=None, min_length=1)
    matched_conditions: list[str] | None = None
    failed_conditions: list[str] | None = None
    request_id: str | None = Field(default=None, min_length=1)
    timestamp: datetime | None = None
    extensions: dict[str, Any] | None = None
