"""ETTP action and context models."""

from datetime import datetime
from typing import Any

from pydantic import Field, model_validator

from ettp.protocol import ETTPModel


class ActionContext(ETTPModel):
    """Optional bounded context associated with an action evaluation."""

    identity: str | None = Field(default=None, min_length=1)
    entity_eid: str | None = Field(default=None, min_length=1)
    capability: str | None = Field(default=None, min_length=1)
    authority: str | None = Field(default=None, min_length=1)
    delegation: str | None = Field(default=None, min_length=1)
    delegation_chain: list[str] | None = None
    emergency_authority: bool | None = None
    environment: dict[str, Any] | None = None
    time: datetime | None = None
    operator: str | None = Field(default=None, min_length=1)
    resource: str | None = Field(default=None, min_length=1)
    extensions: dict[str, Any] | None = None

    @model_validator(mode="after")
    def validate_non_empty(self) -> "ActionContext":
        if not self.model_dump(exclude_none=True):
            raise ValueError("action context must contain at least one property")
        return self


class Action(ETTPModel):
    """A request by an entity to perform an operation against a target."""

    id: str = Field(min_length=1)
    entity_id: str = Field(min_length=1)
    type: str = Field(min_length=1)
    target: str = Field(min_length=1)
    operation: str = Field(min_length=1)
    arguments: dict[str, Any]
    context: ActionContext | None = None
    extensions: dict[str, Any] | None = None
