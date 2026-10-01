"""ETTP policy models."""

from __future__ import annotations

from typing import Any

from pydantic import ConfigDict, Field, model_validator

from ettp.protocol import Effect, ETTPModel


class Condition(ETTPModel):
    """A leaf condition or recursively composed condition group."""

    model_config = ConfigDict(serialize_by_alias=True, populate_by_name=True)

    field: str | None = Field(default=None, min_length=1)
    operator: str | None = Field(default=None, min_length=1)
    value: Any = None
    all: list[Condition] | None = Field(default=None, min_length=1)
    any: list[Condition] | None = Field(default=None, min_length=1)
    not_condition: Condition | None = Field(default=None, alias="not")

    @model_validator(mode="after")
    def validate_shape(self) -> Condition:
        leaf = self.field is not None or self.operator is not None
        group_count = sum(group is not None for group in (self.all, self.any, self.not_condition))
        if leaf and (self.field is None or self.operator is None):
            raise ValueError("leaf conditions require field and operator")
        if leaf and group_count:
            raise ValueError("conditions cannot combine leaf and group forms")
        if not leaf and group_count != 1:
            raise ValueError("conditions require exactly one leaf or logical group")
        return self


class Policy(ETTPModel):
    """A versioned declarative rule describing an effect and conditions."""

    id: str = Field(min_length=1)
    name: str | None = Field(default=None, min_length=1)
    version: str = Field(min_length=1)
    effect: Effect
    conditions: list[Condition]
    priority: int | None = None
    extensions: dict[str, Any] | None = None
