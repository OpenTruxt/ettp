"""Structured inputs available to the Sprint 3 policy evaluator."""

from typing import Any

from pydantic import Field

from ettp.actions import Action, Resource
from ettp.identity import Entity
from ettp.protocol import ETTPModel


class EvaluationContext(ETTPModel):
    """Explicit, bounded inputs used during deterministic policy evaluation."""

    entity: Entity
    action: Action
    resource: Resource | None = None
    trust_context: dict[str, Any] = Field(default_factory=dict)
    environment: dict[str, Any] = Field(default_factory=dict)
