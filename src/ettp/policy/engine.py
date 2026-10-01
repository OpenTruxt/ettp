"""Policy-engine orchestration for deterministic ETTP decisions."""

from __future__ import annotations

import os
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

from ettp.actions import Action, ActionContext
from ettp.decisions import Decision
from ettp.identity import Authority, Delegation, Entity
from ettp.policy.condition import ConditionEvaluationError
from ettp.policy.context import EvaluationContext
from ettp.policy.evaluator import PolicyEvaluator
from ettp.policy.precedence import PrecedenceResolver
from ettp.policy.registry import PolicyRegistry
from ettp.protocol import Effect, EntityStatus
from ettp.sensitive import (
    DetectorRegistry,
    SensitiveDataPolicy,
    SensitivePolicyResult,
    select_sensitive_policy,
)
from ettp.sensitive.redaction import redact_action

if TYPE_CHECKING:
    from ettp.evidence import JSONLStore


class PolicyEngine:
    """Evaluate registered policies and produce a safe ETTP decision."""

    def __init__(
        self,
        registry: PolicyRegistry,
        evaluator: PolicyEvaluator | None = None,
        precedence: PrecedenceResolver | None = None,
        sensitive_detectors: DetectorRegistry | None = None,
        sensitive_policies: tuple[SensitiveDataPolicy, ...] = (),
        evidence_store: JSONLStore | None = None,
        evidence_path: str | Path | None = None,
    ) -> None:
        from ettp.evidence import JSONLStore

        self._registry = registry
        self._evaluator = evaluator or PolicyEvaluator()
        self._precedence = precedence or PrecedenceResolver()
        self._sensitive_detectors = sensitive_detectors
        self._sensitive_policies = sensitive_policies
        default_path = evidence_path or os.environ.get("ETTP_EVIDENCE_PATH", ".ettp/events.jsonl")
        self._evidence_store = evidence_store or JSONLStore(default_path)

    def evaluate(
        self,
        *,
        entity: Entity,
        action: Action,
        context: ActionContext | None = None,
        authority: Authority | None = None,
        delegation: Delegation | None = None,
        delegation_chain: list[Delegation] | None = None,
        request_id: str | None = None,
    ) -> Decision:
        """Evaluate an action and, when configured, persist its governance result."""
        try:
            decision = self._evaluate_decision(
                entity=entity,
                action=action,
                context=context,
                authority=authority,
                delegation=delegation,
                delegation_chain=delegation_chain,
            )
        except Exception as error:
            decision = Decision(
                id=f"decision:{action.id}",
                action_id=action.id,
                effect=Effect.BLOCK,
                reason=f"Policy evaluation failed safely: {type(error).__name__}.",
                reason_code="POLICY_EVALUATION_FAILED",
            )

        try:
            self._evidence_store.record_decision(
                action=action,
                decision=decision,
                entity=entity,
                context=context,
                authority=authority,
                delegation=delegation,
                delegation_chain=delegation_chain,
                request_id=request_id,
            )
        except Exception as error:
            return Decision(
                id=f"decision:{action.id}",
                action_id=action.id,
                effect=Effect.BLOCK,
                reason=f"Evidence could not be persisted safely: {type(error).__name__}.",
                reason_code="EVIDENCE_WRITE_FAILED",
            )
        return decision

    def _evaluate_decision(
        self,
        *,
        entity: Entity,
        action: Action,
        context: ActionContext | None = None,
        authority: Authority | None = None,
        delegation: Delegation | None = None,
        delegation_chain: list[Delegation] | None = None,
    ) -> Decision:
        decision_id = f"decision:{action.id}"
        if entity.status is not EntityStatus.ACTIVE:
            return Decision(
                id=decision_id,
                action_id=action.id,
                effect=Effect.BLOCK,
                reason=f"Entity lifecycle state {entity.status.value} does not permit actions.",
                reason_code=f"ENTITY_{entity.status.value}",
            )
        if action.entity_id != entity.id:
            return Decision(
                id=decision_id,
                action_id=action.id,
                effect=Effect.BLOCK,
                reason="Action entity does not match the evaluated entity.",
                reason_code="ENTITY_MISMATCH",
            )

        runtime_block = self._enforce_sprint5a_security(
            entity=entity,
            action=action,
            context=context,
            authority=authority,
            delegation=delegation,
            delegation_chain=delegation_chain,
        )
        if runtime_block is not None:
            return runtime_block

        evaluation_context = EvaluationContext(
            entity=entity,
            action=action,
            trust_context=context.model_dump() if context is not None else {},
        )
        sensitive_result = self._evaluate_sensitive(action)
        if sensitive_result is not None:
            return Decision(
                id=decision_id,
                action_id=action.id,
                effect=sensitive_result.policy.effect,
                reason=sensitive_result.reason,
                policy_id=sensitive_result.policy.policy_id,
                policy_version=sensitive_result.policy.version,
                reason_code="SENSITIVE_DATA_DETECTED",
            )
        try:
            evaluations = tuple(
                self._evaluator.evaluate(policy, evaluation_context)
                for policy in self._registry.list()
            )
        except ConditionEvaluationError as error:
            return Decision(
                id=decision_id,
                action_id=action.id,
                effect=Effect.BLOCK,
                reason=f"Policy evaluation failed safely: {error}",
                reason_code="POLICY_EVALUATION_FAILED",
            )
        outcome = self._precedence.resolve(evaluations)
        if outcome is None:
            matched_conditions = [
                explanation
                for evaluation in evaluations
                for explanation in evaluation.matched_explanations
            ]
            failed_conditions = [
                explanation
                for evaluation in evaluations
                for explanation in evaluation.failed_explanations
            ]
            return Decision(
                id=decision_id,
                action_id=action.id,
                effect=Effect.BLOCK,
                reason="No registered policy matched the action; default deny applied.",
                reason_code="DEFAULT_DENY",
                matched_conditions=matched_conditions,
                failed_conditions=failed_conditions,
            )

        evaluation = outcome.evaluation
        matched_reasons = "; ".join(evaluation.matched_explanations)
        failed_reasons = "; ".join(evaluation.failed_explanations)
        reason = (
            f"Policy {evaluation.policy_id} version {evaluation.policy_version}: "
            f"{evaluation.explanation}"
        )
        if matched_reasons:
            reason = f"{reason}. {matched_reasons}"
        if failed_reasons:
            reason = f"{reason}. Failed: {failed_reasons}"
        return Decision(
            id=decision_id,
            action_id=action.id,
            effect=evaluation.effect,
            reason=reason,
            policy_id=evaluation.policy_id,
            policy_version=evaluation.policy_version,
            reason_code=f"POLICY_{evaluation.effect.value}",
            matched_conditions=list(evaluation.matched_explanations),
            failed_conditions=list(evaluation.failed_explanations),
        )

    def redact_action(self, action: Action) -> Action:
        """Return a redacted action when configured sensitive detectors match."""
        if self._sensitive_detectors is None:
            return action
        matches = self._sensitive_detectors.detect(action.arguments, field="arguments")
        return redact_action(action, matches)

    def _enforce_sprint5a_security(
        self,
        *,
        entity: Entity,
        action: Action,
        context: ActionContext | None,
        authority: Authority | None,
        delegation: Delegation | None,
        delegation_chain: list[Delegation] | None,
    ) -> Decision | None:
        if (
            context is not None
            and context.entity_eid is not None
            and entity.eid is not None
            and context.entity_eid != entity.eid
        ):
            return Decision(
                id=f"decision:{action.id}",
                action_id=action.id,
                effect=Effect.BLOCK,
                reason="Entity EID does not match the action context.",
                reason_code="ENTITY_EID_MISMATCH",
            )

        if entity.relationships:
            control_relationships = {
                "subAgentOf",
                "controlledBy",
                "governedBy",
                "parentOf",
                "childOf",
                "delegatesTo",
                "authorizedBy",
            }
            has_control_relationship = any(
                relationship.relationship in control_relationships
                for relationship in entity.relationships
            )
            has_explicit_authority = authority is not None
            has_emergency_authority = bool(context is not None and context.emergency_authority)
            if (
                has_control_relationship
                and not has_explicit_authority
                and not has_emergency_authority
            ):
                return Decision(
                    id=f"decision:{action.id}",
                    action_id=action.id,
                    effect=Effect.BLOCK,
                    reason=(
                        "Control tree relationship exists without explicit authority; "
                        "sub-agent and control relationships do not imply authorization."
                    ),
                    reason_code="CONTROL_TREE_UNAUTHORIZED",
                )
            if has_control_relationship and has_emergency_authority and authority is None:
                return Decision(
                    id=f"decision:{action.id}",
                    action_id=action.id,
                    effect=Effect.BLOCK,
                    reason="Emergency authority requires an explicit authority grant.",
                    reason_code="EMERGENCY_AUTHORITY_REQUIRED",
                )

        if authority is not None:
            now = datetime.now(UTC)
            if authority.grantee is not None and authority.grantee not in {
                entity.id,
                entity.eid,
            }:
                return self._security_block(
                    action,
                    "Authority grantee does not match the entity.",
                    "AUTHORITY_GRANTEE_MISMATCH",
                )
            if authority.issued_at is not None and self._as_utc(authority.issued_at) > now:
                return self._security_block(
                    action,
                    "Authority is not active yet.",
                    "AUTHORITY_NOT_YET_VALID",
                )
            if authority.expires_at is not None and self._as_utc(authority.expires_at) <= now:
                return self._security_block(action, "Authority has expired.", "AUTHORITY_EXPIRED")
            if authority.action is not None and not self._authority_matches_action(
                authority, action
            ):
                return Decision(
                    id=f"decision:{action.id}",
                    action_id=action.id,
                    effect=Effect.BLOCK,
                    reason=(
                        "Granted authority does not cover the requested operation. "
                        f"Required action: {authority.action}, got {action.operation}."
                    ),
                    reason_code="AUTHORITY_SCOPE_MISMATCH",
                )
            if authority.capabilities and not self._authority_covers_action(authority, action):
                return self._security_block(
                    action,
                    "Granted authority does not include the requested capability.",
                    "AUTHORITY_CAPABILITY_MISMATCH",
                )
            if self._authority_constraint_violation(authority, action):
                return self._security_block(
                    action,
                    "Granted authority constraints do not cover the requested action.",
                    "AUTHORITY_CONSTRAINT_VIOLATED",
                )

        if delegation is not None:
            now = datetime.now(UTC)
            if delegation.status != "ACTIVE":
                return Decision(
                    id=f"decision:{action.id}",
                    action_id=action.id,
                    effect=Effect.BLOCK,
                    reason=f"Delegation {delegation.delegation_id} is not active.",
                    reason_code="DELEGATION_INACTIVE",
                )
            if delegation.issued_at is not None and self._as_utc(delegation.issued_at) > now:
                return self._security_block(
                    action,
                    "Delegation is not active yet.",
                    "DELEGATION_NOT_YET_VALID",
                )
            if delegation.expires_at is not None and self._as_utc(delegation.expires_at) <= now:
                return self._security_block(action, "Delegation has expired.", "DELEGATION_EXPIRED")
            if (
                delegation.max_delegation_depth is not None
                and delegation.depth >= delegation.max_delegation_depth
            ):
                return Decision(
                    id=f"decision:{action.id}",
                    action_id=action.id,
                    effect=Effect.BLOCK,
                    reason=(
                        f"Delegation depth exceeded for {delegation.delegation_id}: "
                        f"{delegation.depth} >= {delegation.max_delegation_depth}."
                    ),
                    reason_code="DELEGATION_DEPTH_EXCEEDED",
                )
            if delegation.grantee not in {entity.id, entity.eid or "", action.entity_id}:
                return Decision(
                    id=f"decision:{action.id}",
                    action_id=action.id,
                    effect=Effect.BLOCK,
                    reason="Delegation does not match the entity being evaluated.",
                    reason_code="DELEGATION_ENTITY_MISMATCH",
                )
            try:
                delegated_authority = delegation.attenuated_authority(delegation_chain)
            except (TypeError, ValueError) as error:
                return self._security_block(
                    action,
                    f"Delegated authority is invalid: {type(error).__name__}.",
                    "DELEGATION_AUTHORITY_INVALID",
                )
            if delegated_authority.action is not None and not self._authority_matches_action(
                delegated_authority, action
            ):
                return self._security_block(
                    action,
                    "Delegated authority does not cover the requested operation.",
                    "DELEGATION_SCOPE_MISMATCH",
                )
            if delegated_authority.grantee is not None and delegated_authority.grantee not in {
                entity.id,
                entity.eid,
            }:
                return self._security_block(
                    action,
                    "Delegated authority grantee does not match the entity.",
                    "DELEGATION_ENTITY_MISMATCH",
                )
            if (
                delegated_authority.issued_at is not None
                and self._as_utc(delegated_authority.issued_at) > now
            ):
                return self._security_block(
                    action,
                    "Delegated authority is not active yet.",
                    "DELEGATED_AUTHORITY_NOT_YET_VALID",
                )
            if (
                delegated_authority.expires_at is not None
                and self._as_utc(delegated_authority.expires_at) <= now
            ):
                return self._security_block(
                    action,
                    "Delegated authority has expired.",
                    "DELEGATED_AUTHORITY_EXPIRED",
                )
            if delegated_authority.capabilities and not self._authority_covers_action(
                delegated_authority, action
            ):
                return self._security_block(
                    action,
                    "Delegated authority does not include the requested capability.",
                    "DELEGATION_CAPABILITY_MISMATCH",
                )
            if self._authority_constraint_violation(delegated_authority, action):
                return self._security_block(
                    action,
                    "Delegated authority constraints do not cover the requested action.",
                    "DELEGATION_CONSTRAINT_VIOLATED",
                )

        if (
            delegation is not None
            and delegation.parent_delegation is not None
            and not delegation_chain
        ):
            return self._security_block(
                action,
                "Delegated authority provenance chain is required.",
                "DELEGATION_CHAIN_MISSING",
            )

        if delegation_chain:
            now = datetime.now(UTC)
            for chain_item in delegation_chain:
                if chain_item.status != "ACTIVE":
                    return self._security_block(
                        action,
                        f"Delegation ancestor {chain_item.delegation_id} is not active.",
                        "DELEGATION_ANCESTOR_INACTIVE",
                    )
                if chain_item.issued_at is not None and self._as_utc(chain_item.issued_at) > now:
                    return self._security_block(
                        action,
                        f"Delegation ancestor {chain_item.delegation_id} is not active yet.",
                        "DELEGATION_ANCESTOR_NOT_YET_VALID",
                    )
                if chain_item.expires_at is not None and self._as_utc(chain_item.expires_at) <= now:
                    return self._security_block(
                        action,
                        f"Delegation ancestor {chain_item.delegation_id} has expired.",
                        "DELEGATION_ANCESTOR_EXPIRED",
                    )

        if delegation_chain and delegation is not None and delegation.parent_delegation is not None:
            try:
                validated_chain = delegation.validate_chain(delegation_chain)
            except ValueError as exc:
                return Decision(
                    id=f"decision:{action.id}",
                    action_id=action.id,
                    effect=Effect.BLOCK,
                    reason=f"Delegation provenance invalid: {exc}",
                    reason_code="DELEGATION_PROVENANCE_INVALID",
                )
            if validated_chain != [item.delegation_id for item in delegation_chain]:
                return self._security_block(
                    action,
                    "Delegation chain is not in root-to-leaf order or omits a link.",
                    "DELEGATION_PROVENANCE_INVALID",
                )

        if context is not None and context.delegation_chain:
            if delegation is None:
                return Decision(
                    id=f"decision:{action.id}",
                    action_id=action.id,
                    effect=Effect.BLOCK,
                    reason=(
                        "Action references a delegation chain without a matching delegation object."
                    ),
                    reason_code="DELEGATION_CHAIN_MISSING",
                )
            if delegation.delegation_id not in context.delegation_chain:
                return Decision(
                    id=f"decision:{action.id}",
                    action_id=action.id,
                    effect=Effect.BLOCK,
                    reason="Delegation provenance does not match the action context chain.",
                    reason_code="DELEGATION_CHAIN_MISMATCH",
                )

        return None

    @staticmethod
    def _authority_matches_action(authority: Authority, action: Action) -> bool:
        if authority.action is None:
            return True
        normalized = authority.action.lower().replace("_", ".")
        candidates = {
            action.operation.lower(),
            f"{action.type.lower()}.{action.operation.lower()}",
            action.target.lower(),
        }
        if normalized in candidates or (
            normalized.rsplit(".", maxsplit=1)[-1] == action.operation.lower()
        ):
            return True
        return normalized.endswith(".emergency") and PolicyEngine._authority_covers_action(
            authority, action
        )

    @staticmethod
    def _authority_covers_action(authority: Authority, action: Action) -> bool:
        candidates = {
            action.operation,
            f"{action.type.lower()}.{action.operation}",
            action.target,
        }
        return bool(candidates & set(authority.capabilities))

    @staticmethod
    def _authority_constraint_violation(authority: Authority, action: Action) -> bool:
        constraints = authority.constraints
        operation = action.operation.lower()
        amount = action.arguments.get("amount")
        if (
            amount is not None
            and "max_amount" in constraints
            and PolicyEngine._to_number(amount) > PolicyEngine._to_number(constraints["max_amount"])
        ):
            return True
        if (
            amount is not None
            and "min_amount" in constraints
            and PolicyEngine._to_number(amount) < PolicyEngine._to_number(constraints["min_amount"])
        ):
            return True
        allowed_operations = constraints.get("allowed_operations")
        if allowed_operations is not None and operation not in {
            str(item).lower() for item in allowed_operations
        }:
            return True
        denied_operations = constraints.get("denied_operations", [])
        if operation in {str(item).lower() for item in denied_operations}:
            return True
        allowed_resources = constraints.get("allowed_resources")
        if allowed_resources is not None and action.target not in allowed_resources:
            return True
        allowed_targets = constraints.get("allowed_targets")
        return allowed_targets is not None and action.target not in allowed_targets

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)

    @staticmethod
    def _security_block(action: Action, reason: str, reason_code: str) -> Decision:
        return Decision(
            id=f"decision:{action.id}",
            action_id=action.id,
            effect=Effect.BLOCK,
            reason=reason,
            reason_code=reason_code,
        )

    @staticmethod
    def _to_number(value: Any) -> float:
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            return float(value)
        raise TypeError(f"Unsupported numeric value for authority constraint: {value!r}")

    def _evaluate_sensitive(self, action: Action) -> SensitivePolicyResult | None:
        if self._sensitive_detectors is None or not self._sensitive_policies:
            return None
        matches = self._sensitive_detectors.detect(action.arguments, field="arguments")
        return select_sensitive_policy(matches, self._sensitive_policies)
