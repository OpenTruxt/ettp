"""Small deterministic benchmark for the Sprint 3 policy engine."""

from __future__ import annotations

from math import ceil
from time import perf_counter

from ettp import Action, Entity
from ettp.policy import Condition, Policy, PolicyEngine, PolicyRegistry


def _make_engine(policy_count: int) -> tuple[Entity, Action, PolicyEngine]:
    """Build a fixed evaluation workload for benchmark measurements."""
    entity = Entity(
        id="ent_benchmark",
        type="AI_AGENT",
        name="benchmark-agent",
        version="1",
        capabilities=["refund.execute"],
        metadata={},
        protocol_version="0.1",
    )
    action = Action(
        id="act_benchmark",
        entity_id=entity.id,
        type="TOOL_CALL",
        target="refund_customer",
        operation="refund",
        arguments={"amount": 100},
    )
    registry = PolicyRegistry()
    for index in range(policy_count):
        registry.register(
            Policy(
                id=f"benchmark.policy.{index:04d}",
                version="1",
                effect="ALLOW",
                conditions=[Condition(field="action.operation", operator="equals", value="refund")],
            )
        )
    return entity, action, PolicyEngine(registry)


def benchmark_samples(policy_count: int, iterations: int = 100) -> tuple[float, ...]:
    """Return individual evaluation durations in milliseconds."""
    entity, action, engine = _make_engine(policy_count)
    samples: list[float] = []
    for _ in range(iterations):
        started = perf_counter()
        engine.evaluate(entity=entity, action=action)
        samples.append((perf_counter() - started) * 1000)
    return tuple(samples)


def percentile(samples: tuple[float, ...], value: float) -> float:
    """Return a nearest-rank percentile from sorted samples."""
    if not samples or not 0 <= value <= 100:
        raise ValueError("percentile requires samples and a value from 0 to 100")
    ordered = sorted(samples)
    index = max(0, ceil(value / 100 * len(ordered)) - 1)
    return ordered[index]


def benchmark(policy_count: int, iterations: int = 100) -> float:
    """Return average evaluation time in milliseconds for a policy count."""
    samples = benchmark_samples(policy_count, iterations)
    return sum(samples) / len(samples)


if __name__ == "__main__":
    for count in (10, 100, 1_000):
        samples = benchmark_samples(count)
        print(
            f"{count} policies: "
            f"p50={percentile(samples, 50):.3f} ms, "
            f"p95={percentile(samples, 95):.3f} ms, "
            f"p99={percentile(samples, 99):.3f} ms"
        )
