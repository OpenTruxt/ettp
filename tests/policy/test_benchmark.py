from __future__ import annotations

import pytest
from policy_engine import benchmark_samples, percentile


def test_benchmark_reports_percentiles() -> None:
    samples = benchmark_samples(10, iterations=5)

    assert len(samples) == 5
    assert percentile(samples, 50) >= 0
    assert percentile(samples, 95) >= percentile(samples, 50)
    assert percentile(samples, 99) >= percentile(samples, 95)


@pytest.mark.parametrize("value", (-1, 101))
def test_percentile_rejects_invalid_values(value: int) -> None:
    with pytest.raises(ValueError):
        percentile((1.0, 2.0), value)
