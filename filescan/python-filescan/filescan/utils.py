from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterator
from typing import Iterable, Callable, Any


def match_item(a: Any, b: Any) -> bool:
    if isinstance(a, tuple) and isinstance(b, tuple):
        return all((r is ... or l == r) for l, r in zip(a, b))
    return False


def group_items[ItemT, KeyT](
    items: Iterable[ItemT],
    key: Callable[[ItemT], KeyT],
    groups: Iterable[KeyT] | None = None,
) -> Iterator[tuple[KeyT, list[ItemT]]]:
    results = defaultdict(list)
    for item in items:
        results[key(item)].append(item)
    if groups is not None:
        for group in groups:
            matches = []
            for key, value in results.items():
                if match_item(key, group):
                    matches.extend(value)
            yield group, matches
    else:
        yield from results.items()
