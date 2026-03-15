from __future__ import annotations

from typing import Any, List, Optional, Tuple


class BruteForceDB:
    """Linear baseline that stores key-value pairs in a list."""

    def __init__(self) -> None:
        self.data: List[Tuple[int, Any]] = []

    def insert(self, key: int, value: Any) -> None:
        for i, (k, _) in enumerate(self.data):
            if k == key:
                self.data[i] = (key, value)
                return
        self.data.append((key, value))

    def search(self, key: int) -> Any | None:
        for k, v in self.data:
            if k == key:
                return v
        return None

    def delete(self, key: int) -> bool:
        for i, (k, _) in enumerate(self.data):
            if k == key:
                self.data.pop(i)
                return True
        return False

    def update(self, key: int, new_value: Any) -> bool:
        for i, (k, _) in enumerate(self.data):
            if k == key:
                self.data[i] = (k, new_value)
                return True
        return False

    def range_query(self, start: int, end: int) -> List[Tuple[int, Any]]:
        if start > end:
            return []
        return sorted([(k, v) for k, v in self.data if start <= k <= end], key=lambda item: item[0])

    def get_all(self) -> List[Tuple[int, Any]]:
        return sorted(self.data, key=lambda item: item[0])
