from __future__ import annotations

import importlib
from bisect import bisect_left, bisect_right
from dataclasses import dataclass, field
from math import ceil
from pathlib import Path
from typing import Any, List, Optional, Tuple


@dataclass
class BPlusTreeNode:
    is_leaf: bool = False
    keys: List[int] = field(default_factory=list)
    children: List["BPlusTreeNode"] = field(default_factory=list)
    values: List[Any] = field(default_factory=list)
    next: Optional["BPlusTreeNode"] = None


class BPlusTree:
    def __init__(self, order: int = 4) -> None:
        if order < 3:
            raise ValueError("order must be at least 3")

        self.order = order
        self.max_keys = order - 1
        self.root = BPlusTreeNode(is_leaf=True)

    def search(self, key: int) -> Any | None:
        # Search for a key in the B+ tree. Return the associated value if found, else None.
        # Traverse from root to appropriate leaf node.
        leaf = self._find_leaf(key)
        idx = bisect_left(leaf.keys, key)
        if idx < len(leaf.keys) and leaf.keys[idx] == key:
            return leaf.values[idx]
        return None

    def insert(self, key: int, value: Any) -> None:
        """
        Insert key-value pair into the B+ tree.
        Handle root splitting if necessary.
        Maintain sorted order and balance properties.
        """
        self._validate_key(key)

        split_result = self._insert_non_full(self.root, key, value)
        if split_result is not None:
            promoted_key, right_node = split_result
            new_root = BPlusTreeNode(is_leaf=False)
            new_root.keys = [promoted_key]
            new_root.children = [self.root, right_node]
            self.root = new_root

    def _insert_non_full(self, node: BPlusTreeNode, key: int, value: Any) -> Optional[Tuple[int, BPlusTreeNode]]:
        # Recursive helper to insert and split nodes if they overflow.
        if node.is_leaf:
            idx = bisect_left(node.keys, key)

            if idx < len(node.keys) and node.keys[idx] == key:
                node.values[idx] = value
                return None

            node.keys.insert(idx, key)
            node.values.insert(idx, value)

            if len(node.keys) <= self.max_keys:
                return None

            right = BPlusTreeNode(is_leaf=True)
            split_idx = len(node.keys) // 2

            right.keys = node.keys[split_idx:]
            right.values = node.values[split_idx:]

            node.keys = node.keys[:split_idx]
            node.values = node.values[:split_idx]

            right.next = node.next
            node.next = right

            return right.keys[0], right

        child_index = bisect_right(node.keys, key)
        split_result = self._insert_non_full(node.children[child_index], key, value)

        if split_result is not None:
            promoted_key, right_child = split_result
            node.keys.insert(child_index, promoted_key)
            node.children.insert(child_index + 1, right_child)

        if len(node.keys) <= self.max_keys:
            return None

        right_internal = BPlusTreeNode(is_leaf=False)
        mid = len(node.keys) // 2
        promoted = node.keys[mid]

        right_internal.keys = node.keys[mid + 1 :]
        right_internal.children = node.children[mid + 1 :]

        node.keys = node.keys[:mid]
        node.children = node.children[: mid + 1]

        return promoted, right_internal

    def _split_child(self, parent: BPlusTreeNode, index: int) -> None:
        """
        Split the parent child at the given index.
        For leaves: preserve linked-list structure and copy right-leaf first key to the parent.
        For internal nodes: promote middle key and split children.
        """
        child = parent.children[index]

        if child.is_leaf:
            right = BPlusTreeNode(is_leaf=True)
            split_idx = len(child.keys) // 2

            right.keys = child.keys[split_idx:]
            right.values = child.values[split_idx:]

            child.keys = child.keys[:split_idx]
            child.values = child.values[:split_idx]

            right.next = child.next
            child.next = right

            parent.keys.insert(index, right.keys[0])
            parent.children.insert(index + 1, right)
            return

        right = BPlusTreeNode(is_leaf=False)
        mid = len(child.keys) // 2
        promoted = child.keys[mid]

        right.keys = child.keys[mid + 1 :]
        right.children = child.children[mid + 1 :]

        child.keys = child.keys[:mid]
        child.children = child.children[: mid + 1]

        parent.keys.insert(index, promoted)
        parent.children.insert(index + 1, right)

    def delete(self, key: int) -> bool:
        """
        Delete key from the B+ tree.
        Handle underflow by borrowing from siblings or merging nodes.
        Update root if it becomes empty.
        Return True if deletion succeeded, False otherwise.
        """
        self._validate_key(key)

        deleted = self._delete(self.root, key)

        if not self.root.is_leaf and len(self.root.keys) == 0:
            self.root = self.root.children[0]

        return deleted

    def _delete(self, node: BPlusTreeNode, key: int) -> bool:
        # Recursive helper for deletion. Handle leaf and internal nodes.
        # Ensure all nodes maintain minimum keys after deletion.
        if node.is_leaf:
            idx = bisect_left(node.keys, key)
            if idx >= len(node.keys) or node.keys[idx] != key:
                return False

            node.keys.pop(idx)
            node.values.pop(idx)
            return True

        child_index = bisect_right(node.keys, key)
        deleted = self._delete(node.children[child_index], key)

        if not deleted:
            return False

        child = node.children[child_index]
        if len(child.keys) < self._min_keys(child):
            child_index = self._fill_child(node, child_index)

        self._refresh_separators_around(node, child_index)
        return True

    def _fill_child(self, node: BPlusTreeNode, index: int) -> int:
        # Ensure child at given index has enough keys by borrowing from siblings or merging.
        if index > 0 and len(node.children[index - 1].keys) > self._min_keys(node.children[index - 1]):
            self._borrow_from_prev(node, index)
            return index

        if index < len(node.children) - 1 and len(node.children[index + 1].keys) > self._min_keys(node.children[index + 1]):
            self._borrow_from_next(node, index)
            return index

        if index < len(node.children) - 1:
            self._merge(node, index)
            return index

        self._merge(node, index - 1)
        return index - 1

    def _borrow_from_prev(self, node: BPlusTreeNode, index: int) -> None:
        # Borrow a key from the left sibling to prevent underflow.
        child = node.children[index]
        sibling = node.children[index - 1]

        if child.is_leaf:
            child.keys.insert(0, sibling.keys.pop())
            child.values.insert(0, sibling.values.pop())
            node.keys[index - 1] = child.keys[0]
            return

        child.keys.insert(0, node.keys[index - 1])
        node.keys[index - 1] = sibling.keys.pop()
        child.children.insert(0, sibling.children.pop())

    def _borrow_from_next(self, node: BPlusTreeNode, index: int) -> None:
        # Borrow a key from the right sibling to prevent underflow.
        child = node.children[index]
        sibling = node.children[index + 1]

        if child.is_leaf:
            child.keys.append(sibling.keys.pop(0))
            child.values.append(sibling.values.pop(0))
            node.keys[index] = sibling.keys[0]
            return

        child.keys.append(node.keys[index])
        node.keys[index] = sibling.keys.pop(0)
        child.children.append(sibling.children.pop(0))

    def _merge(self, node: BPlusTreeNode, index: int) -> None:
        # Merge child at index with its right sibling. Update parent keys.
        left = node.children[index]
        right = node.children[index + 1]

        if left.is_leaf:
            left.keys.extend(right.keys)
            left.values.extend(right.values)
            left.next = right.next
        else:
            left.keys.append(node.keys[index])
            left.keys.extend(right.keys)
            left.children.extend(right.children)

        node.keys.pop(index)
        node.children.pop(index + 1)

    def update(self, key: int, new_value: Any) -> bool:
        # Update value associated with an existing key. Return True if successful.
        self._validate_key(key)

        leaf = self._find_leaf(key)
        idx = bisect_left(leaf.keys, key)
        if idx < len(leaf.keys) and leaf.keys[idx] == key:
            leaf.values[idx] = new_value
            return True
        return False

    def range_query(self, start_key: int, end_key: int) -> List[Tuple[int, Any]]:
        """
        Return all key-value pairs where start_key <= key <= end_key.
        Traverse leaf nodes using next pointers for efficient range scans.
        """
        self._validate_key(start_key)
        self._validate_key(end_key)

        if start_key > end_key:
            return []

        result: List[Tuple[int, Any]] = []
        leaf = self._find_leaf(start_key)

        while leaf is not None:
            for i, key in enumerate(leaf.keys):
                if key < start_key:
                    continue
                if key > end_key:
                    return result
                result.append((key, leaf.values[i]))
            leaf = leaf.next

        return result

    def get_all(self) -> List[Tuple[int, Any]]:
        # Return all key-value pairs in sorted order using linked leaves.
        result: List[Tuple[int, Any]] = []
        leaf = self._leftmost_leaf()

        while leaf is not None:
            result.extend(zip(leaf.keys, leaf.values))
            leaf = leaf.next

        return result

    def visualize_tree(self):
        # Build and return a Graphviz Digraph for the current B+ tree state.
        graphviz_module = importlib.import_module("graphviz")
        Digraph = graphviz_module.Digraph

        dot = Digraph(comment="B+ Tree")
        dot.attr("graph", rankdir="TB", splines="polyline")
        dot.attr("node", shape="box", style="rounded", fontname="Helvetica")
        dot.attr("edge", fontname="Helvetica")

        self._add_nodes(dot, self.root)
        self._add_edges(dot, self.root)
        return dot

    def _add_nodes(self, dot, node):
        node_id = f"n{id(node)}"

        if node.is_leaf:
            if node.keys:
                pairs = [f"{k}:{node.values[i]}" for i, k in enumerate(node.keys)]
                label = "Leaf\\n" + " | ".join(pairs)
            else:
                label = "Leaf\\nempty"
            dot.node(node_id, label=label)
        else:
            keys_label = " | ".join(str(key) for key in node.keys) if node.keys else "empty"
            label = "Internal\\n" + keys_label
            dot.node(node_id, label=label)

        if not node.is_leaf:
            for child in node.children:
                self._add_nodes(dot, child)

    def _add_edges(self, dot, node):
        node_id = f"n{id(node)}"

        if node.is_leaf:
            if node.next is not None:
                next_id = f"n{id(node.next)}"
                dot.edge(node_id, next_id, style="dashed", color="blue", label="next", constraint="false")
            return

        for child in node.children:
            child_id = f"n{id(child)}"
            dot.edge(node_id, child_id)
            self._add_edges(dot, child)

    def _find_leaf(self, key: int) -> BPlusTreeNode:
        node = self.root
        while not node.is_leaf:
            idx = bisect_right(node.keys, key)
            node = node.children[idx]
        return node

    def _leftmost_leaf(self) -> BPlusTreeNode:
        node = self.root
        while not node.is_leaf:
            node = node.children[0]
        return node

    def _validate_key(self, key: int) -> None:
        if not isinstance(key, int):
            raise TypeError("BPlusTree currently supports integer keys only")

    def _min_keys(self, node: BPlusTreeNode) -> int:
        if node is self.root:
            return 1 if not node.is_leaf else 0
        if node.is_leaf:
            return ceil((self.order - 1) / 2)
        return ceil(self.order / 2) - 1

    def _refresh_separators_around(self, parent: BPlusTreeNode, child_index: int) -> None:
        if child_index > 0 and child_index < len(parent.children):
            sep = self._first_key(parent.children[child_index])
            if sep is not None:
                parent.keys[child_index - 1] = sep

        if child_index + 1 < len(parent.children):
            sep = self._first_key(parent.children[child_index + 1])
            if sep is not None:
                parent.keys[child_index] = sep

    def _first_key(self, node: BPlusTreeNode) -> Optional[int]:
        current = node
        while not current.is_leaf:
            current = current.children[0]
        return current.keys[0] if current.keys else None


def main() -> None:
    tree = BPlusTree(order=4)
    for key in [15, 3, 8, 22, 7, 30, 1, 12, 18, 25, 5, 10]:
        tree.insert(key, f"user_{key}")

    dot = tree.visualize_tree()

    # Build a second, slightly larger demo tree for an additional visualization.
    larger_tree = BPlusTree(order=4)
    for key in [15, 3, 8, 22, 7, 30, 1, 12, 18, 25, 5, 10, 2, 4, 6, 9, 11, 13, 14, 16, 17, 19, 20, 21, 23, 24, 26, 27]:
        larger_tree.insert(key, f"user_{key}")
    larger_dot = larger_tree.visualize_tree()

    output_dir = Path(__file__).resolve().parent / "visualizations"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_base = output_dir / "bplustree_demo"
    larger_output_base = output_dir / "bplustree_demo_large"

    try:
        rendered_path = dot.render(filename=str(output_base), format="png", cleanup=True)
        rendered_larger_path = larger_dot.render(filename=str(larger_output_base), format="png", cleanup=True)
        print(f"B+ tree visualization generated: {rendered_path}")
        print(f"Larger B+ tree visualization generated: {rendered_larger_path}")
    except Exception as exc:
        dot_path = output_base.with_suffix(".dot")
        larger_dot_path = larger_output_base.with_suffix(".dot")
        dot.save(filename=str(dot_path))
        larger_dot.save(filename=str(larger_dot_path))
        print(f"Could not render PNG automatically: {exc}")
        print(f"DOT source saved at: {dot_path}")
        print(f"Larger DOT source saved at: {larger_dot_path}")


if __name__ == "__main__":
    main()
