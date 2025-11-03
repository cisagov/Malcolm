#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Protocol, Optional, Any, Callable, List

from scripts.installer.core.config_item import ConfigItem


class ItemStore(Protocol):
    """Protocol describing the minimal surface for item stores.

    Implementations manage a collection of keyed ConfigItem objects and expose
    consistent methods for read/update/visibility and change observation.
    """

    def get_item(self, key: str) -> Optional[ConfigItem]: ...  # noqa: E704

    def get_value(self, key: str) -> Optional[Any]: ...  # noqa: E704

    def set_value(self, key: str, value: Any) -> None: ...  # noqa: E704

    def is_item_visible(self, key: str) -> bool: ...  # noqa: E704

    def all_keys(self) -> List[str]: ...  # noqa: E704

    def observe(self, key: str, callback: Callable[[Any], None]) -> None: ...  # noqa: E704
