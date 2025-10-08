#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Protocol, Optional, Any, Callable, List

from scripts.installer.core.config_item import ConfigItem


class ItemStore(Protocol):
    """Protocol describing the minimal surface for item stores.

    Implementations manage a collection of keyed ConfigItem objects and expose
    consistent methods for read/update/visibility and change observation.
    """

    def get_item(self, key: str) -> Optional[ConfigItem]:
        ...

    def get_value(self, key: str) -> Optional[Any]:
        ...

    def set_value(self, key: str, value: Any) -> None:
        ...

    def is_item_visible(self, key: str) -> bool:
        ...

    def all_keys(self) -> List[str]:
        ...

    def observe(self, key: str, callback: Callable[[Any], None]) -> None:
        ...
