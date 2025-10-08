#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from typing import Any, Callable


class ObservableStoreMixin:
    """Mixin providing observer registration utilities for stores.

    Expects subclass to define a dict attribute `_observers: dict[str, list[Callable]]`.
    """

    def observe(self, key: str, callback: Callable[[Any], None]) -> None:
        if key not in self._observers:
            self._observers[key] = []
        if callback not in self._observers[key]:
            self._observers[key].append(callback)

    def unobserve(self, key: str, callback: Callable[[Any], None]) -> None:
        if key in self._observers and callback in self._observers[key]:
            self._observers[key].remove(callback)
            if not self._observers[key]:
                del self._observers[key]

