from __future__ import annotations

import asyncclick as click
import json
from typing import Any, Final
from pathlib import Path
from typing import Any, Final


class JSONParamType(click.ParamType):
    name: str = "json"
    types: Any

    def __init__(self, types: Any = ...) -> None:
        self.types = types

    def convert(self, value: str, param, ctx) -> Any:
        try:
            obj = json.loads(value)
        except json.JSONDecodeError:
            self.fail(f"{value!r} is not valid JSON data", param, ctx)
        if self.types is not ... and not isinstance(obj, self.types):
            self.fail(f"{obj!r} is invalid type: {self.types!s}", param, ctx)
        return obj


JSON_OBJECT: Final = JSONParamType(dict)

ExistingFilePath: Final = click.Path(
    exists=True,
    dir_okay=False,
    path_type=Path,
)
AppendFile: Final = click.File(
    mode="a",
    encoding="utf-8",
)

