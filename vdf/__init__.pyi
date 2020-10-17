# -*- coding: utf-8 -*-

from __future__ import annotations

from typing import NamedTuple, Final

__version__: Final[str] = "3.3 1.0"
__author__: Final[tuple[str, str]] = (
    "Rossen Georgiev",
    "Gobot1234",
)

class VersionInfo(NamedTuple):
    major: int
    minor: int
    micro: int
    releaselevel: str

version_info: VersionInfo

from .exceptions import VDFDecodeError
from .io import (
    parse as parse,
    load as load,
    loads as loads,
    dump as dump,
    dumps as dumps,
    binary_load as binary_load,
    binary_loads as binary_loads,
    binary_dump as binary_dump,
    binary_dumps as binary_dumps,
    vbkv_loads as vbkv_loads,
    vbkv_dumps as vbkv_dumps,
)
from .vdf_dict import VDFDict as VDFDict
