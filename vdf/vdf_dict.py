# -*- coding: utf-8 -*-

from typing import Generic, TypeVar

from multidict import MultiDict

__all__ = (
    "VDFDict",
)

_VT = TypeVar("_VT")


class VDFDict(MultiDict[_VT], Generic[_VT]):
    """A dictionary that supports duplicate keys."""
    def __str__(self):
        return repr(self)

    def __repr__(self):
        return f"{self.__class__.__name__}({list(self.items())})"
