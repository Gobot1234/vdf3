# -*- coding: utf-8 -*-

from typing import Optional

__all__ = (
    "VDFDecodeError",
)


class VDFDecodeError(SyntaxError):
    def __init__(
        self, msg: str, lineno: Optional[int] = None, filename: Optional[str] = None, line: Optional[str] = None
    ):
        self.msg = msg
        self.lineno = lineno
        self.filename = filename
        self.line = line
        super().__init__(msg, lineno, filename, line)
