import re
import struct
from binascii import crc32
from io import BufferedIOBase, BytesIO, StringIO
from typing import Any, Generator, Mapping, Type, TypeVar

from .vdf_dict import VDFDict

__all__ = (
    "parse",
    "load",
    "loads",
    "dump",
    "dumps",
    "binary_load",
    "binary_loads",
    "binary_dump",
    "binary_dumps",
    "vbkv_loads",
    "vbkv_dumps",
)

M = TypeVar("M", bound=Mapping)

BOMS = "\ufffe\ufeff"
KV_RE = re.compile(
    r'^("(?P<qkey>(?:\\.|[^\\"])+)"|(?P<key>#?[a-z0-9\-\_\\\?$%<>]+))'
    r"([ \t]*("
    r'"(?P<qval>(?:\\.|[^\\"])*)(?P<vq_end>")?'
    r"|(?P<val>(?:(?<!/)/(?!/)|[a-z0-9\-\_\\\?\*\.$<>])+)"
    r"|(?P<sblock>{[ \t]*)(?P<eblock>})?"
    r"))?",
    flags=re.I,
)


def strip_bom(line: str) -> str:
    return line.lstrip(BOMS)


# string escaping
_UNESCAPE_CHAR_MAP = {
    r"\n": "\n",
    r"\t": "\t",
    r"\v": "\v",
    r"\b": "\b",
    r"\r": "\r",
    r"\f": "\f",
    r"\a": "\a",
    r"\\": "\\",
    r"\?": "?",
    r"\"": '"',
    r"\'": "'",
}
_ESCAPE_CHAR_MAP = {v: k for k, v in _UNESCAPE_CHAR_MAP.items()}


def _re_escape_match(m: re.Match) -> str:
    return _ESCAPE_CHAR_MAP[m.group()]


def _re_unescape_match(m: re.Match) -> str:
    return _UNESCAPE_CHAR_MAP[m.group()]


def _escape(text: str) -> str:
    return re.sub(r"[\n\t\v\b\r\f\a\\?\"']", _re_escape_match, text)


def _unescape(text: str) -> str:
    return re.sub(
        r"(\\n|\\t|\\v|\\b|\\r|\\f|\\a|\\\\|\\\?|\\\"|\\')", _re_unescape_match, text
    )


# parsing and dumping for KV1
def parse(
    s: str,
    mapper: Type[M] = VDFDict,
    escaped: bool = True,
) -> M:
    """Deserialize a string to a Python object.

    Parameters
    -----------
    s: :class:`str`
        The string to parse into a :class:`.VDFDict`.
    mapper: Type[:class:`collections.Mapping`]
        A :class:`dict`-like class to be used after deserialization. Default is :class:`VDFDict`.
    escaped: :class:`bool`
        Whether or not there are escape codes in the ``s``
    """
    if not issubclass(mapper, Mapping):
        raise TypeError(f"Expected mapper to be subclass of dict, got {mapper.__class__}")
    if not isinstance(s, BufferedIOBase):
        raise TypeError(
            "Expected fp to be a file-like object supporting line iteration"
        )

    stack = [mapper()]
    expect_bracket = False

    for lineno, line in enumerate(s, 1):
        if lineno == 1:
            line = strip_bom(line)

        line = line.lstrip()

        # skip empty and comment lines
        if line == "" or line[0] == "/":
            continue

        # one level deeper
        if line[0] == "{":
            expect_bracket = False
            continue

        if expect_bracket:
            raise SyntaxError(
                f"vdf.parse: expected opening bracket {getattr(s, 'name', f'<{s.__class__.__name__}>')} {lineno} 1"
                f" {line}"
            )

        # one level back
        if line[0] == "}":
            if len(stack) > 1:
                stack.pop()
                continue

            raise SyntaxError(
                f"vdf.parse: one too many closing brackets {getattr(s, 'name', f'<{s.__class__.__name__}>')}{lineno}"
                f" 0 {line}"
            )

        # parse keyvalue pairs
        while True:
            match = KV_RE.match(line)

            if not match:
                try:
                    line += next(s)
                    continue
                except StopIteration:
                    raise SyntaxError(
                        f"vdf.parse: unexpected EOF (open key quote?) "
                        f"{getattr(s, 'name', f'<{s.__class__.__name__}>')}, {lineno} 0 {line}"
                    )

            key = (
                match.group("key")
                if match.group("qkey") is None
                else match.group("qkey")
            )
            val = (
                match.group("val")
                if match.group("qval") is None
                else match.group("qval")
            )

            if escaped:
                key = _unescape(key)

            # we have a key with value in parenthesis, so we make a new dict obj (level deeper)
            if val is None:
                _m = mapper()
                stack[-1][key] = _m

                if match.group('eblock') is None:
                    # only expect a bracket if it's not already closed or on the same line
                    stack.append(_m)
                    if match.group('sblock') is None:
                        expect_bracket = True

            # we've matched a simple keyvalue pair, map it to the last dict obj in the stack
            else:
                # if the value is line consume one more line and try to match again,
                # until we get the KeyValue pair
                if match.group("vq_end") is None and match.group("qval") is not None:
                    try:
                        line += next(s)
                        continue
                    except StopIteration:
                        raise SyntaxError(
                            f"vdf.parse: unexpected EOF (open quote for value?) "
                            f"{getattr(s, 'name', f'<{s.__class__.__name__}>')} {lineno} 0 {line}"
                        )

                stack[-1][key] = _unescape(val) if escaped else val

            # exit the loop
            break

    if len(stack) != 1:
        raise SyntaxError(
            f"vdf.parse: unclosed parenthesis or quotes (EOF) "
            f"{getattr(s, 'name', f'<{s.__class__.__name__}>')}, {lineno} 0 {line}"
        )

    return stack.pop()


def loads(s: str, **kwargs: Any) -> M:
    """
    Deserialize a :class:`str` containing a VDF document to a Python object.
    """
    fp = StringIO(s)
    return parse(fp, **kwargs)


def load(fp: BufferedIOBase, **kwargs: Any) -> M:
    """Deserialize a :class:`str` containing a VDF document to a :class:`.VDFDict`."""
    return parse(fp, **kwargs)


def dumps(obj: M, pretty: bool = False, escaped: bool = True) -> str:
    """Serialize ``obj`` to a VDF formatted :class:`str`."""
    if not isinstance(obj, Mapping):
        raise TypeError("Expected data to be a Mapping")

    return "".join(_dump_gen(obj, pretty, escaped))


def dump(obj: M, fp: BufferedIOBase, pretty: bool = False, escaped: bool = True) -> None:
    """Dump a :class:`.VDFDict` a VDF formatted stream."""
    if not isinstance(obj, Mapping):
        raise TypeError(f"Expected data to be an instance of dict not {obj.__class__}")
    if not isinstance(fp, BufferedIOBase):
        raise TypeError(f"Expected fp to be an BufferedIOBase not {fp.__class__}")

    for chunk in _dump_gen(obj, pretty, escaped):
        fp.write(chunk)


def _dump_gen(data: M, pretty: bool = False, escaped: bool = True, level: int = 0) -> Generator[str, None, None]:
    indent = "\t"
    line_indent = ""

    if pretty:
        line_indent = indent * level

    for key, value in data.items():
        if escaped and isinstance(key, str):
            key = _escape(key)

        if isinstance(value, Mapping):
            yield '{0}"{1}"\n{0}}\n'.format(line_indent, key)
            for chunk in _dump_gen(value, pretty, escaped, level + 1):
                yield chunk
            yield "{}}\n".format(line_indent)
        else:
            if escaped and isinstance(value, str):
                value = _escape(value)

            yield f'{line_indent}"{key}" "{value}"\n'


# binary VDF
class BASE_INT(int):
    def __repr__(self):
        return f"{self.__class__.__name__}({int(self)})"


class UINT_64(BASE_INT):
    pass


class INT_64(BASE_INT):
    pass


class POINTER(BASE_INT):
    pass


class COLOR(BASE_INT):
    pass


BIN_NONE = b"\x00"
BIN_STRING = b"\x01"
BIN_INT32 = b"\x02"
BIN_FLOAT32 = b"\x03"
BIN_POINTER = b"\x04"
BIN_WIDESTRING = b"\x05"
BIN_COLOUR = b"\x06"
BIN_UINT64 = b"\x07"
BIN_END = b"\x08"
BIN_INT64 = b"\x0A"
BIN_END_ALT = b"\x0B"


def binary_loads(
    b: bytes, mapper: Type[M] = VDFDict, alt_format: bool = False, raise_on_remaining: bool = True
) -> M:
    """Deserialize bytes to a Python object.

    Parameters
    -----------
    b: :class:`bytes`
        The bytes containing a VDF in "binary form" to parse into a :class:`.VDFDict`.
    mapper: Type[:class:`collections.Mapping`]
        A :class:`dict`-like class to be used after deserialization. Default is :class:`VDFDict`.
    alt_format: :class:`bool`
        Whether or not to use the alternative format. Defaults to ``False``.
    raise_on_remaining: :class:`bool`
        Whether or not to raise an :exc:`SyntaxError` if there is more data to read.
    """
    if not isinstance(b, bytes):
        raise TypeError(f"Expected s to be bytes, got {b.__class__}")

    return binary_load(BytesIO(b), mapper, alt_format, raise_on_remaining)


def binary_load(
    fp: BufferedIOBase,
    mapper: Type[M] = VDFDict,
    alt_format: bool = False,
    raise_on_remaining: bool = False,
) -> M:
    """Deserialize bytes to a Python object.

    Parameters
    -----------
    fp: :class:`BufferedIOBase`
        A buffer containing the VDF info.
    mapper: Type[:class:`collections.Mapping`]
        A :class:`dict`-like class to be used after deserialization. Default is :class:`VDFDict`.
    alt_format: :class:`bool`
        Whether or not to use the alternative format. Defaults to ``False``.
    raise_on_remaining: :class:`bool`
        Whether or not to raise an :exc:`SyntaxError` if there is more data to read.
    """
    if not isinstance(fp, BufferedIOBase):
        raise TypeError(f"fp should be an IOBase not {type(fp)}")
    if not (fp.seekable() and fp.readable()):
        raise ValueError(f"File buffer {fp!r} must be seekable and readable")
    if not issubclass(mapper, Mapping):
        raise TypeError(f"Expected mapper to be subclass of dict, got {type(mapper)}")

    # helpers
    int32 = struct.Struct("<i")
    uint64 = struct.Struct("<Q")
    int64 = struct.Struct("<q")
    float32 = struct.Struct("<f")

    def read_string(fp, wide=False):
        buf, end = b"", -1
        offset = fp.tell()

        # locate string end
        while end == -1:
            chunk = fp.read(64)

            if chunk == b"":
                raise SyntaxError("Unterminated cstring (offset: %d)" % offset)

            buf += chunk
            end = buf.find(b"\x00\x00" if wide else b"\x00")

        if wide:
            end += end % 2

        # rewind fp
        fp.seek(end - len(buf) + (2 if wide else 1), 1)

        # decode string
        result = buf[:end]

        return result.decode("utf-16") if wide else result.decode("utf-8", "replace")

    stack = [mapper()]
    CURRENT_BIN_END = BIN_END if not alt_format else BIN_END_ALT

    for t in iter(lambda: fp.read(1), b""):
        if t == CURRENT_BIN_END:
            if len(stack) > 1:
                stack.pop()
                continue
            break

        key = read_string(fp)

        if t == BIN_NONE:
            _m = mapper()
            stack[-1][key] = _m
            stack.append(_m)
        elif t == BIN_STRING:
            stack[-1][key] = read_string(fp)
        elif t == BIN_WIDESTRING:
            stack[-1][key] = read_string(fp, wide=True)
        elif t in (BIN_INT32, BIN_POINTER, BIN_COLOUR):
            val = int32.unpack(fp.read(int32.size))[0]

            if t == BIN_POINTER:
                val = POINTER(val)
            elif t == BIN_COLOUR:
                val = COLOR(val)

            stack[-1][key] = val
        elif t == BIN_UINT64:
            stack[-1][key] = UINT_64(uint64.unpack(fp.read(int64.size))[0])
        elif t == BIN_INT64:
            stack[-1][key] = INT_64(int64.unpack(fp.read(int64.size))[0])
        elif t == BIN_FLOAT32:
            stack[-1][key] = float32.unpack(fp.read(float32.size))[0]
        else:
            raise SyntaxError(f"Unknown data type at offset {fp.tell() - 1}: {t!r}")

    if len(stack) != 1:
        raise SyntaxError("Reached EOF, but Binary VDF is incomplete")
    if raise_on_remaining and fp.read(1) != b"":
        fp.seek(-1, 1)
        raise SyntaxError(
            "Binary VDF ended at offset %d, but there is more data remaining"
            % (fp.tell() - 1)
        )

    return stack.pop()


def binary_dumps(obj: M, **kwargs: Any):
    """Serialize ``obj`` to a binary VDF formatted ``bytes``."""
    buf = BytesIO()
    binary_dump(obj, buf, **kwargs)
    return buf.getvalue()


def binary_dump(obj: M, fp: BufferedIOBase, **kwargs: Any) -> None:
    """Serialize ``obj`` to a binary VDF formatted :class:`bytes` and write it to a :class:`BufferedIOBase`"""
    if not isinstance(obj, Mapping):
        raise TypeError("Expected obj to be type of Mapping")
    if isinstance(fp, BufferedIOBase):
        raise TypeError(f"Expected fp to be a BufferedIOBase not {fp.__class__}")

    for chunk in _binary_dump_gen(obj, **kwargs):
        fp.write(chunk)


def _binary_dump_gen(obj: M, level: int = 0, alt_format: bool = False) -> Generator[bytes, None, None]:
    if level == 0 and len(obj) == 0:
        return

    int32 = struct.Struct("<i")
    uint64 = struct.Struct("<Q")
    int64 = struct.Struct("<q")
    float32 = struct.Struct("<f")

    for key, value in obj.items():
        if not isinstance(key, str):
            raise TypeError("dict keys must be of type str, got %s" % type(key))
        key = key.encode("utf-8")

        if isinstance(value, Mapping):
            yield BIN_NONE + key + BIN_NONE
            for chunk in _binary_dump_gen(value, level + 1, alt_format=alt_format):
                yield chunk
        elif isinstance(value, UINT_64):
            yield BIN_UINT64 + key + BIN_NONE + uint64.pack(value)
        elif isinstance(value, INT_64):
            yield BIN_INT64 + key + BIN_NONE + int64.pack(value)
        elif isinstance(value, str):
            try:
                value = value.encode("utf-8") + BIN_NONE
                yield BIN_STRING
            except UnicodeError:
                value = value.encode("utf-16") + BIN_NONE * 2
                yield BIN_WIDESTRING
            yield key + BIN_NONE + value
        elif isinstance(value, float):
            yield BIN_FLOAT32 + key + BIN_NONE + float32.pack(value)
        elif isinstance(value, (COLOR, POINTER, int, int)):
            if isinstance(value, COLOR):
                yield BIN_COLOUR
            elif isinstance(value, POINTER):
                yield BIN_POINTER
            else:
                yield BIN_INT32
            yield key + BIN_NONE
            yield int32.pack(value)
        else:
            raise TypeError(f"Unsupported type: {value.__class__}")

    yield BIN_END if not alt_format else BIN_END_ALT


def vbkv_loads(s: bytes, **kwargs) -> M:
    """Deserialize bytes containing a VBKV to a Python object.

    mapper: Type[:class:`collections.Mapping`]
        A :class:`dict`-like class to be used after deserialization. Default is :class:`VDFDict`.
    """
    if s[:4] != b"VBKV":
        raise ValueError("Invalid header")

    checksum = struct.unpack("<i", s[4:8])[0]

    if checksum != crc32(s[8:]):
        raise ValueError("Invalid checksum")

    return binary_loads(s[8:], alt_format=True, **kwargs)


def vbkv_dumps(obj: M) -> bytes:
    """Serialize ``obj`` to a VBKV formatted :class:`bytes`."""
    data = b"".join(_binary_dump_gen(obj, alt_format=True))
    checksum = crc32(data)

    return b"VBKV" + struct.pack("<i", checksum) + data
