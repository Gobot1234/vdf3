import functools
import re
import struct
from binascii import crc32
from collections.abc import Mapping
from io import BytesIO, StringIO

from cpython cimport list

from .exceptions import VDFDecodeError
from .vdf_dict import VDFDict

__all__ = (
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


cdef str BOMS = "\ufffe\ufeff"
cdef str CLOSING_BRACE = "}"
cdef str OPENING_BRACE = "{"
cdef str COMMENTER = "/"
cdef KV_RE = re.compile(
    r'^("(?P<qkey>(?:\\.|[^\\"])+)"|(?P<key>#?[a-z0-9\-_\\?$%<>]+))'
    r"([ \t]*("
    r'"(?P<qval>(?:\\.|[^\\"])*)(?P<vq_end>")?'
    r"|(?P<val>(?:(?<!/)/(?!/)|[a-z0-9\-_\\?*.$<>])+)"
    r"|(?P<sblock>{[ \t]*)(?P<eblock>})?"
    r"))?",
    flags=re.I,
)
cdef _UNESCAPE_RE = re.compile(r"(\\n|\\t|\\v|\\b|\\r|\\f|\\a|\\\\|\\\?|\\\"|\\')")
cdef _ESCAPE_RE = re.compile(r"[\n\t\v\b\r\f\a\\?\"']")

# string escaping
cdef dict _UNESCAPE_CHAR_MAP = {
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
cdef dict _ESCAPE_CHAR_MAP = {v: k for k, v in _UNESCAPE_CHAR_MAP.items()}



cdef str _re_escape_match(m):
    return _ESCAPE_CHAR_MAP[m.group()]


cdef str _re_unescape_match(m):
    return _UNESCAPE_CHAR_MAP[m.group()]


cdef str _escape(str text):
    return _ESCAPE_RE.sub(_re_escape_match, text)


cdef str _unescape(str text):
    return _UNESCAPE_RE.sub(_re_unescape_match, text)


cdef str strip_bom(str line):
    return line.lstrip(BOMS)


# parsing and dumping for KV1
cdef parse(
    in_stream,
    int escaped,
):
    cdef list stack = list((VDFDict(),))
    cdef int expect_bracket = False
    cdef str line
    cdef int lineno
    for lineno, line in enumerate(in_stream, 1):
        if lineno == 1:
            line = strip_bom(line)

        line = line.lstrip()
        if not line:
            continue

        first_char = line[0]
        # skip empty and comment lines
        if first_char == COMMENTER:
            continue

        # one level deeper
        elif first_char == OPENING_BRACE:
            expect_bracket = False
            continue

        elif expect_bracket:
            raise VDFDecodeError(
                msg="expected opening bracket",
                lineno=lineno,
                filename=getattr(in_stream, 'name', f'<{in_stream.__class__.__name__}>'),
                line=line,
            )

        # one level back
        if first_char == CLOSING_BRACE:
            if len(stack) > 1:
                stack.pop()
                continue

            raise VDFDecodeError(
                msg="too many closing brackets",
                lineno=lineno,
                filename=getattr(in_stream, 'name', f'<{in_stream.__class__.__name__}>'),
                line=line,
            )

        # parse keyvalue pairs
        while True:
            match = KV_RE.match(line)

            if match is None:
                try:
                    line += next(in_stream)
                    continue
                except StopIteration:
                    raise VDFDecodeError(
                        msg="unexpected EOF",
                        lineno=lineno,
                        filename=getattr(in_stream, 'name', f'<{in_stream.__class__.__name__}>'),
                        line=line,
                    ) from None

            key = match["key"] if match["qkey"] is None else match["qkey"]
            val = match["val"] if match["qval"] is None else match["qval"]

            if escaped:
                key = _unescape(key)

            # we have a key with value in parenthesis, so we make a new dict obj (level deeper)
            if val is None:
                _m = VDFDict()
                stack[-1][key] = _m

                if match['eblock'] is None:
                    # only expect a bracket if it's not already closed or on the same line
                    stack.append(_m)
                    if match['sblock'] is None:
                        expect_bracket = True

            # we've matched a simple keyvalue pair, map it to the last dict obj in the stack
            else:
                # if the value is line consume one more line and try to match again,
                # until we get the KeyValue pair
                if match["vq_end"] is None and match["qval"] is not None:
                    try:
                        line += next(in_stream)
                        continue
                    except StopIteration:
                        raise VDFDecodeError(
                            msg="unexpected EOF",
                            lineno=lineno,
                            filename=getattr(in_stream, 'name', f'<{in_stream.__class__.__name__}>'),
                            line=line,
                        )

                stack[-1][key] = _unescape(val) if escaped else val

            # exit the loop
            break

    if len(stack) != 1:
        raise VDFDecodeError(
            msg="unclosed parenthesis or quotes",
            lineno=lineno,
            filename=getattr(in_stream, 'name', f'<{in_stream.__class__.__name__}>'),
            line=line,
        )

    return stack.pop()


cpdef loads(s, int escaped = True):
    s = StringIO(s)
    return parse(s, escaped)


cpdef load(fp, int escaped):
    return parse(fp, escaped)


cpdef str dumps(obj, int pretty = False, int escaped = True):
    """Serialize ``obj`` to a VDF formatted :class:`str`."""
    return "".join(_dump_gen(obj, list(), pretty=pretty, escaped=escaped))


cpdef dump(obj, fp, int pretty = False, int escaped = True):
    """Dump a :class:`.VDFDict` a VDF formatted stream."""

    fp.write(dumps(obj, pretty, escaped))


cpdef list _dump_gen(obj, list ret, int pretty=False, int escaped=True, int level=0):
    cdef str indent = "\t"
    cdef str line_indent = indent * level if pretty else ""

    for key, value in obj.items():
        if escaped and isinstance(key, str):
            key = _escape(key)

        if isinstance(value, Mapping):
            ret.append('{0}"{1}"\n{0}}\n'.format(line_indent, key))
            ret.append(_dump_gen(value, ret, pretty, escaped, level + 1))
            ret.append("{}}\n".format(line_indent))
        else:
            if escaped and isinstance(value, str):
                value = _escape(value)
            ret.append(f'{line_indent}"{key}" "{value}"\n')
    return ret

# binary VDF
cdef class BASE_INT(int):
    def __repr__(self) -> str:
        return f"{self.__class__.__name__}({int(self)})"


cdef class UINT_64(BASE_INT):
    pass


cdef class INT_64(BASE_INT):
    pass


cdef class POINTER(BASE_INT):
    pass


cdef class COLOR(BASE_INT):
    pass


cdef bytes BIN_NONE = b"\x00"
cdef bytes BIN_STRING = b"\x01"
cdef bytes BIN_INT32 = b"\x02"
cdef bytes BIN_FLOAT32 = b"\x03"
cdef bytes BIN_POINTER = b"\x04"
cdef bytes BIN_WIDESTRING = b"\x05"
cdef bytes BIN_COLOUR = b"\x06"
cdef bytes BIN_UINT64 = b"\x07"
cdef bytes BIN_END = b"\x08"
cdef bytes BIN_INT64 = b"\x0A"
cdef bytes BIN_END_ALT = b"\x0B"


cpdef binary_loads(bytes b, int alt_format = False, int raise_on_remaining = True):
    """Deserialize bytes to a Python object.

    Parameters
    -----------
    b: :class:`bytes`
        The bytes containing a VDF in "binary form" to parse into a :class:`.VDFDict`.
    alt_format: :class:`bool`
        Whether or not to use the alternative format. Defaults to ``False``.
    raise_on_remaining: :class:`bool`
        Whether or not to raise an :exc:`VDFDecodeError` if there is more data to read.
    """
    return binary_load(BytesIO(b), alt_format, raise_on_remaining)

cdef str _read_string(fp, int wide=False):
    buf, end = b"", -1
    offset = fp.tell()

    # locate string end
    while end == -1:
        chunk = fp.read(64)

        if not chunk:
            raise VDFDecodeError(f"Unterminated cstring (offset: {offset})")

        buf += chunk
        end = buf.find(b"\x00\x00" if wide else b"\x00")

    if wide:
        end += end % 2

    # rewind fp
    fp.seek(end - len(buf) + (2 if wide else 1), 1)

    # decode string
    result = buf[:end]

    return result.decode("utf-16") if wide else result.decode("utf-8", "replace")

cpdef binary_load(
    fp,
    int alt_format=False,
    int raise_on_remaining=False,
):
    """Deserialize bytes to a Python object.

    Parameters
    -----------
    fp: :class:`BufferedIOBase`
        A buffer containing the VDF info.
    mapper: type[:class:`collections.Mapping`]
        A :class:`dict`-like class to be used after deserialization. Default is :class:`VDFDict`.
    alt_format: :class:`bool`
        Whether or not to use the alternative format. Defaults to ``False``.
    raise_on_remaining: :class:`bool`
        Whether or not to raise an :exc:`VDFDecodeError` if there is more data to read.
    """
    # helpers
    cdef int32 = struct.Struct("<i")
    cdef uint64 = struct.Struct("<Q")
    cdef int64 = struct.Struct("<q")
    cdef float32 = struct.Struct("<f")
    cdef list stack = list((VDFDict(),))
    cdef bytes CURRENT_BIN_END = BIN_END if not alt_format else BIN_END_ALT
    func = functools.partial(fp.read, 1)  # lambdas seem to cause a compiler crash atm
    for t in iter(func, b""):
        if t == CURRENT_BIN_END:
            if len(stack) > 1:
                stack.pop()
                continue
            break

        key = _read_string(fp)

        if t == BIN_NONE:
            _m = VDFDict()
            stack[-1][key] = _m
            stack.append(_m)
        elif t == BIN_STRING:
            stack[-1][key] = _read_string(fp)
        elif t == BIN_WIDESTRING:
            stack[-1][key] = _read_string(fp, wide=True)
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
            raise VDFDecodeError(f"Unknown data type at offset {fp.tell() - 1}: {t!r}")

    if len(stack) != 1:
        raise VDFDecodeError("Reached EOF, but Binary VDF is incomplete")
    if raise_on_remaining and fp.read(1) != b"":
        fp.seek(-1, 1)
        raise VDFDecodeError(
            f"Binary VDF ended at offset {fp.tell() - 1}, but there is more data remaining"
        )

    return stack.pop()


cpdef bytes binary_dumps(obj, int alt_format=False, int raise_on_remaining=False):
    """Serialize ``obj`` to a binary VDF formatted ``bytes``."""
    buf = BytesIO()
    binary_dump(obj, buf, alt_format, raise_on_remaining)
    return buf.getvalue()


cpdef binary_dump(obj, fp, int alt_format=False, int raise_on_remaining=False):
    """Serialize ``obj`` to a binary VDF formatted :class:`bytes` and write it to a :class:`BufferedIOBase`"""
    fp.write(b"".join(_binary_dumper(obj, list(), alt_format, raise_on_remaining)))


cdef _binary_dumper(obj, list ret, int level = 0, int alt_format = False):
    if level == 0 and len(obj) == 0:
        return
    cdef int32 = struct.Struct("<i")
    cdef uint64 = struct.Struct("<Q")
    cdef int64 = struct.Struct("<q")
    cdef float32 = struct.Struct("<f")

    for key, value in obj.items():
        key = key.encode("utf-8")

        if isinstance(value, Mapping):
            ret.append(BIN_NONE + key + BIN_NONE)
            ret.append(_binary_dumper(value, ret, level + 1, alt_format=alt_format))
        elif isinstance(value, UINT_64):
            ret.append(BIN_UINT64 + key + BIN_NONE + uint64.pack(value))
        elif isinstance(value, INT_64):
            ret.append(BIN_INT64 + key + BIN_NONE + int64.pack(value))
        elif isinstance(value, str):
            try:
                value = value.encode("utf-8") + BIN_NONE
                ret.append(BIN_STRING)
            except UnicodeError:
                value = value.encode("utf-16") + BIN_NONE * 2
                ret.append(BIN_WIDESTRING)
            ret.append(key + BIN_NONE + value)
        elif isinstance(value, float):
            ret.append(BIN_FLOAT32 + key + BIN_NONE + float32.pack(value))
        elif isinstance(value, int):
            if isinstance(value, COLOR):
                ret.append(BIN_COLOUR)
            elif isinstance(value, POINTER):
                ret.append(BIN_POINTER)
            else:
                ret.append(BIN_INT32)
            ret.append(key + BIN_NONE)
            ret.append(int32.pack(value))
        else:
            raise TypeError(f"Unsupported type: {value.__class__}")

    ret.append(BIN_END if not alt_format else BIN_END_ALT)
    return ret


cpdef vbkv_loads(s: bytes, int raise_on_remaining=False):
    """Deserialize bytes containing a VBKV to a Python object.

    mapper: type[:class:`collections.Mapping`]
        A :class:`dict`-like class to be used after deserialization. Default is :class:`VDFDict`.
    """
    if s[:4] != b"VBKV":
        raise ValueError("Invalid header")

    checksum = struct.unpack("<i", s[4:8])[0]

    if checksum != crc32(s[8:]):
        raise ValueError("Invalid checksum")

    return binary_loads(s[8:], alt_format=True, raise_on_remaining=raise_on_remaining)


cpdef vbkv_dumps(obj):
    """Serialize ``obj`` to a VBKV formatted :class:`bytes`."""
    data = b"".join(_binary_dumper(obj, list(), level=0, alt_format=True))  # not too sure why you need to supply level
    checksum = crc32(data)

    return b"VBKV" + struct.pack("<i", checksum) + data
