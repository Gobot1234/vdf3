VDF 3
======

Pure python module for (de)serialization to and from VDF that works just like ``json``.
[VDF is Valve's KeyValue text file format](https://developer.valvesoftware.com/wiki/KeyValues)

Supports:
- ``kv1``

Installation
------------

**Python 3.7 or higher is required**

```sh
pip install git+https://github.com/ValvePython/vdf
```

Example usage
-------------

For text representation.

```py
import vdf

# parsing vdf from file or string
d = vdf.load(open('file.txt'))
d = vdf.loads(vdf_text)
d = vdf.parse(open('file.txt'))
d = vdf.parse(vdf_text)

# dumping dict as vdf to string
vdf_text = vdf.dumps(d)
indented_vdf = vdf.dumps(d, pretty=True)

# dumping dict as vdf to file
vdf.dump(d, open('file2.txt','w'), pretty=True)
```


For binary representation

```py

d = vdf.binary_loads(vdf_bytes)
b = vdf.binary_dumps(d)

# alternative format - VBKV

d = vdf.binary_loads(vdf_bytes, alt_format=True)
b = vdf.binary_dumps(d, alt_format=True)

# VBKV with header and CRC checking

d = vdf.vbkv_loads(vbkv_bytes)
b = vdf.vbkv_dumps(d)
```

Using an alternative mapper

.. code:: python

  d = vdf.loads(vdf_string, mapper=collections.OrderedDict)
