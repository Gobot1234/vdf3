# -*- coding: utf-8 -*-

# -*- coding: utf-8 -*-

import pathlib
import re

from setuptools import setup

ROOT = pathlib.Path(__file__).parent


with open(ROOT / "vdf" / "__init__.py") as f:
    try:
        VERSION = re.findall(r'^__version__\s*=\s*"([^"]*)"', f.read(), re.MULTILINE)[0]
    except IndexError:
        raise RuntimeError("Version is not set")

if VERSION.endswith(("a", "b")) or "rc" in VERSION:
    # try to find out the commit hash if checked out from git, and append
    # it to __version__ (since we use this value from setup.py, it gets
    # automatically propagated to an installed copy as well)
    try:
        import subprocess

        out = subprocess.getoutput("git rev-list --count HEAD")
        if out:
            version = f"{VERSION}{out.strip()}"
        out = subprocess.getoutput("git rev-parse --short HEAD")
        if out:
            version = f"{VERSION}+g{out.strip()}"
    except Exception:
        pass

with open(ROOT / "README.md", encoding="utf-8") as f:
    README = f.read()


setup(
    name="vdf3",
    author="Gobot1234",
    url="https://github.com/Gobot1234/vdf3",
    project_urls={
        "Code": "https://github.com/Gobot1234/vdf3",
        "Issue tracker": "https://github.com/Gobot1234/vdf3/issues",
    },
    version=VERSION,
    packages=["vdf"],
    license="MIT",
    description="Library for working with Valve's VDF text format",
    requires=["multidict"],
    long_description=README,
    long_description_content_type="text/markdown",
    include_package_data=True,
    python_requires=">=3.7.0",
    download_url=f"https://github.com/Gobot1234/vdf3/archive/{VERSION}.tar.gz",
    keywords="valve keyvalue vdf tf2 dota2 csgo",
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Software Development :: Libraries",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Typing :: Typed",
    ],
)
