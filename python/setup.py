#!/usr/bin/env python

from setuptools import setup, find_packages

LONG_DESCRIPTION = """# payjoin
This is a python library which implements payjoin, BIP178. It uses the Rust-based [Payjoin](https://github.com/payjoin/rust-payjoin) 
as the core implementation of BIP178, sourced from the [Payjoin Dev Kit](https://payjoindevkit.org/).

## Install the package
```shell
pip install payjoin
```

## Usage 
```python
import payjoin as payjoin
"""

setup(
    name='payjoin',
    description="The Python language bindings for the Payjoin Dev Kit",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    include_package_data = True,
    zip_safe=False,
    packages=["payjoin"],
    package_dir={"payjoin": "./src/payjoin"},
    version='0.1.0.dev',
    license="MIT or Apache 2.0",
    author="BitcoinZavior",
    author_email="BitcoinZavior@GMail.Com",
    url="https://LtbL.io",
    author_organization="Let there be Lightning, Inc",
    has_ext_modules=lambda: True,
)
