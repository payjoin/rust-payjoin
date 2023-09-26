#!/usr/bin/env python

from setuptools import setup, find_packages

LONG_DESCRIPTION = """# bdkpython
This repository creates libraries for various programming languages, all using the Rust-based [Payjoin](https://github.com/payjoin/rust-payjoin) 
as the core implementation of BIP178, sourced from the [Payjoin Dev Kit](https://payjoindevkit.org/).

## Install the package
```shell
pip install pdkpython
```

## Usage 
```python
import pdkpython as bdk
"""

setup(
    name='pdkpython',
    description="The Python language bindings for the Payjoin Dev Kit",
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    include_package_data = True,
    zip_safe=False,
    packages=["pdkpython"],
    package_dir={"pdkpython": "./src/pdkpython"},
    version='0.1.0.dev',
    license="MIT or Apache 2.0",
    has_ext_modules=lambda: True,
)
