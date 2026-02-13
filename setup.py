#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from setuptools import setup, find_packages
from os import path
import io

VERSION = '1.0.1' 
DESCRIPTION = 'postleaksNg'

pwd = path.abspath(path.dirname(__file__))
with io.open(path.join(pwd, "README.md"), encoding="utf-8") as readme:
    LONG_DESCRIPTION = readme.read()

setup(
    name="postleaksNg", 
    version=VERSION,
    author="Sébastien Copin",
    author_email="cosad3s@outlook.com",
    license="GPL-3.0 License",
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type="text/markdown",
    packages=find_packages(),
    package_data={
        '': ['config.yml'],
    },
    install_requires=["requests", "argparse", "whispers"],
    url="https://github.com/six2dez/postleaksNg",
    keywords=['leaks', 'postman', 'osint', 'bugbounty'],
    entry_points={
        "console_scripts": [
            "postleaksNg = postleaksNg.__main__:main"
        ]
    },
    include_package_data = True,
    classifiers= [
        "Topic :: Internet :: WWW/HTTP :: Indexing/Search",
        "Topic :: Security",
        "Programming Language :: Python :: 3"
    ]
)