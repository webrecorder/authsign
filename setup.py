#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# vim: ai ts=4 sts=4 et sw=4 nu

import pathlib
from setuptools import setup, find_packages

from authsign import __version__


def read(*names, **kwargs):
    with open(pathlib.Path(".").joinpath(*names), "r") as fh:
        return fh.read()


setup(
    name="authsign",
    version=__version__,
    description="Authenticating Data Signing + Verification Server",
    long_description=read("README.md"),
    long_description_content_type="text/markdown",
    author="Webrecorder Software",
    author_email="info@webrecorder.net",
    url="https://github.com/ikreymer/authsign",
    packages=find_packages(exclude=["tests"]),
    install_requires=[
        line.strip()
        for line in read("requirements.txt").splitlines()
        if not line.strip().startswith("#")
    ],
    test_requires=["pytest", "pytest-asyncio"],
    zip_safe=True,
    package_data={"authsign.trusted": ["*"]},
    data_files={
        "requirements.txt": "requirements.txt",
        "log.json": "log.json",
    },
    entry_points="""
        [console_scripts]
    """,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)",
    ],
    python_requires=">=3.7",
)
