#!/usr/bin/env python
"""Setup code for module."""
import io
import os
import re
import sys

from setuptools import setup


def get_version():
    """Get current version from code."""
    regex = r"__version__\s=\s\"(?P<version>[\d\.]+?)\""
    path = ("pyfireservicerota", "__version__.py")
    return re.search(regex, read(*path)).group("version")


def read(*parts):
    """Read file."""
    filename = os.path.join(os.path.abspath(os.path.dirname(__file__)), *parts)
    sys.stdout.write(filename)
    with io.open(filename, encoding="utf-8", mode="rt") as fp:
        return fp.read()


with open("README.md") as readme_file:
    readme = readme_file.read()

setup(
    author="Ron Klinkien",
    author_email="ron@cyberjunky.nl",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    description="Python 3 API wrapper for FireServiceRota/BrandweerRooster",
    name="pyfireservicerota",
    keywords=["fireservicerota", "brandweerrooster", "api", "client"],
    license="MIT license",
    long_description_content_type="text/markdown",
    long_description=readme,
    url="https://github.com/cyberjunky/python-fireservicerota",
    packages=["pyfireservicerota"],
    version=get_version(),
    install_requires=[
       'pytz',
       'oauthlib',
       'requests',
       'websocket-client',
    ]
)
