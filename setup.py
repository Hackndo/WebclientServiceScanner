#!/usr/bin/env python
# Description:
#   Multithreaded tool to scan for Webclient service "DAV RPC SERVICE" named pipe
#
# Author:
#   pixis (@hackanddo)
#
# Acknowledgments:
#   @tifkin_ https://twitter.com/tifkin_/status/1419806476353298442


import pathlib

from setuptools import setup, find_packages

from webclientservicescanner import __version__

HERE = pathlib.Path(__file__).parent
README = (HERE / "README.md").read_text()

setup(
    name="webclientservicescanner",
    version=__version__,
    author="Pixis",
    author_email="hackndo@gmail.com",
    description="Check running WebClient services on multiple targets",
    long_description=README,
    long_description_content_type="text/markdown",
    packages=find_packages(exclude=["assets",]),
    include_package_data=True,
    url="https://github.com/Hackndo/webclientservicescanner/",
    zip_safe = True,
    license="MIT",
    install_requires=[
        'impacket',
        'netaddr'
    ],
    python_requires='>=3.6',
    classifiers=(
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ),
    entry_points={
        'console_scripts': [
            'webclientservicescanner = webclientservicescanner.console:main',
        ],
    },
)
