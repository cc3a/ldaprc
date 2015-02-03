#!/usr/bin/env python
# -*- Mode: Python; py-indent-offset: 4; coding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 expandtab

## Copyright (C) 2014, University of Zurich and ETH Zurich
## Copyright (C) 2014, Claudio Luck <cluck@ini.uzh.ch>

## Licensed under the terms of the MIT License, see LICENSE file.

from __future__ import print_function

import os
import sys
import codecs
import re

try:
    from configparser import RawConfigParser
except ImportError:
    from ConfigParser import RawConfigParser

try:
    from setuptools import setup
except ImportError:
    if __name__ == "__main__":
        sys.stderr.write("setuptools missing: run `make preare' first\n")
    raise

from setuptools.command.test import test as TestCommand

pth = os.path.dirname(__file__)
with codecs.open(os.path.join(pth, 'ldaprc', '__init__.py')) as init:
    METADATA = dict(re.findall("__([A-Za-z][A-Za-z0-9_]+)__\s*=\s*'([^']+)'", init.read().decode('utf-8')))

if sys.version_info < (3, ):
    extra = {}
else:
    extra = {
        'use_2to3': True,
        'convert_2to3_doctests': ['README.rst'],
    }

README=codecs.open('README.rst', encoding='utf-8').read()

TESTS_REQUIRE = ['pytest']
tox = RawConfigParser() ; tox.read('tox.ini')
for line in tox.get('testenv', 'x_tests_require').split('\n'):
    dep = line.split('#', 1)[0].strip()
    if dep and dep not in TESTS_REQUIRE:
        TESTS_REQUIRE.append(dep)

class PyTest(TestCommand):
    user_options = [('pytest-args=', 'a', "Arguments to pass to py.test")]

    def initialize_options(self):
        TestCommand.initialize_options(self)
        self.pytest_args = []

    def finalize_options(self):
        TestCommand.finalize_options(self)
        self.test_args = []
        self.test_suite = True

    def run_tests(self):
        # Now install_requires are ready:
        import pytest
        errno = pytest.main(self.pytest_args)
        sys.exit(errno)


setup(name='ldaprc',
    version=METADATA['version'],
    description='ldaprc',
    long_description=README,
    author = METADATA['author'],
    author_email = METADATA['author_email'],
    maintainer = 'Claudio Luck',
    maintainer_email = 'claudio.luck@gmail.com',
    url='http://www.ini.uzh.ch',
    license='MIT',
    packages=['ldaprc'],
    tests_require=TESTS_REQUIRE,
    cmdclass={
        "test": PyTest,
    },
    include_package_data=True,
    platforms=["any"],
    classifiers=[
        'Programming Language :: Python',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Development Status :: 3 - Alpha',
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'Topic :: Software Development :: Libraries :: Python Modules',
    ],
    **extra
)

