# -*- coding: utf-8 -*-

import os

from setuptools import setup, find_packages

requires = []
tests_require=[
    'nose',
    'coverage'
]

here = os.path.dirname(__file__)
def _read(name):
    try:
        return open(os.path.join(here, name)).read()
    except:
        return ""


readme = _read("README.md")
license = _read("LICENSE.md")

setup(
    name='oidc',
    version='0.0.1',
    test_suite='oidc',
    author='Kohei YOSHIDA',
    author_email='kohei.yoshida@gehirn.co.jp',
    description='OpenID Connect library for Python 3.',
    long_description=readme,
    license=license,
    url='https://github.com/GehirnInc/python-oidc',
    packages=find_packages(),
    install_requires=requires,
    tests_require=tests_require,
)
