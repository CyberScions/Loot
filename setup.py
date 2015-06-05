#!/usr/bin/env python

from distutils.core import setup
from setuptools import find_packages

setup(name='Loot',
      version='1',
      description='Loot - Extract sensitive information from a file.',
      author='GWF',
      author_email='gwf@gwf.ninja',
      url='https://twitter.com/GuerrillaWF',
      packages=find_packages(),
      scripts = ['loot']
     )
