#!/usr/bin/env python
import os
from setuptools import setup, find_packages


def get_version():
    root_dir = os.path.dirname(os.path.abspath(__file__))
    return open(os.path.join(root_dir, 'VERSION')).read().strip()


with open('requirements.txt') as f:
    requirements = f.read().splitlines()

setup(
    name='shadowline',
    version=get_version(),
    python_requires='>=3.5',
    description=(
        'A Python CLI library for interfacing with the Digital Shadows Portal API.'
    ),
    long_description='A Python CLI library for interfacing with the Digital Shadows Portal API.',
    install_requires=requirements,
    author='Richard Gold',
    author_email='richard.gold@digitalshadows.com',
    license='Copyright (c) 2019 Digital Shadows Ltd',
    copyright='Copyright (c) 2019 Digital Shadows Ltd',
    packages=find_packages(),
    entry_points = {
        'console_scripts': ['shadowline=shadowline.shadowline:main'],
    },
    url="https://www.digitalshadows.com/",
    platforms="linux",
)
