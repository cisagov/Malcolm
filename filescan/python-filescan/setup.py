#!/usr/bin/env python3
import setuptools

setuptools.setup(
    name='filescan',
    version='0.1a',
    author='FIXME',
    description='FIXME',
    license='FIXME',
    packages=setuptools.find_packages(),
    scripts=[
        'bin/filescan_watcher',
        'bin/filescan_scanner_strelka',
        'bin/filescan_logger',
    ],
)
