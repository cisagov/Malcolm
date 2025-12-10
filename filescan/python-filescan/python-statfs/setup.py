from setuptools import setup
from setuptools.extension import Extension
from Cython.Build import cythonize

setup(
    name="python-statfs",
    ext_modules=cythonize(
        [
            Extension(
                "statfs",
                ["statfs.pyx"],
            ),
        ]
    ),
)
