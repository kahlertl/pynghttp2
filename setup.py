import os
from setuptools import setup

def read(fname):
    with open(os.path.join(os.path.dirname(__file__), fname)) as fd:
        return fd.read()

setup(
    name='pynghttp2',
    version='0.1.0',
    description='Asyncio bindings for libnghttp2 based on ctypes',
    long_description=read('README.rst'),
    license='MIT',
    author='Lucas Kahlert',
    author_email='lucas.kahlert@square-src.de',
    url='https://github.com/f3anaro/pynghttp2',
    keywords=['HTTP/2', 'nghttp2', 'bindings', 'asyncio', 'ctypes'],
    packages=['pynghttp2'],
    install_requires=[],
    extras_require={
        'dev': [
            'pytest',
            'pytest-asyncio',
            'pytest-timeout',
            'tox',
        ]
    },
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Software Development',
    ],
)
