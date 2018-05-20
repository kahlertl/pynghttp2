import os
from setuptools import setup

def read(fname):
    with open(os.path.join(os.path.dirname(__file__), fname)) as fd:
        return fd.read()

setup(
    name='pynghttp2',
    version='0.1.0',
    description='Ctypes bindings for libnghttp2',
    long_description=read('README.rst'),
    license='MIT',
    author='Lucas Kahlert',
    author_email='lucas.kahlert@square-src.de',
    url='https://github.com/f3anaro/pynghttp2',
    keywords=['HTTP/2', 'nghttp2', 'bindings', ],
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
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: Implementation :: CPython',
        'Programming Language :: Python :: Implementation :: PyPy',
        'Topic :: Software Development',
    ],
)
