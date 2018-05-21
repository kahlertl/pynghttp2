=========
pynghttp2
=========

.. image:: https://travis-ci.org/f3anaro/pynghttp2.svg?branch=master
    :target: https://travis-ci.org/f3anaro/pynghttp2
    :alt: Build Status

.. image:: https://codecov.io/gh/f3anaro/pynghttp2/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/f3anaro/pynghttp2
    :alt: Code Coverage

.. image:: https://readthedocs.org/projects/pynghttp2/badge/?version=latest
    :target: http://pynghttp2.readthedocs.io/en/latest/?badge=latest
    :alt: Documentation Status

pynghttp2 are simple asyncio Python bindings based on ctypes for the nghttp2_
library. The only thing you need is a ``libnghttp2`` version on your system.

On Debian-based systems you can install nghttp2 simply via apt:

.. code:: bash

    apt-get install libnghttp2-14

The project was created in the context of a student work for an HTTP/2 protocol
gateway in the µPCN_ project - an implementation of Delay-tolerant Networking
(DTN) protocols.


Installation
============

.. code:: bash

    pip install pynghttp2


Examples
========

High-Level API
--------------

.. code:: python

    from pynghttp2 import http2

    # GET request
    resp = await http2.get('http://localhost:64602/ping')

    content = await resp.text()
    assert content == 'pong'

    # POST request
    message = b"Lorem ipsum dolorem"
    resp = await http2.post('http://localhost:64602/echo', data=message)
    echo = await resp.read()
    assert echo == message


Client Session
--------------

.. code:: python

    from pynghttp2 import ClientSession

    # Multiplex two requests
    async with ClientSession(host='localhost', port=64602) as session:
        stream1 = session.get('http://localhost:64602/stream')
        stream2 = session.get('http://localhost:64602/stream')

        await asyncio.gather(stream1.read(), stream2.read())


Server Session
--------------

.. code:: python

    import asyncio
    from pynghttp2 import ServerSession

    async def handle_request(req):
        """Echo the request body"""
        msg = await req.read()
        await req.response(200, data=msg)

    with ServerSession(host='localhost', port=8080) as session:
        while True:
            # Wait for next incoming request
            req = await session

            # Handle each request in its own task to be able to multiplex
            # multiple requests and responses
            asyncio.ensure_future(handle_request(req))


.. _nghttp2: https://nghttp2.org/
.. _µPCN: https://upcn.eu/