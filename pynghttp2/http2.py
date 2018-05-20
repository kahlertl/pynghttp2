"""High-Level functions for simple requests

.. code:: python

    from pynghttp2 import http2

    resp = await http2.get("http://localhost:8000/README.rst")
    content = await resp.text()

"""
import asyncio
from urllib.parse import urlparse
from .sessions import ClientSession


async def request(method, url, data=None, host=None, port=None, loop=None):
    if not loop:
        loop = asyncio.get_event_loop()

    _url = urlparse(url)


    if not host:
        host = _url.netloc.split(':')[0]

    if not port:
        if ':' in _url.netloc:
            port = int(_url.netloc.split(':', 1)[1])
        elif _url.scheme == 'https':
            port = 443
        else:
            port = 80

    if _url.scheme == 'https':
        raise NotImplementedError("HTTPS is currently not supported")

    async with ClientSession(host, port, loop=loop) as client:
        resp = client.request(method, url, data=data)
        await resp
        await resp.read()

    return resp


async def get(*args, **kwargs):
    return await request('GET', *args, **kwargs)


async def post(*args, **kwargs):
    return await request('POST', *args, **kwargs)
