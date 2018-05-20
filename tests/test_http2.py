import pytest
from pynghttp2 import http2
import json


@pytest.mark.asyncio
async def test_get(echo_server, event_loop):
    async with echo_server:
        resp = await http2.get('http://localhost:64602/ping', loop=event_loop)
        pong = await resp.text()
        assert pong == "pong"


@pytest.mark.asyncio
async def test_post(echo_server, event_loop):
    async with echo_server:
        message = b"Lorem ipsum dolorem"
        resp = await http2.post('http://localhost:64602/echo', data=message, loop=event_loop)
        echo = await resp.read()
        assert echo == message


@pytest.mark.asyncio
async def test_custom_url(echo_server, event_loop):
    async with echo_server:
        resp = await http2.get('dtn://groundstation1/ping',
                               host='localhost', port=64602, loop=event_loop)
        pong = await resp.text()
        assert pong == "pong"


@pytest.mark.asyncio
async def test_default_ports():
    with pytest.raises(ConnectionError):
        resp = await http2.get('http://localhost/ping')


@pytest.mark.asyncio
async def test_default_event_loop(echo_server):
    async with echo_server:
        resp = await http2.get('http://localhost:64602/ping')
        pong = await resp.text()
        assert pong == "pong"


@pytest.mark.asyncio
async def test_https_fail(event_loop):
    with pytest.raises(NotImplementedError):
        resp = await http2.get('https://localhost/', loop=event_loop)
