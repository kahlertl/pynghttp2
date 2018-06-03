import asyncio
import json
import pytest
from pynghttp2 import ClientSession, ServerSession, StreamClosedError, nghttp2


@pytest.mark.asyncio
async def test_connection_refused(event_loop):
    with pytest.raises(ConnectionError):
        async with ClientSession(host='localhost', port=64602, loop=event_loop) as session:
            pass


@pytest.mark.asyncio
async def test_ping(echo_server, event_loop):
    async with echo_server:
        async with ClientSession(host='localhost', port=64602, loop=event_loop) as session:
            assert session.request_allowed() == True, "It must be allowed to send requests"

            resp = session.get('http://localhost:64602/ping')
            assert resp.content.at_eof() == False, "Response must not be at EOF before sending"
            await resp

            assert resp.status == 200
            assert resp.content_length == 4
            assert resp.content_type == 'text/plain'

            # Wait for response content
            pong = await resp.text()
            assert resp.content.at_eof() == True, "Response must be at EOF after receiving"
            assert pong == "pong"

            # Check if content is correctly cached
            pong = await resp.text()
            assert pong == "pong", "Repeated call to read should return identical results"


@pytest.mark.asyncio
async def test_echo(echo_server, event_loop):
    async with echo_server:
        async with ClientSession(host='localhost', port=64602, loop=event_loop) as session:
            msg = b"Hello world!"
            resp = session.post('http://localhost:64602/echo', data=msg)
            await resp
            echo = await resp.read()
            assert echo == msg, "Echo message must be the same"


@pytest.mark.asyncio
async def test_stream(echo_server, event_loop):
    async with echo_server:
        async with ClientSession(host='localhost', port=64602, loop=event_loop) as session:
            resp = session.get('http://localhost:64602/stream')
            await resp

            size = 0
            while not resp.content.at_eof():
                chunk = await resp.content.read(2 ** 16)
                size += len(chunk)

            assert size == resp.content_length


@pytest.mark.asyncio
async def test_interleave_streams(echo_server, event_loop):
    async with echo_server:
        async with ClientSession(host='localhost', port=64602, loop=event_loop) as session:
            stream1 = session.get('http://localhost:64602/stream')
            stream2 = session.get('http://localhost:64602/stream')

            await stream1
            await stream2

            size1 = 0
            size2 = 0
            while not stream1.content.at_eof() or not stream2.content.at_eof():
                if not stream1.content.at_eof():
                    chunk = await stream1.content.read(2 ** 16)
                    size1 += len(chunk)

                if not stream2.content.at_eof():
                    chunk = await stream2.content.read(2 ** 16)
                    size2 += len(chunk)

            assert size1 == stream1.content_length
            assert size2 == stream2.content_length


@pytest.mark.asyncio
async def test_max_concurrect_streams(echo_server, event_loop):
    echo_server.settings = [
        (nghttp2.settings_id.MAX_CONCURRENT_STREAMS, 1),
    ]
    async with echo_server:
        async with ClientSession(host='localhost', port=64602, loop=event_loop) as session:
            resp1 = session.get('http://localhost:64602/ping')
            resp2 = session.get('http://localhost:64602/ping')
            task = await asyncio.gather(resp1, resp2)


@pytest.mark.asyncio
async def test_interleave_streams_with_tasks(echo_server, event_loop):
    async def read_stream(resp):
        size = 0
        await resp

        while not resp.content.at_eof():
            chunk = await resp.content.read(2 ** 14)
            size += len(chunk)

        assert size == resp.content_length

    async with echo_server:
        async with ClientSession(host='localhost', port=64602, loop=event_loop) as session:
            stream1 = session.get('http://localhost:64602/stream')
            stream2 = session.get('http://localhost:64602/stream')

            await asyncio.gather(read_stream(stream1), read_stream(stream2), loop=event_loop)


@pytest.mark.asyncio
async def test_block_stream(echo_server, event_loop):
    async with echo_server:
        async with ClientSession(host='localhost', port=64602, loop=event_loop) as session:
            stream1 = session.get('http://localhost:64602/stream')
            stream2 = session.get('http://localhost:64602/stream')

            await stream1
            await stream2

            # Read stream 2 first. This should block DATA blocks of stream 1
            size2 = 0
            while not stream2.content.at_eof():
                chunk = await stream2.content.read(2 ** 16)
                size2 += len(chunk)

            size1 = 0
            while not stream1.content.at_eof():
                chunk = await stream1.content.read(2 ** 16)
                size1 += len(chunk)

            assert size1 == stream1.content_length
            assert size2 == stream2.content_length


@pytest.mark.asyncio
async def test_json(echo_server, event_loop):
    async with echo_server:
        async with ClientSession(host='localhost', port=64602, loop=event_loop) as session:
            msg = json.dumps({
                "status": "ok",
                "error": None,
            }).encode()

            resp = session.post('http://localhost:64602/echo', data=msg)
            await resp
            echo = await resp.json()
            assert echo["status"] == "ok"
            assert echo["error"] == None

            resp = session.post('http://localhost:64602/echo', data="invalid json")
            await resp
            echo = await resp.json()
            assert echo == None


@pytest.mark.asyncio
async def test_client_terminate(echo_server, event_loop):
    async with echo_server:
        async with ClientSession(host='localhost', port=64602, loop=event_loop) as session:
            await session.terminate()

@pytest.mark.asyncio
async def test_client_terminate_with_request(echo_server, event_loop):
    async with echo_server:
        async with ClientSession(host='localhost', port=64602, loop=event_loop) as session:
            resp = session.get('http://localhost:64602/ping')

            # Terminate the session with a specific error code
            await session.terminate(nghttp2.error_code.INTERNAL_ERROR)

            # The error code is expected in the exception raised by all further operations
            with pytest.raises(ConnectionResetError) as excinfo:
                await resp
                await resp.text()
            assert "INTERNAL_ERROR" in str(excinfo.value)

            with pytest.raises(ConnectionError) as excinfo:
                resp = session.get('http://localhost:64602/ping')

